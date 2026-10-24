"""Honeytoken listener (Flask): hidden decoy endpoints that no legitimate
visitor has a reason to touch.

* ``create_app()``       - the lightweight listener used by ``agent-watch serve``.
* ``agentwatch.honeypot`` - extends this same app with a fuller decoy site.

Safety properties (enforced here and covered by tests):
  * binds to 127.0.0.1 by default; non-loopback needs an explicit flag;
  * serves only synthetic, unusable content; makes NO outbound requests;
  * request bodies are read at most MAX_BODY_BYTES+1 bytes; every logged
    field is sanitised and length-capped (no log injection);
  * credential-bearing headers are redacted, never stored;
  * the JSONL file is size-capped and created with mode 0600;
  * the tarpit (optional) is hard-capped at MAX_TARPIT_S per response and
    limited to a few concurrent delayed responses.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json as _json
import os
import re
import secrets
import threading
from collections import OrderedDict
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from flask import Flask, Response, g, has_request_context, jsonify, request
from markupsafe import escape
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from . import frontier
from .scrubber import Scrubber, get_default_scrubber
from .state import StateStore
from .leads import (DEFAULT_MAX_LOG_BYTES, MAX_BODY_BYTES, MAX_PATH, LeadWriter,
                    make_lead, sanitize_headers, sanitize_query, sanitize_text, utc_iso)

BEACON_PATH = "/api/v1/telemetry/nav"     # v4: minimal interaction beacon; v6: challenge proof + five booleans (six stored)
BEACON_KEYS = ("webdriver_present", "pointer_trail_seen", "dom_automation_props")   # v4 keys (required in every beacon)
BEACON_MAX_BYTES = 512
BEACON_RATE_PER_MIN = 60
BEACON_RATE_MAX_KEYS = 2000
# v4 inline script (kept for reference / tests; v6 pages embed frontier.beacon_script()).  On a click on an internal link it POSTs ONE small JSON object with three booleans:
# navigator.webdriver === true; whether pointer/touch movement happened before the click; whether Playwright/CDP-style
# globals exist on window.  No identifiers, no fingerprinting surface beyond these three bits, no third-party requests.
BEACON_SCRIPT = (
    "<script>(function(){var m=0,f=function(){m=1};"
    "addEventListener('pointermove',f,{passive:true});addEventListener('touchmove',f,{passive:true});"
    "addEventListener('touchstart',f,{passive:true});"
    "addEventListener('click',function(e){var t=e.target,a=t&&t.closest&&t.closest('a[href^=\"/\"]');if(!a)return;"
    "var p=false;try{for(var k in window){if(/^(__playwright|__pw|cdc_|\\$cdc_|__nightmare|_phantom|callPhantom|__selenium|__webdriver)/.test(k)){p=true;break}}}catch(_){}"
    "try{fetch('" + BEACON_PATH + "',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',keepalive:true,"
    "body:JSON.stringify({webdriver_present:navigator.webdriver===true,pointer_trail_seen:!!m,dom_automation_props:p})})}catch(_){}"
    "},true)})();</script>"
)
SCHEMA_PARAM = "client_schema_rev"        # camouflaged, required-looking parameter advertised only in /openapi.json
SCHEMA_PARAM_DEFAULT = "2026.04-ai"       # its "default" value in the decoy schema
ACCESS_SCHEMA = "agentwatch.access/1"     # mirrored request stream (every request, decoy or not)
MAX_LINKS_PER_RESPONSE = 60
MIRROR_HEADERS = ("accept", "accept-language", "accept-encoding", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
                  "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
                  "dnt", "connection")
_ANCHOR = re.compile(r"<a\s[^>]*?href\s*=\s*(?:'([^']*)'|\"([^\"]*)\")", re.I)
_PATHLIKE = re.compile(r"(?:^|[\s\"'(\[])(/[A-Za-z0-9_\-./]{1,100})")
_SESSION_CANARY = re.compile(r"sc-[0-9a-f]{10}")
_JA4 = re.compile(r"^[tqd][0-9]{2}[di][0-9]{2}[0-9]{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
MAX_CONTENT_LENGTH = 16 * 1024   # WSGI-level cap on any request body (413 beyond this)
MAX_TARPIT_S = 10.0            # absolute per-response cap, regardless of settings
MAX_TARPIT_CONCURRENT = 4
ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
FAKE_KEY_PREFIX = "AWFAKE-DO-NOT-USE-"
FAKE_USER = "svc_synthetic_backup"


# --------------------------------------------------------------------------
# registry of decoys / tokens
# --------------------------------------------------------------------------
@dataclass
class Decoy:
    name: str
    kind: str
    token_id: str
    path: str
    description: str = ""


@dataclass
class Canary:
    slug: str
    canary_id: str      # used in /canary/<id>
    token_id: str
    phrase: str         # unique text planted in the page body


_WORDS = ("maple", "otter", "cobalt", "juniper", "saffron", "tundra", "quartz", "willow")


class DecoyRegistry:
    """Creates and remembers unique token ids, fake keys and canary phrases.

    Token ids are HMAC(secret, name): stable for a given seed (handy for
    tests / reproducible demos), unpredictable when no seed is given.
    """

    def __init__(self, seed: Optional[str] = None) -> None:
        self._secret = (seed or secrets.token_hex(16)).encode()
        self.decoys: dict[str, Decoy] = {}
        self.fake_keys: dict[str, str] = {}        # fake key -> token_id
        self.fake_passwords: dict[str, str] = {}   # fake password -> token_id
        self.canaries: dict[str, Canary] = {}      # canary_id -> Canary
        self.tool_canaries: dict[str, Canary] = {}  # canaries planted in decoy MCP tool responses (checked on echo)

    def _digest(self, label: str) -> str:
        return hmac.new(self._secret, label.encode(), hashlib.sha256).hexdigest()

    digest = _digest   # public alias used by the decoy modules

    def token_id(self, name: str, prefix: str = "ht") -> str:
        return f"{prefix}-{self._digest(name)[:12]}"

    def add_decoy(self, name: str, kind: str, path: str, description: str = "") -> Decoy:
        d = Decoy(name, kind, self.token_id(name), path, description)
        self.decoys[name] = d
        return d

    def fake_key(self, name: str) -> str:
        """An obviously synthetic API key that maps back to a token id."""
        key = f"{FAKE_KEY_PREFIX}{self._digest('key:' + name)[:16].upper()}"
        self.fake_keys[key] = self.token_id("key:" + name, "ck")
        return key

    def fake_password(self, name: str) -> str:
        pw = f"NOT-A-REAL-PASSWORD-{self._digest('pw:' + name)[:8]}"
        self.fake_passwords[pw] = self.token_id("pw:" + name, "cp")
        return pw

    def add_canary(self, slug: str) -> Canary:
        h = self._digest("canary:" + slug)
        word = _WORDS[int(h[12:14], 16) % len(_WORDS)]
        c = Canary(slug, h[:12], f"cn-{h[:12]}", f"AWCANARY-{h[16:24]}-{word}")
        self.canaries[c.canary_id] = c
        return c

    def add_tool_canary(self, name: str) -> Canary:
        """Canary phrase returned by a decoy MCP tool; presenting it anywhere later is a canary_phrase_echo."""
        h = self._digest("toolcanary:" + name)
        word = _WORDS[int(h[12:14], 16) % len(_WORDS)]
        c = Canary(name, h[:12], f"cn-{h[:12]}", f"AWCANARY-{h[16:24]}-{word}")
        self.tool_canaries[c.canary_id] = c
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "decoys": [d.__dict__ for d in self.decoys.values()],
            "canaries": [c.__dict__ for c in self.canaries.values()],
            "tool_canaries": [c.__dict__ for c in self.tool_canaries.values()],
            "fake_keys": dict(self.fake_keys),
            "fake_passwords": dict(self.fake_passwords),
            "note": "all values are synthetic and unusable",
        }


# --------------------------------------------------------------------------
# tarpit (optional, always capped)
# --------------------------------------------------------------------------
class Tarpit:
    """Per-IP growing delay for decoy responses, hard-capped.

    delay = min(max_s, base_s * hits_from_this_ip).  Disabled when base_s == 0.
    At most MAX_TARPIT_CONCURRENT responses are delayed at once so the
    tarpit cannot be turned into a resource-exhaustion vector.
    """

    def __init__(self, base_s: float = 0.0, max_s: float = 5.0,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.base_s = max(0.0, base_s)
        self.max_s = min(max(0.0, max_s), MAX_TARPIT_S)
        self._sleep = sleep
        self._hits: dict[str, int] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_TARPIT_CONCURRENT)

    def delay_for(self, ip: str) -> float:
        if self.base_s <= 0:
            return 0.0
        with self._lock:
            if len(self._hits) > 10_000:       # bound memory
                self._hits.clear()
            n = self._hits[ip] = self._hits.get(ip, 0) + 1
        return min(self.max_s, self.base_s * n)

    def apply(self, delay: float) -> None:
        if delay <= 0 or not self._slots.acquire(blocking=False):
            return
        try:
            self._sleep(min(delay, MAX_TARPIT_S))
        finally:
            self._slots.release()


# --------------------------------------------------------------------------
# recorder
# --------------------------------------------------------------------------
_TOKEN_JSON = re.compile(r'("(?:handoff_token|nonce)"\s*:\s*")([^"\\]{1,200})(")')
_TOKEN_QS = re.compile(r"(?<![A-Za-z0-9_])((?:handoff_)?token|nonce)=([^&\s]{1,200})")


def ref(prefix: str, value: str, n: int = 12) -> str:
    """Stable, non-reversible reference id for a secret value (the raw value is never logged)."""
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:n]}"


def redact_board_tokens(text: str) -> str:
    """Replace coordination-board handoff tokens/nonces by reference ids (no raw values on disk)."""
    text = _TOKEN_JSON.sub(lambda m: f"{m.group(1)}[ref:{ref('t', m.group(2))}]{m.group(3)}", text)
    return _TOKEN_QS.sub(lambda m: f"{m.group(1)}=[ref:{ref('t', m.group(2))}]", text)


@dataclass
class Context:
    """Shared per-app state, available as ``app.extensions['agentwatch']``."""
    registry: DecoyRegistry
    writer: LeadWriter
    tarpit: Tarpit
    clock: Callable[[], datetime]
    body_cap: int = MAX_BODY_BYTES
    decoy_endpoints: set[str] = field(default_factory=set)
    extra_disallow: list[str] = field(default_factory=list)    # extensions add robots.txt Disallow paths
    extra_home_html: list[str] = field(default_factory=list)   # extensions add visible home-page links
    app: Optional[Flask] = None
    # last response (time, bytes) per client session, for the timing fields of leads (bounded)
    last_seen: "OrderedDict[str, tuple[datetime, int]]" = field(default_factory=OrderedDict)
    state: Optional[StateStore] = None
    scrubber: Optional[Scrubber] = None
    trust_forwarded_for: bool = False   # test/simulation hook, OFF by default, separate from behind_proxy
    behind_proxy: bool = False          # werkzeug ProxyFix active (remote_addr already corrected)
    access_writer: Optional[LeadWriter] = None   # mirrored request stream (every request); None = disabled
    _seen_lock: threading.Lock = field(default_factory=threading.Lock)
    beacon_rate: Any = None             # v6: frontier.LRURateLimiter for the beacon endpoint
    llm_rate: Any = None                # v6: frontier.LRURateLimiter for the chat-completions decoy

    def decoy_route(self, rule: str, decoy: Decoy) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a view for *rule* as a decoy endpoint (all common methods)."""
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            assert self.app is not None
            endpoint = f"decoy_{decoy.name}_{len(self.decoy_endpoints)}"
            self.decoy_endpoints.add(endpoint)
            return self.app.route(rule, methods=ALL_METHODS, endpoint=endpoint, strict_slashes=False)(fn)
        return deco

    # ---- request capture -------------------------------------------------
    # ---- request capture -------------------------------------------------
    def read_body(self, cap: Optional[int] = None) -> bytes:
        """Request body, read at most ``cap + 1`` bytes (memoised per request).

        ``cap`` defaults to the global body cap; endpoints that legitimately take larger bodies
        (the coordination board) call this first with their own, still bounded, cap.
        """
        if "agentwatch_body" in g:
            return g.agentwatch_body  # type: ignore[no-any-return]
        cap = min(self.body_cap if cap is None else cap, MAX_CONTENT_LENGTH)
        body = b""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                if request.content_length is not None and request.content_length <= cap:
                    body = request.get_data(cache=True)             # small, declared length
                else:
                    body = request.stream.read(cap + 1)             # never reads more than cap+1
            except RequestEntityTooLarge:                           # MAX_CONTENT_LENGTH enforced by werkzeug
                body = b""
                g.body_too_large = True
        g.agentwatch_body = body
        return body

    # ---- mirrored access stream + session canary --------------------------------------------------------
    def session_canary(self) -> str:
        """Per-session value served only inside machine-readable docs (/openapi.json); presenting it proves the client
        parsed that body and reused the value.  Unpredictable to clients (HMAC of the session id)."""
        return "sc-" + self.registry.digest("canary:" + self.session_id())[:10]

    @staticmethod
    def extract_links(resp: Response) -> Optional[list[str]]:
        """Local paths this response offers the client: <a href> for HTML; path-like strings for JSON/text docs
        (OpenAPI paths, llms.txt links, error-body diagnostic URLs).  Paths only, deduplicated, capped."""
        if resp.direct_passthrough or resp.mimetype not in ("text/html", "application/json", "text/plain", "application/yaml"):
            return None
        body = resp.get_data()[:65536].decode("utf-8", "replace")
        found: list[str] = []
        if resp.mimetype == "text/html":
            cands = [a or b for a, b in _ANCHOR.findall(body)]
        else:
            cands = _PATHLIKE.findall(body)
        for c in cands:
            if not c.startswith("/") or c.startswith("//"):
                continue
            path = c.split("#", 1)[0].split("?", 1)[0]
            if path and path not in found:
                found.append(sanitize_text(path, MAX_PATH))
            if len(found) >= MAX_LINKS_PER_RESPONSE:
                break
        return found

    def mirror(self, resp: Response, lead_event_id: Optional[str]) -> None:
        """Write every request to the mirrored access stream (gateway-style JSON line, scrubbed by the writer).

        This is what lets passive detectors (asset starvation, unlinked jumps, timing) see requests that never touch a
        decoy.  ``links`` records what this response offered the client (the honeypot serves its own pages, so the
        link graph is known exactly).  Query strings pass through the scrubber like everything else on disk."""
        if self.access_writer is None:
            return
        raw_q = redact_board_tokens(sanitize_text(request.query_string.decode("utf-8", "replace"), MAX_PATH))
        hdrs = {h: sanitize_text(request.headers.get(h, ""), 200) for h in MIRROR_HEADERS if request.headers.get(h)}
        rec: dict[str, Any] = {
            "schema": ACCESS_SCHEMA,
            "timestamp": utc_iso(self.clock()),
            "client_ip": sanitize_text(self.client_ip(), 64),
            "method": sanitize_text(request.method, 16),
            "path": sanitize_text(request.path, MAX_PATH),
            "query": raw_q,
            "status": resp.status_code,
            "bytes": resp.calculate_content_length() or 0,
            "user_agent": sanitize_text(request.headers.get("User-Agent", ""), 300),
            "referer": sanitize_text(request.headers.get("Referer", ""), 300),
            "headers": hdrs,
            "content_type": resp.mimetype,
            "links": self.extract_links(resp),
        }
        if lead_event_id:
            rec["lead_event_id"] = lead_event_id
        if g.get("beacon_offered"):
            rec["beacon_script"] = True                  # this response embedded the interaction beacon (so one is expected)
        if g.get("beacon"):
            rec["beacon"] = g.beacon                     # exactly the six validated booleans (v6; v4 had three)
        if g.get("cursor_required") or g.get("cursor_prov"):
            rec["cursor_prov"] = g.get("cursor_prov")    # v6: "html" | "schema" | None (cursor-bearing routes only)
        if g.get("signals"):
            rec["signals"] = sorted(set(g.signals))      # v6 event-contract signal names seen on this request
        if self.behind_proxy:       # JA4 is only trustworthy when set by an edge we control (see docs/ja4-tls-fingerprinting.md)
            ja4 = request.headers.get("X-JA4", "").strip()
            if _JA4.match(ja4):
                rec["ja4"] = ja4
        self.access_writer.write(rec)

    def client_ip(self) -> str:
        """Source IP: the socket peer.  Only if ``trust_forwarded_for`` is on (OFF by default) the first
        valid address in X-Forwarded-For is used instead - intended for tests/simulations or a trusted
        reverse proxy, because any client can forge that header."""
        peer = request.remote_addr or "unknown"
        if self.trust_forwarded_for and not self.behind_proxy:
            first = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            try:
                return str(ipaddress.ip_address(first))
            except ValueError:
                pass
        return peer

    def session_key(self) -> str:
        return f"{self.client_ip()}|{request.headers.get('User-Agent', '')}"

    def session_id(self) -> str:
        """Stable 10-hex id for the current client session (IP + User-Agent), unpredictable to clients."""
        return self.registry.digest("sess:" + self.session_key())[:10]

    # ---- per-client memory of which decoy kinds were already touched (shared across workers) -------
    def _keys(self) -> list[str]:
        return [f"s:{self.session_id()}", f"i:{self.client_ip()}"]

    def remember_hit(self, kind: str) -> None:
        if self.state is not None:
            self.state.add_hit(self._keys(), kind)

    def prior_hit_kinds(self) -> set[str]:
        """Decoy kinds this session or this IP already touched (before the current request)."""
        return self.state.hit_kinds(self._keys()) if self.state is not None else set()

    def timing_snapshot(self) -> dict[str, Any]:
        """Seconds since this session's previous response and that response's size."""
        with self._seen_lock:
            prev = self.last_seen.get(self.session_key())
        if prev is None:
            return {"since_prev_response_s": None, "prev_response_bytes": None, "approx_prev_tokens": None}
        at, size = prev
        return {"since_prev_response_s": round((self.clock() - at).total_seconds(), 3),
                "prev_response_bytes": size, "approx_prev_tokens": round(size / 4)}

    def note_response(self, size: int) -> None:
        with self._seen_lock:
            key = self.session_key()
            self.last_seen[key] = (self.clock(), size)
            self.last_seen.move_to_end(key)
            while len(self.last_seen) > 5000:
                self.last_seen.popitem(last=False)

    def flush_pending(self, resp: Response) -> None:
        """Complete and write the lead recorded during this request (needs the response size)."""
        size = resp.calculate_content_length() or 0
        lead = g.pop("pending_lead", None)
        g.last_lead_id = lead["event_id"] if lead is not None else None
        if lead is not None:
            lead["request"]["response_bytes"] = size
            lead["request"]["response_status"] = resp.status_code
            self.writer.write(lead)
        self.note_response(size)

    def capture_request(self, status: int) -> dict[str, Any]:
        """Sanitised, capped snapshot of the current Flask request."""
        body = self.read_body()
        truncated = len(body) > self.body_cap or bool(g.get("body_too_large"))
        preview = sanitize_text(body[: self.body_cap].decode("utf-8", "replace"), self.body_cap)
        if g.get("omit_body_preview"):      # v6: beacon leads never store the beacon body (booleans only, see telemetry_nav)
            preview = "[omitted: beacon body is never stored]"
        headers = list(request.headers.items())
        board = request.path.startswith("/api/v1/coordination-board")
        if board:
            preview = redact_board_tokens(preview)
        raw_query = sanitize_text(request.query_string.decode("utf-8", "replace"), MAX_PATH)
        query = sanitize_query({k: v for k, v in request.args.lists()})
        if board:
            raw_query = redact_board_tokens(raw_query)
            query = {k: [f"[ref:{ref('t', v)}]" if k in ("token", "nonce", "handoff_token") else v for v in vs]
                     for k, vs in query.items()}
        return {
            "method": sanitize_text(request.method, 16),
            "path": sanitize_text(request.path, MAX_PATH),
            "raw_query": raw_query,
            "query": query,
            "headers": sanitize_headers(headers),
            "user_agent": sanitize_text(request.headers.get("User-Agent", ""), 300),
            "referer": sanitize_text(request.headers.get("Referer", ""), 300),
            "body_preview": preview,
            "body_bytes_read": min(len(body), self.body_cap),
            "body_truncated": truncated,
            "content_length": request.content_length,
            "response_status": status,
        }

    def scan_matches(self, snap_text_sources: Sequence[str]) -> dict[str, list[str]]:
        """Find decoy credentials / canary phrases presented by the client."""
        hay = "\n".join(snap_text_sources)
        creds = [t for k, t in self.registry.fake_keys.items() if k in hay]
        creds += [t for p, t in self.registry.fake_passwords.items() if p in hay]
        canaries = [c.token_id for c in (*self.registry.canaries.values(), *self.registry.tool_canaries.values())
                    if c.phrase in hay]
        return {"credential_token_ids": sorted(set(creds)), "canary_ids": sorted(set(canaries))}

    # ---- recording ---------------------------------------------------------
    def record(self, *, decoy_name: str, kind: str, token_id: str, status: int = 200,
               event_type: str = "honeytoken_hit", priority: str = "high",
               tags: Optional[list[str]] = None, detail: Optional[dict[str, Any]] = None,
               extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Write one lead/context event for the current request and return it.

        ``extra`` adds already-sanitised top-level structures (``coordination``, ``cognitive_capture``)."""
        snap = self.capture_request(status)
        # scan the RAW credential headers too (they are redacted in the snapshot)
        raw_sources = [request.headers.get(h, "") for h in ("Authorization", "X-API-Key", "Api-Key", "Cookie")]
        raw_sources += [snap["raw_query"], snap["body_preview"]]
        matches = self.scan_matches(raw_sources)
        delay = self.tarpit.delay_for(self.client_ip()) if priority == "high" else 0.0
        all_tags = list(tags or [])
        if matches["credential_token_ids"]:
            all_tags.append("decoy_credential_presented")
        if matches["canary_ids"]:
            all_tags.append("canary_phrase_presented")
        lead = make_lead(
            now=self.clock(), source_ip=self.client_ip(), decoy_name=decoy_name,
            kind=kind, token_id=token_id, request=snap, event_type=event_type, priority=priority,
            matches=matches, tags=all_tags, tarpit_delay_s=delay,
            detail=detail, timing=self.timing_snapshot(), extra=extra,
        )
        if event_type == "honeytoken_hit":
            self.remember_hit(kind)
        g.pending_lead = lead          # written by flush_pending() once the response size is known
        g.lead_logged = True
        self.tarpit.apply(delay)
        return lead

    def hit(self, decoy: Decoy, status: int = 200, tags: Optional[list[str]] = None,
            detail: Optional[dict[str, Any]] = None, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Record a high-priority lead for a decoy endpoint."""
        return self.record(decoy_name=decoy.name, kind=decoy.kind, token_id=decoy.token_id,
                           status=status, tags=tags, detail=detail, extra=extra)


def get_context() -> Context:
    from flask import current_app
    return current_app.extensions["agentwatch"]  # type: ignore[no-any-return]


# --------------------------------------------------------------------------
# app factory
# --------------------------------------------------------------------------
def add_signal(name: str) -> None:
    """Attach a v6 event-contract signal name to the current request's access record."""
    if has_request_context():
        g.setdefault("signals", [])
        g.signals.append(name)


def require_cursor(ctx: "Context", param: str, target: str) -> Optional[Response]:
    """v6 load-bearing cursor check.  None when ``request.args[param]`` is a valid cursor for *target* (provenance recorded on
    the access record); otherwise a plain 400 "Missing Required Cursor" (tampered / foreign cursors count as missing)."""
    g.cursor_required = True
    prov = frontier.check_cursor(ctx.registry.digest, request.args.get(param), target)
    g.cursor_prov = prov
    if prov is None:
        add_signal("missing_required_cursor")
        return Response("Missing Required Cursor\n", status=400, mimetype="text/plain")
    if prov == "schema":
        add_signal("schema_provenance_cursor")
    return None


def _html(body: str, title: str = "Acme Synthetic Corp") -> Response:
    head = frontier.beacon_script("")
    if has_request_context():
        g.beacon_offered = True
        from flask import current_app
        ctx = current_app.extensions.get("agentwatch")
        if ctx is not None:      # v6: per-page, per-time-bucket challenge + layout probe (no client identifiers)
            head = frontier.challenge_html(ctx.registry.digest, request.path, ctx.clock().timestamp()) + head
    # Pages reference a stylesheet, a script, a favicon and a logo (all served `no-store`, so a warm cache cannot
    # explain a client that never fetches them): a browser-like client loads them, a text-only agent does not.
    return Response(f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title>"
                    "<link rel='stylesheet' href='/static/site.css'><link rel='icon' href='/favicon.ico'>"
                    "<script src='/static/site.js' defer></script>" + head + "</head>"
                    f"<body><img src='/static/logo.svg' alt='' width='24' height='24'>{body}</body></html>",
                    mimetype="text/html")


def create_app(
    log_path: str | Path = "honeytoken-leads.jsonl",
    *,
    seed: Optional[str] = None,
    clock: Optional[Callable[[], datetime]] = None,
    body_cap: int = MAX_BODY_BYTES,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
    tarpit_s: float = 0.0,
    tarpit_max_s: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    registry_path: Optional[str | Path] = None,
    trust_forwarded_for: bool = False,
    behind_proxy: Optional[bool] = None,
    state_path: Optional[str | Path] = None,
    scrubber: Optional[Scrubber] = None,
    board_max_sessions: int = 2000,
    access_log_path: Optional[str | Path] = None,
    mirror_access: bool = True,
    extensions: Sequence[Callable[[Flask, Context], None]] = (),
) -> Flask:
    """Build the honeytoken listener.

    *extensions* are callables ``(app, ctx)`` that register extra decoys; the
    honeypot uses this hook.  ``body_cap`` is clamped to MAX_BODY_BYTES.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    scrub = scrubber or get_default_scrubber()
    if behind_proxy is None:
        behind_proxy = os.environ.get("AGENT_WATCH_BEHIND_PROXY", "") == "1"
    if behind_proxy:
        # One trusted reverse-proxy hop (nginx overwrites X-Forwarded-For with $remote_addr).
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]
    registry = DecoyRegistry(seed)
    ctx = Context(
        registry=registry,
        writer=LeadWriter(log_path, max_log_bytes, scrub),
        tarpit=Tarpit(tarpit_s, tarpit_max_s, sleep),
        clock=clock or (lambda: datetime.now(timezone.utc)),
        body_cap=min(body_cap, MAX_BODY_BYTES),
        trust_forwarded_for=trust_forwarded_for,
        behind_proxy=bool(behind_proxy),
        state=StateStore(state_path or Path(str(log_path) + ".state.sqlite"), board_max_sessions),
        scrubber=scrub,
        access_writer=LeadWriter(access_log_path or (str(log_path) + ".access.jsonl"), max_log_bytes, scrub)
        if mirror_access else None,
    )
    app.extensions["agentwatch"] = ctx
    app.config["JSON_SORT_KEYS"] = False

    hidden = registry.add_decoy("hidden_link", "hidden_link", f"/staff-portal-{registry._digest('hid')[:6]}",
                                "page reachable only via an invisible link in the home page HTML")
    backup = registry.add_decoy("admin_backup", "robots_disallow", "/admin-backup/",
                                "listed under Disallow in robots.txt, linked nowhere")
    key_in_comment = registry.fake_key("html_comment")
    ctx.app = app
    decoy_route = ctx.decoy_route

    @app.get("/")
    def home() -> Response:
        nav = "".join(ctx.extra_home_html)
        return _html(
            "<h1>Acme Synthetic Corp</h1><p>Internal demo site (synthetic content).</p>"
            + frontier.inversion_list(frontier.inversion_link(), f"<nav><a href='/about'>About</a> {nav}</nav>") +
            f"<!-- TODO remove before launch: api_key={escape(key_in_comment)} (synthetic, unusable) -->"
            f"<a href='{escape(hidden.path)}' style='display:none' aria-hidden='true' tabindex='-1'>staff</a>"
        )

    @app.get("/about")
    def about() -> Response:
        return _html("<h1>About</h1><p>Nothing to see; this is a synthetic honeypot site.</p>")

    beacon_rate = frontier.LRURateLimiter(BEACON_RATE_PER_MIN, BEACON_RATE_MAX_KEYS)   # v5 review: LRU, evicts oldest 25%
    ctx.beacon_rate = beacon_rate      # tests inspect it

    @app.post(BEACON_PATH)
    def telemetry_nav() -> Response:
        """Interaction beacon (v6, challenge-bound).  Body: {proof, page, + five booleans}.  The server verifies the proof against
        the page's challenge (current or previous 5-minute bucket) and stores ONLY six booleans (``challenge_proof_ok`` plus the
        five) on the mirrored access record; the proof and page are used for verification and discarded.  A beacon with a missing /
        canned / invalid proof (incl. a v4-style three-key beacon) is recorded as a low-severity ``beacon_forged`` lead.
        Size-limited (512 B), rate-capped per client IP (LRU map), 204 with no body."""
        now = ctx.clock().timestamp()
        if not beacon_rate.allow(ctx.client_ip(), now):
            return Response("", status=429, headers={"Retry-After": "30"})
        raw = ctx.read_body(BEACON_MAX_BYTES)
        if len(raw) > BEACON_MAX_BYTES:
            return Response("", status=413)
        try:
            doc = _json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return Response("", status=400)
        if not isinstance(doc, dict) or any(not isinstance(doc.get(k), bool) for k in BEACON_KEYS):
            return Response("", status=400)
        # kinematic_dwell_ok may be null (inconclusive: touch / OS tap-to-click 0–4 ms dwell).
        # Other BEACON_BOOLS remain strict booleans when present.
        for k in frontier.BEACON_BOOLS:
            if k not in doc:
                continue
            if k == "kinematic_dwell_ok":
                if doc[k] is not None and not isinstance(doc[k], bool):
                    return Response("", status=400)
            elif not isinstance(doc[k], bool):
                return Response("", status=400)
        ok = frontier.verify_proof(registry.digest, doc.get("page", ""), doc.get("proof", ""), now)
        def _beacon_bool(k):
            if k not in doc:
                return None
            if k == "kinematic_dwell_ok" and doc[k] is None:
                return None
            return bool(doc[k])
        g.beacon = {"challenge_proof_ok": ok, **{k: _beacon_bool(k) for k in frontier.BEACON_BOOLS}}
        if not ok:
            add_signal("beacon_forged")
            g.omit_body_preview = True
            ctx.record(decoy_name="beacon_challenge", kind="beacon_forged", token_id=registry.token_id("beacon_challenge"),
                       status=204, tags=["beacon_forged"], detail={"proof_present": "proof" in doc})
        return Response("", status=204)

    @app.get("/static/site.css")
    def asset_css() -> Response:
        return Response("body{font-family:sans-serif;margin:2em}\n", mimetype="text/css")

    @app.get("/static/site.js")
    def asset_js() -> Response:
        return Response("/* synthetic honeypot site script */\n", mimetype="application/javascript")

    @app.get("/static/logo.svg")
    def asset_logo() -> Response:
        return Response("<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24'><rect width='24' height='24' "
                        "fill='#445'/></svg>", mimetype="image/svg+xml")

    @app.get("/favicon.ico")
    def asset_favicon() -> Response:
        return Response(b"\x00\x00\x01\x00\x00\x00", mimetype="image/x-icon")

    @app.get("/robots.txt")
    def robots() -> Response:
        ctx.record(decoy_name="robots_txt", kind="robots_fetch", token_id=registry.token_id("robots_txt"),
                   event_type="decoy_context", priority="info", tags=["recon"])
        lines = ["User-agent: *", f"Disallow: {backup.path}", f"Disallow: {hidden.path}/"]
        lines += [f"Disallow: {p}" for p in ctx.extra_disallow]
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    @decoy_route(hidden.path, hidden)
    @decoy_route(hidden.path + "/<path:rest>", hidden)
    def hidden_page(rest: str = "") -> Response:
        ctx.hit(hidden)
        return _html("<h1>Staff portal</h1><p>Synthetic page. Login disabled.</p>", "Staff portal")

    @decoy_route("/admin-backup/", backup)
    @decoy_route("/admin-backup/<path:rest>", backup)
    def backup_page(rest: str = "") -> Response:
        ctx.hit(backup)
        return _html(
            "<h1>Index of /admin-backup/</h1><pre>db_dump_synthetic.sql.txt\ncredentials_synthetic.txt</pre>"
            "<p>All files are synthetic placeholders.</p>", "Index of /admin-backup/")

    @app.after_request
    def finish(resp: Response) -> Response:
        if g.get("body_too_large") and resp.status_code != 413:
            resp = jsonify({"error": "payload_too_large", "max_bytes": MAX_CONTENT_LENGTH})
            resp.status_code = 413
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        if resp.mimetype == "text/html":
            resp.headers["Content-Security-Policy"] = frontier.HONEYPOT_CSP      # v5 review (see frontier.HONEYPOT_CSP note)
        ctx.flush_pending(resp)
        ctx.mirror(resp, g.get("last_lead_id"))
        return resp

    @app.errorhandler(413)
    def too_large(_exc: Exception) -> tuple[Response, int]:
        """JSON 413; the attempt is logged (sanitised, no body) unless a handler already logged it."""
        if not g.get("lead_logged") and request.endpoint not in (None,):
            g.body_too_large = True
            ctx.record(decoy_name="request_too_large", kind="request_too_large",
                       token_id=registry.token_id("request_too_large", "dd"), status=413,
                       event_type="decoy_context", priority="info", tags=["oversized_request"])
        return jsonify({"error": "payload_too_large", "max_bytes": MAX_CONTENT_LENGTH}), 413

    for ext in extensions:
        ext(app, ctx)

    # Camouflaged-schema parameter and per-session canary reuse on ANY path (high-signal single events)
    @app.after_request
    def schema_and_session_signals(resp: Response) -> Response:
        signals: list[tuple[str, str, str]] = []     # (decoy name, lead kind, tag)
        if SCHEMA_PARAM in request.args:
            signals.append(("schema_param", "schema_param_use", "schema_param_use"))
        hay = request.query_string.decode("utf-8", "replace")
        if request.method in ("POST", "PUT", "PATCH") and request.content_length:
            hay += " " + ctx.read_body().decode("utf-8", "replace")
        presented = set(_SESSION_CANARY.findall(hay))
        if presented:
            mine = ctx.session_canary()
            signals.append(("session_canary", "session_canary_param",
                            "session_canary_param" if mine in presented else "session_canary_foreign"))
        for name, kind, tag in signals:
            pending = g.get("pending_lead")
            if pending is not None and pending["event_type"] == "honeytoken_hit":
                if tag not in pending["tags"]:          # a decoy lead is already being written: tag it, no second lead
                    pending["tags"].append(tag)
                pending["detail"][tag] = True
            else:                                       # none yet, or only an informational context event: raise a lead
                ctx.record(decoy_name=name, kind=kind, token_id=registry.token_id(name, "sg"), status=resp.status_code,
                           tags=[tag], detail={tag: True})
        return resp

    # Catch decoy credentials / canary phrases presented on ANY path
    @app.after_request
    def credential_reuse(resp: Response) -> Response:
        if g.get("lead_logged") or request.endpoint in ctx.decoy_endpoints:
            return resp
        sources = [request.headers.get(h, "") for h in ("Authorization", "X-API-Key", "Api-Key", "Cookie")]
        sources.append(request.query_string.decode("utf-8", "replace"))
        if request.method in ("POST", "PUT", "PATCH") and request.content_length:
            sources.append(ctx.read_body().decode("utf-8", "replace"))
        matches = ctx.scan_matches([s for s in sources if s])
        if matches["credential_token_ids"]:
            ctx.record(decoy_name="credential_reuse", kind="fake_credential_use",
                       token_id=matches["credential_token_ids"][0], status=resp.status_code,
                       tags=["credential_reuse"])
        elif matches["canary_ids"]:
            ctx.record(decoy_name="canary_echo", kind="canary_phrase_echo",
                       token_id=matches["canary_ids"][0], status=resp.status_code, tags=["canary_echo"])
        return resp

    # ---- log hygiene: no sink may emit raw query strings / secrets (see safelog.py) ----------------------------
    from .safelog import install_safe_logging
    install_safe_logging()

    @app.errorhandler(Exception)
    def unhandled(exc: Exception) -> Any:
        """Last-resort handler: HTTP errors pass through; anything else is a generic JSON 500 and the log line names
        only the exception class and the query-free path (never the request line, query or body)."""
        if isinstance(exc, HTTPException):
            return exc
        app.logger.error("unhandled %s on %s", type(exc).__name__, request.path)
        return jsonify({"error": "internal_error", "synthetic": True}), 500

    if registry_path:
        import json
        Path(registry_path).write_text(json.dumps(scrub.scrub(registry.to_dict()), indent=2) + "\n", encoding="utf-8")
    return app


# --------------------------------------------------------------------------
# server runner
# --------------------------------------------------------------------------
def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


EXPOSURE_WARNING = (
    "WARNING: binding to a non-loopback address exposes a deliberately deceptive, "
    "intentionally leaky decoy site. Only do this inside an isolated network "
    "segment/VM with no route to production or sensitive data."
)


def check_bind(host: str, allow_nonlocal: bool = False) -> None:
    """Refuse (SystemExit) a non-loopback bind unless explicitly allowed."""
    if not is_loopback(host):
        if not allow_nonlocal:
            raise SystemExit(f"refusing to bind {host!r}: only loopback is allowed by default "
                             "(pass --allow-nonlocal inside an isolated sandbox to override)")
        print(EXPOSURE_WARNING)


def run_server(app: Flask, host: str = "127.0.0.1", port: int = 8099, allow_nonlocal: bool = False) -> None:
    """Run the Flask dev server (localhost only unless explicitly overridden).

    The werkzeug request handler is replaced by one that logs the query-free path and routes every message through
    ``safelog.safe_text`` - the stock handler prints raw query strings to the console (found in a live demo)."""
    from .safelog import install_safe_logging, make_request_handler
    check_bind(host, allow_nonlocal)
    install_safe_logging()
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True,
            request_handler=make_request_handler())
