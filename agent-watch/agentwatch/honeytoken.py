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

from flask import Flask, Response, g, jsonify, request
from markupsafe import escape
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from .scrubber import Scrubber, get_default_scrubber
from .state import StateStore
from .leads import (DEFAULT_MAX_LOG_BYTES, MAX_BODY_BYTES, MAX_PATH, LeadWriter,
                    make_lead, sanitize_headers, sanitize_query, sanitize_text)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "decoys": [d.__dict__ for d in self.decoys.values()],
            "canaries": [c.__dict__ for c in self.canaries.values()],
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
    _seen_lock: threading.Lock = field(default_factory=threading.Lock)

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
        canaries = [c.token_id for c in self.registry.canaries.values() if c.phrase in hay]
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
def _html(body: str, title: str = "Acme Synthetic Corp") -> Response:
    return Response(f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title></head>"
                    f"<body>{body}</body></html>", mimetype="text/html")


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
            f"<nav><a href='/about'>About</a> {nav}</nav>"
            f"<!-- TODO remove before launch: api_key={escape(key_in_comment)} (synthetic, unusable) -->"
            f"<a href='{escape(hidden.path)}' style='display:none' aria-hidden='true' tabindex='-1'>staff</a>"
        )

    @app.get("/about")
    def about() -> Response:
        return _html("<h1>About</h1><p>Nothing to see; this is a synthetic honeypot site.</p>")

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
        ctx.flush_pending(resp)
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
    """Run the Flask dev server (localhost only unless explicitly overridden)."""
    check_bind(host, allow_nonlocal)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
