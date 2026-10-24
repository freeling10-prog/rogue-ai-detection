"""Log parsing: Nginx/Apache combined, JSON-lines API-gateway logs, and
honeypot lead records (JSONL written by agentwatch.honeytoken/honeypot).

The format is auto-detected per line, so mixed files work.  Malformed lines
are counted, never fatal.  Very long lines are skipped (defensive cap).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from .models import Request

MAX_LINE_BYTES = 64 * 1024
ACCESS_SCHEMA = "agentwatch.access/1"
LEAD_SCHEMA = "agentwatch.lead/1"
MAX_LINKS = 60
# JA4 (TLS client fingerprint) and JA4H (HTTP header fingerprint) shapes; anything else is dropped, never stored.
JA4_RE = re.compile(r"^[tqd][0-9]{2}[di][0-9]{2}[0-9]{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
JA4H_RE = re.compile(r"^[a-z]{2}[0-9]{2}[nc][rn][0-9]{2}[a-z0-9]{4}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$")

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)

_TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "start_time")
_IP_KEYS = ("client_ip", "remote_addr", "source_ip", "src_ip", "ip")
_STATUS_KEYS = ("status", "status_code", "response_status")
_PATH_KEYS = ("path", "uri", "url", "request_uri")
_UA_KEYS = ("user_agent", "ua")


@dataclass
class ParseResult:
    requests: list[Request] = field(default_factory=list)
    errors: int = 0                   # malformed / over-long lines
    context_events: int = 0           # non-hit honeypot events (informational)
    lines: int = 0
    mirror_merged: int = 0            # mirrored access records merged into their honeypot lead (not double counted)


def parse_timestamp(value: Any) -> datetime:
    """Parse epoch seconds/ms, ISO-8601 (with Z) or combined-log time to UTC."""
    if isinstance(value, bool):
        raise ValueError("bad timestamp")
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000.0 if value > 1e11 else float(value)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        pass
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return parse_timestamp(float(text))
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _split_target(target: str) -> tuple[str, str]:
    parts = urlsplit(target)
    return parts.path or "/", parts.query


def parse_combined_line(line: str, line_no: int = 0) -> Optional[Request]:
    """Parse one Nginx/Apache combined-format line, or return None."""
    m = COMBINED_RE.match(line)
    if not m:
        return None
    try:
        ts = parse_timestamp(m["time"])
    except ValueError:
        return None
    path, query = _split_target(m["target"])
    size = 0 if m["size"] in (None, "-") else int(m["size"])
    ref = (m["referer"] or "").replace('\\"', '"')
    ua = (m["ua"] or "").replace('\\"', '"')
    return Request(
        ts=ts, ip=m["ip"], method=m["method"], path=path, query=query,
        status=int(m["status"]), size=size, ua="" if ua == "-" else ua,
        referer="" if ref == "-" else ref, raw=line.rstrip("\n"), line_no=line_no,
    )


def _first(d: dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


BEACON_KEYS = ("webdriver_present", "pointer_trail_seen", "dom_automation_props")             # v4: required
BEACON_V6_KEYS = ("challenge_proof_ok", "kinematic_dwell_ok", "inertial_scroll_ok")           # v6: optional (None when absent)
SIGNAL_NAMES = ("beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
                "schema_provenance_cursor", "missing_required_cursor", "parasitic_session_fork", "llmjacking_probe")


def parse_json_line(line: str, line_no: int = 0) -> tuple[Optional[Request], bool]:
    """Parse one JSON-lines record.

    Returns (request, is_context_event).  Honeypot records with
    ``event_type == "honeytoken_hit"`` become Requests tagged with their decoy;
    other honeypot event types are informational context and return (None, True).
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None, False
    if not isinstance(obj, dict):
        return None, False

    event_type = obj.get("event_type")
    nested = obj.get("request") if isinstance(obj.get("request"), dict) else {}
    if event_type is not None and event_type != "honeytoken_hit":
        return None, True
    try:
        ts = parse_timestamp(_first(obj, _TS_KEYS))
        ip = str(_first(obj, _IP_KEYS) or _first(nested, _IP_KEYS) or "")
        method = str(_first(obj, ("method", "http_method")) or nested.get("method") or "GET").upper()
        raw_path = str(_first(obj, _PATH_KEYS) or _first(nested, _PATH_KEYS) or "")
        if not ip or not raw_path:
            return None, False
        path, query = _split_target(raw_path)
        q_extra = _first(obj, ("query", "query_string")) or nested.get("raw_query") or nested.get("query")
        if isinstance(q_extra, dict):
            from urllib.parse import urlencode
            q_extra = urlencode(q_extra, doseq=True)
        if q_extra and not query:
            query = str(q_extra).lstrip("?")
        headers_obj = obj.get("headers") or nested.get("headers") or {}
        headers = {str(k).lower(): str(v) for k, v in headers_obj.items()} if isinstance(headers_obj, dict) else {}
        ua = str(_first(obj, _UA_KEYS) or nested.get("user_agent") or headers.get("user-agent") or "")
        status_raw = _first(obj, _STATUS_KEYS)
        status = int(status_raw) if status_raw is not None else 0
        latency = _first(obj, ("latency_ms", "duration_ms"))
        if latency is None and obj.get("request_time") is not None:
            latency = float(obj["request_time"]) * 1000.0
    except (ValueError, TypeError, AttributeError):
        return None, False

    req = Request(
        ts=ts, ip=ip, method=method, path=path, query=query, status=status,
        size=int(obj.get("bytes", obj.get("size", 0)) or 0), ua=ua,
        referer=str(obj.get("referer") or nested.get("referer") or headers.get("referer") or ""),
        headers=headers, latency_ms=float(latency) if latency is not None else None,
        raw=line.rstrip("\n"), line_no=line_no,
    )
    schema = obj.get("schema")
    links = obj.get("links")
    if isinstance(links, list):
        req.served_links = [str(x)[:512] for x in links[:MAX_LINKS] if isinstance(x, str)]
    req.content_type = str(obj.get("content_type") or "")[:100]
    req.lead_event_id = str(obj.get("lead_event_id") or "")[:64]
    req.headers_logged = schema in (ACCESS_SCHEMA, LEAD_SCHEMA)
    req.beacon_offered = obj.get("beacon_script") is True
    bc = obj.get("beacon")
    if isinstance(bc, dict) and all(isinstance(bc.get(k), bool) for k in BEACON_KEYS):
        beacon: dict[str, Optional[bool]] = {k: bool(bc[k]) for k in BEACON_KEYS}   # strictly booleans; anything else is dropped
        for k in BEACON_V6_KEYS:
            beacon[k] = bc[k] if isinstance(bc.get(k), bool) else None
        req.beacon = beacon
    if "cursor_prov" in obj:
        req.cursor_route = True
        req.cursor_prov = obj["cursor_prov"] if obj.get("cursor_prov") in ("html", "schema") else None
    sig = obj.get("signals")
    if isinstance(sig, list):
        req.signals = [s for s in sig[:12] if isinstance(s, str) and s in SIGNAL_NAMES]
    ja4 = str(obj.get("ja4") or "").strip()
    ja4h = str(obj.get("ja4h") or "").strip()
    req.ja4 = ja4 if JA4_RE.match(ja4) else ""        # optional; malformed values are dropped, a missing one is normal
    req.ja4h = ja4h if JA4H_RE.match(ja4h) else ""
    if event_type:
        req.event_id = str(obj.get("event_id") or "")[:64]     # lets the mirrored access record of the same request be merged away
        tags = obj.get("tags")
        req.tags = [str(t)[:64] for t in tags[:20]] if isinstance(tags, list) else []
    if event_type == "honeytoken_hit":
        decoy = obj.get("decoy") if isinstance(obj.get("decoy"), dict) else {}
        req.source = "honeypot"
        req.token_id = str(obj.get("token_id") or decoy.get("token_id") or "") or None
        req.decoy_kind = str(decoy.get("kind") or obj.get("decoy_kind") or "unknown")
        if not req.status:
            req.status = int(nested.get("response_status") or obj.get("response_status") or 200)
        req.size = int(nested.get("response_bytes") or 0)
        detail = obj.get("detail")
        req.detail = dict(detail) if isinstance(detail, dict) else {}
        cap = obj.get("cognitive_capture")
        req.capture = dict(cap) if isinstance(cap, dict) else {}
        coord = obj.get("coordination")
        evs = coord.get("events") if isinstance(coord, dict) else None
        req.events = [e for e in evs if isinstance(e, dict)][:20] if isinstance(evs, list) else []
        # readable evidence line instead of the (long) raw JSON lead
        req.raw = (f"[honeypot lead] {ts.isoformat(timespec='seconds')} {ip} {method} {path}"
                   f"{'?' + query if query else ''} decoy={req.decoy_kind} token={req.token_id}")[:300]
    return req, False


def parse_lines(lines: Iterable[str]) -> ParseResult:
    """Parse an iterable of log lines in any supported format."""
    result = ParseResult()
    for n, line in enumerate(lines, 1):
        result.lines += 1
        stripped = line.strip()
        if not stripped:
            continue
        if len(stripped.encode("utf-8", "replace")) > MAX_LINE_BYTES:
            result.errors += 1
            continue
        if stripped.startswith("{"):
            req, ctx = parse_json_line(stripped, n)
            if ctx:
                result.context_events += 1
                continue
        else:
            req = parse_combined_line(stripped, n)
        if req is None:
            result.errors += 1
        else:
            result.requests.append(req)
    result.requests.sort(key=lambda r: r.ts)   # stable: ties keep file order
    return result


def parse_file(path: str | Path) -> ParseResult:
    """Parse a log file (read-only, undecodable bytes replaced)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)


def merge_results(results: list[ParseResult]) -> ParseResult:
    """Combine several ParseResults (e.g. access log + gateway log + leads)."""
    merged = ParseResult()
    for r in results:
        merged.requests.extend(r.requests)
        merged.errors += r.errors
        merged.context_events += r.context_events
        merged.lines += r.lines
    merged.requests.sort(key=lambda r: r.ts)
    return merged
