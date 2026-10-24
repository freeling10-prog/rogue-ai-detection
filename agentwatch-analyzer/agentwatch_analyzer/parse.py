"""Parse commodity web server access logs into a common event dict.

Formats: nginx (combined), caddy (JSON), cloudflare (approx combined / JSON), json (generic).
Offline only — never opens a network connection.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import urlsplit

# nginx combined: IP - - [time] "METHOD path proto" status size "referer" "ua"
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class Event:
    ts: str
    ip: str
    method: str
    path: str
    query: str = ""
    status: int = 0
    size: int = 0
    referer: str = ""
    ua: str = ""
    host: str = ""
    content_type: str = ""
    links: list[str] = field(default_factory=list)  # if present in JSON access streams
    raw_format: str = ""
    session_hint: str = ""

    def path_key(self) -> str:
        return self.path or "/"

    def referer_path(self) -> str:
        if not self.referer or self.referer == "-":
            return ""
        try:
            p = urlsplit(self.referer).path
            return p or "/"
        except Exception:
            return ""


def _split_path(target: str) -> tuple[str, str]:
    if not target or target == "-":
        return "/", ""
    if "?" in target:
        p, q = target.split("?", 1)
        return p or "/", q
    return target, ""


def _ts_iso_from_nginx(t: str) -> str:
    try:
        dt = datetime.strptime(t, TIME_FMT)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return t


def parse_nginx_line(line: str) -> Optional[Event]:
    m = NGINX_RE.match(line.strip())
    if not m:
        return None
    path, query = _split_path(m.group("path"))
    try:
        status = int(m.group("status"))
    except ValueError:
        status = 0
    try:
        size = int(m.group("size")) if m.group("size") != "-" else 0
    except ValueError:
        size = 0
    return Event(
        ts=_ts_iso_from_nginx(m.group("time")),
        ip=m.group("ip"),
        method=m.group("method"),
        path=path,
        query=query,
        status=status,
        size=size,
        referer=m.group("referer"),
        ua=m.group("ua"),
        raw_format="nginx",
    )


def parse_json_obj(obj: dict) -> Optional[Event]:
    if not isinstance(obj, dict):
        return None
    # Cloudflare / generic / agent-watch access.jsonl shapes
    ip = str(obj.get("client_ip") or obj.get("ip") or obj.get("ClientIP") or obj.get("remote_ip") or "")
    path_raw = str(obj.get("path") or obj.get("uri") or obj.get("ClientRequestURI") or obj.get("request") or "")
    method = str(obj.get("method") or obj.get("ClientRequestMethod") or "GET")
    if path_raw.startswith("GET ") or path_raw.startswith("POST "):
        # caddy/nginx json sometimes puts "GET /path HTTP/1.1"
        parts = path_raw.split()
        if len(parts) >= 2:
            method, path_raw = parts[0], parts[1]
    path, query = _split_path(path_raw)
    if not path and obj.get("ClientRequestPath"):
        path, query = _split_path(str(obj["ClientRequestPath"]))
    if obj.get("query") and not query:
        query = str(obj["query"]).lstrip("?")
    ua = str(obj.get("user_agent") or obj.get("ua") or obj.get("ClientRequestUserAgent") or
             (obj.get("headers") or {}).get("user-agent") or "")
    referer = str(obj.get("referer") or obj.get("ClientRequestReferer") or
                  (obj.get("headers") or {}).get("referer") or "")
    status = int(obj.get("status") or obj.get("EdgeResponseStatus") or obj.get("status_code") or 0)
    size = int(obj.get("bytes") or obj.get("size") or obj.get("EdgeResponseBytes") or 0)
    ts = str(obj.get("timestamp") or obj.get("ts") or obj.get("EdgeStartTimestamp") or "")
    if isinstance(obj.get("ts"), (int, float)):
        ts = datetime.fromtimestamp(float(obj["ts"]), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    links = obj.get("links") if isinstance(obj.get("links"), list) else []
    links = [str(x) for x in links if isinstance(x, str)][:200]
    if not ip or not path:
        return None
    return Event(
        ts=ts or "1970-01-01T00:00:00Z",
        ip=ip,
        method=method.upper(),
        path=path,
        query=query,
        status=status,
        size=size,
        referer=referer,
        ua=ua,
        host=str(obj.get("host") or obj.get("ClientRequestHost") or ""),
        content_type=str(obj.get("content_type") or ""),
        links=links,
        raw_format="json",
        session_hint=str(obj.get("session_id") or ""),
    )


def parse_caddy_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return parse_nginx_line(line)
    # Caddy JSON access log nesting
    if "request" in obj and isinstance(obj["request"], dict):
        req = obj["request"]
        flat = {
            "ip": (req.get("remote_ip") or (req.get("client_ip") or "")),
            "method": req.get("method"),
            "path": req.get("uri") or req.get("path"),
            "ua": (req.get("headers") or {}).get("User-Agent", [""])[0]
            if isinstance((req.get("headers") or {}).get("User-Agent"), list)
            else (req.get("headers") or {}).get("User-Agent", ""),
            "referer": (req.get("headers") or {}).get("Referer", [""])[0]
            if isinstance((req.get("headers") or {}).get("Referer"), list)
            else (req.get("headers") or {}).get("Referer", ""),
            "status": obj.get("status"),
            "bytes": obj.get("size"),
            "ts": obj.get("ts"),
            "host": (req.get("host") or ""),
        }
        return parse_json_obj(flat)
    return parse_json_obj(obj)


def detect_format(sample: str) -> str:
    s = sample.strip()
    if not s:
        return "nginx"
    if s.startswith("{"):
        try:
            obj = json.loads(s.splitlines()[0])
            if isinstance(obj, dict) and ("request" in obj or "ClientRequestURI" in obj or "path" in obj or "client_ip" in obj):
                if "request" in obj:
                    return "caddy"
                if "ClientRequestURI" in obj or "EdgeResponseStatus" in obj:
                    return "cloudflare"
                return "json"
        except json.JSONDecodeError:
            pass
    return "nginx"


def iter_events(path: Path, fmt: str = "auto") -> Iterator[Event]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return
    if fmt == "auto":
        fmt = detect_format(lines[0])
    for ln in lines:
        ev: Optional[Event] = None
        if fmt == "nginx":
            ev = parse_nginx_line(ln)
        elif fmt == "caddy":
            ev = parse_caddy_line(ln)
        elif fmt in ("json", "cloudflare"):
            try:
                ev = parse_json_obj(json.loads(ln))
            except json.JSONDecodeError:
                ev = parse_nginx_line(ln)
        else:
            ev = parse_nginx_line(ln) or parse_caddy_line(ln)
        if ev:
            yield ev


def event_to_dict(ev: Event) -> dict[str, Any]:
    return asdict(ev)
