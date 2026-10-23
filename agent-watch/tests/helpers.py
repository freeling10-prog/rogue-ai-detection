"""Small builders for hand-made logs used across the tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from agentwatch.config import load_config
from agentwatch.models import Request, Session
from agentwatch.sessions import build_sessions

T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (X11; Linux x86_64) Test"
CFG = load_config()


def mk(t: float, path: str = "/", query: str = "", status: int = 200, ua: str = UA, ip: str = "192.0.2.1",
       headers: Optional[dict[str, str]] = None, referer: str = "", size: int = 0) -> Request:
    return Request(ts=T0 + timedelta(seconds=t), ip=ip, method="GET", path=path, query=query, status=status,
                   ua=ua, referer=referer, headers=headers or {}, size=size,
                   raw=f'{ip} - - [t+{t}] "GET {path}{"?" + query if query else ""}" {status}')


def sess(reqs: list[Request], cfg=None) -> Session:
    out = build_sessions(sorted(reqs, key=lambda r: r.ts), cfg or CFG)
    assert len(out) == 1, f"expected one session, got {len(out)}"
    return out[0]
