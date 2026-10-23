"""Core data model shared by the parser, detectors and scoring engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import parse_qs


@dataclass
class Request:
    """One normalised HTTP request, from an access log or a honeypot lead."""

    ts: datetime                      # timezone-aware, always UTC
    ip: str
    method: str
    path: str                         # path only, no query string
    query: str = ""                   # raw query string, no leading '?'
    status: int = 0
    size: int = 0
    ua: str = ""
    referer: str = ""
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    latency_ms: Optional[float] = None
    raw: str = ""                     # original log line (evidence)
    line_no: int = 0
    source: str = "log"               # "log" | "honeypot"
    token_id: Optional[str] = None    # honeypot decoy token id, if a lead
    decoy_kind: Optional[str] = None  # honeypot decoy kind, if a lead
    detail: dict[str, Any] = field(default_factory=dict)  # honeypot lead detail (step, origin, tool...)
    capture: dict[str, Any] = field(default_factory=dict)  # cognitive_capture (UNTRUSTED, attacker-controlled)
    events: list[dict[str, Any]] = field(default_factory=list)  # coordination issuance/use events
    # --- v3: mirrored access stream / link graph ---------------------------------------------------------
    served_links: Optional[list[str]] = None   # local paths the response offered the client; None = not known (plain logs)
    content_type: str = ""                     # response media type when the log knows it (mirror / gateway)
    event_id: str = ""                         # lead event id (honeypot leads)
    lead_event_id: str = ""                    # on a mirrored access record: the lead that describes the same request
    tags: list[str] = field(default_factory=list)  # lead tags (e.g. schema_param_use, mcp_list_then_call)
    headers_logged: bool = False               # the log format carries the browser-header family (mirror / leads)
    ja4: str = ""                              # OPTIONAL TLS fingerprint from a trusted edge; parsed only, never scored
    ja4h: str = ""                             # OPTIONAL HTTP-header fingerprint (JA4H); parsed only, never scored

    @property
    def params(self) -> dict[str, list[str]]:
        """Parsed query parameters (blank values kept)."""
        return parse_qs(self.query, keep_blank_values=True)

    @property
    def target(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path

    def evidence_line(self, limit: int = 200) -> str:
        """Short human-readable evidence string for reports."""
        text = self.raw.strip() or (
            f"{self.ts.isoformat()} {self.ip} {self.method} {self.target} {self.status}"
        )
        return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class Session:
    """A group of requests believed to come from one client."""

    session_id: str
    ip: str
    requests: list[Request]

    @property
    def start(self) -> datetime:
        return self.requests[0].ts

    @property
    def end(self) -> datetime:
        return self.requests[-1].ts

    @property
    def user_agents(self) -> list[str]:
        seen: dict[str, None] = {}
        for r in self.requests:
            seen.setdefault(r.ua, None)
        return list(seen)


@dataclass
class Finding:
    """One detector observation with the requests that support it."""

    detector: str                     # adaptation | tool_chain | param_evasion | honeytoken
    kind: str                         # sub-type, e.g. ua_change, cache_busting
    summary: str                      # human-readable sentence
    evidence: list[Request] = field(default_factory=list)
    data: dict[str, object] = field(default_factory=dict)
