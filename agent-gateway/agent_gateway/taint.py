"""Per-session taint state, egress classes, and provenance-tagged scratchpad.

Maps to ATLAS mitigation AML.M0030 (Restrict Tool Invocation on Untrusted Data).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


# --- Egress classes (not merely read vs write) ---------------------------------
EGRESS_EXTERNAL_READ = "external_read"
EGRESS_INTERNAL_READ = "internal_read"
EGRESS_WRITE = "write"
EGRESS_SEND = "send"
EGRESS_CREDS = "creds"
EGRESS_BUS = "bus"
EGRESS_SPAWN = "spawn"
EGRESS_META = "meta"  # tools/list etc.

TOOL_EGRESS: dict[str, str] = {
    # Untrusted ingest / external parameter egress
    "web.fetch": EGRESS_EXTERNAL_READ,
    "web.search": EGRESS_EXTERNAL_READ,
    "http.request": EGRESS_EXTERNAL_READ,
    "browser.navigate": EGRESS_EXTERNAL_READ,
    "fetch_url": EGRESS_EXTERNAL_READ,
    "read_external_url": EGRESS_EXTERNAL_READ,
    "search_external_kb": EGRESS_EXTERNAL_READ,
    "search_docs": EGRESS_EXTERNAL_READ,
    # Internal reads
    "file.read": EGRESS_INTERNAL_READ,
    "read_internal_secrets": EGRESS_CREDS,  # sensitive
    "secrets.get": EGRESS_CREDS,
    "vault.read": EGRESS_CREDS,
    "credentials.get": EGRESS_CREDS,
    "read_session_note": EGRESS_INTERNAL_READ,
    "lookup_order_status": EGRESS_INTERNAL_READ,
    "read_customer_ticket": EGRESS_EXTERNAL_READ,  # customer content = untrusted ingest
    # Namespace and status observations (v14 Predicate C adapters)
    "file.exists": EGRESS_INTERNAL_READ,
    "file.stat": EGRESS_INTERNAL_READ,
    "file.list": EGRESS_INTERNAL_READ,
    "list_files": EGRESS_INTERNAL_READ,
    "status.get": EGRESS_INTERNAL_READ,
    # Writes / sends
    "file.write": EGRESS_WRITE,
    "save_session_note": EGRESS_WRITE,
    "update_ticket_memo": EGRESS_WRITE,
    "update_ticket_status": EGRESS_WRITE,
    "credentials.put": EGRESS_CREDS,
    "credentials.pass_through": EGRESS_CREDS,
    "webhook.send": EGRESS_SEND,
    "email.send": EGRESS_SEND,
    "send_email": EGRESS_SEND,
    "send_outbound_report": EGRESS_SEND,
    "send_webhook": EGRESS_SEND,
    # Agent bus / spawn
    "post_internal_bus": EGRESS_BUS,
    "poll_internal_bus": EGRESS_INTERNAL_READ,
    "spawn_subagent": EGRESS_SPAWN,
    # Meta
    "tools.list": EGRESS_META,
    # MCP wire proxy: server content reads (taint is applied on the response
    # for non-core servers, in mcp_proxy.py)
    "mcp.resources/read": EGRESS_INTERNAL_READ,
    "mcp.prompts/get": EGRESS_INTERNAL_READ,
}

# Tools whose successful call marks session TAINTED (untrusted ingest)
UNTRUSTED_INGEST_TOOLS = frozenset({
    "web.fetch", "web.search", "http.request", "browser.navigate",
    "fetch_url", "read_external_url", "search_external_kb", "search_docs",
    "read_customer_ticket", "file.read",
})

SENSITIVE_READ_TOOLS = frozenset({
    "credentials.get", "secrets.get", "vault.read", "read_internal_secrets",
})

# While TAINTED, these egress classes need OOB (unless allowlisted constrained sink)
BLOCKED_EGRESS_WHILE_TAINTED = frozenset({
    EGRESS_WRITE, EGRESS_SEND, EGRESS_CREDS, EGRESS_BUS,
})

# Core MCP servers whose tools/list descriptions are capability-pinned (not auto-taint)
CORE_MCP_SERVERS = frozenset({"core", "internal", "builtin"})


@dataclass
class ScratchpadEntry:
    note_id: str
    body: str
    taint_inherited: bool
    source_session: str
    created_at: float = field(default_factory=time.time)


@dataclass
class SessionState:
    session_id: str
    agent_key: str
    root_parent_key: str = ""  # Root Parent Principal for R12 freeze
    tainted: bool = False
    sensitive_read: bool = False
    taint_source_id: str = ""
    taint_reasons: list[str] = field(default_factory=list)
    delegation_depth: int = 0
    step_index: int = 0
    children_spawned: int = 0
    last_untrusted_read_at: float = 0.0
    last_sensitive_read_at: float = 0.0
    history: list[dict[str, Any]] = field(default_factory=list)
    # Chained HMAC capability (macaroon-style). Empty until the PEP mints one.
    capability_token: str = ""
    allow_egress: bool = True
    # Non-empty: every later call waits for a bound OOB approval (MCP rug pull).
    review_hold: str = ""

    def mark_tainted(self, reason: str, source_id: str = "") -> None:
        self.tainted = True
        self.taint_reasons.append(reason)
        self.last_untrusted_read_at = time.time()
        if source_id and not self.taint_source_id:
            self.taint_source_id = source_id

    def mark_sensitive(self) -> None:
        self.sensitive_read = True
        self.last_sensitive_read_at = time.time()


@dataclass
class SharedState:
    """Lab in-memory scratchpad + bus (process-local)."""
    scratchpad: dict[str, ScratchpadEntry] = field(default_factory=dict)
    bus: list[dict[str, Any]] = field(default_factory=list)
    # root_parent_key -> child count
    children_by_parent: dict[str, int] = field(default_factory=dict)


def egress_class(tool_name: str) -> str:
    return TOOL_EGRESS.get(tool_name, EGRESS_WRITE)  # unknown tools treated as write (fail closed)


def places_params_on_external_boundary(tool_name: str, arguments: Optional[dict]) -> bool:
    """True when tool *parameters* cross an external boundary (query/URL search params).

    Bare ingest URLs without a query string (e.g. read_external_url of a page) establish
    TAINTED but are not themselves treated as exfil channels. search_* tools and URLs with
    ?q=... / query= fields are gated under the lethal-trifecta policy (AML.T0086).
    """
    args = arguments or {}
    if tool_name in ("search_external_kb", "search_docs", "web.search"):
        return True
    for key in ("query", "q", "search"):
        if args.get(key) not in (None, ""):
            return True
    for key in ("url", "href", "endpoint"):
        val = str(args.get(key) or "")
        if "?" in val and "=" in val.split("?", 1)[-1]:
            return True
    return False
