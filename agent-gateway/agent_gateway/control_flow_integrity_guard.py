"""Control-flow integrity guard: untrusted reads cannot steer privileged tool calls.

A deterministic information-flow check in the style of CaMeL and FIDES.
Each session carries a confidentiality-free, integrity-only label:
``trust_level`` (``TRUSTED`` until the session ingests output from an
untrusted tool, then ``UNTRUSTED`` for the rest of the session; it never
goes back) and the list of ``taint_sources``.

Privileges come from a ``UserCapabilityManifest`` pinned while the session
is still trusted, i.e. derived from the user's original prompt before any
untrusted read. A manifest lists grants: a sink class (``write``,
``delete``, ``execute``, ``spend``, ``external_send``), an optional tool
pattern, and target patterns (``fnmatch``, case-insensitive). It can be
HMAC-signed; a guard built with a key only accepts signed manifests.

After the session is ``UNTRUSTED``:

- ``CFI_TAINTED_PRIVILEGED_SINK``: a privileged sink with no grant for its
  class (and tool).
- ``CFI_UNENDORSED_TARGET``: a granted sink whose target (path, URL,
  recipient, command, ...) matches none of the grant's target patterns.

While the session is ``TRUSTED`` every call is the user's own and is
allowed. Untrusted sources are ``web_fetch``-style reads, external issue /
PR / email reads, and tools from MCP servers not marked verified; callers
can also mark taint explicitly. Denials and taint transitions are appended
to an optional SHA-256 hash-chained log (``audit_chain.py`` format).
In ``PolicyEngine`` a manifest only narrows: a call this guard allows still
passes every other gate.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

TRUSTED, UNTRUSTED = "TRUSTED", "UNTRUSTED"
TAINTED_SINK = "CFI_TAINTED_PRIVILEGED_SINK"
UNENDORSED_TARGET = "CFI_UNENDORSED_TARGET"
RULE_CODES = (TAINTED_SINK, UNENDORSED_TARGET)
SINK_CLASSES = ("write", "delete", "execute", "spend", "external_send")

DEFAULT_UNTRUSTED_TOOLS = frozenset({
    "webfetch", "websearch", "web.fetch", "web.search", "web_fetch", "read_external_url", "fetch_url",
    "browser.fetch", "browse", "curl", "read_email", "email.read", "gmail.read", "read_issue",
    "github.read_issue", "github.get_issue", "github.get_pull_request", "read_pull_request",
    "read_customer_ticket", "search_external_kb",
})
_UNTRUSTED_WORDS = re.compile(r"fetch|browse|scrape|crawl|(?:read|get|list)_?(?:email|mail|inbox|issue|pull|pr|"
                              r"comment|message|ticket)|web_?search")
DEFAULT_SINKS: dict[str, str] = {
    "write": "write", "edit": "write", "multiedit": "write", "notebookedit": "write", "file.write": "write",
    "save_session_note": "write", "update_ticket_memo": "write", "update_ticket_status": "write",
    "delete": "delete", "file.delete": "delete", "rm": "delete",
    "bash": "execute", "shell": "execute", "exec": "execute", "run_command": "execute", "spawn_subagent": "execute",
    "send_email": "external_send", "send_webhook": "external_send", "http.post": "external_send",
    "post_message": "external_send", "slack.post": "external_send", "git.push": "external_send",
    "transfer_funds": "spend", "create_payment": "spend", "purchase": "spend", "refund": "spend",
}
_SINK_WORDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("spend", re.compile(r"pay|purchase|transfer|refund|charge|buy|invoice")),
    ("delete", re.compile(r"delete|remove|destroy|drop|truncate|purge")),
    ("execute", re.compile(r"exec|shell|bash|run_?(?:command|script)|eval|spawn|deploy")),
    ("external_send", re.compile(r"send|post|publish|email|webhook|upload|share|push|notify|message")),
    ("write", re.compile(r"write|edit|update|create|save|put|patch|insert|append|set_")),
)
TARGET_KEYS = ("file_path", "path", "notebook_path", "url", "uri", "to", "recipient", "recipients", "email",
               "channel", "destination", "dest", "target", "repo", "repository", "branch", "command", "cmd",
               "account", "payee", "order_id", "ticket_id", "id")


@dataclass(frozen=True)
class CapabilityGrant:
    sink: str
    targets: tuple[str, ...] = ("*",)
    tool: str = "*"

    def as_dict(self) -> dict:
        return {"sink": self.sink, "targets": list(self.targets), "tool": self.tool}


@dataclass(frozen=True)
class UserCapabilityManifest:
    session_id: str
    grants: tuple[CapabilityGrant, ...] = ()
    issued_at: float = 0.0
    signature: str = ""

    def body(self) -> bytes:
        return json.dumps({"session_id": self.session_id, "issued_at": self.issued_at,
                           "grants": [g.as_dict() for g in self.grants]},
                          sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signed(self, key: bytes) -> "UserCapabilityManifest":
        sig = hmac.new(key, self.body(), hashlib.sha256).hexdigest()
        return UserCapabilityManifest(self.session_id, self.grants, self.issued_at, sig)

    @classmethod
    def from_dict(cls, data: dict) -> "UserCapabilityManifest":
        grants = tuple(CapabilityGrant(str(g["sink"]), tuple(str(t) for t in g.get("targets") or ("*",)),
                                       str(g.get("tool") or "*")) for g in data.get("grants") or [])
        return cls(str(data["session_id"]), grants, float(data.get("issued_at") or 0.0),
                   str(data.get("signature") or ""))


@dataclass
class SessionLabel:
    trust_level: str = TRUSTED
    taint_sources: list[str] = field(default_factory=list)
    manifest: Optional[UserCapabilityManifest] = None


@dataclass(frozen=True)
class CfiDecision:
    allowed: bool
    rule_code: str
    sink: str = ""
    target: str = ""
    trust_level: str = TRUSTED
    detail: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "sink": self.sink, "target": self.target,
                "trust_level": self.trust_level, "detail": self.detail}


def _norm(name: str) -> str:
    return str(name).strip().casefold()


class ControlFlowIntegrityGuard:
    """Per-session integrity label plus a pre-taint capability manifest."""

    def __init__(self, *, key: Optional[bytes] = None, audit_log: Optional[Path] = None,
                 untrusted_tools: Iterable[str] = DEFAULT_UNTRUSTED_TOOLS, sinks: Optional[dict[str, str]] = None,
                 verified_mcp_servers: Iterable[str] = ()) -> None:
        self._key = key
        self.sessions: dict[str, SessionLabel] = {}
        self.untrusted_tools = frozenset(_norm(t) for t in untrusted_tools)
        self.sinks = {_norm(k): v for k, v in (sinks or DEFAULT_SINKS).items()}
        self.verified_mcp = frozenset(_norm(s) for s in verified_mcp_servers)
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None

    def _log(self, **fields: Any) -> None:
        if self.chain is not None:
            self.chain.append({"ts": round(time.time(), 6), **fields})

    def label(self, session_id: str) -> SessionLabel:
        return self.sessions.setdefault(str(session_id), SessionLabel())

    # --- manifest ----------------------------------------------------------------

    def pin_manifest(self, manifest: UserCapabilityManifest) -> None:
        """Pin the user's grants. Refused once the session is untrusted, or when a keyed guard sees a bad signature."""
        lab = self.label(manifest.session_id)
        if lab.trust_level != TRUSTED:
            raise ValueError("capability manifest must be pinned before the session reads untrusted data")
        if lab.manifest is not None:
            raise ValueError("a capability manifest is already pinned for this session")
        for g in manifest.grants:
            if g.sink not in SINK_CLASSES:
                raise ValueError(f"unknown sink class: {g.sink!r}")
        if self._key is not None:
            expected = hmac.new(self._key, manifest.body(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, manifest.signature or ""):
                raise ValueError("capability manifest signature does not verify")
        lab.manifest = manifest
        self._log(kind="cfi_manifest_pinned", session_id=manifest.session_id,
                  manifest_sha256=hashlib.sha256(manifest.body()).hexdigest())

    # --- classification -------------------------------------------------------------

    def is_untrusted_source(self, tool_name: str) -> bool:
        name = _norm(tool_name)
        if name in self.untrusted_tools:
            return True
        if name.startswith("mcp__"):
            server = name.split("__")[1] if name.count("__") >= 2 else ""
            if server not in self.verified_mcp:
                return True
        return bool(_UNTRUSTED_WORDS.search(name)) and self.sink_class(tool_name) is None

    def sink_class(self, tool_name: str) -> Optional[str]:
        name = _norm(tool_name)
        if name in self.sinks:
            return self.sinks[name]
        base = name.split("__")[-1]
        if re.match(r"(?:read|get|list|fetch|search|view|lookup|find|query|poll|describe)(?:_|\.|$)", base):
            return None
        for sink, pattern in _SINK_WORDS:
            if pattern.search(base):
                return sink
        return None

    @staticmethod
    def targets_of(args: Any) -> list[str]:
        if not isinstance(args, dict):
            return []
        out: list[str] = []
        for k in TARGET_KEYS:
            v = args.get(k)
            if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
                out.append(str(v))
            elif isinstance(v, list):
                out.extend(str(x) for x in v if isinstance(x, (str, int)) and not isinstance(x, bool))
        return out

    # --- taint -------------------------------------------------------------------

    def mark_untrusted(self, session_id: str, source: str) -> None:
        lab = self.label(session_id)
        if source not in lab.taint_sources:
            lab.taint_sources.append(source)
        if lab.trust_level != UNTRUSTED:
            lab.trust_level = UNTRUSTED
            self._log(kind="cfi_taint", session_id=session_id, source=source)

    # --- decision ------------------------------------------------------------------

    def evaluate(self, session_id: str, tool_name: str, args: Any = None) -> CfiDecision:
        """Decide one call. An untrusted source is allowed and taints the session for later calls."""
        lab = self.label(session_id)
        sink = self.sink_class(tool_name)
        if sink is None:
            if self.is_untrusted_source(tool_name):
                self.mark_untrusted(session_id, tool_name)
            return CfiDecision(True, "CFI_NOT_PRIVILEGED", trust_level=lab.trust_level)
        if lab.trust_level == TRUSTED:
            return CfiDecision(True, "CFI_TRUSTED_SESSION", sink, trust_level=TRUSTED)
        targets = self.targets_of(args)
        grants = [g for g in (lab.manifest.grants if lab.manifest else ())
                  if g.sink == sink and fnmatch.fnmatchcase(_norm(tool_name), _norm(g.tool))]
        if not grants:
            return self._deny(session_id, tool_name, CfiDecision(
                False, TAINTED_SINK, sink, ",".join(targets)[:200], UNTRUSTED,
                f"no pre-taint grant for {sink}; taint from {', '.join(lab.taint_sources[:3])}"))
        if not targets:
            return self._deny(session_id, tool_name, CfiDecision(
                False, UNENDORSED_TARGET, sink, "", UNTRUSTED, "call names no target to check against the grant"))
        patterns = [_norm(p) for g in grants for p in g.targets]
        for t in targets:
            if not any(fnmatch.fnmatchcase(_norm(t), p) for p in patterns):
                return self._deny(session_id, tool_name, CfiDecision(
                    False, UNENDORSED_TARGET, sink, t[:200], UNTRUSTED, "target outside the pre-taint grant"))
        return CfiDecision(True, "CFI_ENDORSED", sink, ",".join(targets)[:200], UNTRUSTED)

    def _deny(self, session_id: str, tool_name: str, d: CfiDecision) -> CfiDecision:
        self._log(kind=d.rule_code, session_id=session_id, tool=tool_name, verdict="DENY", rule_code=d.rule_code,
                  sink=d.sink, target_sha256=hashlib.sha256(d.target.encode("utf-8")).hexdigest()[:16])
        return d
