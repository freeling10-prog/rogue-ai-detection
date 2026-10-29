"""Dynamic MCP rug-pull and tool-poisoning guard.

Keeps a registry snapshot that maps ``(server_id, tool_name)`` to a SHA-256
fingerprint of the tool's normalized description and canonical input schema,
and checks every listing a server sends against it:

- ``MCP_DESCRIPTION_POISONING``: the tool description, or any ``description``
  / ``title`` / string ``default`` / ``enum`` value anywhere in its input
  schema, carries a hidden instruction marker: an HTML comment, an
  ``<IMPORTANT>`` / ``<system>``-style tag, zero-width, bidi-control, or
  Unicode tag characters, a credential file path (``~/.ssh``, ``id_rsa``,
  ``.aws/credentials``), a directive to read or pass ``.env``, private or
  SSH keys, or "the contents of" a file / key / secret, an "ignore previous
  instructions" / "do not tell the user" phrase, or a ``sidenote``-style
  smuggling parameter. A poisoned tool is not pinned.
- ``MCP_TOOL_SHADOWING``: the tool name (case-folded, separators removed) is
  already owned by another active server, or is a core built-in tool name.
- ``MCP_DEFINITION_DRIFT``: a pinned tool's fingerprint changed and the
  listing carries no re-approval token for the new fingerprint. The tool
  stays quarantined (``check_call`` denies it) until a token issued by
  ``issue_reapproval`` (HMAC with the gateway key) is presented.

Pins and denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). ``snapshot()`` returns the registry with a
digest over it. Lexical checks: a description can still mislead in plain
words, and a malicious tool pinned at first sight is pinned as it is.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

DRIFT = "MCP_DEFINITION_DRIFT"
SHADOWING = "MCP_TOOL_SHADOWING"
POISONING = "MCP_DESCRIPTION_POISONING"
RULE_CODES = (DRIFT, SHADOWING, POISONING)
_REAPPROVAL_LABEL = b"agent-gateway.mcp-rugpull.reapproval/1"

# Claude Code and common agent built-ins a third-party server must not re-register.
CORE_BUILTIN_TOOLS = frozenset({
    "read", "write", "edit", "multiedit", "bash", "glob", "grep", "ls", "webfetch", "websearch",
    "notebookedit", "notebookread", "task", "todowrite", "todoread", "killshell", "bashoutput",
})

_INVISIBLE_RE = re.compile("[​‌‍‎‏⁠-⁤﻿‪-‮⁦-⁩"
                           "\U000e0000-\U000e007f]")
_POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("html_comment", re.compile(r"<!--.*?-->|<!--", re.S)),
    ("instruction_tag", re.compile(
        r"<\s*/?\s*(?:important|system|instructions?|secret|admin|assistant|user|context|hidden)\b[^>]*>", re.I)),
    ("credential_directive", re.compile(
        r"(?:~|\$HOME|%USERPROFILE%)/\.ssh\b|/\.ssh/|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials\b", re.I)),
    ("exfil_directive", re.compile(
        r"\b(?:read|cat|open|send|include|pass|upload|attach|forward|copy|leak)\b[^.\n]{0,80}"
        r"(?:[\s/'\"`]\.env\b|private[ _-]?keys?\b|ssh[ _-]?keys?\b"
        r"|contents?\s+of\s+[^.\n]{0,40}(?:file|config|key|secret|token))", re.I)),
    ("override_phrase", re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|rules?|messages?)"
        r"|\bdo\s+not\s+(?:tell|mention|inform|reveal\s+(?:this\s+)?to)\s+(?:the\s+)?user"
        r"|\bwithout\s+(?:telling|informing|notifying)\s+(?:the\s+)?user", re.I)),
)
_SMUGGLING_PARAMS = frozenset({"sidenote", "side_note", "sidenotes", "hidden_note", "notes_for_model",
                               "assistant_note", "context_for_model"})


def normalize_name(name: str) -> str:
    """Tool name as compared for ownership: NFKC, case-folded, separators removed."""
    return re.sub(r"[\s_.\-/:]+", "", unicodedata.normalize("NFKC", str(name)).casefold())


def normalize_description(text: Any) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(text or "")).split())


def canonical_schema(schema: Any) -> str:
    return json.dumps(schema if schema is not None else {}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def fingerprint(tool: dict) -> str:
    """SHA-256 over the normalized description and canonical input schema of one tool."""
    body = normalize_description(tool.get("description")) + "\x00" + canonical_schema(
        tool.get("inputSchema", tool.get("input_schema")))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _schema_texts(schema: Any, path: str = "inputSchema") -> Iterable[tuple[str, str]]:
    if isinstance(schema, dict):
        for k, v in schema.items():
            here = f"{path}.{k}"
            if k in ("description", "title") and isinstance(v, str):
                yield here, v
            elif k == "default" and isinstance(v, str):
                yield here, v
            elif k == "enum" and isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        yield f"{here}[{i}]", item
            elif k == "properties" and isinstance(v, dict):
                for prop in v:
                    if str(prop).casefold() in _SMUGGLING_PARAMS:
                        yield f"{here}.{prop}", f"<smuggling-parameter:{prop}>"
                yield from _schema_texts(v, here)
            else:
                yield from _schema_texts(v, here)
    elif isinstance(schema, list):
        for i, item in enumerate(schema):
            yield from _schema_texts(item, f"{path}[{i}]")


def scan_definition(tool: dict) -> Optional[dict]:
    """First hidden-instruction marker in a tool definition, as ``{"field", "marker"}``, or None."""
    texts = [("description", str(tool.get("description") or ""))]
    texts += list(_schema_texts(tool.get("inputSchema", tool.get("input_schema"))))
    for field, text in texts:
        if text.startswith("<smuggling-parameter:"):
            return {"field": field, "marker": "smuggling_parameter"}
        if _INVISIBLE_RE.search(text):
            return {"field": field, "marker": "invisible_characters"}
        for marker, pattern in _POISON_PATTERNS:
            if pattern.search(text):
                return {"field": field, "marker": marker}
    return None


@dataclass(frozen=True)
class RugPullVerdict:
    ok: bool
    code: str
    server_id: str
    tool: str
    fingerprint: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"ok": self.ok, "code": self.code, "server_id": self.server_id, "tool": self.tool,
                "fingerprint": self.fingerprint, "detail": self.detail}


class McpRugPullGuard:
    """Registry of pinned MCP tool fingerprints with drift, shadowing, and poisoning checks."""

    def __init__(self, *, audit_log: Optional[Path] = None, core_tools: Iterable[str] = CORE_BUILTIN_TOOLS,
                 key: Optional[bytes] = None) -> None:
        self.pins: dict[tuple[str, str], str] = {}
        self.owners: dict[str, str] = {}  # normalized name -> server_id
        self.quarantined: dict[tuple[str, str], str] = {}  # (server, tool) -> code
        self.core = frozenset(normalize_name(t) for t in core_tools)
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None
        self._key = key

    def _log(self, kind: str, **fields: Any) -> None:
        if self.chain is not None:
            self.chain.append({"ts": round(time.time(), 6), "kind": kind, **fields})

    def _reapproval_key(self) -> bytes:
        if self._key is not None:
            return self._key
        from .capability import hmac_key
        return hmac.new(hmac_key(), _REAPPROVAL_LABEL, hashlib.sha256).digest()

    def issue_reapproval(self, server_id: str, tool_name: str, new_fingerprint: str) -> str:
        """Token that accepts one specific new definition. Issue it after a person reviews the change."""
        msg = f"{server_id}\x00{tool_name}\x00{new_fingerprint}".encode("utf-8")
        return hmac.new(self._reapproval_key(), msg, hashlib.sha256).hexdigest()

    def _approved(self, server_id: str, tool_name: str, fp: str, token: Optional[str]) -> bool:
        return bool(token) and hmac.compare_digest(self.issue_reapproval(server_id, tool_name, fp), str(token))

    def register_listing(self, server_id: str, tools: list[dict], *, session_id: str = "",
                         approvals: Optional[dict[str, str]] = None) -> list[RugPullVerdict]:
        """Check one ``tools/list`` from ``server_id``. Returns one verdict per tool."""
        approvals = approvals or {}
        out: list[RugPullVerdict] = []
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            name = str(tool["name"])
            fp = fingerprint(tool)
            key = (server_id, name)
            v = self._check_one(server_id, name, tool, fp, approvals.get(name))
            if v.ok:
                if self.pins.get(key) != fp:
                    self.pins[key] = fp
                    self._log("mcp_registry_pin", server_id=server_id, tool=name, fingerprint=fp,
                              session_id=session_id)
                self.quarantined.pop(key, None)
            else:
                if v.code != SHADOWING:
                    self.quarantined[key] = v.code
                self._log(v.code, server_id=server_id, tool=name, fingerprint=fp, detail=v.detail,
                          session_id=session_id, verdict="DENY", rule_code=v.code)
            out.append(v)
        return out

    def _check_one(self, server_id: str, name: str, tool: dict, fp: str, token: Optional[str]) -> RugPullVerdict:
        poison = scan_definition(tool)
        if poison is not None:
            return RugPullVerdict(False, POISONING, server_id, name, fp, f"{poison['marker']} in {poison['field']}")
        norm = normalize_name(name)
        owner = self.owners.get(norm)
        if norm in self.core:
            return RugPullVerdict(False, SHADOWING, server_id, name, fp, "name of a core built-in tool")
        if owner is not None and owner != server_id:
            return RugPullVerdict(False, SHADOWING, server_id, name, fp, f"name owned by server {owner!r}")
        pinned = self.pins.get((server_id, name))
        if pinned is not None and pinned != fp and not self._approved(server_id, name, fp, token):
            return RugPullVerdict(False, DRIFT, server_id, name, fp, f"pinned {pinned[:16]}, now {fp[:16]}")
        self.owners.setdefault(norm, server_id)
        return RugPullVerdict(True, "MCP_DEFINITION_PINNED", server_id, name, fp)

    def check_call(self, server_id: str, tool_name: str) -> RugPullVerdict:
        """Deny a call to a quarantined (drifted or poisoned) tool."""
        code = self.quarantined.get((server_id, tool_name))
        if code is not None:
            return RugPullVerdict(False, code, server_id, tool_name, detail="tool is quarantined")
        return RugPullVerdict(True, "MCP_DEFINITION_PINNED", server_id, tool_name,
                              self.pins.get((server_id, tool_name), ""))

    def release_server(self, server_id: str) -> None:
        """Forget a disconnected server's ownership so another server may register its names."""
        for norm in [n for n, owner in self.owners.items() if owner == server_id]:
            del self.owners[norm]

    def snapshot(self) -> dict:
        pins = {f"{s}/{t}": fp for (s, t), fp in sorted(self.pins.items())}
        body = json.dumps(pins, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"pins": pins, "snapshot_sha256": hashlib.sha256(body).hexdigest(),
                "quarantined": {f"{s}/{t}": c for (s, t), c in sorted(self.quarantined.items())}}
