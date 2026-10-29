"""Zero-trust first-listing MCP capability and schema profile guard.

``mcp_rugpull_guard.py`` catches a tool that changes after it is pinned; a
tool that is malicious in its very first listing is pinned as it is. This
guard checks every listing, the first one included, against a capability
profile for the server:

``PURE_TRANSFORM`` < ``READ_ONLY`` < ``LOCAL_WORKSPACE`` < ``EXTERNAL_NETWORK``
< ``PRIVILEGED``.

A server's profile is assigned (``profiles={"github": "EXTERNAL_NETWORK"}``)
or, for an unverified server, nothing is granted. ``infer_profile`` reports
the least profile a listing would need.

Rule codes:

- ``MCP_FIRST_SEEN_OVERPRIVILEGED``: an input schema asks the model for a
  credential (``api_key``, ``password``, ``private_key``, ``session_token``,
  ``aws_secret``, ``client_secret`` ...; pagination tokens and token limits
  are not credentials) or for shell / code execution (``command``, ``cmd``,
  ``shell``, ``script``, ``eval``, ``exec``) that the server's profile does
  not grant. Credentials are granted from ``EXTERNAL_NETWORK`` up,
  execution only to ``PRIVILEGED``; an unverified server is granted
  neither.
- ``MCP_SCHEMA_PURPOSE_MISMATCH``: a tool named for a read / format /
  compute action (``format_``, ``lint_``, ``get_``, ``list_``,
  ``calculate_``, ``parse_``, ``read_``, ``search_``, ``validate_`` ...)
  declares destructive or side-effecting properties (``delete``,
  ``overwrite``, ``webhook``, ``callback_url``, ``upload``, ``recipient``,
  ``command`` ...), or, on a ``PRIVILEGED`` server, a wildcard schema
  (explicit ``additionalProperties: true`` and no declared properties).
- ``MCP_TOOL_NAMESPACE_FLOOD``: one listing from one server carries more
  than ``max_tools_per_server`` tools (default 32). Tools past the limit are
  refused; the first ones keep their own verdicts.

Property names are split into words (``snake_case``, ``kebab-case``,
``camelCase``) and checked recursively through nested objects and arrays.
Denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). Structural checks only: a tool whose schema is
clean but whose server misbehaves is out of scope.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

OVERPRIVILEGED = "MCP_FIRST_SEEN_OVERPRIVILEGED"
PURPOSE_MISMATCH = "MCP_SCHEMA_PURPOSE_MISMATCH"
NAMESPACE_FLOOD = "MCP_TOOL_NAMESPACE_FLOOD"
RULE_CODES = (OVERPRIVILEGED, PURPOSE_MISMATCH, NAMESPACE_FLOOD)

PROFILES = ("PURE_TRANSFORM", "READ_ONLY", "LOCAL_WORKSPACE", "EXTERNAL_NETWORK", "PRIVILEGED")
_RANK = {p: i for i, p in enumerate(PROFILES)}
CREDENTIAL_PROFILE = "EXTERNAL_NETWORK"
EXEC_PROFILE = "PRIVILEGED"
DEFAULT_MAX_TOOLS = 32

_BENIGN_VERBS = frozenset({"format", "lint", "get", "list", "calculate", "calc", "compute", "parse", "read",
                           "search", "find", "view", "describe", "count", "validate", "check", "convert",
                           "render", "preview", "summarize", "lookup", "query", "fetch", "show", "inspect"})
_SIDE_EFFECT_WORDS = frozenset({"delete", "remove", "drop", "truncate", "destroy", "purge", "wipe", "overwrite",
                                "webhook", "callback", "upload", "recipient", "recipients", "exfil", "notify",
                                "forward", "command", "cmd", "shell", "script", "exec", "eval"})
_SIDE_EFFECT_PHRASES = (("send", "to"), ("write", "to"), ("output", "path"), ("save", "path"), ("save", "to"),
                        ("post", "to"), ("upload", "url"), ("callback", "url"))
_EXEC_WORDS = frozenset({"command", "cmd", "shell", "script", "eval", "exec", "bash", "powershell", "sh"})
_CRED_WORDS = frozenset({"password", "passwd", "passphrase", "secret", "secrets", "credential", "credentials",
                         "apikey", "privatekey", "pat"})
_CRED_PHRASES = (("api", "key"), ("private", "key"), ("secret", "key"), ("access", "key"), ("client", "secret"),
                 ("aws", "secret"), ("ssh", "key"))
_TOKEN_QUALIFIERS = frozenset({"access", "session", "auth", "bearer", "refresh", "api", "id", "oauth", "github",
                               "slack", "jwt", "csrf", "personal", "service"})
_NOT_CRED_QUALIFIERS = frozenset({"page", "next", "continuation", "cursor", "sync", "max", "min", "num", "count",
                                  "limit", "prev", "previous", "start", "end", "total"})


def words(name: str) -> list[str]:
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", str(name))  # XApiKey -> X_ApiKey
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", spaced)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.casefold()) if w]


def _has_phrase(ws: list[str], phrase: tuple[str, ...]) -> bool:
    n = len(phrase)
    return any(tuple(ws[i:i + n]) == phrase for i in range(len(ws) - n + 1))


def is_credential_param(name: str) -> bool:
    ws = words(name)
    if any(w in _CRED_WORDS for w in ws) or any(_has_phrase(ws, p) for p in _CRED_PHRASES):
        return True
    if "token" in ws or "tokens" in ws:
        others = {w for w in ws if w not in ("token", "tokens")}
        if others & _NOT_CRED_QUALIFIERS:
            return False
        return "token" in ws and (not others or bool(others & _TOKEN_QUALIFIERS))
    return False


def is_exec_param(name: str) -> bool:
    return any(w in _EXEC_WORDS for w in words(name))


def is_side_effect_param(name: str) -> bool:
    ws = words(name)
    return any(w in _SIDE_EFFECT_WORDS for w in ws) or any(_has_phrase(ws, p) for p in _SIDE_EFFECT_PHRASES)


def _properties(schema: Any, path: str = "") -> Iterable[tuple[str, str]]:
    """``(dotted path, property name)`` for every declared property, nested objects and arrays included."""
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            here = f"{path}.{name}" if path else str(name)
            yield here, str(name)
            yield from _properties(sub, here)
    for key in ("items", "additionalProperties"):
        if isinstance(schema.get(key), dict):
            yield from _properties(schema[key], f"{path}[]" if key == "items" else path)
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key) or []:
            yield from _properties(sub, path)


def is_wildcard(schema: Any) -> bool:
    """Explicit ``additionalProperties: true`` (or an unconstrained ``{}``) and no declared properties."""
    if not isinstance(schema, dict):
        return False
    extra = schema.get("additionalProperties")
    return not schema.get("properties") and (extra is True or extra == {})


def benign_verb(tool_name: str) -> Optional[str]:
    ws = words(tool_name.split("__")[-1])
    return ws[0] if ws and ws[0] in _BENIGN_VERBS else None


@dataclass(frozen=True)
class CapabilityVerdict:
    ok: bool
    code: str
    server_id: str
    tool: str
    detail: str = ""
    first_seen: bool = True

    def as_dict(self) -> dict:
        return {"ok": self.ok, "code": self.code, "server_id": self.server_id, "tool": self.tool,
                "detail": self.detail, "first_seen": self.first_seen}


@dataclass
class _Server:
    profile: Optional[str]
    listings: int = 0
    refused: dict[str, str] = field(default_factory=dict)


class McpCapabilityManifestGuard:
    """Checks each server listing, from the first, against its capability profile."""

    def __init__(self, *, profiles: Optional[dict[str, str]] = None, max_tools_per_server: int = DEFAULT_MAX_TOOLS,
                 audit_log: Optional[Path] = None) -> None:
        for p in (profiles or {}).values():
            if p not in _RANK:
                raise ValueError(f"unknown capability profile: {p!r}")
        self.profiles = {str(k).casefold(): v for k, v in (profiles or {}).items()}
        self.max_tools = max(1, int(max_tools_per_server))
        self.servers: dict[str, _Server] = {}
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None

    def profile_of(self, server_id: str) -> Optional[str]:
        return self.profiles.get(str(server_id).casefold())

    @staticmethod
    def infer_profile(tools: list[dict]) -> str:
        """The least profile a listing needs, from its parameter names."""
        need = "PURE_TRANSFORM"
        for tool in tools:
            schema = tool.get("inputSchema", tool.get("input_schema")) if isinstance(tool, dict) else None
            for _path, name in _properties(schema):
                ws = set(words(name))
                if is_exec_param(name):
                    return "PRIVILEGED"
                if is_credential_param(name) or ws & {"url", "uri", "endpoint", "webhook", "host", "email"}:
                    need = max(need, "EXTERNAL_NETWORK", key=_RANK.__getitem__)
                elif ws & {"path", "file", "dir", "directory", "filename"}:
                    need = max(need, "LOCAL_WORKSPACE", key=_RANK.__getitem__)
                elif need == "PURE_TRANSFORM" and ws & {"id", "query", "key", "name"}:
                    need = "READ_ONLY"
        return need

    def _check_tool(self, server_id: str, profile: Optional[str], tool: dict, first: bool) -> CapabilityVerdict:
        name = str(tool.get("name") or "")
        schema = tool.get("inputSchema", tool.get("input_schema"))
        rank = _RANK.get(profile, -1) if profile else -1
        for path, prop in _properties(schema):
            if is_exec_param(prop) and rank < _RANK[EXEC_PROFILE]:
                return CapabilityVerdict(False, OVERPRIVILEGED, server_id, name,
                                         f"execution parameter {path!r} not granted to {profile or 'unverified'}",
                                         first)
            if is_credential_param(prop) and rank < _RANK[CREDENTIAL_PROFILE]:
                return CapabilityVerdict(False, OVERPRIVILEGED, server_id, name,
                                         f"credential parameter {path!r} not granted to {profile or 'unverified'}",
                                         first)
        verb = benign_verb(name)
        if verb is not None:
            for path, prop in _properties(schema):
                if is_side_effect_param(prop):
                    return CapabilityVerdict(False, PURPOSE_MISMATCH, server_id, name,
                                             f"{verb}_ tool declares side-effecting parameter {path!r}", first)
            if profile == "PRIVILEGED" and is_wildcard(schema):
                return CapabilityVerdict(False, PURPOSE_MISMATCH, server_id, name,
                                         f"{verb}_ tool on a privileged server accepts any arguments", first)
        return CapabilityVerdict(True, "MCP_CAPABILITY_COMPLIANT", server_id, name, profile or "unverified", first)

    def register_listing(self, server_id: str, tools: list[dict], *, session_id: str = "") -> list[CapabilityVerdict]:
        server = self.servers.setdefault(server_id, _Server(self.profile_of(server_id)))
        first = server.listings == 0
        server.listings += 1
        out: list[CapabilityVerdict] = []
        named = [t for t in tools if isinstance(t, dict) and t.get("name")]
        for i, tool in enumerate(named):
            if i >= self.max_tools:
                v = CapabilityVerdict(False, NAMESPACE_FLOOD, server_id, str(tool["name"]),
                                      f"{len(named)} tools in one listing; limit {self.max_tools}", first)
            else:
                v = self._check_tool(server_id, server.profile, tool, first)
            if v.ok:
                server.refused.pop(v.tool, None)
            else:
                server.refused[v.tool] = v.code
                if self.chain is not None:
                    self.chain.append({"ts": round(time.time(), 6), "kind": v.code, "verdict": "DENY",
                                       "rule_code": v.code, "server_id": server_id, "tool": v.tool,
                                       "detail": v.detail, "first_seen": first, "session_id": session_id})
            out.append(v)
        return out

    def check_call(self, server_id: str, tool_name: str) -> CapabilityVerdict:
        server = self.servers.get(server_id)
        code = server.refused.get(tool_name) if server else None
        if code is not None:
            return CapabilityVerdict(False, code, server_id, tool_name, "tool refused at listing", False)
        return CapabilityVerdict(True, "MCP_CAPABILITY_COMPLIANT", server_id, tool_name, first_seen=False)
