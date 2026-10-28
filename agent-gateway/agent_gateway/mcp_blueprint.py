"""Reference harness for client MCP engagements, wrapped in the PEP.

``HardenedMcpBlueprint`` hosts three kinds of tool handler behind
``PolicyEngine.evaluate_call`` and records every call, allowed or denied, in
a SHA-256 hash-chained log (``audit_chain.py``):

- ``query``: a read-only, parameterized SQL template fixed at registration.
  The template must be a single ``SELECT`` / ``WITH`` statement; callers
  supply only scalar named parameters and a row limit, capped at
  ``max_rows`` (never above 100). Rows past the cap are dropped even if the
  executor returns them.
- ``lookup``: a scoped read against a SaaS or internal API. Its output is
  scanned by ``tool_output_scanner`` like any untrusted tool result.
- ``write``: a confirmed task-creation or update call. Each call needs a
  one-time ``confirmation_token`` bound to the session, tool name, and exact
  arguments, issued by ``issue_confirmation`` once a person has approved it.

Tool names whose words include a mutation verb on the deny list (``delete``,
``refund``, ``cancel``, ``drop``, ``truncate``, ``bulk_export``) are denied
unless that verb is listed in ``approved_verbs``; an approved verb still
needs confirmation. Returned records have configured sensitive fields
(``api_key``, ``secret``, ``ssn``, ``password``, ``token`` by default)
replaced with ``[REDACTED]`` before they leave the harness.

``tools_list`` and ``handle_jsonrpc`` expose the same tools as MCP
``tools/list`` / ``tools/call``; a confirmation token travels in
``params._meta["agentgate/confirmation_token"]``. Nothing here opens a socket.
These are configuration and validation controls for a lab reference build.
They are not a certification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import capability
from .audit_chain import ChainWriter, canonical
from .pep import PolicyEngine
from .scrub import scrub_obj

ROW_LIMIT_CEILING = 100
REDACTED = "[REDACTED]"
DEFAULT_REDACT_KEYS = ("api_key", "secret", "ssn", "password", "token")
DEFAULT_DENIED_VERBS = ("delete", "refund", "cancel", "drop", "truncate", "bulk_export")
CONFIRMATION_TTL_S = 900
META_CONFIRMATION = "agentgate/confirmation_token"
_CONFIRM_LABEL = b"agent-gateway.mcp-blueprint.confirmation/1"
_SQL_DENY_RE = re.compile(
    r"\b(insert|update|delete|merge|upsert|replace|drop|alter|create|truncate|grant|revoke|attach|detach|"
    r"pragma|vacuum|copy|call|exec|execute|lock|set)\b", re.IGNORECASE)
_SQL_COMMENT_RE = re.compile(r"--|/\*")
_SQL_PARAM_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")

QUERY, LOOKUP, WRITE = "query", "lookup", "write"
COMPLIANT = "COMPLIANT"


def _words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def _contains_phrase(words: list[str], phrase: list[str]) -> bool:
    n = len(phrase)
    return any(words[i:i + n] == phrase for i in range(len(words) - n + 1))


def validate_read_only_sql(sql: str) -> list[str]:
    """Named parameters of a read-only template. Raises ``ValueError`` when the template is not read-only."""
    body = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", body):
        raise ValueError("query template must start with SELECT or WITH")
    if ";" in body:
        raise ValueError("query template must be a single statement")
    if _SQL_COMMENT_RE.search(body):
        raise ValueError("query template must not contain comments")
    literal_free = re.sub(r"'(?:[^']|'')*'", "''", body)
    bad = _SQL_DENY_RE.search(literal_free)
    if bad:
        raise ValueError(f"query template contains a non-read-only keyword: {bad.group(0)}")
    return sorted(set(_SQL_PARAM_RE.findall(literal_free)))


@dataclass
class BlueprintTool:
    name: str
    kind: str
    handler: Callable[..., Any]
    description: str = ""
    input_schema: dict = field(default_factory=lambda: {"type": "object"})
    sql: str = ""
    params: tuple[str, ...] = ()
    max_rows: int = ROW_LIMIT_CEILING

    def descriptor(self) -> dict:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


@dataclass
class BlueprintResult:
    ok: bool
    rule_code: str
    tool: str
    result: Any = None
    message: str = ""
    redacted_fields: int = 0
    rows: Optional[int] = None
    audit_entry_hash: str = ""

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class HardenedMcpBlueprint:
    """Allowlisted MCP tool host: PEP gate, row cap, field redaction, confirmed writes, chained audit log."""

    def __init__(
        self,
        engine: PolicyEngine,
        agent_key: str,
        *,
        audit_log: Path,
        max_rows: int = ROW_LIMIT_CEILING,
        redact_keys: Iterable[str] = DEFAULT_REDACT_KEYS,
        denied_verbs: Iterable[str] = DEFAULT_DENIED_VERBS,
        approved_verbs: Iterable[str] = (),
        confirmation_ttl_s: float = CONFIRMATION_TTL_S,
    ) -> None:
        if not isinstance(max_rows, int) or isinstance(max_rows, bool) or not 1 <= max_rows <= ROW_LIMIT_CEILING:
            raise ValueError(f"max_rows must be an int between 1 and {ROW_LIMIT_CEILING}")
        self.engine = engine
        self.agent_key = agent_key
        self.max_rows = max_rows
        self.redact_terms = [_words(k) for k in redact_keys if _words(k)]
        self.denied_verbs = {v: _words(v) for v in denied_verbs}
        self.approved_verbs = {v.lower() for v in approved_verbs}
        self.confirmation_ttl_s = confirmation_ttl_s
        self.tools: dict[str, BlueprintTool] = {}
        self.chain = ChainWriter(Path(audit_log))
        self._used_nonces: set[str] = set()
        self._clock = time.time

    # --- registration ------------------------------------------------------------

    def _add(self, tool: BlueprintTool) -> BlueprintTool:
        if not tool.name or tool.name in self.tools:
            raise ValueError(f"tool name missing or already registered: {tool.name!r}")
        self.tools[tool.name] = tool
        return tool

    def register_query(self, name: str, sql: str, executor: Callable[[str, dict, int], list],
                       *, description: str = "", max_rows: Optional[int] = None) -> BlueprintTool:
        """Register a read-only parameterized query. ``executor(sql, params, limit)`` returns rows."""
        params = validate_read_only_sql(sql)
        cap = min(self.max_rows, max_rows or self.max_rows)
        props = {p: {"type": ["string", "integer", "number", "boolean", "null"]} for p in params}
        props["limit"] = {"type": "integer", "minimum": 1, "maximum": cap}
        schema = {"type": "object", "properties": props, "required": params, "additionalProperties": False}
        return self._add(BlueprintTool(name, QUERY, executor, description, schema, sql.strip().rstrip(";"),
                                       tuple(params), cap))

    def register_lookup(self, name: str, handler: Callable[[dict], Any], *, description: str = "",
                        input_schema: Optional[dict] = None) -> BlueprintTool:
        return self._add(BlueprintTool(name, LOOKUP, handler, description, input_schema or {"type": "object"}))

    def register_write(self, name: str, handler: Callable[[dict], Any], *, description: str = "",
                       input_schema: Optional[dict] = None) -> BlueprintTool:
        """Register a write / task-creation tool. Every call needs a confirmation token."""
        return self._add(BlueprintTool(name, WRITE, handler, description, input_schema or {"type": "object"}))

    # --- confirmation tokens -----------------------------------------------------

    def _confirm_key(self) -> bytes:
        return hmac.new(capability.hmac_key(), _CONFIRM_LABEL, hashlib.sha256).digest()

    def _confirm_mac(self, session_id: str, tool_name: str, arguments: dict, nonce: str, exp: int) -> str:
        body = b"|".join([session_id.encode(), tool_name.encode(), canonical(arguments), nonce.encode(),
                          str(exp).encode()])
        return hmac.new(self._confirm_key(), body, hashlib.sha256).hexdigest()

    def issue_confirmation(self, session_id: str, tool_name: str, arguments: dict) -> str:
        """One-time token for exactly this (session, tool, arguments). Call after a person approves."""
        nonce = secrets.token_hex(12)
        exp = int(self._clock() + self.confirmation_ttl_s)
        mac = self._confirm_mac(session_id, tool_name, dict(arguments), nonce, exp)
        self.chain.append({"ts": self._clock(), "kind": "confirmation_issued", "session_id": session_id,
                           "tool": tool_name, "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest()[:16],
                           "expires": exp})
        return f"agc1.{nonce}.{exp}.{mac}"

    def _check_confirmation(self, session_id: str, tool_name: str, arguments: dict,
                            token: Optional[str]) -> Optional[str]:
        if not token:
            return "CONFIRMATION_REQUIRED"
        parts = str(token).split(".")
        if len(parts) != 4 or parts[0] != "agc1" or not parts[2].isdigit():
            return "CONFIRMATION_INVALID"
        _, nonce, exp, mac = parts
        expected = self._confirm_mac(session_id, tool_name, arguments, nonce, int(exp))
        if not hmac.compare_digest(expected, mac):
            return "CONFIRMATION_INVALID"
        if int(exp) < self._clock():
            return "CONFIRMATION_EXPIRED"
        if nonce in self._used_nonces:
            return "CONFIRMATION_REPLAYED"
        self._used_nonces.add(nonce)
        return None

    # --- redaction ---------------------------------------------------------------

    def _sensitive(self, key: str) -> bool:
        words = _words(str(key))
        return any(_contains_phrase(words, term) for term in self.redact_terms)

    def redact(self, obj: Any) -> tuple[Any, int]:
        """Copy of ``obj`` with sensitive fields replaced. Returns (copy, fields redacted)."""
        if isinstance(obj, dict):
            out, n = {}, 0
            for k, v in obj.items():
                if self._sensitive(k):
                    out[k] = REDACTED
                    n += 1
                else:
                    out[k], m = self.redact(v)
                    n += m
            return out, n
        if isinstance(obj, (list, tuple)):
            items = [self.redact(v) for v in obj]
            return [v for v, _ in items], sum(m for _, m in items)
        return obj, 0

    # --- call path ---------------------------------------------------------------

    def _denied_verb(self, tool_name: str) -> Optional[str]:
        words = _words(tool_name)
        for verb, phrase in self.denied_verbs.items():
            if _contains_phrase(words, phrase) and verb.lower() not in self.approved_verbs:
                return verb
        return None

    def _record(self, session_id: str, tool_name: str, res: BlueprintResult, arguments: dict,
                elapsed_ms: float) -> BlueprintResult:
        entry = self.chain.append({
            "ts": self._clock(), "kind": "mcp_blueprint_call", "session_id": session_id, "tool": tool_name,
            "verdict": "ALLOW" if res.ok else "DENY", "rule_code": res.rule_code, "rows": res.rows,
            "redacted_fields": res.redacted_fields, "args": scrub_obj(arguments),
            "elapsed_ms": round(elapsed_ms, 4),
        })
        res.audit_entry_hash = entry["entry_hash"]
        return res

    def call(self, session_id: str, tool_name: str, arguments: Optional[dict] = None,
             confirmation_token: Optional[str] = None) -> BlueprintResult:
        t0 = time.thread_time_ns()
        args = dict(arguments or {})
        res = self._call(session_id, tool_name, args, confirmation_token)
        return self._record(session_id, tool_name, res, args, (time.thread_time_ns() - t0) / 1e6)

    def _call(self, session_id: str, tool_name: str, args: dict, token: Optional[str]) -> BlueprintResult:
        def deny(code: str, message: str) -> BlueprintResult:
            return BlueprintResult(False, code, tool_name, message=message)

        verb = self._denied_verb(tool_name)
        if verb is not None:
            return deny("MUTATION_VERB_DENIED", f"mutation verb '{verb}' is not approved for this engagement")
        tool = self.tools.get(tool_name)
        if tool is None:
            return deny("TOOL_NOT_ALLOWLISTED", "tool is not on the read-only / confirmed-write allowlist")

        params: dict = {}
        limit = tool.max_rows
        if tool.kind == QUERY:
            extra = set(args) - set(tool.params) - {"limit"}
            missing = set(tool.params) - set(args)
            if extra or missing:
                return deny("QUERY_PARAMETER_INVALID",
                            f"unexpected {sorted(extra)} / missing {sorted(missing)} parameters")
            for p in tool.params:
                v = args[p]
                if v is not None and not isinstance(v, (str, int, float, bool)):
                    return deny("QUERY_PARAMETER_INVALID", f"parameter {p!r} must be a scalar")
                params[p] = v
            if "limit" in args:
                limit = args["limit"]
                if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
                    return deny("QUERY_PARAMETER_INVALID", "limit must be a positive integer")
                if limit > tool.max_rows:
                    return deny("ROW_LIMIT_EXCEEDED", f"limit {limit} exceeds the cap of {tool.max_rows} rows")
        if tool.kind == WRITE:
            problem = self._check_confirmation(session_id, tool_name, args, token)
            if problem is not None:
                return deny(problem, "write tools need a one-time confirmation token for these exact arguments")

        pep = self.engine.evaluate_call(self.agent_key, session_id, tool_name, args)
        if not pep.get("ok"):
            return deny("POLICY_DENIED", f"PolicyEngine: {pep.get('error')}")

        try:
            if tool.kind == QUERY:
                raw = list(tool.handler(tool.sql, params, limit) or [])[:limit]
            else:
                raw = tool.handler(args)
        except Exception as exc:  # noqa: BLE001 - a handler failure is reported, not raised to the client
            return deny("HANDLER_ERROR", type(exc).__name__)
        if tool.kind == LOOKUP:
            raw = self.engine.scan_tool_output(self.agent_key, session_id, tool_name, raw)["result"]
        out, n = self.redact(raw)
        rows = len(out) if tool.kind == QUERY else None
        return BlueprintResult(True, COMPLIANT, tool_name, result=out, redacted_fields=n, rows=rows)

    # --- MCP JSON-RPC surface ----------------------------------------------------

    def tools_list(self) -> list[dict]:
        return [t.descriptor() for t in self.tools.values()]

    def handle_jsonrpc(self, message: dict, session_id: str) -> dict:
        """Answer one MCP ``tools/list`` or ``tools/call`` request."""
        rid = message.get("id") if isinstance(message, dict) else None
        method = message.get("method") if isinstance(message, dict) else None
        params = message.get("params") if isinstance(message, dict) and isinstance(message.get("params"), dict) else {}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.tools_list()}}
        if method != "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        res = self.call(session_id, str(params.get("name") or ""), args, meta.get(META_CONFIRMATION))
        if not res.ok:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32044, "message": res.message,
                "data": {"rule_code": res.rule_code, "audit_entry_hash": res.audit_entry_hash}}}
        text = json.dumps(res.result, default=str, ensure_ascii=False)
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": text}], "isError": False,
            "_meta": {"agentgate/rule_code": res.rule_code, "agentgate/redacted_fields": res.redacted_fields,
                      "agentgate/audit_entry_hash": res.audit_entry_hash}}}
