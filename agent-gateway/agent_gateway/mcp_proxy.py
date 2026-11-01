"""Native MCP JSON-RPC 2.0 wire interceptor around the PEP.

Zero dependencies (standard library only). The proxy sits on the wire between
one MCP client (the agent harness) and one MCP server and sees every message
in both directions. It does not open sockets or spawn processes: the caller
moves the bytes (stdio, loopback HTTP, a test) and asks the proxy what to do
with each message.

Intercepted methods:

- ``tools/list`` (server response): non-core servers taint the session via the
  PEP. The first complete listing per session pins
  ``sha256(canonical {name, description, inputSchema})`` for every tool. A later
  listing that changes or adds a pinned definition is an MCP rug pull: the
  proxy records ``mcp_rug_pull_detected`` (approximate AML.T0051), the PEP
  appends ``allow_egress=false`` to the session ``agw1.`` capability, every later
  ``tools/call`` is held for a bound one-time OOB approval, and the client
  keeps seeing the pinned definitions. Every listing is also registered with
  the engine's ``schema_integrity_guard``: digests are pinned per server
  across sessions, so drift seen by a fresh session is denied too
  (``SCHEMA_DRIFT_DENIED``), and a tool whose name collides with one pinned
  on another server (``TOOL_SHADOWING_DENIED``) is not served. A signed
  manifest update travels in ``result._meta["agentgate/schema_manifest"]``
  as ``{tool name: HMAC}``.
- ``tools/call`` (client request): evaluated by ``PolicyEngine.evaluate_call``.
  A denied call is answered with a JSON-RPC error and never reaches the
  server. Results of sensitive reads are fingerprinted for de-obfuscation and
  registered with the engine's ``temporal_accumulator_guard``, whose window
  for released arguments is kept per (session, ``mcp:<server>``), so a value
  split across calls to one server is denied (``SHARDED_EXFIL_DENIED``).
- ``resources/read`` and ``prompts/get`` (client request, server response):
  gated by the PEP; content from a non-core server taints the session. A
  ``resources/read`` URI is looked up in the engine's
  ``memory_provenance_guard`` ledger: the session inherits the taint of the
  session that wrote it, and a record whose HMAC fails is denied
  (``PROVENANCE_TAMPER_DENIED``) before the request reaches the server.
- Every ``tools/call``, ``resources/read``, and ``prompts/get`` result is
  scanned by ``tool_output_scanner.py`` before it reaches the client. A
  finding taints the session, attenuates the ``agw1.`` token, and the result
  is forwarded with invisible Unicode removed.
- ``sampling/createMessage`` and ``elicitation/create`` (server-initiated):
  the params are scanned before they can reach the model. Sampling is
  rejected while the session is tainted, held for review, or lacks the
  root-keyed ``grant:sampling=`` caveat. Elicitation is not forwarded when
  the scan finds injection or the session is already tainted; nothing here
  freezes a credential.
- ``resources/list``, ``resources/subscribe``, ``prompts/list``, and server
  notifications are scanned the same way. A result or error whose id is not
  the canonical id of an in-flight request is not forwarded.

JSON-RPC ids are null, string, or int, with no coercion between those forms.
``"7"``, ``7``, and ``7.0`` are not the same id. ``handle_line`` parses with
``loads_strict`` (the Flask ``/mcp`` parser): a leading BOM, duplicate object
keys, lone surrogates, NUL, non-UTF-8, non-finite numbers, and a number a
binary float cannot carry exactly are rejected at -32700. A batch is rejected
whole. An id that is already in flight is rejected and the original request
stays pending. Elicitation and other held server requests use -32081, not
-32077, which is Predicate C.

OOB approval for a held call travels in ``params._meta``:
``{"agentgate/approval_token": "...", "agentgate/bound_step_index": N}``.
The proxy strips ``agentgate/*`` keys before forwarding.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Optional

from .canonical_argument_confinement import loads_strict, plain_numbers
from .common import Denied
from .pep import PolicyEngine
from .taint import CORE_MCP_SERVERS

JSONRPC = "2.0"
CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"
META_PREFIX = "agentgate/"
META_APPROVAL = "agentgate/approval_token"
META_BOUND_STEP = "agentgate/bound_step_index"
META_CAPABILITY = "agentgate/capability_token"
META_SCHEMA_MANIFEST = "agentgate/schema_manifest"
ERR_PARSE = -32700
ERR_INVALID = -32600

GATED_CLIENT_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
INTERCEPTED_METHODS = frozenset({
    "tools/list", "tools/call", "resources/read", "prompts/get", "sampling/createMessage",
    "elicitation/create", "resources/list", "resources/subscribe", "prompts/list",
})
# Non-core listings and reads carry another server's bytes into the session.
_UNTRUSTED_RESULTS = frozenset({
    "resources/read", "resources/list", "resources/subscribe", "resources/templates/list",
    "prompts/get", "prompts/list",
})
_PSEUDO_TOOL = {"resources/read": "mcp.resources/read", "prompts/get": "mcp.prompts/get"}
# -32077 is Predicate C (CAUSALITY_LAUNDERING_DENIED) on main. Elicitation
# keeps its own code so a held server request is not reported as causality.
ERR_ELICITATION = -32081


class WireReject(Exception):
    def __init__(self, code: int, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def canonical_id(rid: Any) -> tuple:
    """One id form: null, string, or int. No bool, float, or coercion."""
    if rid is None:
        return ("null",)
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        raise WireReject(ERR_INVALID, "id must be null, string, or int")
    if isinstance(rid, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in rid):
            raise WireReject(ERR_INVALID, "lone surrogate")
        return ("str", rid)
    return ("int", rid)


def _reject_surrogates(obj: Any, depth: int = 0) -> None:
    if depth > 32:
        raise WireReject(ERR_INVALID, "invalid request")
    if isinstance(obj, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in obj):
            raise WireReject(ERR_INVALID, "lone surrogate")
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                _reject_surrogates(key, depth + 1)
            _reject_surrogates(value, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _reject_surrogates(value, depth + 1)


# ``loads_strict`` reasons that the wire-canonical tests name explicitly.
# The code stays -32700, the same parse error Flask ``/mcp`` returns.
_WIRE_PARSE_MESSAGES = {
    "WIRE_BOM": "bom",
    "DUPLICATE_KEY": "duplicate key",
    "LONE_SURROGATE": "lone surrogate",
}


def _wire_parse_message(exc: Denied) -> str:
    reason = exc.args[0] if exc.args else ""
    return _WIRE_PARSE_MESSAGES.get(reason, "parse error")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def tool_digest(tool: dict) -> str:
    """SHA-256 over the pinned fields of one tool definition."""
    pinned = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }
    return hashlib.sha256(canonical(pinned)).hexdigest()


def error_response(rid: Any, code: int, message: str, data: Optional[dict] = None) -> dict:
    err: dict[str, Any] = {"code": int(code), "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": JSONRPC, "id": rid, "error": err}


@dataclass
class FilterResult:
    """What to do with one message.

    ``forward``: messages to deliver in the original direction.
    ``reply``: messages to send back to the sender instead.
    """
    decision: str
    forward: list[dict] = field(default_factory=list)
    reply: list[dict] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


@dataclass
class _Pending:
    method: str
    params: dict
    tool_name: str = ""


class McpWireProxy:
    """One client <-> one server MCP session, filtered through ``PolicyEngine``."""

    def __init__(
        self,
        engine: PolicyEngine,
        agent_key: str,
        session_id: str,
        server_name: str,
        capability_token: Optional[str] = None,
    ):
        self.engine = engine
        self.agent_key = agent_key
        self.session_id = session_id
        self.server_name = server_name or "unknown"
        self.capability_token = capability_token
        self._unpresented = capability_token
        self.pins: dict[str, str] = {}
        self._pinned_defs: dict[str, dict] = {}
        self._pin_complete = False
        self._pending: dict[str, _Pending] = {}
        self._server_pending: dict[str, str] = {}

    # --- helpers --------------------------------------------------------------

    @property
    def destination(self) -> str:
        """Accumulator window key for calls through this proxy."""
        return f"mcp:{self.server_name}"

    @property
    def is_core_server(self) -> bool:
        core = {c.lower() for c in CORE_MCP_SERVERS}
        reg = self.engine.cfg.registry_path
        if reg.is_file():
            try:
                core |= {str(c).lower() for c in json.loads(reg.read_text()).get("core_mcp_servers") or []}
            except (ValueError, OSError):
                pass
        return self.server_name.lower() in core

    def _cap(self, params: Optional[dict] = None) -> Optional[str]:
        """A token the client presents in ``_meta``, else the constructor token once.

        After that the PEP's own session copy is authoritative.
        """
        meta = (params or {}).get("_meta") if isinstance((params or {}).get("_meta"), dict) else {}
        tok = meta.get(META_CAPABILITY) or self._unpresented
        self._unpresented = None
        return str(tok) if tok else None

    def _track(self, out: dict) -> None:
        tok = out.get("capability_token")
        if isinstance(tok, str) and tok:
            self.capability_token = tok

    @staticmethod
    def _key(rid: Any) -> tuple:
        return canonical_id(rid)

    @staticmethod
    def _strip_meta(msg: dict) -> dict:
        params = msg.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
            return msg
        meta = {k: v for k, v in params["_meta"].items() if not str(k).startswith(META_PREFIX)}
        new_params = dict(params)
        if meta:
            new_params["_meta"] = meta
        else:
            new_params.pop("_meta", None)
        return {**msg, "params": new_params}

    @staticmethod
    def _deny_data(out: dict) -> dict:
        keys = ("error", "tainted", "sensitive_read", "atlas", "step_index", "allow_egress", "capability_token")
        data = {k: out[k] for k in keys if k in out}
        data["atlas_approximate"] = True
        if "approval_webhook" in out:
            data["awaiting_approval"] = True
        return data

    # --- entry points ---------------------------------------------------------

    def handle(self, direction: str, message: Any) -> FilterResult:
        """Filter one decoded JSON-RPC message.

        A batch is rejected whole. Callers that still have the wire bytes
        should use ``handle_line``, which also rejects a BOM, duplicate keys,
        and lone surrogates.
        """
        if isinstance(message, list):
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "batch rejected")])
        if not isinstance(message, dict) or message.get("jsonrpc") != JSONRPC:
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "invalid request")])
        try:
            _reject_surrogates(message)
            if "id" in message:
                canonical_id(message.get("id"))
        except WireReject as exc:
            return FilterResult("invalid", reply=[error_response(None, exc.code, exc.detail)])
        if direction == CLIENT_TO_SERVER:
            return self._from_client(message)
        if direction == SERVER_TO_CLIENT:
            return self._from_server(message)
        raise ValueError(f"unknown direction: {direction}")

    def handle_line(self, direction: str, line: str) -> FilterResult:
        """Newline-delimited stdio framing: one JSON document per line.

        The bytes go through ``loads_strict`` and ``plain_numbers(exact=True)``,
        the same parser as Flask ``/mcp``. That rejects a BOM, any encoding
        other than strict UTF-8, NUL, lone surrogates, duplicate keys, NaN,
        and a number a binary float cannot carry exactly. A JSON-RPC batch is
        rejected whole. An id that was a non-integer token (``7.0``) is
        rejected before integral decimals collapse to ``int``, so it is not
        id ``7``.
        """
        if isinstance(line, str):
            if line.startswith("\ufeff"):
                return FilterResult("invalid", reply=[error_response(None, ERR_PARSE, "bom")])
            raw = line.encode("utf-8", "surrogatepass")
        elif isinstance(line, (bytes, bytearray)):
            raw = bytes(line)
        else:
            return FilterResult("invalid", reply=[error_response(None, ERR_PARSE, "parse error")])
        try:
            parsed = loads_strict(raw)
        except Denied as exc:
            return FilterResult("invalid", reply=[error_response(None, ERR_PARSE, _wire_parse_message(exc))])
        if isinstance(parsed, list):
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "batch rejected")])
        if not isinstance(parsed, dict):
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "invalid request")])
        if "id" in parsed and type(parsed["id"]) is Decimal:
            return FilterResult(
                "invalid",
                reply=[error_response(None, ERR_INVALID, "id must be null, string, or int")],
            )
        try:
            message = plain_numbers(parsed, exact=True)
        except Denied as exc:
            return FilterResult("invalid", reply=[error_response(None, ERR_PARSE, _wire_parse_message(exc))])
        return self.handle(direction, message)

    # --- client -> server -----------------------------------------------------

    def _from_client(self, msg: dict) -> FilterResult:
        method = msg.get("method")
        has_id = "id" in msg
        rid = msg.get("id") if has_id else None
        if method is None:
            # A response from the client (e.g. to sampling/createMessage).
            if not has_id:
                return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "response missing id")])
            if self._server_pending.pop(self._key(rid), None) is None:
                return FilterResult("unmatched", reply=[error_response(rid, ERR_INVALID, "unmatched response id")])
            return FilterResult("pass", forward=[msg])
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if has_id and self._key(rid) in self._pending:
            return FilterResult("deny", reply=[error_response(rid, ERR_INVALID, "id reuse")])
        if method in GATED_CLIENT_METHODS:
            return self._gate_client_call(msg, method, params)
        if has_id:
            self._pending[self._key(rid)] = _Pending(method=str(method), params=params)
        return FilterResult("pass", forward=[self._strip_meta(msg)])

    def _gate_client_call(self, msg: dict, method: str, params: dict) -> FilterResult:
        rid = msg.get("id")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if method == "tools/call":
            tool = str(params.get("name") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        elif method == "resources/read":
            tool = _PSEUDO_TOOL[method]
            arguments = {"uri": str(params.get("uri") or "")}
        else:
            tool = _PSEUDO_TOOL[method]
            arguments = {"name": str(params.get("name") or "")}
            if isinstance(params.get("arguments"), dict):
                arguments["arguments"] = params["arguments"]
        bound = meta.get(META_BOUND_STEP)
        if method == "tools/call":
            drift = self.engine.check_schema_call(self.agent_key, self.session_id, self.server_name, tool, arguments)
            if drift is not None:
                self._track(drift)
                reply = error_response(rid, drift["code"], drift["message"], self._deny_data(drift))
                return FilterResult("deny", reply=[reply] if rid is not None else [], detail=drift)
        out = self.engine.evaluate_call(
            self.agent_key, self.session_id, tool, arguments,
            approval_token=meta.get(META_APPROVAL),
            bound_step_index=int(bound) if bound is not None else None,
            capability_token=self._cap(params),
            destination=self.destination,
        )
        self._track(out)
        if not out.get("ok"):
            reply = error_response(rid, out.get("code", -32000),
                                   out.get("message") or str(out.get("error")), self._deny_data(out))
            return FilterResult("deny", reply=[reply] if "id" in msg else [], detail=out)
        if "id" in msg:
            self._pending[self._key(rid)] = _Pending(method=method, params=params, tool_name=tool)
        return FilterResult("allow", forward=[self._strip_meta(msg)], detail=out)

    # --- server -> client -----------------------------------------------------

    def _from_server(self, msg: dict) -> FilterResult:
        method = msg.get("method")
        has_id = "id" in msg
        rid = msg.get("id") if has_id else None
        if method is not None:
            if method == "sampling/createMessage":
                return self._gate_sampling(msg)
            if method == "elicitation/create":
                return self._gate_elicitation(msg)
            if str(method).startswith("notifications/"):
                return self._inspect_notification(msg)
            return self._inspect_server_request(msg)
        if not has_id or ("result" in msg) == ("error" in msg):
            # A response needs an id and exactly one of result or error.
            return FilterResult("invalid", reply=[error_response(
                rid if has_id else None, ERR_INVALID, "invalid response")])
        pending = self._pending.pop(self._key(rid), None)
        if pending is None:
            # Different id spelling ("7" vs 7) is not a match and is not forwarded.
            return FilterResult("unmatched", reply=[error_response(rid, ERR_INVALID, "unmatched response id")])
        if pending.method == "tools/list" and "result" in msg:
            return self._scan_delivery(self._on_tools_list(msg), "tools/list")
        decision = "pass"
        field = "result" if "result" in msg else "error"
        if pending.method == "tools/call" and field == "result":
            self.engine.ingest_tool_result(self.agent_key, self.session_id, pending.tool_name, msg.get("result"))
            # Predicate D learns values from the real result before the agent sees it.
            try:
                self.engine.ingest_dynamic_result(self.agent_key, self.session_id, pending.tool_name,
                                                  msg.get("result"))
            except ValueError as exc:
                reason = str(exc)
                reply = error_response(rid, -32075, "result withheld",
                                       {"error": "dynamic_ingression_denied", "reason": reason})
                return FilterResult("withheld", forward=[reply], detail={"reason": reason})
        if pending.method in _UNTRUSTED_RESULTS and not self.is_core_server and field == "result":
            self.engine.mark_untrusted_ingest(
                self.agent_key, self.session_id, f"mcp.{pending.method}:{self.server_name}",
            )
            decision = "tainted"
        return self._scan_delivery(FilterResult(decision, forward=[msg]),
                                   pending.tool_name or pending.method, field)

    def _scan_delivery(self, result: FilterResult, tool_name: str, field: Optional[str] = None) -> FilterResult:
        """Scan a server payload that can reach the model. Unreadable payloads are not forwarded."""
        if not result.forward:
            return result
        msg = result.forward[0]
        if not isinstance(msg, dict):
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "invalid response")])
        if field is None:
            field = "result" if "result" in msg else "error" if "error" in msg else None
        if field is None or field not in msg:
            return result
        scanned = self.engine.scan_tool_output(
            self.agent_key, self.session_id, tool_name, msg.get(field),
            include_sinks=tool_name != "tools/list",
        )
        if not scanned["findings"]:
            return result
        self.capability_token = self.engine.sessions[self.session_id].capability_token
        decision = result.decision if result.decision not in ("pass", "pinned", "tainted", "allow") else "injection_flagged"
        detail = dict(result.detail)
        detail["findings"] = scanned["findings"]
        return FilterResult(decision, forward=[{**msg, field: scanned["result"]}],
                            reply=list(result.reply), detail=detail)

    def _inspect_notification(self, msg: dict) -> FilterResult:
        scanned = self.engine.scan_tool_output(
            self.agent_key, self.session_id, str(msg.get("method") or "notification"), msg.get("params"),
        )
        if scanned["findings"]:
            self.capability_token = self.engine.sessions[self.session_id].capability_token
            self.engine._alert("mcp_notification_held", {
                "session_id": self.session_id, "server": self.server_name,
                "atlas": "AML.T0051", "atlas_approximate": True,
            })
            return FilterResult("injection_flagged", detail={"findings": scanned["findings"]})
        return FilterResult("pass", forward=[msg])

    def _inspect_server_request(self, msg: dict) -> FilterResult:
        if "id" not in msg:
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "request missing id")])
        rid = msg.get("id")
        if self._key(rid) in self._server_pending:
            return FilterResult("deny", reply=[error_response(rid, ERR_INVALID, "id reuse")])
        scanned = self.engine.scan_tool_output(
            self.agent_key, self.session_id, str(msg.get("method") or ""), msg.get("params"),
        )
        if scanned["findings"]:
            self.capability_token = self.engine.sessions[self.session_id].capability_token
            return FilterResult("deny", reply=[error_response(rid, ERR_ELICITATION, "server_request_held")],
                                detail={"findings": scanned["findings"]})
        self._server_pending[self._key(rid)] = str(msg.get("method") or "")
        return FilterResult("pass", forward=[msg])

    def _gate_elicitation(self, msg: dict) -> FilterResult:
        """Server-initiated elicitation. Injection and a tainted session are not forwarded."""
        if "id" not in msg:
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "request missing id")])
        rid = msg.get("id")
        if self._key(rid) in self._server_pending:
            return FilterResult("deny", reply=[error_response(rid, ERR_INVALID, "id reuse")])
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        scanned = self.engine.scan_tool_output(
            self.agent_key, self.session_id, "elicitation/create", params,
        )
        sess = self.engine.sessions.get(self.session_id)
        blocked = bool(scanned["findings"]) or (
            sess is not None and (sess.tainted or bool(sess.review_hold) or not sess.allow_egress))
        if blocked:
            if sess is not None:
                self.capability_token = sess.capability_token
            self.engine._alert("elicitation_rejected", {
                "session_id": self.session_id, "server": self.server_name,
                "atlas": "AML.T0051", "atlas_approximate": True,
            })
            return FilterResult("deny", reply=[error_response(rid, ERR_ELICITATION, "elicitation_rejected")],
                                detail={"findings": scanned["findings"]})
        self._server_pending[self._key(rid)] = "elicitation/create"
        return FilterResult("allow", forward=[msg])

    def _gate_sampling(self, msg: dict) -> FilterResult:
        if "id" not in msg:
            return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "request missing id")])
        rid = msg.get("id")
        if self._key(rid) in self._server_pending:
            return FilterResult("deny", reply=[error_response(rid, ERR_INVALID, "id reuse")])
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        # A finding taints the session. Do not re-present the pre-scan token:
        # that token still allows egress, and adopting it would be an upgrade.
        scanned = self.engine.scan_tool_output(
            self.agent_key, self.session_id, "sampling/createMessage", params,
        )
        if scanned["findings"]:
            self._unpresented = None
            token = None
        else:
            token = self._cap()
        out = self.engine.evaluate_sampling(
            self.agent_key, self.session_id, params, capability_token=token,
        )
        self._track(out)
        if not out.get("ok"):
            reply = error_response(rid, out.get("code", -32000), str(out.get("error")), self._deny_data(out))
            return FilterResult("deny", reply=[reply], detail=out)
        self._server_pending[self._key(rid)] = "sampling/createMessage"
        return FilterResult("allow", forward=[msg], detail=out)

    def _on_tools_list(self, msg: dict) -> FilterResult:
        result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        tools = [t for t in (result.get("tools") or []) if isinstance(t, dict)]
        out = self.engine.evaluate_tools_list(
            self.agent_key, self.session_id, self.server_name, tools, capability_token=self._cap(),
        )
        self._track(out)
        if not out.get("ok"):
            reply = error_response(msg.get("id"), out.get("code", -32000), str(out.get("error")))
            return FilterResult("deny", forward=[reply], detail=out)

        changes: list[dict] = []
        served: list[dict] = []
        pinned_before = set(self.pins)
        for tool in tools:
            name = str(tool.get("name") or "")
            digest = tool_digest(tool)
            pinned = self.pins.get(name)
            if pinned is None and not self._pin_complete:
                self.pins[name] = digest
                self._pinned_defs[name] = tool
                served.append(tool)
            elif pinned is None:
                changes.append({"tool": name, "change": "added", "seen_sha256": digest})
            elif pinned != digest:
                changes.append({"tool": name, "change": "mutated", "pinned_sha256": pinned, "seen_sha256": digest})
                served.append(self._pinned_defs[name])
            else:
                served.append(tool)
        if not result.get("nextCursor"):
            self._pin_complete = True

        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        manifest = meta.get(META_SCHEMA_MANIFEST) if isinstance(meta.get(META_SCHEMA_MANIFEST), dict) else None
        verdicts = self.engine.register_tool_schemas(self.agent_key, self.session_id, self.server_name, tools,
                                                     manifest)
        refused = {v["tool"]: v for v in verdicts if not v["ok"]}
        # Drop refused tools. Drift on a tool this proxy pinned earlier keeps serving that pinned definition.
        kept = [t for t in served if (n := str(t.get("name") or "")) not in refused
                or (refused[n]["code"] == "SCHEMA_DRIFT_DENIED" and n in pinned_before)]

        if not changes and not refused:
            return FilterResult("pinned", forward=[msg], detail={"pins": len(self.pins)})
        safe = {**msg, "result": {**result, "tools": kept}}
        if not changes:
            return FilterResult("schema_denied", forward=[safe], detail={"schema": list(refused.values())})
        finding = self.engine.flag_rug_pull(self.agent_key, self.session_id, self.server_name, changes)
        self.capability_token = self.engine.sessions[self.session_id].capability_token
        if refused:
            finding = {**finding, "schema": list(refused.values())}
        return FilterResult("rug_pull", forward=[safe], detail=finding)
