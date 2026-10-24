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
  keeps seeing the pinned definitions.
- ``tools/call`` (client request): evaluated by ``PolicyEngine.evaluate_call``.
  A denied call is answered with a JSON-RPC error and never reaches the
  server. Results of sensitive reads are fingerprinted for de-obfuscation.
- ``resources/read`` and ``prompts/get`` (client request, server response):
  gated by the PEP; content from a non-core server taints the session.
- Every ``tools/call``, ``resources/read``, and ``prompts/get`` result is
  scanned by ``tool_output_scanner.py`` before it reaches the client. A
  finding taints the session, attenuates the ``agw1.`` token, and the result
  is forwarded with invisible Unicode removed.
- ``sampling/createMessage`` (server-initiated request): rejected while the
  session is tainted, held for review, or lacks the root-keyed
  ``grant:sampling=`` caveat in its ``agw1.`` token.

Every other method and notification passes through unchanged.

OOB approval for a held call travels in ``params._meta``:
``{"agentgate/approval_token": "...", "agentgate/bound_step_index": N}``.
The proxy strips ``agentgate/*`` keys before forwarding.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .pep import PolicyEngine
from .taint import CORE_MCP_SERVERS

JSONRPC = "2.0"
CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"
META_PREFIX = "agentgate/"
META_APPROVAL = "agentgate/approval_token"
META_BOUND_STEP = "agentgate/bound_step_index"
META_CAPABILITY = "agentgate/capability_token"
ERR_PARSE = -32700
ERR_INVALID = -32600

GATED_CLIENT_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
INTERCEPTED_METHODS = frozenset({
    "tools/list", "tools/call", "resources/read", "prompts/get", "sampling/createMessage",
})
_PSEUDO_TOOL = {"resources/read": "mcp.resources/read", "prompts/get": "mcp.prompts/get"}


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
    def _key(rid: Any) -> str:
        return json.dumps(rid, sort_keys=True, default=str)

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
        """Filter one decoded JSON-RPC message or batch."""
        if isinstance(message, list):
            if not message:
                return FilterResult("invalid", reply=[error_response(None, ERR_INVALID, "empty batch")])
            agg = FilterResult("batch")
            for item in message:
                res = self.handle(direction, item)
                agg.forward.extend(res.forward)
                agg.reply.extend(res.reply)
            return agg
        if not isinstance(message, dict) or message.get("jsonrpc") != JSONRPC:
            rid = message.get("id") if isinstance(message, dict) else None
            return FilterResult("invalid", reply=[error_response(rid, ERR_INVALID, "invalid request")])
        if direction == CLIENT_TO_SERVER:
            return self._from_client(message)
        if direction == SERVER_TO_CLIENT:
            return self._from_server(message)
        raise ValueError(f"unknown direction: {direction}")

    def handle_line(self, direction: str, line: str) -> FilterResult:
        """Newline-delimited stdio framing: one JSON document per line."""
        try:
            message = json.loads(line)
        except (ValueError, TypeError):
            return FilterResult("invalid", reply=[error_response(None, ERR_PARSE, "parse error")])
        return self.handle(direction, message)

    # --- client -> server -----------------------------------------------------

    def _from_client(self, msg: dict) -> FilterResult:
        method = msg.get("method")
        rid = msg.get("id")
        if method is None:
            # A response from the client (e.g. to sampling/createMessage).
            self._server_pending.pop(self._key(rid), None)
            return FilterResult("pass", forward=[msg])
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method in GATED_CLIENT_METHODS:
            return self._gate_client_call(msg, method, params)
        if rid is not None:
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
        out = self.engine.evaluate_call(
            self.agent_key, self.session_id, tool, arguments,
            approval_token=meta.get(META_APPROVAL),
            bound_step_index=int(bound) if bound is not None else None,
            capability_token=self._cap(params),
        )
        self._track(out)
        if not out.get("ok"):
            reply = error_response(rid, out.get("code", -32000),
                                   out.get("message") or str(out.get("error")), self._deny_data(out))
            return FilterResult("deny", reply=[reply] if rid is not None else [], detail=out)
        if rid is not None:
            self._pending[self._key(rid)] = _Pending(method=method, params=params, tool_name=tool)
        return FilterResult("allow", forward=[self._strip_meta(msg)], detail=out)

    # --- server -> client -----------------------------------------------------

    def _from_server(self, msg: dict) -> FilterResult:
        method = msg.get("method")
        rid = msg.get("id")
        if method is not None:
            if method == "sampling/createMessage":
                return self._gate_sampling(msg)
            if rid is not None:
                self._server_pending[self._key(rid)] = str(method)
            return FilterResult("pass", forward=[msg])
        pending = self._pending.pop(self._key(rid), None)
        if pending is None or "result" not in msg:
            return FilterResult("pass", forward=[msg])
        if pending.method == "tools/list":
            return self._on_tools_list(msg)
        decision = "pass"
        if pending.method == "tools/call":
            self.engine.ingest_tool_result(self.agent_key, self.session_id, pending.tool_name, msg.get("result"))
        if pending.method in ("resources/read", "prompts/get") and not self.is_core_server:
            self.engine.mark_untrusted_ingest(
                self.agent_key, self.session_id, f"mcp.{pending.method}:{self.server_name}",
            )
            decision = "tainted"
        if pending.method in ("tools/call", "resources/read", "prompts/get"):
            # Scan before the result reaches the agent loop; forward it with invisible characters removed.
            scanned = self.engine.scan_tool_output(
                self.agent_key, self.session_id, pending.tool_name or pending.method, msg.get("result"),
            )
            if scanned["findings"]:
                self.capability_token = self.engine.sessions[self.session_id].capability_token
                return FilterResult("injection_flagged", forward=[{**msg, "result": scanned["result"]}],
                                    detail={"findings": scanned["findings"]})
        return FilterResult(decision, forward=[msg])

    def _gate_sampling(self, msg: dict) -> FilterResult:
        rid = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        out = self.engine.evaluate_sampling(
            self.agent_key, self.session_id, params, capability_token=self._cap(),
        )
        self._track(out)
        if not out.get("ok"):
            reply = error_response(rid, out.get("code", -32000), str(out.get("error")), self._deny_data(out))
            return FilterResult("deny", reply=[reply] if rid is not None else [], detail=out)
        if rid is not None:
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

        if not changes:
            return FilterResult("pinned", forward=[msg], detail={"pins": len(self.pins)})
        finding = self.engine.flag_rug_pull(self.agent_key, self.session_id, self.server_name, changes)
        self.capability_token = self.engine.sessions[self.session_id].capability_token
        safe = {**msg, "result": {**result, "tools": served}}
        return FilterResult("rug_pull", forward=[safe], detail=finding)
