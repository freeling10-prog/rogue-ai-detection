"""Optional loopback HTTP surface.

The policy engine (``pep.py``) and the MCP wire proxy (``mcp_proxy.py``) do not
import this module. Flask is imported only here. Install it with the ``http``
extra: ``pip install 'agent-gateway[http]'``.

``/mcp`` and ``/v1/call`` return the engine's decision, including
``release_at_ms`` when a leakage budget assigned a slot. They do not perform
the backend call. The caller must not forward that call before
``release_at_ms``.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from .canonical_argument_confinement import loads_strict, plain_numbers
from .common import Denied as ReferenceDenied
from .pep import PepConfig, PolicyEngine
from .registry import Registry


def create_app(cfg: Optional[PepConfig] = None, engine: Optional[PolicyEngine] = None) -> Flask:
    cfg = cfg or PepConfig()
    registry = Registry.load(cfg.registry_path)
    cfg.freeze_seconds = registry.freeze_seconds
    cfg.max_children_per_parent = registry.max_children_per_parent
    eng = engine or PolicyEngine(registry, cfg=cfg)

    app = Flask("agent_gateway")
    app.config["POLICY_ENGINE"] = eng
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_body_bytes

    def _limit_error(code: int, reason: str):
        return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": reason}}), code

    def _check_limits(session_id: str, arguments: Any):
        """Return an error response when a request exceeds a configured limit, else None."""
        if len(session_id) > cfg.max_id_len:
            return _limit_error(400, "session_id too long")
        if session_id not in eng.sessions and len(eng.sessions) >= cfg.max_sessions:
            return _limit_error(429, "session limit reached")
        if arguments is not None and len(json.dumps(arguments, default=str)) > cfg.max_arg_bytes:
            return _limit_error(413, "arguments too large")
        return None

    @app.errorhandler(413)
    def _too_large(_exc):
        return _limit_error(413, "request body too large")

    @app.before_request
    def _loopback_only():
        if cfg.allow_nonlocal:
            return None
        # Reject non-loopback Host / remote
        ra = request.remote_addr or ""
        if ra not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "loopback_only", "message": "PEP binds to 127.0.0.1; pass --allow-nonlocal only in isolated lab"}), 403
        return None

    @app.get("/health")
    def health():
        eng.registry.lift_expired(eng.now())
        return jsonify({"ok": True, "service": "agent-gateway", "bind": "loopback", "version": "0.3.0"})

    def _agent_key_from_request(body: dict) -> str:
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        params = body.get("params") or {}
        return str(params.get("agent_key") or body.get("agent_key") or "")

    @app.post("/mcp")
    def mcp_rpc():
        # Raw bytes through the strict parser: no BOM / UTF-16 / lone surrogates /
        # duplicate keys / NaN, and exact Decimal numbers for Predicate S.
        try:
            body = loads_strict(request.get_data(cache=False))
        except RequestEntityTooLarge:
            raise
        except ReferenceDenied as exc:
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": "parse error", "data": {"reason": str(exc)}}}), 400
        if not isinstance(body, dict):
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}), 400
        wire = body
        body = plain_numbers(body)
        rid = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}
        agent_key = _agent_key_from_request(body)
        session_id = str(params.get("session_id") or request.headers.get("X-Session-Id") or "sess-default")

        bad = _check_limits(session_id, params.get("arguments") if method == "tools/call" else None)
        if bad is not None:
            return bad

        cap_tok = params.get("capability_token") or request.headers.get("X-Capability-Token") or None
        if method == "tools/list":
            out = eng.evaluate_tools_list(
                agent_key, session_id,
                server_name=str(params.get("server") or params.get("server_name") or ""),
                descriptions=list(params.get("tools") or params.get("descriptions") or []),
                capability_token=str(cap_tok) if cap_tok else None,
            )
            if not out.get("ok"):
                return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": out.get("code", -32000), "message": out.get("error")}})
            return jsonify({"jsonrpc": "2.0", "id": rid, "result": out})

        if method == "tools/call":
            name = str(params.get("name") or params.get("tool") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            wire_params = wire.get("params") if isinstance(wire.get("params"), dict) else {}
            wire_arguments = (wire_params.get("arguments")
                              if isinstance(wire_params.get("arguments"), dict) else {})
            token = params.get("approval_token") or request.headers.get("X-Approval-Token")
            depth = int(params.get("delegation_depth") or 0)
            parent = params.get("parent_key")
            bound = params.get("bound_step_index")
            out = eng.evaluate_call(
                agent_key, session_id, name, arguments,
                approval_token=token, delegation_depth=depth, parent_key=parent,
                bound_step_index=int(bound) if bound is not None else None,
                capability_token=str(cap_tok) if cap_tok else None,
                wire_arguments=wire_arguments,
            )
            if not out.get("ok"):
                return jsonify({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": out.get("code", -32000), "message": out.get("message") or out.get("error"),
                    "data": {k: out[k] for k in (
                        "error", "tainted", "sensitive_read", "atlas", "step_index",
                        "allow_egress", "capability_token",
                    ) if k in out},
                }})
            return jsonify({"jsonrpc": "2.0", "id": rid, "result": out})

        return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}})

    # Convenience non-JSON-RPC helpers for unit tests
    @app.post("/v1/call")
    def v1_call():
        body = request.get_json(force=True, silent=True) or {}
        agent_key = _agent_key_from_request(body) or str(body.get("agent_key") or "")
        bound = body.get("bound_step_index")
        cap_tok = body.get("capability_token") or request.headers.get("X-Capability-Token") or None
        bad = _check_limits(str(body.get("session_id") or "sess"), body.get("arguments"))
        if bad is not None:
            return bad
        out = eng.evaluate_call(
            agent_key,
            str(body.get("session_id") or "sess"),
            str(body.get("tool") or body.get("name") or ""),
            body.get("arguments") if isinstance(body.get("arguments"), dict) else {},
            approval_token=body.get("approval_token"),
            delegation_depth=int(body.get("delegation_depth") or 0),
            parent_key=body.get("parent_key"),
            bound_step_index=int(bound) if bound is not None else None,
            capability_token=str(cap_tok) if cap_tok else None,
        )
        return jsonify(out), (200 if out.get("ok") else 403)

    return app


def run_server(cfg: PepConfig) -> None:
    if not cfg.allow_nonlocal and cfg.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Refusing non-loopback bind without --allow-nonlocal")
    app = create_app(cfg)
    app.run(host=cfg.host, port=cfg.port, threaded=True)
