"""HTTP-path resource limits (lab). In-process PolicyEngine use is not limited."""
from __future__ import annotations

from agent_gateway.pep import PepConfig, create_app
from tests.conftest import KEY_A, REG


def _client(state_dir, **limits):
    cfg = PepConfig(registry_path=REG, alert_log=state_dir / "alerts.jsonl", **limits)
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client()


def _call(c, session="s1", arguments=None):
    return c.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"agent_key": KEY_A, "session_id": session,
                   "name": "lookup_order_status", "arguments": arguments or {"order_id": "A-1"}},
    })


def test_oversized_body_rejected(state_dir):
    c = _client(state_dir, max_body_bytes=1024)
    r = _call(c, arguments={"order_id": "x" * 5000})
    assert r.status_code == 413


def test_oversized_arguments_rejected(state_dir):
    c = _client(state_dir, max_arg_bytes=64)
    r = _call(c, arguments={"order_id": "x" * 500})
    assert r.status_code == 413
    assert _call(c).status_code == 200


def test_session_cap_and_existing_session_still_served(state_dir):
    c = _client(state_dir, max_sessions=2)
    assert _call(c, "a").status_code == 200
    assert _call(c, "b").status_code == 200
    assert _call(c, "c").status_code == 429
    assert _call(c, "a").status_code == 200


def test_long_session_id_rejected(state_dir):
    c = _client(state_dir, max_id_len=16)
    assert _call(c, "s" * 17).status_code == 400
