"""Chained HMAC capability attenuation (macaroon-style caveats).

Lab policy gate only. Freeze and block still apply only to registered keys.
The web honeypot path is not in this package.
"""
from __future__ import annotations

import json
from base64 import urlsafe_b64decode

from agent_gateway import approve, capability
from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState
from tests.conftest import KEY_A, REG


def _b64d(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return urlsafe_b64decode(text + pad)


def test_token_format_is_deterministic_and_bound():
    a = capability.mint("sess-1", KEY_A)
    b = capability.mint("sess-1", KEY_A)
    token = capability.serialize(a)
    assert token == capability.serialize(b)
    assert token.startswith("agw1.")
    prefix, payload_b64, sig = token.split(".")
    assert prefix == "agw1"
    payload = json.loads(_b64d(payload_b64))
    assert payload["v"] == 1
    assert payload["id"] == "sess-1"
    assert payload["caveats"] == [
        f"bind:session={capability.session_binding('sess-1')}",
        f"bind:agent={capability.agent_binding(KEY_A)}",
        "allow_egress=true",
    ]
    assert sig == a.signature
    verified = capability.verify(token)
    assert verified is not None and verified.allows_egress is True
    assert capability.agent_matches(verified, KEY_A)
    assert not capability.agent_matches(verified, "agk_demo_registered_0002")


def test_holder_cannot_strip_reorder_or_reenable_egress():
    mac = capability.mint("sess-h", KEY_A)
    denied = capability.attenuate(mac, capability.CAVEAT_DENY_EGRESS)
    denied = capability.attenuate(denied, capability.taint_source_caveat("read_external_url:1"))
    token = capability.serialize(denied)
    # Holder path: no root key, only the embedded tag.
    widened = capability.attenuate_token(token, capability.CAVEAT_ALLOW_EGRESS)
    checked = capability.verify(widened)
    assert checked is not None and checked.allows_egress is False

    stripped = capability.serialize(capability.Capability(
        denied.session_id, denied.caveats[:3], denied.signature,
    ))
    assert capability.verify(stripped) is None

    reordered = capability.serialize(capability.Capability(
        denied.session_id,
        (denied.caveats[0], denied.caveats[2], denied.caveats[1], denied.caveats[3]),
        denied.signature,
    ))
    assert capability.verify(reordered) is None

    flipped = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert capability.verify(flipped) is None

    foreign = capability.serialize(capability.mint("sess-h", KEY_A, key=b"other-root-key-not-shared!!"))
    assert capability.verify(foreign) is None
    assert capability.verify(foreign, key=b"other-root-key-not-shared!!") is not None


def test_untrusted_read_attenuates_in_place(engine: PolicyEngine):
    sid = "cap-read"
    out = engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/poison"})
    assert out["ok"] is True
    assert out["allow_egress"] is False
    cap = capability.verify(out["capability_token"])
    assert cap is not None and cap.allows_egress is False
    assert cap.taint_source
    assert engine.sessions[sid].tainted is True
    send = engine.evaluate_call(KEY_A, sid, "send_email", {"to": "a@b.c", "body": "x"})
    assert send["ok"] is False
    assert send["allow_egress"] is False


def test_preimage_and_appended_allow_cannot_upgrade(engine: PolicyEngine):
    sid = "cap-upgrade"
    out = engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/p"})
    token = out["capability_token"]
    pre = capability.serialize(capability.mint(sid, KEY_A))
    assert capability.verify(pre).allows_egress is True
    replay = engine.evaluate_call(
        KEY_A, sid, "send_email", {"to": "a@b.c", "body": "x"}, capability_token=pre,
    )
    assert replay["ok"] is False
    assert replay["error"] == "capability_upgrade_rejected"
    assert engine.sessions[sid].allow_egress is False

    widened = capability.attenuate_token(token, capability.CAVEAT_ALLOW_EGRESS)
    assert capability.verify(widened).allows_egress is False
    again = engine.evaluate_call(
        KEY_A, sid, "send_email", {"to": "a@b.c", "body": "y"}, capability_token=widened,
    )
    assert again["ok"] is False
    assert engine.sessions[sid].allow_egress is False
    plain = engine.evaluate_call(KEY_A, sid, "file.write", {"path": "/tmp/x", "body": "no"})
    assert plain["ok"] is False


def test_holder_attenuation_is_honored_without_root_key(engine: PolicyEngine):
    sid = "cap-holder-pep"
    benign = engine.evaluate_call(KEY_A, sid, "lookup_order_status", {"order_id": 1})
    assert benign["ok"] and benign["allow_egress"] is True
    denied_tok = capability.attenuate_token(benign["capability_token"], capability.CAVEAT_DENY_EGRESS)
    out = engine.evaluate_call(
        KEY_A, sid, "send_webhook", {"url": "http://127.0.0.1/hook"}, capability_token=denied_tok,
    )
    assert out["ok"] is False
    assert engine.sessions[sid].allow_egress is False
    assert engine.sessions[sid].tainted is True


def test_stateless_worker_verifies_chain_and_oob_still_one_shot(engine: PolicyEngine, state_dir):
    """A second engine shares only the HMAC key and the OOB approval directory."""
    sid = "cap-cross"
    first = engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/poison"})
    token = first["capability_token"]
    assert capability.verify(token).allows_egress is False

    other = PolicyEngine(
        Registry.load(REG),
        shared=SharedState(),
        cfg=PepConfig(registry_path=REG, alert_log=state_dir / "alerts-b.jsonl"),
    )
    assert other.sessions == {}
    args = {"to": "team@internal.local", "body": "Status OK"}
    denied = other.evaluate_call(KEY_A, sid, "send_email", args, capability_token=token)
    assert denied["ok"] is False
    assert denied["error"] == "post_taint_outbound_gated"
    assert other.sessions[sid].allow_egress is False

    stripped = capability.verify(token)
    forged = capability.serialize(capability.Capability(
        stripped.session_id, stripped.caveats[:3], stripped.signature,
    ))
    bad = other.evaluate_call(KEY_A, sid, "send_email", args, capability_token=forged)
    assert bad["error"] == "capability_rejected"
    assert other.sessions[sid].allow_egress is False

    step = denied["step_index"]
    rec = approve.mint(sid, step, "send_email", args, taint_source_id=other.sessions[sid].taint_source_id)
    ok = other.evaluate_call(
        KEY_A, sid, "send_email", args,
        approval_token=rec["token"], bound_step_index=step, capability_token=token,
    )
    assert ok["ok"] is True
    # OOB does not upgrade the capability chain.
    assert other.sessions[sid].allow_egress is False
    assert capability.verify(other.sessions[sid].capability_token).allows_egress is False
    replay = other.evaluate_call(
        KEY_A, sid, "send_email", args,
        approval_token=rec["token"], bound_step_index=step, capability_token=token,
    )
    assert replay["ok"] is False


def test_foreign_and_mismatched_tokens_rejected(engine: PolicyEngine):
    foreign = capability.serialize(capability.mint("s-foreign", KEY_A, key=b"other-root-key-not-shared!!"))
    out = engine.evaluate_call(
        KEY_A, "s-foreign", "send_email", {"to": "a@b.c", "body": "x"}, capability_token=foreign,
    )
    assert out["error"] == "capability_rejected"

    other_sess = capability.serialize(capability.mint("other-session", KEY_A))
    # Attenuate so a naive compare cannot treat it as the fresh mint for s-bind.
    other_sess = capability.attenuate_token(other_sess, capability.CAVEAT_DENY_EGRESS)
    bound = engine.evaluate_call(KEY_A, "s-bind", "lookup_order_status", {"order_id": 3})
    assert bound["ok"]
    mismatch = engine.evaluate_call(
        KEY_A, "s-bind", "send_email", {"to": "a@b.c", "body": "x"}, capability_token=other_sess,
    )
    assert mismatch["error"] == "capability_rejected"
    assert engine.sessions["s-bind"].allow_egress is True


def test_outsider_is_not_enrolled_or_frozen(engine: PolicyEngine):
    token = engine.evaluate_call(KEY_A, "s-out", "lookup_order_status", {"order_id": 1})["capability_token"]
    out = engine.evaluate_call(
        "visitor_public", "s-out", "send_email", {"to": "a@b.c", "body": "x"}, capability_token=token,
    )
    assert out["error"] == "unregistered_agent"
    assert "capability_token" not in out
    assert engine.registry.is_frozen_key("visitor_public", engine.now()) is False
    assert engine._freeze_root("visitor_public", "nope") == []
    assert engine.registry.is_frozen_key("visitor_public", engine.now()) is False
    # Registered root freeze still does not touch the outsider.
    engine._freeze_root(KEY_A, "lab")
    assert engine.registry.is_frozen_key(KEY_A, engine.now())
    assert engine.registry.is_frozen_key("visitor_public", engine.now()) is False


def test_constrained_sink_survives_attenuation(engine: PolicyEngine):
    sid = "cap-ticket"
    assert engine.evaluate_call(KEY_A, sid, "read_customer_ticket", {"ticket_id": "T-9"})["allow_egress"] is False
    ok = engine.evaluate_call(KEY_A, sid, "update_ticket_status", {"order_id": 9, "status": "shipped"})
    assert ok["ok"] is True and ok.get("constrained_sink") is True
    bad = engine.evaluate_call(KEY_A, sid, "update_ticket_memo", {"text": "free text from the ticket"})
    assert bad["ok"] is False


def test_mcp_returns_attenuated_capability_and_stays_on_loopback(client):
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_external_url",
            "arguments": {"url": "http://127.0.0.1/poison"},
            "session_id": "http-1",
            "agent_key": KEY_A,
        },
    }
    rv = client.post("/mcp", json=body)
    assert rv.status_code == 200
    result = rv.get_json()["result"]
    assert result["allow_egress"] is False
    token = result["capability_token"]
    assert capability.verify(token).allows_egress is False

    denied = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {"to": "a@b.c", "body": "x"},
            "session_id": "http-1",
            "agent_key": KEY_A,
            "capability_token": token,
        },
    })
    assert denied.status_code == 200  # JSON-RPC error is in the body
    err = denied.get_json()["error"]
    assert err["data"]["allow_egress"] is False
    assert err["data"]["error"] == "post_taint_outbound_gated"

    blocked = client.get("/health", environ_overrides={"REMOTE_ADDR": "203.0.113.5"})
    assert blocked.status_code == 403
    assert client.get("/health").status_code == 200
