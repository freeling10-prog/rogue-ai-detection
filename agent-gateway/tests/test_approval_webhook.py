"""Interactive approval webhook: scrubbed payload, hash-bound one-time callbacks.

No network. Delivery stays off unless webhook_deliver is set.
"""
from __future__ import annotations

import json
import urllib.request

from agent_gateway.approval_webhook import (
    ACTION_APPROVE_ONCE,
    ACTION_DENY_FREEZE,
    LABEL_APPROVE_ONCE,
    LABEL_DENY_FREEZE,
    apply_callback,
    build_approval_payload,
    verify_callback,
)
from agent_gateway.pep import PolicyEngine
from tests.conftest import KEY_A

NOW = 1_700_000_000
SECRET = "sk-abcdefghijklmnopqrstuvwxyz"
EMAIL = "ops@example.com"
BEARER = "Bearer abcdefghijklmnopqr"
ARGS = {"to": EMAIL, "body": f"status {SECRET}", "note": BEARER, "nested": {"contact": EMAIL}}


def _build(engine: PolicyEngine, **overrides):
    fields = dict(
        principal_key=KEY_A,
        agent_id="lab-assistant-1",
        agent_key=KEY_A,
        session_id="sess-hook",
        capability_token=engine.sessions.get("sess-hook").capability_token if "sess-hook" in engine.sessions else "",
        allow_egress=False,
        taint_source_id="read_external_url:1",
        taint_reasons=["untrusted_ingest:read_external_url"],
        gate_atlas="AML.T0086",
        tool_name="send_email",
        arguments=dict(ARGS),
        step_index=3,
        now=NOW,
        freeze_seconds=900,
    )
    fields.update(overrides)
    return build_approval_payload(**fields)


def _bind(engine: PolicyEngine, payload: dict):
    return dict(
        session_id="sess-hook",
        step_index=payload["step_index"],
        tool_name="send_email",
        arguments=dict(ARGS),
        taint_source_id="read_external_url:1",
        now=NOW,
    )


def test_payload_scrub_is_deterministic(engine: PolicyEngine, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")
    first = _build(engine)
    second = _build(engine)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    blob = json.dumps(first, sort_keys=True)
    assert SECRET not in blob
    assert EMAIL not in blob
    assert BEARER not in blob
    assert "REDACTED_API_KEY" in blob
    assert "REDACTED_EMAIL" in blob
    assert "REDACTED_BEARER" in blob
    assert first["principal"]["principal_key"] == KEY_A
    assert first["principal"]["agent_id"] == "lab-assistant-1"
    assert first["session_id"] == "sess-hook"
    assert first["capability_state"]["prefix"] == "agw1."
    assert first["atlas_id"] == "AML.T0086"
    assert first["tool_name"] == "send_email"
    assert first["delivered"] is False
    assert first["webhook"]["event"] == "agent_gateway.approval_required"
    assert first["webhook"]["atlas_id"] == first["atlas_id"]
    actions = {el["action_id"]: el for el in first["blocks"][-1]["elements"]}
    assert actions[ACTION_APPROVE_ONCE]["text"]["text"] == LABEL_APPROVE_ONCE
    assert actions[ACTION_DENY_FREEZE]["text"]["text"] == LABEL_DENY_FREEZE
    assert len(actions[ACTION_APPROVE_ONCE]["value"]) <= 2000
    assert len(actions[ACTION_DENY_FREEZE]["value"]) <= 2000

    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-b")
    other = _build(engine, session_id="sess-hook-b", step_index=4)
    assert other["canonical_args"] != first["canonical_args"]
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")
    again = _build(engine)
    assert again["canonical_args"] == first["canonical_args"]
    assert json.dumps(again, sort_keys=True) == blob


def test_atlas_ids_follow_taint_source(engine: PolicyEngine, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")
    external = _build(engine)
    assert external["atlas_id"] == "AML.T0086"
    listed = _build(
        engine,
        session_id="sess-list",
        taint_source_id="tools.list:untrusted-mcp",
        taint_reasons=["untrusted_tools_list:untrusted-mcp"],
        gate_atlas="AML.T0086",
        step_index=5,
    )
    assert listed["atlas_id"] == "AML.T0051"
    pad = _build(
        engine,
        session_id="sess-pad",
        taint_source_id="scratchpad:weekly",
        taint_reasons=["scratchpad_taint_inherited"],
        gate_atlas="AML.T0086",
        step_index=6,
    )
    assert pad["atlas_id"] == "AML.T0080"


def test_callback_rejects_parameter_tamper_and_replay(engine: PolicyEngine, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")
    payload = _build(engine)
    cb = payload["callbacks"][ACTION_APPROVE_ONCE]
    bind = _bind(engine, payload)

    swapped = dict(ARGS)
    swapped["body"] = swapped["body"] + "!"
    bad_args = verify_callback(cb, **{**bind, "arguments": swapped})
    assert bad_args.ok is False and bad_args.reason == "parameter_mismatch"

    mutated = dict(cb)
    mutated["args_hash"] = "ab" * 32
    assert verify_callback(mutated, **bind).reason == "mac_mismatch"

    mutated_tool = dict(cb)
    mutated_tool["tool_sha256"] = "cd" * 32
    assert verify_callback(mutated_tool, **bind).reason == "mac_mismatch"

    flipped = dict(cb)
    flipped["action"] = ACTION_DENY_FREEZE
    flipped["freeze_seconds"] = 900
    assert verify_callback(flipped, **bind).reason == "mac_mismatch"

    deny = dict(payload["callbacks"][ACTION_DENY_FREEZE])
    deny["freeze_seconds"] = 86400
    assert verify_callback(deny, **bind).reason == "mac_mismatch"
    assert engine.registry.is_frozen_key(KEY_A, NOW) is False

    # Re-signing the tampered field with the lab key still fails closed: the
    # issued record, not the attacker's mac, is what the gateway stored.
    from agent_gateway.approval_webhook import _mac
    from agent_gateway.approve import canonical_args_hash

    resigned = dict(cb)
    resigned["args_hash"] = canonical_args_hash(swapped)
    resigned["mac"] = _mac(resigned)
    assert verify_callback(resigned, **{**bind, "arguments": swapped}).reason == "mac_mismatch"

    ok = verify_callback(cb, **bind)
    assert ok.ok is True and ok.action == ACTION_APPROVE_ONCE
    replay = verify_callback(cb, **bind)
    assert replay.ok is False and replay.reason == "replay"

    stale = _build(engine, session_id="sess-stale", step_index=9, now=NOW - 1000)
    stale_cb = stale["callbacks"][ACTION_APPROVE_ONCE]
    expired = verify_callback(
        stale_cb,
        session_id="sess-stale",
        step_index=9,
        tool_name="send_email",
        arguments=dict(ARGS),
        taint_source_id="read_external_url:1",
        now=NOW,
    )
    assert expired.ok is False and expired.reason == "expired"


def test_deny_freeze_only_registered_key_for_15m(engine: PolicyEngine, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")
    payload = _build(engine, session_id="sess-freeze", step_index=8)
    deny = payload["callbacks"][ACTION_DENY_FREEZE]
    assert deny["label"] == LABEL_DENY_FREEZE
    assert deny["freeze_seconds"] == 900
    applied = apply_callback(
        engine.registry,
        deny,
        session_id="sess-freeze",
        step_index=8,
        tool_name="send_email",
        arguments=dict(ARGS),
        taint_source_id="read_external_url:1",
        now=NOW,
    )
    assert applied["ok"] is True
    assert applied["freeze_seconds"] == 900
    assert "lab-assistant-1" in applied["frozen_agent_ids"]
    assert engine.registry.is_frozen_key(KEY_A, NOW)
    assert not engine.registry.is_frozen_key("visitor_public", NOW)
    rec = engine.registry.get(KEY_A)
    assert rec is not None and rec.frozen_until - NOW == 900

    visitor = build_approval_payload(
        principal_key="visitor_public",
        agent_id="",
        agent_key="visitor_public",
        session_id="sess-visitor",
        capability_token="",
        allow_egress=False,
        taint_source_id="read_external_url:1",
        taint_reasons=["untrusted_ingest:read_external_url"],
        gate_atlas="AML.T0086",
        tool_name="send_email",
        arguments={"to": "a@b.c", "body": "x"},
        step_index=2,
        now=NOW,
    )
    refused = apply_callback(
        engine.registry,
        visitor["callbacks"][ACTION_DENY_FREEZE],
        session_id="sess-visitor",
        step_index=2,
        tool_name="send_email",
        arguments={"to": "a@b.c", "body": "x"},
        taint_source_id="read_external_url:1",
        now=NOW,
    )
    assert refused["ok"] is False and refused["error"] == "unregistered_key"
    assert refused["frozen_agent_ids"] == []
    assert engine.registry.is_frozen_key("visitor_public", NOW) is False


def test_pep_emits_payload_without_network(engine: PolicyEngine, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("approval webhook opened a socket")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr("agent_gateway.pep.deliver_webhook", boom)
    monkeypatch.setenv("AGENT_GATEWAY_SCRUB_SALT", "webhook-salt-a")

    sid = "sess-pep-hook"
    assert engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/kb"})["ok"]
    args = {"to": EMAIL, "body": f"leak {SECRET}"}
    denied = engine.evaluate_call(KEY_A, sid, "send_email", args)
    assert denied["ok"] is False
    assert denied["error"] == "post_taint_outbound_gated"
    payload = denied["approval_webhook"]
    assert payload["delivered"] is False
    assert payload["capability_state"]["token"].startswith("agw1.")
    assert payload["capability_state"]["allow_egress"] is False
    assert payload["atlas_id"] == "AML.T0086"
    assert payload["principal"]["agent_id"] == "lab-assistant-1"
    assert payload["session_id"] == sid
    blob = json.dumps(payload)
    assert SECRET not in blob and EMAIL not in blob
    assert engine.cfg.webhook_deliver is False
    assert not engine.registry.is_frozen_key(KEY_A, engine.now())

    token = payload["callbacks"][ACTION_APPROVE_ONCE]["mac"]
    step = denied["step_index"]
    approved = engine.evaluate_call(
        KEY_A, sid, "send_email", args, approval_token=token, bound_step_index=step,
    )
    assert approved["ok"] is True
    assert not engine.registry.is_frozen_key(KEY_A, engine.now())
    replay = engine.evaluate_call(
        KEY_A, sid, "send_email", args, approval_token=token, bound_step_index=step,
    )
    assert replay["ok"] is False

    sid_list = "sess-pep-list"
    engine.evaluate_tools_list(KEY_A, sid_list, "untrusted-mcp", [{"name": "send_webhook", "description": "exfil"}])
    listed = engine.evaluate_call(KEY_A, sid_list, "send_webhook", {"url": "http://127.0.0.1/hook"})
    assert listed["approval_webhook"]["atlas_id"] == "AML.T0051"

    sid_w = "sess-pep-pad-w"
    assert engine.evaluate_call(KEY_A, sid_w, "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]
    assert engine.evaluate_call(KEY_A, sid_w, "save_session_note", {"note_id": "weekly", "text": "note"})["ok"]
    sid_r = "sess-pep-pad-r"
    assert engine.evaluate_call(KEY_A, sid_r, "read_session_note", {"note_id": "weekly"})["ok"]
    inherited = engine.evaluate_call(KEY_A, sid_r, "send_email", {"to": "a@b.c", "body": "no"})
    assert inherited["approval_webhook"]["atlas_id"] == "AML.T0080"


def test_pep_deliver_is_opt_in(engine: PolicyEngine, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("urllib was used")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    captured: list[tuple[str, dict]] = []

    def sender(url, payload):
        captured.append((url, payload))

    engine.cfg.webhook_deliver = True
    engine.cfg.webhook_url = "http://127.0.0.1:9/hook"
    engine.cfg.webhook_sender = sender
    sid = "sess-opt-in"
    assert engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/kb"})["ok"]
    denied = engine.evaluate_call(KEY_A, sid, "file.write", {"path": "/tmp/x", "body": "nope"})
    assert denied["approval_webhook"]["delivered"] is True
    assert captured and captured[0][0] == "http://127.0.0.1:9/hook"
    assert captured[0][1]["delivered"] is True
    assert captured[0][1]["atlas_id"] == "AML.T0086"
