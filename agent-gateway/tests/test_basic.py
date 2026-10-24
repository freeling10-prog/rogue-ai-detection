"""Basic policy-gate tests for the lab insider PEP."""
from __future__ import annotations

import time

from agent_gateway import approve
from agent_gateway.pep import PolicyEngine
from agent_gateway.scrub import scrub_text
from tests.conftest import KEY_A, KEY_B


def test_unregistered_key_rejected(engine: PolicyEngine):
    out = engine.evaluate_call("not_a_key", "s1", "web.fetch", {"url": "http://127.0.0.1/"})
    assert out["ok"] is False and out["error"] == "unregistered_agent"


def test_taint_blocks_write_send_creds(engine: PolicyEngine):
    sid = "sess-basic-1"
    assert engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1:18098/kb/poisoned"})["ok"]
    assert engine.sessions[sid].tainted
    for tool, args in (
        ("file.write", {"path": "/tmp/x", "body": "nope"}),
        ("send_email", {"to": "a@b.c", "body": "x"}),
        ("credentials.get", {"name": "api"}),
    ):
        out = engine.evaluate_call(KEY_A, sid, tool, args)
        assert out["ok"] is False, tool


def test_bound_approval_unblocks_once(engine: PolicyEngine, state_dir):
    sid = "sess-oob-1"
    engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/x"})
    args = {"to": "team@internal.local", "body": "Status OK"}
    denied = engine.evaluate_call(KEY_A, sid, "send_email", args)
    assert denied["ok"] is False
    step = denied["step_index"]
    rec = approve.mint(sid, step, "send_email", args, taint_source_id=engine.sessions[sid].taint_source_id)
    ok = engine.evaluate_call(KEY_A, sid, "send_email", args, approval_token=rec["token"], bound_step_index=step)
    assert ok["ok"] is True
    # replay rejected
    again = engine.evaluate_call(KEY_A, sid, "send_email", args, approval_token=rec["token"], bound_step_index=step)
    assert again["ok"] is False


def test_freeze_and_auto_lift(engine: PolicyEngine):
    sid = "sess-freeze"
    engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/x"})
    engine._freeze_root(KEY_A, "test")
    assert engine.registry.is_frozen_key(KEY_A, engine.now())
    # child sharing root also frozen
    child = "agk_demo_child_0001"
    assert engine.registry.is_frozen_key(child, engine.now())
    # auto-lift
    for rec in engine.registry.agents.values():
        if rec.frozen_until:
            rec.frozen_until = engine.now() - 1
    lifted = engine.registry.lift_expired(engine.now())
    assert lifted
    assert not engine.registry.is_frozen_key(KEY_A, engine.now())


def test_depth_and_children_quotas(engine: PolicyEngine):
    sid = "sess-spawn"
    # depth 0 can spawn
    assert engine.evaluate_call(KEY_A, sid, "spawn_subagent", {"child_api_key": "x1"}, delegation_depth=0)["ok"]
    assert engine.evaluate_call(KEY_A, sid, "spawn_subagent", {"child_api_key": "x2"}, delegation_depth=0)["ok"]
    assert engine.evaluate_call(KEY_A, sid, "spawn_subagent", {"child_api_key": "x3"}, delegation_depth=0)["ok"]
    fourth = engine.evaluate_call(KEY_A, sid, "spawn_subagent", {"child_api_key": "x4"}, delegation_depth=0)
    assert fourth["ok"] is False and fourth["error"] == "max_children_per_parent"
    # depth already at max cannot spawn
    deep = engine.evaluate_call(KEY_A, "sess-deep", "spawn_subagent", {}, delegation_depth=1)
    assert deep["ok"] is False and deep["error"] == "max_delegation_depth"


def test_loopback_reject_nonlocal(client):
    # Flask test client uses 127.0.0.1 remote_addr by default — health works
    assert client.get("/health").status_code == 200


def test_scrubbing_deterministic():
    a = scrub_text("Bearer SUPERSECRETTOKEN123456 and user@example.com")
    b = scrub_text("Bearer SUPERSECRETTOKEN123456 and user@example.com")
    assert a == b
    assert "SUPERSECRET" not in a
    assert "user@example.com" not in a
    assert "REDACTED" in a
