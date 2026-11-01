"""v12.6 wiring for the fork/join conservation ledger (fork_join_vector_validator).

``tests/test_validators.py`` exercises the module in isolation. This file
exercises it through ``pep.py``: shared budgets across branches, fractional
tokens, ledger-wide cleanup state, stale clocks, denial charging, spawn
auto-forks, taint along forks and joins, and the SARIF rule.
"""
from __future__ import annotations

import pytest

from agent_gateway.fork_join_vector_validator import SEND, UNIT, Root
from agent_gateway.pep import _V12_CODES, FORK_JOIN_LEDGER_DENIED, PolicyEngine
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from tests.conftest import KEY_A

P0 = (UNIT,) + (0,) * 15
P0_TO_P1 = (P0, (0, UNIT) + (0,) * 14)
P1_TO_P0 = ((0, UNIT) + (0,) * 14, P0)
TRANSITIONS = {"file.write": P0_TO_P1, "list_files": P1_TO_P0}


def grant(denials=0, outbound=0, *tokens) -> tuple[int, ...]:
    return (denials, outbound) + tuple(tokens) + (0,) * (16 - len(tokens))


def send(engine: PolicyEngine, session: str, body: str = "weekly summary") -> dict:
    return engine.evaluate_call(KEY_A, session, "send_email", {"to": "ops@example.com", "body": body})


def write(engine: PolicyEngine, session: str) -> dict:
    return engine.evaluate_call(KEY_A, session, "file.write", {"path": "/workspace/a.txt", "body": "x"})


def reason(out: dict) -> str:
    assert out["allowed"] is False and out["rule_code"] == FORK_JOIN_LEDGER_DENIED, out
    return out["fork_join"]["reason"]


def test_engine_is_inert_until_a_ledger_is_attached(engine: PolicyEngine) -> None:
    assert engine.fork_ledgers == {}
    assert send(engine, "s-inert", "x" * 2000)["allowed"] is True
    assert engine.evaluate_call(KEY_A, "s-inert", "spawn_subagent", {"child_api_key": "k"})["ok"]
    assert engine.fork_ledgers == {}


def test_children_spend_the_root_budget_not_a_fresh_one(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(denials=3, outbound=300, tokens=(0,) * 16))
    engine.fork_branch("root", "kid", grant(1, 150))
    assert send(engine, "kid")["allowed"] is True
    used = owner.root.spent[1]
    assert 0 < used < 150 and owner.root.branches[0].wallet[1] == 150
    while owner.root.branches[1].wallet[1] >= used:
        assert send(engine, "kid")["allowed"] is True
    assert reason(send(engine, "kid")) == "OUTBOUND_BUDGET"
    assert send(engine, "root")["allowed"] is True  # the root keeps its own share
    assert owner.root.conserved()
    assert _V12_CODES[FORK_JOIN_LEDGER_DENIED] == -32074
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)


def test_fractional_token_cannot_fire_until_joined(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(tokens=P0), TRANSITIONS)
    engine.fork_branch("root", "kid", grant(0, 0, UNIT // 2))
    assert reason(write(engine, "kid")) == "INSUFFICIENT_TOKENS"
    assert reason(write(engine, "root")) == "INSUFFICIENT_TOKENS"
    engine.join_branch("root", "kid")
    assert write(engine, "root")["allowed"] is True
    assert owner.root.branches[0].wallet[2:4] == (0, UNIT) and owner.root.conserved()
    assert reason(write(engine, "kid")) == "BRANCH_INACTIVE"


def test_cleanup_state_held_by_a_child_blocks_every_branch_from_sending(engine: PolicyEngine) -> None:
    engine.attach_fork_join("root", Root.make(tokens=P0, obligation_mask=0b10), TRANSITIONS)
    engine.fork_branch("root", "kid", grant(1, 0, UNIT))
    assert write(engine, "kid")["allowed"] is True  # kid now holds cleanup state in P1
    assert reason(send(engine, "root")) == "UNSETTLED_OBLIGATION"
    assert engine.evaluate_call(KEY_A, "kid", "list_files", {"path": "/workspace"})["allowed"] is True
    assert send(engine, "root")["allowed"] is True


def test_every_denial_spends_the_shared_denial_budget(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(denials=2, outbound=4096, tokens=(0,) * 16))
    engine.fork_branch("root", "kid", grant(1, 2000))
    assert reason(send(engine, "kid", "x" * 600)) == "SEND_LIMIT"  # 512-byte cap per send
    assert owner.root.spent[0] == 1 and owner.root.branches[1].wallet[0] == 0
    assert reason(send(engine, "kid")) == "DENIAL_BUDGET"  # bytes remain, denials do not
    assert owner.root.spent[0] == 1  # nothing left to charge
    assert send(engine, "root")["allowed"] is True and owner.root.conserved()


def test_a_dispatch_planned_on_a_stale_clock_never_commits(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(outbound=1000, tokens=(0,) * 16))
    sess = engine.get_session("root", KEY_A)
    plan = engine._fork_join_plan(sess, "send_email", {"to": "a@example.com", "body": "x"}, "send")
    owner.apply(0, owner.clock(0), [(SEND, 10)])  # a concurrent dispatch commits first
    with pytest.raises(ValueError, match="STALE_CLOCK"):
        engine._fork_join_commit(plan)
    assert owner.root.spent[1] == 10 and owner.root.conserved()


def test_spawn_auto_forks_an_empty_branch(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(tokens=(0,) * 16))
    out = engine.evaluate_call(KEY_A, "root", "spawn_subagent",
                               {"child_api_key": "k", "child_session_id": "kid"})
    assert out["ok"] is True
    assert engine.fork_ledgers["kid"] == (owner, 1)
    assert owner.root.branches[1].wallet == (0,) * 18
    assert reason(send(engine, "kid")) == "DENIAL_BUDGET"


def test_taint_follows_forks_and_joins(engine: PolicyEngine) -> None:
    engine.attach_fork_join("root", Root.make(tokens=(0,) * 16))
    engine.fork_branch("root", "kid")
    engine.get_session("root", KEY_A)
    engine.mark_untrusted_ingest(KEY_A, "kid", "fixture")
    engine.evaluate_call(KEY_A, "kid", "lookup_order_status", {"order_id": 1})  # commits branch taint
    assert engine.sessions["root"].tainted is False
    engine.join_branch("root", "kid")
    assert engine.sessions["root"].tainted is True

    engine.fork_branch("root", "kid2")
    assert engine.get_session("kid2", KEY_A).tainted is True


def test_sarif_declares_the_fork_join_rule() -> None:
    assert FORK_JOIN_LEDGER_DENIED in RULES and FORK_JOIN_LEDGER_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": FORK_JOIN_LEDGER_DENIED, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == FORK_JOIN_LEDGER_DENIED


# --- Round-2 red-team: two-phase prepare/commit on spawn_subagent ---------------------

METADATA = "http://169.254.169.254/latest/meta-data/"


def test_downstream_denied_spawns_leave_no_ghost_branches(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(tokens=(0,) * 16))
    for i in range(7):
        out = engine.evaluate_call(KEY_A, "root", "spawn_subagent",
                                   {"child_session_id": f"ghost{i}", "url": METADATA})
        assert out["allowed"] is False and out["error"] == "ssrf_boundary_violation", out
    assert len(owner.root.branches) == 1
    assert not any(f"ghost{i}" in engine.fork_ledgers for i in range(7))
    out = engine.evaluate_call(KEY_A, "root", "spawn_subagent",
                               {"child_api_key": "k", "child_session_id": "kid"})
    assert out["ok"] is True
    assert engine.fork_ledgers["kid"] == (owner, 1) and len(owner.root.branches) == 2
    assert owner.root.conserved()


def test_denied_call_charges_only_the_denial_unit(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(denials=3, outbound=4096, tokens=(0,) * 16))
    before = owner.root.branches[0].wallet
    out = engine.evaluate_call(KEY_A, "root", "send_webhook", {"url": METADATA, "payload": "x" * 100})
    assert out["allowed"] is False
    after = owner.root.branches[0].wallet
    assert after[0] == before[0] - 1  # one denial unit
    assert after[1] == before[1]      # no outbound bytes for a call that never left


def test_denied_call_still_mirrors_branch_taint(engine: PolicyEngine) -> None:
    owner = engine.attach_fork_join("root", Root.make(tokens=(0,) * 16))
    engine.get_session("root", KEY_A)
    engine.mark_untrusted_ingest(KEY_A, "root", "fixture")
    out = engine.evaluate_call(KEY_A, "root", "send_webhook", {"url": METADATA, "payload": "x"})
    assert out["allowed"] is False
    assert owner.root.branches[0].taint == 1
