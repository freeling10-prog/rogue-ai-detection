"""v12.3 wiring for the Petri-net transition gate (linear_obligation_validator).

``tests/test_validators.py`` exercises the module in isolation. This file
exercises it through ``pep.py``: the decision path, the JSON-RPC code, the
commit-after-all-checks ordering, and the SARIF rule set.
"""
from __future__ import annotations

import json

import pytest

from agent_gateway.linear_obligation_validator import ObligationManifest, TransitionSpec
from agent_gateway.pep import (
    _V12_CODES,
    OBLIGATION_PROTOCOL_DENIED,
    SIMILARITY_LEAK_DENIED,
    PolicyEngine,
)
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from tests.conftest import KEY_A

# Places: P0 ready, P1 staging buffer open. P1 is resource cleanup state that
# must be settled before the outbound step, which itself moves no tokens.
CLEANUP_MASK = 0x0F0


def manifest() -> ObligationManifest:
    return ObligationManifest(0x1, CLEANUP_MASK, (
        TransitionSpec("lab", "file.write", (1,), (0, 1), False),
        TransitionSpec("lab", "list_files", (0, 1), (1,), False),
        TransitionSpec("lab", "send_email", (), (), True),
    ))


def call(engine: PolicyEngine, session: str, tool: str) -> dict:
    args = {"send_email": {"to": "ops@example.com", "body": "weekly summary"},
            "file.write": {"path": "/workspace/summary.txt", "body": "summary"},
            "list_files": {"path": "/workspace"}}[tool]
    return engine.evaluate_call(KEY_A, session, tool, args)


def test_engine_has_no_net_until_attached(engine: PolicyEngine) -> None:
    assert engine.obligation_nets == {}
    assert call(engine, "s-inert", "send_email")["allowed"] is True


def test_cycle_settles_cleanup_state_before_outbound_step(engine: PolicyEngine) -> None:
    net = engine.attach_obligation_net("s-net", manifest())

    early = call(engine, "s-net", "list_files")
    assert early["allowed"] is False and early["rule_code"] == OBLIGATION_PROTOCOL_DENIED
    assert early["obligation"]["reason"] == "INSUFFICIENT_TOKENS"

    assert call(engine, "s-net", "file.write")["allowed"] is True
    unsettled = call(engine, "s-net", "send_email")
    assert unsettled["allowed"] is False
    assert unsettled["obligation"]["reason"] == "UNSETTLED_OBLIGATION"
    assert unsettled["obligation"]["marking"] == "0000000000000010"

    assert call(engine, "s-net", "list_files")["allowed"] is True
    assert call(engine, "s-net", "send_email")["allowed"] is True
    assert net.marking == 0x1 and net.sequence == 3
    assert _V12_CODES[OBLIGATION_PROTOCOL_DENIED] == -32071
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)


def test_unknown_transition_fails_closed(engine: PolicyEngine) -> None:
    engine.attach_obligation_net("s-unknown", manifest())
    out = engine.evaluate_call(KEY_A, "s-unknown", "calendar.read", {"day": "monday"})
    assert out["allowed"] is False and out["obligation"]["reason"] == "UNKNOWN_TRANSITION"


def test_marking_does_not_advance_when_a_later_validator_denies(engine: PolicyEngine) -> None:
    secret = "SYNTHETIC_CFG_TOKEN_ALPHA_99281746"
    engine.configure_similarity_matcher(b"obligation-wiring-test-key-32byte", (secret,))
    net = engine.attach_obligation_net("s-order", manifest())
    assert call(engine, "s-order", "file.write")["allowed"] is True
    assert call(engine, "s-order", "list_files")["allowed"] is True
    before = (net.marking, net.sequence)
    out = engine.evaluate_call(KEY_A, "s-order", "send_email",
                               {"to": "ops@example.com", "body": f"value={secret}"})
    assert out["allowed"] is False and out["rule_code"] == SIMILARITY_LEAK_DENIED
    assert (net.marking, net.sequence) == before
    assert secret not in json.dumps(engine.findings)


def test_manifest_violating_conservation_is_never_attached(engine: PolicyEngine) -> None:
    minting = ObligationManifest(0x1, 0, (TransitionSpec("lab", "file.write", (1,), (2,), False),))
    with pytest.raises(ValueError):
        engine.attach_obligation_net("s-mint", minting)
    assert "s-mint" not in engine.obligation_nets


def test_sarif_declares_the_obligation_rule() -> None:
    assert OBLIGATION_PROTOCOL_DENIED in RULES and OBLIGATION_PROTOCOL_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": OBLIGATION_PROTOCOL_DENIED, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == OBLIGATION_PROTOCOL_DENIED
