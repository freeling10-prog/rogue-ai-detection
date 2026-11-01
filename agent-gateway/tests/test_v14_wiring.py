"""v14 wiring for Predicates C, E, B and A through ``pep.py``.

``tests/test_validators.py`` exercises each module in isolation with its
state machine. This file covers the decision path: inert until attached, the
JSON-RPC codes, two-phase commit (denied calls leave no state), C taint
reaching A and E before they authorize, B's auto-lifting lock and opaque
envelope, and the SARIF rules.
"""
from __future__ import annotations

import pytest

from agent_gateway.blindfold_opaque_fault_validator import LOCK_SECONDS, BlindfoldSealer, verify_receipt
from agent_gateway.causality_laundering_validator import CausalityValidator
from agent_gateway.event_channel_capacity_validator import EventChannelBudget, EventManifest
from agent_gateway.pep import (
    _V12_CODES,
    BLINDFOLD_ENVELOPE,
    BLINDFOLD_PERTURBATION_DENIED,
    CAUSALITY_LAUNDERING_DENIED,
    EVENT_CHANNEL_CAPACITY_DENIED,
    REACHABILITY_CONFINEMENT_DENIED,
    PolicyEngine,
)
from agent_gateway.reachability_confinement_validator import Node, ReachabilityPolicy
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from tests.conftest import KEY_A

METADATA = "http://169.254.169.254/latest/meta-data/"
V14 = (CAUSALITY_LAUNDERING_DENIED, EVENT_CHANNEL_CAPACITY_DENIED, BLINDFOLD_PERTURBATION_DENIED,
       REACHABILITY_CONFINEMENT_DENIED)


def call(engine: PolicyEngine, session: str, tool: str, **args) -> dict:
    return engine.evaluate_call(KEY_A, session, tool, args)


def send(engine: PolicyEngine, session: str, body: str = "weekly summary") -> dict:
    return call(engine, session, "send_email", to="team@example.org", body=body)


def rule(out: dict, code: str) -> dict:
    assert out["allowed"] is False and out["rule_code"] == code, out
    return out


def test_codes_are_new_and_unique() -> None:
    assert [_V12_CODES[c] for c in V14] == [-32077, -32078, -32079, -32080]
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)
    assert BLINDFOLD_ENVELOPE["code"] == -32079


def test_engine_is_inert_until_attached(engine: PolicyEngine) -> None:
    assert not (engine.causality or engine.event_budgets or engine.blindfolds or engine.reachability)
    assert call(engine, "s", "file.write", path="/workspace/a", body="x")["allowed"] is True
    assert send(engine, "s")["allowed"] is True
    assert call(engine, "s", "send_webhook", url=METADATA, payload="x")["error"] == "ssrf_boundary_violation"


# --- C ---------------------------------------------------------------------------------

def test_absence_laundering_across_sessions_is_caught(engine: PolicyEngine) -> None:
    shared = CausalityValidator()
    engine.attach_causality("writer", shared)
    engine.attach_causality("reader", shared)
    # The writer decides, based on untrusted data, to create then delete a flag file.
    engine.causality_push_pc("writer", True)
    assert call(engine, "writer", "file.write", path="/workspace/flag", body="")["allowed"] is True
    assert call(engine, "writer", "file.delete", path="/workspace/flag")["allowed"] is True
    engine.causality_pop_pc("writer")
    assert engine.sessions["writer"].tainted is False  # nothing was read: no explicit taint
    # A clean reader probes the (now absent) name: the tombstone's label taints it.
    out = call(engine, "reader", "file.exists", path="/workspace/flag")
    assert out["allowed"] is True and out["tainted"] is True
    assert send(engine, "reader")["error"] == "post_taint_outbound_gated"


def test_denied_mutation_records_no_label(engine: PolicyEngine) -> None:
    shared = CausalityValidator()
    engine.attach_causality("w", shared)
    engine.causality_push_pc("w", True)
    out = call(engine, "w", "file.write", path="/workspace/x", url=METADATA)
    assert out["allowed"] is False and out["error"] == "ssrf_boundary_violation"
    assert "/workspace/x" not in shared.entries


def test_status_labels_reach_observers(engine: PolicyEngine) -> None:
    shared = CausalityValidator()
    engine.attach_causality("a", shared)
    engine.attach_causality("b", shared)
    engine.causality_push_pc("a", True)
    assert call(engine, "a", "status.set", target="job-1", status="skipped")["allowed"] is True
    assert call(engine, "b", "status.get", target="job-1")["tainted"] is True


def test_out_of_model_paths_are_denied(engine: PolicyEngine) -> None:
    engine.attach_causality("w", CausalityValidator())
    too_deep = "/workspace/" + "d/" * 16 + "x"  # 17 components below the root
    out = rule(call(engine, "w", "file.delete", path=too_deep), CAUSALITY_LAUNDERING_DENIED)
    assert out["code"] == -32077 and out["causality"]["reason"] == "C_PATH"
    # Paths outside the modeled root are not C's to judge.
    assert call(engine, "w", "file.read", path="/srv/data/report.txt")["allowed"] is True


# --- A ---------------------------------------------------------------------------------

POLICY = ReachabilityPolicy([
    Node("start", (1, 2)),
    Node("lookup_order_status", (3,)),
    Node("web.fetch", (3,)),
    Node("send_email", (), terminal=True, forbidden_if_tainted=True),
])


def test_calls_follow_viable_paths_only(engine: PolicyEngine) -> None:
    engine.attach_reachability("s", POLICY)
    out = rule(send(engine, "s"), REACHABILITY_CONFINEMENT_DENIED)
    assert out["code"] == -32080 and out["reachability"]["reason"] == "A_UNREACHABLE"
    assert rule(call(engine, "s", "file.write", path="/x"), REACHABILITY_CONFINEMENT_DENIED)[
        "reachability"]["reason"] == "A_NOT_IN_POLICY"
    assert engine.reachability_finish("s")["allowed"] is False
    assert call(engine, "s", "lookup_order_status", order_id=1)["allowed"] is True
    assert send(engine, "s")["allowed"] is True
    assert engine.reachability_finish("s")["allowed"] is True


def test_taint_prunes_the_forbidden_sink_before_any_other_gate(engine: PolicyEngine) -> None:
    pruner = engine.attach_reachability("s", POLICY)
    assert call(engine, "s", "web.fetch", url="https://example.org")["allowed"] is True
    out = rule(send(engine, "s"), REACHABILITY_CONFINEMENT_DENIED)
    assert out["reachability"]["tainted"] is True and pruner.candidates() == ()


def test_denied_call_does_not_advance_the_workflow(engine: PolicyEngine) -> None:
    pruner = engine.attach_reachability("s", POLICY)
    out = call(engine, "s", "lookup_order_status", order_id=1, url=METADATA)
    assert out["error"] == "ssrf_boundary_violation"
    assert pruner.step == 0


def test_c_taint_reaches_a_before_it_authorizes(engine: PolicyEngine) -> None:
    shared = CausalityValidator()
    engine.attach_causality("writer", shared)
    engine.attach_causality("reader", shared)
    engine.attach_reachability("reader", ReachabilityPolicy([
        Node("start", (1,)), Node("file.exists", (2,)),
        Node("send_email", (), terminal=True, forbidden_if_tainted=True)]))
    engine.causality_push_pc("writer", True)
    call(engine, "writer", "file.write", path="/workspace/flag", body="")
    # The probe taints the reader before A authorizes it. Every path after the
    # probe ends at a forbidden sink, so A denies the probe itself: the
    # existence bit is never returned.
    out = rule(call(engine, "reader", "file.exists", path="/workspace/flag"), REACHABILITY_CONFINEMENT_DENIED)
    assert out["reachability"]["tainted"] is True and out["tainted"] is True


# --- E ---------------------------------------------------------------------------------

def test_selection_budget_is_charged_only_with_live_pins(engine: PolicyEngine) -> None:
    manifest = EventManifest(("send_email",), (4,))  # 4 combinations -> 8 quarter bits
    budget = engine.attach_event_budget("s", EventChannelBudget("root", "email", 32), manifest)
    for _ in range(5):
        assert send(engine, "s")["allowed"] is True  # nothing to protect: charge 0
    assert budget.spent == 0
    holder = engine.attach_ingression("s")
    engine.cfg.lab_fixture_outputs["lookup_order_status"] = "host billing-db.internal"
    call(engine, "s", "lookup_order_status", order_id=1)
    assert holder.used == 1
    for _ in range(3):
        assert send(engine, "s")["allowed"] is True
    assert budget.spent == 24
    out = rule(send(engine, "s"), EVENT_CHANNEL_CAPACITY_DENIED)
    assert out["code"] == -32078 and out["event_channel"]["reason"] == "E_CAPACITY"


def test_denied_events_are_released_and_ineligible_tools_refused(engine: PolicyEngine) -> None:
    manifest = EventManifest(("send_email",), (4,))
    budget = engine.attach_event_budget("s", EventChannelBudget("root", "email", 32), manifest)
    holder = engine.attach_ingression("s")
    engine.cfg.lab_fixture_outputs["lookup_order_status"] = "host billing-db.internal"
    call(engine, "s", "lookup_order_status", order_id=1)
    assert holder.used == 1
    out = send(engine, "s", "reach billing-db.internal")  # E reserves, then D denies
    assert out["rule_code"] == "DYNAMIC_INGRESSION_DENIED"
    assert budget.spent == 0 and budget.pending == {}
    assert rule(call(engine, "s", "send_webhook", url="https://example.org/h", payload="x"),
                EVENT_CHANNEL_CAPACITY_DENIED)["event_channel"]["reason"] == "E_INELIGIBLE"


# --- B ---------------------------------------------------------------------------------

def sealer(t: list) -> BlindfoldSealer:
    return BlindfoldSealer(b"r" * 32, clock=lambda: t[0])


def test_near_neighbor_retry_locks_the_branch_and_auto_lifts(engine: PolicyEngine) -> None:
    t = [0.0]
    s = engine.attach_blindfold("s", sealer(t))
    first = call(engine, "s", "send_webhook", url=METADATA, payload="quarterly numbers")
    assert first["error"] == "ssrf_boundary_violation"
    assert len(engine.blindfold_receipts["s"]) == 1
    assert verify_receipt(engine.blindfold_receipts["s"][0], b"r" * 32)
    nudged = call(engine, "s", "send_webhook", url=METADATA.replace("meta-data", "meta-datb"),
                  payload="quarterly numbers")
    out = rule(nudged, BLINDFOLD_PERTURBATION_DENIED)
    assert out["code"] == -32079 and out["blindfold"]["human_review_lead"] is True
    assert out["blindfold"]["auto_lift_seconds"] == LOCK_SECONDS
    assert rule(send(engine, "s"), BLINDFOLD_PERTURBATION_DENIED)["blindfold"]["reason"] == "B_LOCKED"
    assert send(engine, "other-session")["allowed"] is True  # not attached: unaffected
    t[0] = LOCK_SECONDS
    assert send(engine, "s")["allowed"] is True  # the lock lifted by itself
    assert s.refusals and len(engine.blindfold_receipts["s"]) == 1  # B's own denials are not sealed


def test_opaque_wire_makes_every_refusal_identical(engine: PolicyEngine) -> None:
    t = [0.0]
    engine.attach_blindfold("s", sealer(t), opaque_wire=True)
    engine.attach_reachability("s", POLICY)
    ssrf = call(engine, "s", "lookup_order_status", order_id=1, url=METADATA)
    reach = call(engine, "s", "file.write", path="/x")
    strip = {"capability_token", "allow_egress"}
    assert {k: v for k, v in ssrf.items() if k not in strip} == BLINDFOLD_ENVELOPE
    assert {k: v for k, v in reach.items() if k not in strip} == BLINDFOLD_ENVELOPE
    assert len(engine.blindfold_receipts["s"]) == 2
    # People still see the real reason in the decision log and findings.
    assert any(f["kind"] == REACHABILITY_CONFINEMENT_DENIED for f in engine.findings)


def test_default_sealer_uses_the_gateway_key_and_engine_clock(engine: PolicyEngine) -> None:
    s = engine.attach_blindfold("s")
    assert s.lock_seconds == LOCK_SECONDS
    with pytest.raises(ValueError):
        engine.attach_blindfold("s")


def test_sarif_declares_the_v14_rules() -> None:
    for code in V14:
        assert code in RULES and code in _LOG_KIND_RULES
        doc = build_sarif({"gateway_findings": {"rows": [
            {"kind": code, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
        assert validate_sarif(doc) == []
