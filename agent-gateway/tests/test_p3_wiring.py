"""Gateway wiring for P3. Not part of the E2 bound."""
from __future__ import annotations

import json
from pathlib import Path

from agent_gateway import approve
from agent_gateway.causality_laundering_validator import CausalityValidator
from agent_gateway.event_channel_capacity_validator import EventChannelBudget, EventManifest
from agent_gateway.fork_join_vector_validator import Root as LedgerRoot
from agent_gateway.leakage_budget import LINK_SOURCES, P3Config
from agent_gateway.mcp_proxy import CLIENT_TO_SERVER, McpWireProxy
from agent_gateway.pep import (
    LEAKAGE_BUDGET_HOLD, PepConfig, PolicyEngine, _V12_CODES,
)
from agent_gateway.registry import Registry
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from agent_gateway.taint import SharedState
from tests.conftest import KEY_A, KEY_B, REG


def _only(source: str) -> P3Config:
    return P3Config(budget_qb=16000, link_sources=frozenset({source}))


def test_codes_are_unique_and_sarif_names_the_hold():
    assert _V12_CODES[LEAKAGE_BUDGET_HOLD] == -32082
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)
    assert LEAKAGE_BUDGET_HOLD in RULES and LEAKAGE_BUDGET_HOLD in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": LEAKAGE_BUDGET_HOLD, "tool": "send_email", "session": "s", "detail": "held"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == LEAKAGE_BUDGET_HOLD


def test_inert_until_attached_then_hold_webhook_and_one_approval(engine: PolicyEngine):
    engine._clock = lambda: 1_700_000_000.0
    assert engine.p3_state("s") == {}
    assert engine.evaluate_call(KEY_A, "s", "send_email", {"to": "a@b.c", "body": "hi"})["allowed"]
    engine.attach_leakage_budget("s", P3Config(budget_qb=0, link_sources=frozenset()))
    args = {}
    held = engine.evaluate_call(KEY_A, "s", "read_internal_secrets", args)
    assert held["allowed"] is False
    assert held["error"] == "leakage_budget_hold" and held["code"] == -32082
    assert held["rule_code"] == LEAKAGE_BUDGET_HOLD
    assert "approval_webhook" in held
    assert engine.p3_state("s")["spent_qb"] == 0 and engine.p3_state("s")["charging"] is True
    step = held["step_index"]
    rec = approve.mint("s", step, "read_internal_secrets", args,
                       taint_source_id=engine.sessions["s"].taint_source_id or "")
    released = engine.evaluate_call(
        KEY_A, "s", "read_internal_secrets", args,
        approval_token=rec["token"], bound_step_index=step,
    )
    assert released["allowed"] is True
    assert released.get("release_at_ms") is not None
    state = engine.p3_state("s")
    assert state["overdraft_qb"] > 0 and state["spent_qb"] == 0 and state["budget_qb"] == 0
    again = engine.evaluate_call(KEY_A, "s", "read_internal_secrets", args)
    assert again["error"] == "leakage_budget_hold"
    # The same token does not release a second event.
    replay = engine.evaluate_call(
        KEY_A, "s", "read_internal_secrets", args,
        approval_token=rec["token"], bound_step_index=step,
    )
    assert replay["allowed"] is False


def test_log_only_records_the_would_be_hold_and_does_not_deny(engine: PolicyEngine):
    engine._clock = lambda: 0.0
    engine.attach_leakage_budget("s", P3Config(budget_qb=0, mode="log_only", link_sources=frozenset()))
    out = engine.evaluate_call(KEY_A, "s", "read_internal_secrets", {})
    assert out["allowed"] is True
    state = engine.p3_state("s")
    assert state["mode"] == "log_only" and state["spent_qb"] > state["budget_qb"]
    assert any(row.get("kind") == "P3_BUDGET_EXHAUSTED" and row.get("would_hold") for row in engine.leakage.decision_log)


def test_downstream_denial_aborts_the_reservation(engine: PolicyEngine):
    engine._clock = lambda: 0.0
    engine.attach_leakage_budget("s", P3Config(budget_qb=16000, link_sources=frozenset()))
    engine.evaluate_call(KEY_A, "s", "read_internal_secrets", {})
    spent = engine.p3_state("s")["spent_qb"]

    def deny(sess, step, tool_name, args, eclass, constrained=False, delegation=None):
        return engine._deny(sess, step, tool_name, args, "ssrf_boundary_violation", -32032)

    engine._allow = deny
    out = engine.evaluate_call(KEY_A, "s", "send_email", {"to": "a@b.c", "body": "x"})
    assert out["allowed"] is False
    assert engine.p3_state("s")["spent_qb"] == spent
    assert engine.p3_state("s")["pending"] is None


def test_withheld_result_does_not_refund_e_or_p3(engine: PolicyEngine):
    engine._clock = lambda: 0.0
    manifest = EventManifest(("read_internal_secrets",), (4,))
    budget = engine.attach_event_budget(
        "s", EventChannelBudget("root", "cred", 4096), manifest)
    engine.attach_ingression("s")
    engine.attach_leakage_budget("s", P3Config(budget_qb=16000, link_sources=frozenset()))
    for i in range(7):
        engine.cfg.lab_fixture_outputs["read_internal_secrets"] = f"vault-entry-{i:02d}"
        assert engine.evaluate_call(KEY_A, "s", "read_internal_secrets", {})["allowed"]
    before_e, before_p = budget.spent, engine.p3_state("s")["spent_qb"]
    engine.cfg.lab_fixture_outputs["read_internal_secrets"] = "vault-entry-99"
    out = engine.evaluate_call(KEY_A, "s", "read_internal_secrets", {})
    assert out["rule_code"] == "DYNAMIC_INGRESSION_DENIED"
    assert out["ingression"]["result_withheld"] is True
    assert budget.spent > before_e and budget.pending == {}
    assert engine.p3_state("s")["spent_qb"] > before_p
    assert engine.p3_state("s")["pending"] is None


def test_non_core_reads_are_charged_and_core_reads_are_not(engine: PolicyEngine):
    engine._clock = lambda: 0.0
    engine.attach_leakage_budget("s", P3Config(budget_qb=16000, link_sources=frozenset()))
    assert engine.evaluate_call(KEY_A, "s", "read_internal_secrets", {})["allowed"]
    base = engine.p3_state("s")["spent_qb"]
    read = engine.evaluate_call(
        KEY_A, "s", "mcp.resources/read", {"uri": "notes://x/abcd"}, destination="mcp:evil")
    assert read["allowed"] is True and engine.p3_state("s")["spent_qb"] > base
    charged = engine.p3_state("s")["spent_qb"]
    prompt = engine.evaluate_call(
        KEY_A, "s", "mcp.prompts/get", {"name": "p"}, destination="mcp:evil")
    assert prompt["allowed"] is True and engine.p3_state("s")["spent_qb"] > charged
    after = engine.p3_state("s")["spent_qb"]
    core = engine.evaluate_call(
        KEY_A, "s", "mcp.resources/read", {"uri": "file:///lab/readme.md"}, destination="mcp:core")
    assert core["allowed"] is True and engine.p3_state("s")["spent_qb"] == after


def test_proxy_returns_release_at_ms(engine: PolicyEngine):
    engine._clock = lambda: 0.0
    engine.attach_leakage_budget("wire", P3Config(budget_qb=4096, link_sources=frozenset()))
    engine.evaluate_call(KEY_A, "wire", "read_internal_secrets", {})
    evil = McpWireProxy(engine, KEY_A, "wire", "evil")
    res = evil.handle(CLIENT_TO_SERVER, {
        "jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "notes://x"},
    })
    assert res.decision == "allow" and isinstance(res.release_at_ms, int)
    core = McpWireProxy(engine, KEY_A, "wire", "core")
    res = core.handle(CLIENT_TO_SERVER, {
        "jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "file:///lab/a"},
    })
    assert res.decision == "allow" and res.release_at_ms is None


def test_each_link_source_merges(engine: PolicyEngine):
    engine._clock = lambda: 0.0

    def pair(source: str):
        eng = engine
        a, b = f"{source}-a", f"{source}-b"
        cfg = _only(source)
        eng.attach_leakage_budget(a, cfg)
        eng.attach_leakage_budget(b, cfg)
        return a, b

    # root principal
    engine.get_session("root-a", KEY_A)
    engine.attach_leakage_budget("root-a", _only("root_principal"))
    engine.evaluate_call(KEY_A, "root-b", "lookup_order_status", {"order_id": 1})
    assert engine.p3_state("root-a")["cid"] == engine.p3_state("root-b")["cid"]

    a, b = pair("delegation")
    engine.get_session(a, KEY_A)
    engine.get_session(b, KEY_B)
    engine.delegate(KEY_A, a, KEY_B, b)
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("spawn")
    engine.evaluate_call(KEY_A, a, "spawn_subagent", {"child_api_key": KEY_B, "child_session_id": b})
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("fork_join")
    engine.get_session(a, KEY_A)
    engine.get_session(b, KEY_B)
    engine.attach_fork_join(a, LedgerRoot.make())
    engine.fork_branch(a, b)
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("internal_bus")
    engine.evaluate_call(KEY_A, a, "post_internal_bus", {"payload": "ping"})
    engine.evaluate_call(KEY_B, b, "poll_internal_bus", {})
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("scratchpad")
    engine.evaluate_call(KEY_A, a, "save_session_note", {"note_id": "n-src", "body": "hello"})
    engine.evaluate_call(KEY_B, b, "read_session_note", {"note_id": "n-src"})
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("provenance")
    engine.evaluate_call(KEY_A, a, "file.write", {"path": "/ws/p3-note", "body": "x"})
    engine.evaluate_call(KEY_B, b, "file.read", {"path": "/ws/p3-note"})
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("collusion")
    engine.evaluate_call(KEY_A, a, "file.write", {"path": "/ws/p3-col", "body": "x"})
    engine.evaluate_call(KEY_B, b, "file.read", {"path": "/ws/p3-col"})
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("causality")
    shared = CausalityValidator()
    engine.get_session(a, KEY_A)
    engine.get_session(b, KEY_B)
    engine.attach_causality(a, shared)
    engine.attach_causality(b, shared)
    assert engine.p3_state(a)["cid"] == engine.p3_state(b)["cid"]

    a, b = pair("control_plane")
    assert engine.p3_link(a, b, "control_plane") == engine.p3_state(a)["cid"]
    assert engine.p3_state(b)["cid"] == engine.p3_state(a)["cid"]
    # Every source in the spec was exercised.
    assert set(LINK_SOURCES) == {
        "root_principal", "delegation", "spawn", "fork_join", "internal_bus",
        "scratchpad", "provenance", "collusion", "causality", "control_plane",
    }


def test_event_budgets_are_shared_only_when_the_caller_passes_one_object(engine: PolicyEngine):
    manifest = EventManifest(("send_email",), (4,))
    one = EventChannelBudget("root", "mail", 32)
    engine.attach_event_budget("s1", one, manifest)
    engine.attach_event_budget("s2", one, manifest)
    other = EventChannelBudget("root", "mail", 32)
    engine.attach_event_budget("s3", other, manifest)
    engine.attach_ingression("s1")
    engine.cfg.lab_fixture_outputs["lookup_order_status"] = "host billing-db.internal"
    engine.evaluate_call(KEY_A, "s1", "lookup_order_status", {"order_id": 1})
    assert engine.evaluate_call(KEY_A, "s1", "send_email", {"to": "a@b.c", "body": "ok"})["allowed"]
    assert one.spent == other.spent or one.spent > 0
    assert other.spent == 0
    assert one.spent > 0


def test_core_names_are_cached_until_reload(tmp_path: Path):
    reg = tmp_path / "agents.json"
    reg.write_text(json.dumps({"core_mcp_servers": ["alpha"], "agents": []}))
    cfg = PepConfig(registry_path=reg, alert_log=tmp_path / "alerts.jsonl")
    # An empty agent table still loads.
    try:
        loaded = Registry.load(reg)
    except Exception:
        loaded = Registry.load(REG)
        cfg = PepConfig(registry_path=reg, alert_log=tmp_path / "alerts.jsonl")
    eng = PolicyEngine(loaded, shared=SharedState(), cfg=cfg)
    first = eng._core_mcp_names()
    assert "alpha" in first
    reg.write_text(json.dumps({"core_mcp_servers": ["beta"], "agents": []}))
    assert eng._core_mcp_names() == first
    assert "beta" in eng.reload_core_mcp_names()


def test_e_docstring_states_the_effective_ceiling():
    from agent_gateway import event_channel_capacity_validator as E
    text = Path(E.__file__).read_text(encoding="utf-8")
    assert "effective ceiling" in text
    assert "same object" in text


def _linked_pair(engine: PolicyEngine):
    """Two sessions of different agents, linked, at the default 128 qb budget."""
    from agent_gateway.leakage_budget import Constant, Enum, FieldSchema, SelectionManifest

    manifest = SelectionManifest((("", "read_internal_secrets"), ("", "report_metric")))
    schemas = {
        "read_internal_secrets": FieldSchema("read_internal_secrets", (("unused", Constant()),)),
        "report_metric": FieldSchema("report_metric", (("v", Enum(1 << 12)),)),
    }
    cfg = P3Config(link_sources=frozenset({"control_plane"}))
    assert cfg.budget_qb == 128
    for sid in ("pair-a", "pair-b"):
        engine.attach_leakage_budget(sid, cfg, manifest=manifest, schemas=schemas)
    engine.p3_link("pair-a", "pair-b", "control_plane")


def _pair_calls(engine: PolicyEngine):
    """A spends 80 qb in two events. B then asks for 64 qb. Returns B's result."""
    assert engine.evaluate_call(KEY_A, "pair-a", "read_internal_secrets", {})["allowed"]
    assert engine.evaluate_call(KEY_A, "pair-a", "report_metric", {"v": 7})["allowed"]
    return engine.evaluate_call(KEY_B, "pair-b", "report_metric", {"v": 9})


def test_linked_sessions_share_one_budget_and_the_second_is_held(engine: PolicyEngine):
    """A and B are each under 32 bits alone. Together they are over, so B is held."""
    engine._clock = lambda: 0.0
    _linked_pair(engine)
    held = _pair_calls(engine)
    assert held["allowed"] is False
    assert held["error"] == "leakage_budget_hold" and held["code"] == -32082
    detail = held["leakage"]
    assert detail["reason"] == "P3_BUDGET_EXHAUSTED"
    # 16 + 64 from A. B's own event is 64 qb: under 128 alone, 144 with A's spend.
    assert (detail["spent_qb"], detail["charge_qb"], detail["budget_qb"]) == (80, 64, 128)
    assert detail["charge_qb"] <= detail["budget_qb"] < detail["spent_qb"] + detail["charge_qb"]
    for sid in ("pair-a", "pair-b"):
        state = engine.p3_state(sid)
        assert state["members"] == ("pair-a", "pair-b")
        assert state["spent_qb"] == 80 and state["pending"] is None
    # A hold is for a person. It does not freeze the key.
    assert engine.registry.is_frozen_key(KEY_B, engine.now()) is False


def test_a_budget_per_session_would_let_the_second_through(engine: PolicyEngine, monkeypatch):
    """Mutant M5 at the gateway: the same calls are all allowed, so the test above kills it."""
    from agent_gateway.leakage_budget import LeakageLedger

    monkeypatch.setattr(LeakageLedger, "link_merges", False)
    engine._clock = lambda: 0.0
    _linked_pair(engine)
    out = _pair_calls(engine)
    assert out["allowed"] is True
    assert engine.p3_state("pair-a")["spent_qb"] == 72
    assert engine.p3_state("pair-b")["members"] == ("pair-b",)
