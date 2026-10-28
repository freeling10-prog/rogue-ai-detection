"""memory_provenance_guard and temporal_accumulator_guard wired through PolicyEngine, McpWireProxy, and SARIF."""
from __future__ import annotations

import dataclasses

import pytest

from agent_gateway.audit_report import summarize_decision_log
from agent_gateway.mcp_proxy import CLIENT_TO_SERVER, SERVER_TO_CLIENT, McpWireProxy
from agent_gateway.memory_provenance_guard import canonical_resource_id
from agent_gateway.pep import PolicyEngine
from agent_gateway.sarif_export import build_sarif, validate_sarif
from tests.conftest import KEY_A, KEY_B

ZW = "​"


def _taint(engine: PolicyEngine, sid: str) -> None:
    assert engine.evaluate_call(KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]


def _tamper(engine: PolicyEngine, uri: str, **changes) -> None:
    ledger = engine.provenance._ledger
    h = canonical_resource_id(uri)
    ledger[h] = dataclasses.replace(ledger[h], **changes)


# --- lineage through evaluate_call ------------------------------------------------

def test_clean_reader_inherits_taint_from_the_writing_session(engine: PolicyEngine):
    _taint(engine, "writer")
    assert engine.evaluate_call(KEY_A, "writer", "save_session_note", {"note_id": "n1", "text": "x"})["ok"]
    read = engine.evaluate_call(KEY_B, "reader", "read_session_note", {"note_id": "n1"})
    assert read["ok"] is True and read["tainted"] is True
    sess = engine.sessions["reader"]
    assert "provenance_taint_inherited" in sess.taint_reasons and sess.allow_egress is False
    out = engine.evaluate_call(KEY_B, "reader", "send_email", {"to": "a@b.c", "body": "x"})
    assert out["error"] == "post_taint_outbound_gated"


def test_ledger_still_taints_when_the_scratchpad_flag_is_cleared(engine: PolicyEngine):
    _taint(engine, "writer")
    engine.evaluate_call(KEY_A, "writer", "save_session_note", {"note_id": "n2", "text": "x"})
    engine.shared.scratchpad["n2"].taint_inherited = False  # shared state edited behind the gateway
    assert engine.evaluate_call(KEY_B, "reader", "read_session_note", {"note_id": "n2"})["tainted"] is True


def test_tampered_record_denies_the_read(engine: PolicyEngine):
    _taint(engine, "writer")
    engine.evaluate_call(KEY_A, "writer", "save_session_note", {"note_id": "n3", "text": "x"})
    _tamper(engine, "scratchpad:n3", taint_level=0)
    out = engine.evaluate_call(KEY_B, "reader", "read_session_note", {"note_id": "n3"})
    assert out["ok"] is False and out["error"] == "provenance_tamper_denied" and out["code"] == -32042
    assert out["atlas"] == "AML.T0080.000" and out["provenance"]["verdict"] == "PROVENANCE_TAMPER_DENIED"
    assert engine.sessions["reader"].tainted is True


def test_clean_note_round_trip_stays_clean(engine: PolicyEngine):
    assert engine.evaluate_call(KEY_A, "w", "save_session_note", {"note_id": "ok", "text": "lunch at 1"})["ok"]
    read = engine.evaluate_call(KEY_B, "r", "read_session_note", {"note_id": "ok"})
    assert read["ok"] is True and read["tainted"] is False
    assert engine.evaluate_call(KEY_B, "r", "send_email", {"to": "a@b.c", "body": "hi"})["ok"] is True


def test_ledger_export_and_load_through_the_engine(engine: PolicyEngine, state_dir):
    _taint(engine, "writer")
    engine.evaluate_call(KEY_A, "writer", "save_session_note", {"note_id": "n4", "text": "x"})
    exported = engine.export_provenance_ledger()
    assert exported["records"] and all("hmac_tag" in r for r in exported["records"])
    bad = {**exported, "records": [{**exported["records"][0], "taint_level": 0}]}
    with pytest.raises(ValueError):
        engine.load_provenance_ledger(bad)
    engine.load_provenance_ledger(exported)
    assert engine.export_provenance_ledger() == exported


# --- lineage through the MCP proxy (resources/read) ---------------------------------

def _read_resource(proxy: McpWireProxy, rid: int, uri: str):
    return proxy.handle(CLIENT_TO_SERVER, {"jsonrpc": "2.0", "id": rid, "method": "resources/read",
                                           "params": {"uri": uri}})


def test_proxy_resource_read_inherits_lineage(engine: PolicyEngine):
    engine.provenance.record_write("memory://kb/plan", "upstream-session", 1, 0)
    proxy = McpWireProxy(engine, KEY_A, "mcp-r", "core")
    res = _read_resource(proxy, 1, "memory://kb/plan")
    assert res.decision == "allow" and res.forward
    assert engine.sessions["mcp-r"].tainted is True
    assert engine.sessions["mcp-r"].taint_source_id.startswith("provenance:")


def test_proxy_resource_read_of_tampered_record_never_reaches_server(engine: PolicyEngine):
    engine.provenance.record_write("memory://kb/plan", "upstream-session", 1, 0)
    _tamper(engine, "memory://kb/plan", writer_session_id="someone-else")
    res = _read_resource(McpWireProxy(engine, KEY_A, "mcp-t", "core"), 1, "memory://kb/plan")
    assert res.decision == "deny" and not res.forward
    err = res.reply[0]["error"]
    assert err["code"] == -32042 and err["data"]["error"] == "provenance_tamper_denied"


# --- temporal accumulator through evaluate_call and the proxy -----------------------

def test_watermark_characters_accumulate_across_released_calls(engine: PolicyEngine):
    for i in range(3):
        out = engine.evaluate_call(KEY_A, "wm", "send_email", {"to": "a@b.c", "body": f"part {i}{ZW}"})
        assert out["ok"] is True, out
    out = engine.evaluate_call(KEY_A, "wm", "send_email", {"to": "a@b.c", "body": f"end{ZW}"})
    assert out["ok"] is False and out["error"] == "sharded_exfil_denied" and out["code"] == -32043
    assert out["accumulator"]["rule"] == "CUMULATIVE_WATERMARK_THRESHOLD"
    assert engine.sessions["wm"].tainted is True


def test_compound_emoji_text_is_not_counted(engine: PolicyEngine):
    family = "\U0001F468‍\U0001F469‍\U0001F467‍\U0001F466"
    for i in range(6):
        assert engine.evaluate_call(KEY_A, "emoji", "send_email",
                                    {"to": "a@b.c", "body": f"photo {i} {family}"})["ok"] is True


def test_session_scoped_canary_does_not_touch_other_sessions(engine: PolicyEngine):
    engine.register_canary("SCOPED_CANARY_TOKEN_5512", session_id="owner")
    assert engine.accumulator.protected_count("owner") == 1
    assert engine.accumulator.protected_count("bystander") == 0
    assert engine.evaluate_call(KEY_B, "bystander", "send_email",
                                {"to": "a@b.c", "body": "SCOPED_CANARY_TOKEN_5512"})["ok"] is True


def _send(proxy: McpWireProxy, rid: int, body: str):
    return proxy.handle(CLIENT_TO_SERVER, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                                           "params": {"name": "send_email",
                                                      "arguments": {"to": "a@b.c", "body": body}}})


def test_proxy_window_is_keyed_by_server(engine: PolicyEngine):
    core = McpWireProxy(engine, KEY_A, "mcp-w", "core")
    assert core.destination == "mcp:core"
    for i in range(3):
        assert _send(core, i + 1, f"chunk{ZW}").decision == "allow"
    # The same session through another server starts its own window.
    other = McpWireProxy(engine, KEY_A, "mcp-w", "mail-mcp")
    assert _send(other, 1, f"hello{ZW}").decision == "allow"
    res = _send(core, 9, f"last{ZW}")
    assert res.decision == "deny" and not res.forward
    assert res.reply[0]["error"]["data"]["error"] == "sharded_exfil_denied"
    finding = [f for f in engine.findings if f["kind"] == "sharded_exfil_denied"][-1]
    assert finding["destination"] == "mcp:core"


# --- decision log -> audit summary -> SARIF -----------------------------------------

def test_provenance_and_accumulator_findings_reach_sarif(engine: PolicyEngine):
    _taint(engine, "writer")
    engine.evaluate_call(KEY_A, "writer", "save_session_note", {"note_id": "s", "text": "x"})
    _tamper(engine, "scratchpad:s", capability_mask=(1 << 64) - 1)
    engine.evaluate_call(KEY_B, "reader", "read_session_note", {"note_id": "s"})
    for _ in range(4):
        engine.evaluate_call(KEY_A, "wm", "send_email", {"to": "a@b.c", "body": f"x{ZW}"})
    summary = summarize_decision_log(engine.alert_path)
    assert summary["counts"]["provenance_tamper_denied"] == 1
    assert summary["counts"]["sharded_exfil_denied"] == 1
    doc = build_sarif({"gateway_findings": summary})
    assert validate_sarif(doc) == []
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "OWASP-Agentic/ASI06 (approximate)" in rules["provenance_tamper_denied"]["properties"]["tags"]
    assert {"provenance_tamper_denied", "sharded_exfil_denied"} <= {r["ruleId"] for r in doc["runs"][0]["results"]}
