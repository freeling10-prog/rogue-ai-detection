"""v12.7 wiring for dynamic ingression pins (dynamic_ingression_validator).

``tests/test_validators.py`` exercises the module in isolation. This file
exercises it through ``pep.py``: enrollment from tool results before the agent
sees them, outbound denial, the canary watermark, withheld results, the
non-evicting store, the proxy entry point, and the SARIF rule.
"""
from __future__ import annotations

import json

import pytest

from agent_gateway.pep import _V12_CODES, DYNAMIC_INGRESSION_DENIED, PolicyEngine
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from tests.conftest import KEY_A

RESPONSE = "Connect to billing-db.internal as ops@example.com with key sk-live-7f3a9c."


def read_note(engine: PolicyEngine, session: str, body: str) -> dict:
    """An internal read whose lab result body is ``body`` (general allow path)."""
    engine.cfg.lab_fixture_outputs["lookup_order_status"] = body
    return engine.evaluate_call(KEY_A, session, "lookup_order_status", {"order_id": 1})


def send(engine: PolicyEngine, session: str, body: str) -> dict:
    return engine.evaluate_call(KEY_A, session, "send_email", {"to": "team@example.org", "body": body})


def denied(out: dict) -> dict:
    assert out["allowed"] is False and out["rule_code"] == DYNAMIC_INGRESSION_DENIED, out
    return out["ingression"]


def test_engine_is_inert_until_attached(engine: PolicyEngine) -> None:
    assert engine.ingressions == {}
    assert read_note(engine, "s-inert", RESPONSE)["allowed"] is True
    assert send(engine, "s-inert", "key sk-live-7f3a9c")["allowed"] is True


def test_values_learned_from_a_response_are_blocked_outbound(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-learn")
    assert read_note(engine, "s-learn", RESPONSE)["allowed"] is True
    assert holder.used == 3  # the key, the internal host, the e-mail address

    for body in ("key sk-live-7f3a9c", "s k - l i v e - 7 f 3 a 9 c", "host billing-db.internal",
                 "reach ops@example.com"):
        detail = denied(send(engine, "s-learn", body))
        assert detail["reason"] == "D_MATCH" and detail["direction"] == "outbound"
        assert isinstance(detail["slot"], int)
    assert send(engine, "s-learn", "weekly summary attached")["allowed"] is True
    assert "sk-live-7f3a9c" not in json.dumps(engine.findings)
    assert _V12_CODES[DYNAMIC_INGRESSION_DENIED] == -32075
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)


def test_bespoke_result_paths_are_scanned_too(engine: PolicyEngine) -> None:
    # A scratchpad note written by another session reaches the agent through
    # read_session_note's own allow path, not the general one.
    assert engine.evaluate_call(KEY_A, "s-writer", "save_session_note",
                                {"note_id": "n1", "body": RESPONSE})["allowed"] is True
    holder = engine.attach_ingression("s-reader")
    out = engine.evaluate_call(KEY_A, "s-reader", "read_session_note", {"note_id": "n1"})
    assert out["allowed"] is True and out["result"]["body"] == RESPONSE
    assert holder.used == 3
    assert denied(send(engine, "s-reader", "sk-live-7f3a9c"))["reason"] == "D_MATCH"


def test_watermarked_secret_is_enrolled_as_the_agent_reads_it(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-wm")
    out = engine.evaluate_call(KEY_A, "s-wm", "read_internal_secrets", {})
    assert out["allowed"] is True and "​" in out["result"]["secret"]
    assert holder.used == 1  # the visible secret only, not the tool name
    detail = denied(engine.evaluate_call(KEY_A, "s-wm", "file.write",
                                         {"path": "/workspace/x", "body": "secret_value_123"}))
    assert detail["reason"] == "D_MATCH"


def test_capacity_is_all_or_nothing_and_never_evicts(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-cap")
    nine = " ".join(f"sk-key{i:02d}" for i in range(9))
    out = denied(read_note(engine, "s-cap", nine))
    assert out == {"reason": "D_CAPACITY", "direction": "inbound", "slots_used": 0,
                   "result_withheld": True}
    assert holder.used == 0

    assert read_note(engine, "s-cap", " ".join(f"sk-key{i:02d}" for i in range(8)))["allowed"] is True
    assert denied(read_note(engine, "s-cap", "fresh sk-newkey9"))["reason"] == "D_CAPACITY"
    assert holder.used == 8
    assert denied(send(engine, "s-cap", "sk-key00"))["reason"] == "D_MATCH"
    # A repeated value needs no new slot.
    assert read_note(engine, "s-cap", "again sk-key03")["allowed"] is True


def test_unscannable_responses_are_withheld(engine: PolicyEngine) -> None:
    engine.attach_ingression("s-bounds")
    blob = "A" * 200
    assert denied(read_note(engine, "s-bounds", f"data {blob}"))["reason"] == "D_TOKEN_SIZE"
    assert denied(read_note(engine, "s-bounds", "word " * 900))["reason"] == "D_TEXT"


def test_outbound_strings_are_bounded_once_anything_is_enrolled(engine: PolicyEngine) -> None:
    engine.attach_ingression("s-query")
    long_body = "lorem ipsum " * 60
    assert send(engine, "s-query", long_body)["allowed"] is True  # nothing enrolled yet
    assert read_note(engine, "s-query", RESPONSE)["allowed"] is True
    assert denied(send(engine, "s-query", long_body))["reason"] == "D_QUERY_SIZE"


def test_proxy_entry_point(engine: PolicyEngine) -> None:
    assert engine.ingest_dynamic_result(KEY_A, "s-proxy", "web.fetch", {"body": "sk-abc12345"}) == 0
    engine.attach_ingression("s-proxy")
    assert engine.ingest_dynamic_result(KEY_A, "s-proxy", "web.fetch",
                                        {"body": "use sk-abc12345", "api_key": "short-key"}) == 2
    with pytest.raises(ValueError, match="D_CAPACITY"):
        engine.ingest_dynamic_result(KEY_A, "s-proxy", "web.fetch",
                                     {"body": " ".join(f"sk-more{i}" for i in range(7))})
    assert denied(send(engine, "s-proxy", "short-key"))["reason"] == "D_MATCH"


def test_sarif_declares_the_ingression_rule() -> None:
    assert DYNAMIC_INGRESSION_DENIED in RULES and DYNAMIC_INGRESSION_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": DYNAMIC_INGRESSION_DENIED, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == DYNAMIC_INGRESSION_DENIED
