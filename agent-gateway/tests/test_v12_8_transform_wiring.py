"""v12.8 wiring for transform-invariant pins (transform_invariant_validator).

``tests/test_validators.py`` exercises the module in isolation. This file
exercises it through ``pep.py``: static pins, disguised values in outbound
calls, the atomic extension from Predicate D, the work budget, and SARIF.
"""
from __future__ import annotations

import json
import random
import string

import pytest

from agent_gateway.pep import (
    _V12_CODES,
    DYNAMIC_INGRESSION_DENIED,
    TRANSFORM_INVARIANT_DENIED,
    PolicyEngine,
)
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from tests.conftest import KEY_A

SECRET = "sk-live-7f3a9cQ2"
RESPONSE = "Connect to billing-db.internal as ops@example.com with key sk-live-7f3a9c."


def send(engine: PolicyEngine, session: str, body: str) -> dict:
    return engine.evaluate_call(KEY_A, session, "send_email", {"to": "team@example.org", "body": body})


def read(engine: PolicyEngine, session: str, body: str) -> dict:
    engine.cfg.lab_fixture_outputs["lookup_order_status"] = body
    return engine.evaluate_call(KEY_A, session, "lookup_order_status", {"order_id": 1})


def reason(out: dict) -> str:
    assert out["allowed"] is False and out["rule_code"] == TRANSFORM_INVARIANT_DENIED, out
    return out["transform"]["reason"]


def test_engine_is_inert_until_attached(engine: PolicyEngine) -> None:
    assert engine.transform_indexes == {}
    assert send(engine, "s-inert", SECRET[::-1])["allowed"] is True


def test_disguised_static_pin_is_denied(engine: PolicyEngine) -> None:
    engine.attach_transform_index("s-static", (SECRET,))
    shifted = "".join(chr(ord(c) + 1) for c in SECRET)
    masked = "".join(chr(ord(c) ^ 0x01) for c in SECRET)
    blocks = "".join(reversed([SECRET[i:i + 4] for i in range(0, 16, 4)]))
    for body, expected in [(f"ref {SECRET[::-1]}", "Z_TRANSFORM"), (shifted, "Z_TRANSFORM"),
                           (masked, "Z_TRANSFORM"), (blocks, "Z_BLOCKS")]:
        assert reason(send(engine, "s-static", body)) == expected
    assert send(engine, "s-static", "weekly summary attached")["allowed"] is True
    assert SECRET not in json.dumps(engine.findings) and SECRET[::-1] not in json.dumps(engine.findings)
    assert _V12_CODES[TRANSFORM_INVARIANT_DENIED] == -32076
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)


def test_values_learned_by_d_are_pinned_in_the_same_step(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-sync")
    index = engine.attach_transform_index("s-sync")
    assert read(engine, "s-sync", RESPONSE)["allowed"] is True
    assert holder.used == index.used == 3
    # D's forward check misses the reversed key; Z's reverse view catches it.
    assert reason(send(engine, "s-sync", "c9a3f7-evil-ks")) == "Z_TRANSFORM"


def test_attaching_after_d_catches_up(engine: PolicyEngine) -> None:
    engine.attach_ingression("s-late")
    assert read(engine, "s-late", RESPONSE)["allowed"] is True
    index = engine.attach_transform_index("s-late", ("Mountainview",))
    assert index.used == 4
    with pytest.raises(ValueError):
        engine.attach_transform_index("s-late")


def test_a_full_index_stops_d_from_enrolling_hard_values(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-full")
    index = engine.attach_transform_index("s-full", tuple(f"static-pin-{i:02d}" for i in range(23)))
    engine.cfg.lab_fixture_outputs["read_internal_secrets"] = "vault-entry-01"
    out = engine.evaluate_call(KEY_A, "s-full", "read_internal_secrets", {})  # two hard values, room for one
    assert out["allowed"] is False and out["rule_code"] == DYNAMIC_INGRESSION_DENIED
    assert out["ingression"]["reason"] == "Z_CAPACITY" and out["ingression"]["result_withheld"]
    assert holder.hard_used == 0 and index.used == 23


def test_soft_values_fill_z_only_while_it_has_room(engine: PolicyEngine) -> None:
    holder = engine.attach_ingression("s-room")
    index = engine.attach_transform_index("s-room", tuple(f"static-pin-{i:02d}" for i in range(22)))
    out = read(engine, "s-room", RESPONSE)  # three soft values, room for two in Z
    assert out["allowed"] is True  # an untrusted response never wedges the session
    assert holder.soft_used == 3 and index.used == 24
    # Z took the first two soft values (the host, the address); the key stays D-only.
    assert reason(send(engine, "s-room", "billing-db.internal"[::-1])) == "Z_TRANSFORM"


def test_work_budget_and_query_size(engine: PolicyEngine) -> None:
    pin = "".join(random.Random(3).choices(string.ascii_letters + string.digits, k=128))
    index = engine.attach_transform_index("s-work", (pin,))
    assert len(index.pins[0].blocks) == 32  # 6 * 5 + 4 * 32 = 158 credits per query byte
    text = ("weekly summary for the team " * 20)
    assert send(engine, "s-work", text[:207])["allowed"] is True  # 207 * 158 = 32706
    assert reason(send(engine, "s-work", text[:208])) == "Z_WORK"  # 208 * 158 = 32864
    assert reason(send(engine, "s-work", text[:513])) == "Z_QUERY_SIZE"
    # Reads are not outbound: unchecked.
    assert engine.evaluate_call(KEY_A, "s-work", "lookup_order_status",
                                {"order_id": 1, "note": text})["allowed"] is True


def test_pin_bounds_fail_at_attach(engine: PolicyEngine) -> None:
    with pytest.raises(ValueError, match="Z_PIN_SIZE"):
        engine.attach_transform_index("s-bad", ("abc",))
    assert "s-bad" not in engine.transform_indexes


def test_sarif_declares_the_transform_rule() -> None:
    assert TRANSFORM_INVARIANT_DENIED in RULES and TRANSFORM_INVARIANT_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": TRANSFORM_INVARIANT_DENIED, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == TRANSFORM_INVARIANT_DENIED
