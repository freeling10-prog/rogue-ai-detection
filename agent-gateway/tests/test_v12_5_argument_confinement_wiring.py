"""v12.5 wiring for argument canonicalization and command confinement.

``tests/test_validators.py`` exercises canonical_argument_confinement in
isolation. This file exercises it through ``pep.py``: the decision path, the
JSON-RPC code, the canonical bytes and argv on the allow result, typed
commands feeding the workspace model and label transducer, and SARIF.
"""
from __future__ import annotations

import pytest

from agent_gateway.canonical_argument_confinement import FieldPolicy, Policy
from agent_gateway.pep import (
    _V12_CODES,
    ARGUMENT_CONFINEMENT_DENIED,
    FS_LABEL_FLOW_DENIED,
    WORKSPACE_EFFECT_DENIED,
    PolicyEngine,
)
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from agent_gateway.workspace_path_validator import Node
from tests.conftest import KEY_A

ORDER_POLICY = Policy((
    FieldPolicy("order_id", "number", required=True),
    FieldPolicy("fields", "set"),
    FieldPolicy("verbose", "bool", default=b"false"),
))


def lookup(engine: PolicyEngine, session: str, **args) -> dict:
    return engine.evaluate_call(KEY_A, session, "lookup_order_status", args)


def filesystem() -> dict[str, Node]:
    return {"/ws": Node("dir"), "/ws/out": Node("dir"),
            "/ws/out/a": Node("file", (1, 1)), "/ws/out/b": Node("file", (1, 4)),
            "/ws/.mcp.json": Node("file", (1, 2))}


def test_engine_is_inert_until_a_tool_is_pinned(engine: PolicyEngine) -> None:
    assert engine.argument_policies == {} and engine.command_tools == set()
    out = lookup(engine, "s-inert", order_id=1, extra="anything")
    assert out["allowed"] is True and "confinement" not in out


def test_equivalent_argument_objects_dispatch_identical_bytes(engine: PolicyEngine) -> None:
    engine.pin_argument_policy("lookup_order_status", ORDER_POLICY)
    first = lookup(engine, "s-canon", order_id=123, fields=["status", "eta"], verbose=False)
    second = lookup(engine, "s-canon", fields=["eta", "status"], order_id=123.0)
    assert first["allowed"] is True and second["allowed"] is True
    expected = '{"fields":["eta","status"],"order_id":123}'
    assert first["confinement"]["canonical_arguments"] == expected
    assert second["confinement"] == first["confinement"]
    assert first["confinement"]["policy"] == ORDER_POLICY.commitment


@pytest.mark.parametrize("args, reason", [
    ({"order_id": 1, "note": "x"}, "UNKNOWN_FIELD"),
    ({"fields": ["eta"]}, "REQUIRED_FIELD"),
    ({"order_id": float("nan")}, "NONFINITE"),
    ({"order_id": 1, "fields": ["eta", "eta"]}, "DUPLICATE_ELEMENT"),
    ({"order_id": 1, "fields": [["eta"]]}, "WIRE_DEPTH"),
    ({"order_id": 1e20}, "NUMBER_LIMIT"),
    ({"order_id": True}, "FIELD_TYPE"),
])
def test_argument_policy_denials(engine: PolicyEngine, args: dict, reason: str) -> None:
    engine.pin_argument_policy("lookup_order_status", ORDER_POLICY)
    out = lookup(engine, "s-deny", **args)
    assert out["allowed"] is False and out["rule_code"] == ARGUMENT_CONFINEMENT_DENIED
    assert out["confinement"] == {"reason": reason, "kind": "arguments",
                                  "policy": ORDER_POLICY.commitment}
    assert _V12_CODES[ARGUMENT_CONFINEMENT_DENIED] == -32073
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)


def test_typed_command_operands_cannot_become_options(engine: PolicyEngine) -> None:
    engine.pin_command_tool("file.copy")
    injected = engine.evaluate_call(KEY_A, "s-cmd", "file.copy",
                                    {"utility": "cp", "operands": ["-rf", "out/b"]})
    assert injected["allowed"] is False and injected["rule_code"] == ARGUMENT_CONFINEMENT_DENIED
    assert injected["confinement"] == {"reason": "OPERAND_OPTION", "kind": "command"}

    allowed = engine.evaluate_call(KEY_A, "s-cmd", "file.copy",
                                   {"utility": "cp", "operands": ["./-rf", "out/b"]})
    assert allowed["allowed"] is True
    assert allowed["confinement"] == {"kind": "command", "argv": ["cp", "--", "./-rf", "out/b"]}

    extra = engine.evaluate_call(KEY_A, "s-cmd", "file.copy",
                                 {"utility": "cp", "operands": ["a", "b"], "flags": "-f"})
    assert extra["confinement"]["reason"] == "COMMAND_ARGUMENTS"


def test_typed_commands_feed_the_workspace_model_and_label_transducer(engine: PolicyEngine) -> None:
    engine.pin_command_tool("file.edit")
    engine.attach_workspace_snapshot("s-typed", filesystem())
    transducer = engine.attach_fs_transducer("s-typed", filesystem())

    # The sed script is an expression, never parsed as shell text.
    edit = engine.evaluate_call(KEY_A, "s-typed", "file.edit",
                                {"utility": "sed", "operands": ["out/b"], "script": "s/a/b/g"})
    assert edit["allowed"] is True
    assert edit["confinement"]["argv"] == ["sed", "-i", "--", "s/a/b/g", "out/b"]

    missing = engine.evaluate_call(KEY_A, "s-typed", "file.edit",
                                   {"utility": "tee", "operands": ["out/nodir/x"]})
    assert missing["rule_code"] == WORKSPACE_EFFECT_DENIED
    assert missing["shell"]["reason"] == "MISSING_COMPONENT"

    copy = engine.evaluate_call(KEY_A, "s-typed", "file.edit",
                                {"utility": "cp", "operands": [".mcp.json", "out/a"]})
    assert copy["allowed"] is True
    sent = engine.evaluate_call(KEY_A, "s-typed", "send_email",
                                {"to": "ops@example.com", "body": "summary", "path": "/ws/out/a"})
    assert sent["allowed"] is False and sent["rule_code"] == FS_LABEL_FLOW_DENIED
    assert transducer.generation == 2


def test_confinement_result_never_leaks_into_a_later_call(engine: PolicyEngine) -> None:
    engine.pin_argument_policy("lookup_order_status", ORDER_POLICY)
    assert "confinement" in lookup(engine, "s-leak", order_id=7)
    other = engine.evaluate_call(KEY_A, "s-leak", "read_session_note", {"note_id": 1})
    assert other["allowed"] is True and "confinement" not in other


def test_a_tool_is_pinned_one_way_only(engine: PolicyEngine) -> None:
    engine.pin_command_tool("file.copy")
    with pytest.raises(ValueError):
        engine.pin_argument_policy("file.copy", ORDER_POLICY)
    engine.pin_argument_policy("lookup_order_status", ORDER_POLICY)
    with pytest.raises(ValueError):
        engine.pin_command_tool("lookup_order_status")
    with pytest.raises(TypeError):
        engine.pin_argument_policy("other", {"order_id": "number"})


def test_sarif_declares_the_confinement_rule() -> None:
    assert ARGUMENT_CONFINEMENT_DENIED in RULES and ARGUMENT_CONFINEMENT_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": ARGUMENT_CONFINEMENT_DENIED, "tool": "file.copy", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == ARGUMENT_CONFINEMENT_DENIED
