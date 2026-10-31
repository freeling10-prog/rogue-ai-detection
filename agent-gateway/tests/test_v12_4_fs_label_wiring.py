"""v12.4 wiring for the file label transducer (symbolic_fs_transducer).

``tests/test_validators.py`` exercises the module in isolation. This file
exercises it through ``pep.py``: the decision path, the JSON-RPC code, the
commit-after-all-checks ordering, broker rebases, and the SARIF rule set.
"""
from __future__ import annotations

import json

from agent_gateway.pep import (
    _V12_CODES,
    FS_LABEL_FLOW_DENIED,
    SIMILARITY_LEAK_DENIED,
    WORKSPACE_EFFECT_DENIED,
    PolicyEngine,
)
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES, build_sarif, validate_sarif
from agent_gateway.symbolic_fs_transducer import Confidentiality, Integrity
from agent_gateway.workspace_path_validator import Node, Snapshot
from tests.conftest import KEY_A


def filesystem() -> dict[str, Node]:
    return {"/ws": Node("dir"), "/ws/out": Node("dir"),
            "/ws/out/a": Node("file", (1, 1)), "/ws/out/b": Node("file", (1, 4)),
            "/ws/out/c": Node("file", (1, 5)), "/ws/.mcp.json": Node("file", (1, 2)),
            "/ws/.git": Node("dir")}


def shell(engine: PolicyEngine, session: str, command: str, **extra) -> dict:
    return engine.evaluate_call(KEY_A, session, "run_shell", {"command": command, **extra})


def send(engine: PolicyEngine, session: str, path: str) -> dict:
    return engine.evaluate_call(KEY_A, session, "send_email",
                                {"to": "ops@example.com", "body": "weekly summary", "path": path})


def test_engine_has_no_transducer_until_attached(engine: PolicyEngine) -> None:
    assert engine.fs_transducers == {}
    assert send(engine, "s-inert", "/ws/.mcp.json")["allowed"] is True


def test_protected_file_copied_then_sent_is_denied(engine: PolicyEngine) -> None:
    t = engine.attach_fs_transducer("s-launder", filesystem())
    assert shell(engine, "s-launder", "cp .mcp.json out/a")["allowed"] is True
    assert t.label_at("out/a").confidentiality is Confidentiality.PROTECTED
    assert t.generation == 1

    laundered = send(engine, "s-launder", "/ws/out/a")
    assert laundered["allowed"] is False and laundered["rule_code"] == FS_LABEL_FLOW_DENIED
    assert laundered["fs_label"]["reason"] == "CONFIDENTIAL_SOURCE_TO_EGRESS"
    assert laundered["fs_label"]["axis"] == "confidentiality"
    direct = send(engine, "s-launder", "/ws/.mcp.json")
    assert direct["allowed"] is False and direct["rule_code"] == FS_LABEL_FLOW_DENIED

    assert send(engine, "s-launder", "/ws/out/c")["allowed"] is True
    assert _V12_CODES[FS_LABEL_FLOW_DENIED] == -32072
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)
    assert ".mcp.json" not in json.dumps([f for f in engine.findings
                                          if f["kind"] == FS_LABEL_FLOW_DENIED])


def test_untrusted_write_back_cannot_feed_an_execution_sink(engine: PolicyEngine) -> None:
    t = engine.attach_fs_transducer("s-exec", filesystem())
    t.observe_untrusted()  # The broker reports untrusted content in the session.
    assert shell(engine, "s-exec", "echo x > out/b")["allowed"] is True
    assert t.label_at("out/b").integrity is Integrity.UNTRUSTED
    assert t.label_at("out/c").integrity is Integrity.TRUSTED

    out = engine.evaluate_call(KEY_A, "s-exec", "run_script", {"path": "/ws/out/b"})
    assert out["allowed"] is False and out["rule_code"] == FS_LABEL_FLOW_DENIED
    assert out["fs_label"]["reason"] == "UNTRUSTED_SOURCE_TO_EXEC_SINK"
    assert out["fs_label"]["session_integrity"] == "UNTRUSTED"

    chmod = shell(engine, "s-exec", "chmod 755 out/b")
    assert chmod["allowed"] is False and chmod["fs_label"]["reason"] == "UNTRUSTED_CHMOD_TARGET"


def test_workspace_model_denial_leaves_labels_unchanged(engine: PolicyEngine) -> None:
    t = engine.attach_fs_transducer("s-base", filesystem())
    out = shell(engine, "s-base", "ln out/a out/z")
    assert out["allowed"] is False and out["rule_code"] == WORKSPACE_EFFECT_DENIED
    assert out["shell"] == {"reason": "HARDLINK_CREATION_DISABLED", "modeled": True,
                            "generation": 0, "via": "fs_transducer"}
    assert t.generation == 0 and t.state.overlay == {}


def test_labels_do_not_advance_when_a_later_validator_denies(engine: PolicyEngine) -> None:
    secret = "SYNTHETIC_CFG_TOKEN_ALPHA_99281746"
    engine.configure_similarity_matcher(b"fs-label-wiring-test-key-32bytes!", (secret,))
    t = engine.attach_fs_transducer("s-order", filesystem())
    out = shell(engine, "s-order", "cp .mcp.json out/a", note=f"value={secret}")
    assert out["allowed"] is False and out["rule_code"] == SIMILARITY_LEAK_DENIED
    assert t.generation == 0
    assert t.label_at("out/a").confidentiality is Confidentiality.PUBLIC


def test_created_file_label_survives_a_broker_rebase(engine: PolicyEngine) -> None:
    t = engine.attach_fs_transducer("s-rebase", filesystem())
    assert shell(engine, "s-rebase", "cp .mcp.json out/new")["allowed"] is True
    missing = send(engine, "s-rebase", "/ws/out/new")
    assert missing["rule_code"] == WORKSPACE_EFFECT_DENIED  # Not in the old model yet.

    t.rebase(Snapshot({**filesystem(), "/ws/out/new": Node("file", (1, 9))}, 1))
    published = send(engine, "s-rebase", "/ws/out/new")
    assert published["allowed"] is False and published["rule_code"] == FS_LABEL_FLOW_DENIED


def test_sarif_declares_the_fs_label_rule() -> None:
    assert FS_LABEL_FLOW_DENIED in RULES and FS_LABEL_FLOW_DENIED in _LOG_KIND_RULES
    doc = build_sarif({"gateway_findings": {"rows": [
        {"kind": FS_LABEL_FLOW_DENIED, "tool": "send_email", "session": "s1", "detail": "denied"}]}})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"][0]["ruleId"] == FS_LABEL_FLOW_DENIED
