"""OASIS SARIF 2.1.0 exporter. Output validates cleanly; audit --sarif round-trips."""
from __future__ import annotations

import json
import socket
from pathlib import Path

from hypothesis import given, settings, strategies as st

from agent_gateway.audit_chain import verify_audit_dir
from agent_gateway.cli import main
from agent_gateway.sarif_export import RULES, SARIF_VERSION, build_sarif, validate_sarif

FIX = Path(__file__).parent / "fixtures" / "audit" / "access-jsonl"

SAMPLE_REPORT = {
    "source_log": "lab/access.jsonl",
    "toxic_combinations": {
        "totals": {"toxic": 2},
        "paths": [
            {"toxic": True, "hops": 2, "severity": "critical", "path": ["web.fetch", "vault.read", "send_email"],
             "classes": ["external_read", "sensitive_read", "send"], "channel": ["body"]},
            {"toxic": False, "hops": 2, "severity": "high", "path": ["web.fetch", "file.read", "use_key"],
             "classes": ["external_read", "internal_read", "credential_use"], "channel": ["x"]},
        ],
    },
    "gateway_findings": {
        "counts": {"ssrf_boundary_violation": 1, "toxic_combinations": 1},
        "rows": [
            {"kind": "ssrf_boundary_violation", "tool": "web.fetch", "session": "s1",
             "atlas": "AML.T0053", "detail": "cloud_metadata_target"},
            {"kind": "toxic_combinations", "tool": "", "session": "s1", "atlas": "AML.T0086", "detail": "toxic paths: 2"},
        ],
    },
    "findings_preview": [
        {"rule_id": "R8", "title": "UA mismatch", "summary": "...", "atlas": ["AML.T0051"], "session": "sess-9"},
    ],
}


def test_build_sarif_shape_and_validates():
    doc = build_sarif(SAMPLE_REPORT)
    assert validate_sarif(doc) == []
    assert doc["version"] == SARIF_VERSION and "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AgentGate"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_rule_ids = {r["ruleId"] for r in run["results"]}
    assert result_rule_ids <= rule_ids  # every result references a declared rule
    # toxic_combinations summary row is not duplicated as a result (per-path results cover it)
    assert "toxic_combination" in rule_ids and "ssrf_boundary_violation" in rule_ids
    # only the toxic path (not the protected one) becomes a result
    toxic_results = [r for r in run["results"] if r["ruleId"] == "toxic_combination"]
    assert len(toxic_results) == 1 and toxic_results[0]["level"] == "warning"
    ssrf = [r for r in run["results"] if r["ruleId"] == "ssrf_boundary_violation"]
    assert ssrf and ssrf[0]["level"] == "error"
    for r in run["results"]:
        assert r["message"]["text"] and r["locations"] and r["partialFingerprints"]


def test_validator_catches_malformed():
    assert "version must be '2.1.0'" in validate_sarif({"version": "1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]})
    assert any("driver.name" in e for e in validate_sarif({"version": "2.1.0", "$schema": "x", "runs": [{"tool": {}}]}))
    bad_level = {"version": "2.1.0", "$schema": "x",
                 "runs": [{"tool": {"driver": {"name": "A", "rules": [{"id": "r"}]}},
                           "results": [{"ruleId": "r", "level": "fatal", "message": {"text": "x"},
                                        "locations": [{"logicalLocations": [{"fullyQualifiedName": "y"}]}]}]}]}
    assert any("not a SARIF level" in e for e in validate_sarif(bad_level))
    missing_msg = {"version": "2.1.0", "$schema": "x",
                   "runs": [{"tool": {"driver": {"name": "A", "rules": [{"id": "r"}]}},
                             "results": [{"ruleId": "r", "message": {},
                                          "locations": [{"note": "no real location"}]}]}]}
    probs = validate_sarif(missing_msg)
    assert any("message.text" in e for e in probs) and any("location" in e for e in probs)


def test_empty_report_is_valid_sarif():
    doc = build_sarif({})
    assert validate_sarif(doc) == []
    assert doc["runs"][0]["results"] == []


def test_every_rule_has_a_level_in_catalog():
    for rid, (level, name, atlas, help_text) in RULES.items():
        assert level in {"error", "warning", "note", "none"}
        assert name and help_text


def _forbid_connect(monkeypatch):
    def _blocked(*_a, **_k):
        raise AssertionError("socket opened")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


def test_audit_sarif_in_report_dir_is_manifest_covered(tmp_path, monkeypatch, capsys):
    _forbid_connect(monkeypatch)
    inv = tmp_path / "tools.json"
    inv.write_text(json.dumps({"tools": [
        {"name": "web.fetch", "class": "external_read", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
        {"name": "vault.read", "class": "sensitive_read", "inputSchema": {"type": "object", "properties": {"p": {"type": "string"}}}},
        {"name": "send_email", "class": "send", "inputSchema": {"type": "object", "properties": {"body": {"type": "string"}}}},
    ]}), encoding="utf-8")
    out = tmp_path / "report"
    assert main(["audit", str(FIX), "--out-dir", str(out), "--tool-inventory", str(inv), "--sarif", "findings.sarif"]) == 0
    sarif = out / "findings.sarif"
    assert sarif.is_file()
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert validate_sarif(doc) == []
    assert any(r["ruleId"] == "toxic_combination" for r in doc["runs"][0]["results"])
    # Covered by the manifest, so verify passes and a tampered SARIF is caught.
    capsys.readouterr()
    assert main(["verify", str(out)]) == 0
    assert "findings.sarif" in {k for k in json.loads((out / "audit_manifest.json").read_text())["files"]}
    sarif.write_text(sarif.read_text(encoding="utf-8").replace("AgentGate", "Tampered", 1), encoding="utf-8")
    assert verify_audit_dir(out)["ok"] is False


def test_audit_sarif_outside_report_dir(tmp_path, monkeypatch):
    _forbid_connect(monkeypatch)
    out = tmp_path / "report"
    external = tmp_path / "scan" / "findings.sarif"
    external.parent.mkdir()
    assert main(["audit", str(FIX), "--out-dir", str(out), "--sarif", str(external)]) == 0
    assert external.is_file()
    assert validate_sarif(json.loads(external.read_text(encoding="utf-8"))) == []
    # Written outside the audit dir, so it is not in the manifest (cannot be covered).
    assert "findings.sarif" not in {k for k in json.loads((out / "audit_manifest.json").read_text())["files"]}


_KIND = st.sampled_from(sorted(set(RULES) - {"toxic_combination", "analyzer_match"}))


@settings(max_examples=120, deadline=None, database=None)
@given(
    rows=st.lists(st.fixed_dictionaries({
        "kind": _KIND,
        "tool": st.text(max_size=20),
        "session": st.text(max_size=12),
        "atlas": st.sampled_from(["AML.T0051", "AML.T0053", "AML.T0086"]),
        "detail": st.text(max_size=40),
    }), max_size=8),
    toxic=st.lists(st.fixed_dictionaries({
        "toxic": st.booleans(),
        "hops": st.integers(min_value=2, max_value=3),
        "severity": st.sampled_from(["high", "critical"]),
        "path": st.lists(st.text(min_size=1, max_size=8), min_size=2, max_size=4),
        "classes": st.lists(st.text(min_size=1, max_size=8), min_size=2, max_size=4),
        "channel": st.lists(st.text(max_size=8), max_size=2),
    }), max_size=8),
)
def test_property_generated_reports_always_validate(rows, toxic):
    report = {"gateway_findings": {"counts": {}, "rows": rows},
              "toxic_combinations": {"totals": {"toxic": 0}, "paths": toxic},
              "findings_preview": []}
    doc = build_sarif(report)
    assert validate_sarif(doc) == []
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in declared for r in doc["runs"][0]["results"])
