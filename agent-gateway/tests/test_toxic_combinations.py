"""Static toxic-flow graph over a tool inventory, and its audit section. Offline."""
from __future__ import annotations

import json
import socket
from pathlib import Path

from hypothesis import given, settings, strategies as st

from agent_gateway.audit_chain import verify_audit_dir
from agent_gateway.cli import main
from agent_gateway.pep import PolicyEngine
from agent_gateway.toxic_combinations import analyze, render_svg, tool_class
from tests.conftest import KEY_A

FIX = Path(__file__).parent / "fixtures" / "audit" / "access-jsonl"
S = {"type": "string"}


def _obj(**props):
    return {"type": "object", "properties": props}


INVENTORY = {"tools": [
    {"name": "web.fetch", "class": "external_read", "inputSchema": _obj(url=S)},
    {"name": "vault.read", "class": "sensitive_read", "inputSchema": _obj(path=S)},
    {"name": "file.read", "class": "internal_read", "inputSchema": _obj(path=S)},
    {"name": "send_email", "class": "send", "inputSchema": _obj(to=S, body=S)},
    {"name": "update_ticket_status", "class": "write",
     "inputSchema": _obj(order_id={"type": "integer"}, status={"enum": ["shipped", "pending"]})},
    {"name": "set_ticket_tag", "class": "write", "inputSchema": _obj(tag={"type": "string", "maxLength": 12})},
    {"name": "use_deploy_key", "class": "credential_use", "agw1_boundary": True, "inputSchema": _obj(cmd=S)},
]}


def _paths(report, toxic=True):
    return {tuple(p["path"]) for p in report["paths"] if p["toxic"] is toxic}


def test_enumerates_2hop_and_3hop():
    r = analyze(INVENTORY).as_dict()
    toxic = _paths(r)
    assert ("web.fetch", "vault.read", "send_email") in toxic
    assert ("web.fetch", "file.read", "send_email") in toxic
    assert ("web.fetch", "vault.read", "web.fetch") in toxic  # query-parameter egress
    assert ("web.fetch", "file.read", "vault.read", "send_email") in toxic
    assert ("web.fetch", "vault.read", "file.read", "send_email") in toxic
    # Sinks without a free-text channel are not paths.
    assert all("update_ticket_status" not in p and "set_ticket_tag" not in p for p in toxic)
    assert set(r["constrained_sinks"]) == {"update_ticket_status", "set_ticket_tag"}
    # A sink behind a hard agw1. boundary is protected, not toxic.
    assert ("web.fetch", "vault.read", "use_deploy_key") in _paths(r, toxic=False)
    t = r["totals"]
    assert (t["toxic_2hop"], t["toxic_3hop"]) == (4, 4)
    assert (t["protected_2hop"], t["protected_3hop"]) == (2, 2)
    sev = {tuple(p["path"]): p["severity"] for p in r["paths"]}
    assert sev[("web.fetch", "vault.read", "send_email")] == "critical"
    assert sev[("web.fetch", "file.read", "send_email")] == "high"
    assert r["atlas"] == "AML.T0086" and r["atlas_approximate"] is True


def test_no_source_or_no_sink_means_no_paths():
    reads_only = {"tools": [t for t in INVENTORY["tools"] if t["name"] != "web.fetch"]}
    assert analyze(reads_only).as_dict()["paths"] == []
    no_sink = {"tools": [t for t in INVENTORY["tools"] if t["class"] in ("external_read", "sensitive_read")]}
    no_sink["tools"][0] = {**no_sink["tools"][0], "inputSchema": _obj(page={"type": "integer"})}
    assert analyze(no_sink).as_dict()["paths"] == []


def test_inventory_wide_boundary_and_labels():
    r = analyze({**INVENTORY, "agw1_boundary": True}).as_dict()
    assert r["totals"]["toxic"] == 0 and r["totals"]["protected"] > 0
    assert tool_class({"name": "read_internal_secrets"}) == "sensitive_read"
    assert tool_class({"name": "x", "class": "creds"}) == "credential_use"
    assert tool_class({"name": "frobnicate"}) == "write"  # fail closed
    assert tool_class({"name": "sendSlackMessage"}) == "send"


def test_svg_is_static_and_escaped():
    inv = {"tools": [*INVENTORY["tools"], {"name": "<script>x</script>", "class": "send", "inputSchema": _obj(b=S)}]}
    svg = render_svg(analyze(inv).as_dict())
    assert svg.startswith("<svg") and "<script>" not in svg and "&lt;script&gt;" in svg
    assert "class='tox'" in svg and "class='ok'" in svg


_CLASSES = ["external_read", "internal_read", "sensitive_read", "write", "send", "credential_use"]


@settings(max_examples=150, deadline=None, database=None)
@given(tools=st.lists(
    st.tuples(st.sampled_from(_CLASSES), st.booleans(), st.booleans()), min_size=1, max_size=9,
))
def test_property_paths_match_brute_force(tools):
    inv = {"tools": [
        {"name": f"t{i}", "class": cls,
         "inputSchema": _obj(body=S) if free else _obj(n={"type": "integer"}),
         "agw1_boundary": boundary}
        for i, (cls, free, boundary) in enumerate(tools)
    ]}
    r = analyze(inv).as_dict()
    names = {t["name"]: t for t in inv["tools"]}
    src = [n for n, t in names.items() if t["class"] == "external_read"]
    reads = [n for n, t in names.items() if t["class"] in ("internal_read", "sensitive_read")]
    sinks = [n for n, t in names.items()
             if (t["class"] in ("write", "send", "credential_use", "external_read"))
             and t["inputSchema"]["properties"].get("body")]
    expect2 = {(s, a, z) for s in src for a in reads for z in sinks if z != a}
    expect3 = {(s, a, b, z) for s in src for a in reads for b in reads if a != b
               for z in sinks if z not in (a, b)}
    got = {tuple(p["path"]) for p in r["paths"]}
    if not r["truncated"]:
        assert got == expect2 | expect3
    for p in r["paths"]:
        assert p["toxic"] is (not names[p["path"][-1]]["agw1_boundary"])
    assert r["totals"]["toxic"] + r["totals"]["protected"] == len(expect2) + len(expect3)


def _forbid_connect(monkeypatch):
    def _blocked(*_a, **_k):
        raise AssertionError("audit opened a socket")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


def test_tool_list_only_audit(tmp_path: Path, monkeypatch, capsys):
    _forbid_connect(monkeypatch)
    src = tmp_path / "tool-list-only"
    src.mkdir()
    (src / "tool-inventory.json").write_text(json.dumps(INVENTORY), encoding="utf-8")
    out = tmp_path / "report"
    assert main(["audit", str(src), "--out-dir", str(out)]) == 0
    html = (out / "audit-report.html").read_text(encoding="utf-8")
    assert "Toxic combinations" in html and "<svg" in html
    assert "web.fetch → vault.read → send_email" in html
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert findings["toxic_combinations"]["totals"]["toxic_2hop"] == 4
    assert (out / "tool-inventory.json").is_file()
    pdf = (out / "audit-report.pdf").read_bytes().decode("latin-1")
    assert "Toxic 2-hop: 4" in pdf
    capsys.readouterr()
    assert main(["verify", str(out)]) == 0
    res = verify_audit_dir(out)
    assert {"file:findings.json", "file:tool-inventory.json", "file:audit-report.html"} <= {c["check"] for c in res["checks"]}
    # Editing the toxic section is caught by the manifest.
    doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    doc["toxic_combinations"]["paths"] = []
    (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
    assert verify_audit_dir(out)["ok"] is False


def test_audit_merges_toxic_into_analyzer_findings_and_gateway_section(tmp_path: Path, engine: PolicyEngine):
    engine.evaluate_tools_list(KEY_A, "inv", "core", INVENTORY["tools"])
    engine.evaluate_call(KEY_A, "inv", "web.fetch", {"url": "http://169.254.169.254/"})
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps(INVENTORY), encoding="utf-8")
    out = tmp_path / "report"
    assert main(["audit", str(FIX), "--out-dir", str(out), "--tool-inventory", str(inv),
                 "--decision-log", str(engine.alert_path)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert findings["schema"] == "agentwatch-analyzer.findings/1"  # analyzer doc kept
    assert findings["findings"]  # analyzer findings kept
    assert findings["toxic_combinations"]["totals"]["toxic"] == 8
    counts = findings["gateway_findings"]["counts"]
    assert counts["toxic_combinations"] >= 1 and counts["ssrf_boundary_violation"] == 1
    html = (out / "audit-report.html").read_text(encoding="utf-8")
    assert "Gateway findings (decision log)" in html
    assert verify_audit_dir(out)["ok"] is True
    assert main(["audit", str(FIX), "--out-dir", str(out), "--tool-inventory", str(tmp_path / "nope")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"tools": 5}', encoding="utf-8")
    assert main(["audit", str(FIX), "--out-dir", str(out), "--tool-inventory", str(bad)]) == 2


def test_pep_records_inventory_from_tools_list(engine: PolicyEngine):
    out = engine.evaluate_tools_list(KEY_A, "inv2", "core", INVENTORY["tools"])
    assert out["toxic_combinations"]["toxic"] == 8
    assert engine.toxic["inv2"]["totals"]["toxic_2hop"] == 4
    assert "send_email" in engine.sink_tools("inv2")


def test_empty_dir_without_inventory_still_rejected(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["audit", str(empty)]) == 2
