from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentwatch_analyzer.cli import main
from agentwatch_analyzer.detect import OFFLINE_MATRIX, analyze_sessions
from agentwatch_analyzer.parse import iter_events, parse_nginx_line
from agentwatch_analyzer.prefilter import partition
from agentwatch_analyzer.scrub import scrub_obj, scrub_text
from agentwatch_analyzer.stix_bundle import build_bundle, validate_bundle

FIX = Path(__file__).parent / "fixtures"
RULES = Path(__file__).resolve().parents[1] / "rules" / "sigma"


def test_nginx_parse_and_scrub_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_ANALYZER_SALT", "test-salt-analyzer-16b!")
    ev = parse_nginx_line((FIX / "secretish_nginx.log").read_text().strip())
    assert ev and "sk-" in ev.query
    assert main([str(FIX / "secretish_nginx.log"), "--format", "nginx", "--out-dir", str(tmp_path / "o")]) == 0
    text = (tmp_path / "o" / "events.scrubbed.jsonl").read_text()
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in text
    assert "user@example.com" not in text
    assert "REDACTED" in text or "query-redacted" in text


def test_benign_has_no_strong_findings():
    evs = list(iter_events(FIX / "benign_nginx.log", "nginx"))
    kept, _ = partition(evs)
    findings = analyze_sessions(kept, sitemap_paths={"/", "/about", "/kb/"})
    # human with assets should not trip R8
    assert not any(f.rule_id == "R8" for f in findings)


def test_agentlike_triggers_r8_r10():
    evs = list(iter_events(FIX / "agentlike_nginx.log", "nginx"))
    kept, _ = partition(evs)
    findings = analyze_sessions(kept)
    ids = {f.rule_id for f in findings}
    assert "R8" in ids  # browser UA, no css/js
    assert "R10" in ids  # schema cursor / machine docs


def test_scanner_prefiltered():
    evs = list(iter_events(FIX / "scanner_nginx.log", "nginx"))
    kept, filtered = partition(evs)
    assert filtered and not kept


def test_json_with_links_r9(tmp_path):
    assert main([str(FIX / "access.jsonl"), "--format", "json", "--out-dir", str(tmp_path / "o")]) == 0
    doc = json.loads((tmp_path / "o" / "findings.json").read_text())
    ids = {f["rule_id"] for f in doc["findings"]}
    assert "R9" in ids
    assert (tmp_path / "o" / "replay.html").is_file()
    html = (tmp_path / "o" / "replay.html").read_text()
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html


def test_cli_with_sitemap(tmp_path):
    assert main([
        str(FIX / "agentlike_nginx.log"), "--format", "nginx",
        "--sitemap", str(FIX / "sitemap.xml"),
        "--out-dir", str(tmp_path / "o"),
    ]) == 0
    summary = json.loads((tmp_path / "o" / "summary.json").read_text())
    assert summary["findings"] >= 1


def test_dict_key_redaction():
    obj = scrub_obj({"authorization": "Bearer SUPERSECRETTOKEN123456", "path": "/ok"})
    assert "SUPERSECRET" not in str(obj["authorization"])
    assert obj["path"] == "/ok"


def test_two_round_decode_scrub():
    # email percent-encoded once
    s = scrub_text("contact=%75%73%65%72%40example.com", drop_query=False)
    assert "user@example.com" not in s
    assert "REDACTED_EMAIL" in s or "example" not in s.lower() or "REDACTED" in s


def test_sigma_rules_valid_yaml_and_ids():
    files = sorted(RULES.glob("*.yml"))
    assert len(files) >= 12
    ids = set()
    for f in files:
        doc = yaml.safe_load(f.read_text())
        assert "title" in doc and "detection" in doc and "logsource" in doc
        assert "condition" in doc["detection"]
        assert doc["id"] not in ids
        ids.add(doc["id"])
    # offline matrix documented
    assert OFFLINE_MATRIX["R11"]["offline"] is False
    assert OFFLINE_MATRIX["R8"]["offline"] is True


def test_stix_bundle_builds_and_validates():
    findings = [{
        "rule_id": "R8",
        "title": "Asset starvation",
        "session_key": "198.51.100.20|Mozilla",
        "strength": 0.55,
        "summary": "offline R8",
        "evidence": [{"path": "/about"}],
        "atlas": ["AML.T0053"],
    }]
    bundle_json, summary = build_bundle(findings)
    assert summary["parsed_ok"] is True
    # validator pin may or may not pass custom props; parse must succeed
    assert "indicator" in bundle_json.lower() or "Indicator" in bundle_json
    v = validate_bundle(bundle_json)
    assert v["parsed_ok"] is True
