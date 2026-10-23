import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentwatch.cli import main
from agentwatch.config import load_config
from agentwatch.pipeline import run_pipeline
from agentwatch.report import build_report, render_text
from agentwatch.synthetic import generate_demo

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    art = generate_demo(out, seed=7)
    results, parsed = run_pipeline([art["access_log"], art["gateway_log"], art["leads"]], load_config())
    by_ip: dict[str, list] = {}
    for r in results:
        by_ip.setdefault(r.session.ip, []).append(r)
    truth = {t.ip: t for t in art["truth"]}
    best = {ip: max(rs, key=lambda r: len(r.session.requests)) for ip, rs in by_ip.items()}
    return {"out": out, "art": art, "results": results, "parsed": parsed, "truth": truth, "best": best}


def of(demo, label):
    return [demo["best"][ip] for ip, t in demo["truth"].items() if t.label == label]


def test_every_actor_found_and_labelled_correctly(demo):
    assert demo["parsed"].errors == 0
    for ip, t in demo["truth"].items():
        assert demo["best"][ip].label == t.label, (t.name, demo["best"][ip].label)


def test_adaptive_agents_outscore_humans_and_static_bots(demo):
    agents = of(demo, "agent")
    others = of(demo, "human") + of(demo, "static_bot")
    assert len(agents) == 9 and len(others) == 11
    assert min(r.agent_score for r in agents) > max(r.agent_score for r in others)
    assert min(r.agent_score for r in agents) >= load_config()["thresholds"]["agent"]
    assert max(r.agent_score for r in others) < load_config()["thresholds"]["medium"]


def test_agents_get_high_severity_and_explanations(demo):
    for r in of(demo, "agent"):
        assert r.severity in ("high", "critical") and len(r.reasons) >= 3
        assert any(f.detector in ("adaptation", "honeytoken", "coordination") for f in r.findings)


def test_agents_use_honeytokens_where_expected(demo):
    by_name = {t.name: demo["best"][ip] for ip, t in demo["truth"].items()}
    assert by_name["gullible RAG agent C"].honeytoken_hits and by_name["adaptive agent B (enumeration)"].honeytoken_hits
    kinds = {f.kind for f in by_name["gullible RAG agent C"].honeytoken_hits}
    assert "canary_follow" in kinds and "fake_admin_api" in kinds
    assert not by_name["adaptive agent A (chains)"].honeytoken_hits      # A is caught on behaviour alone
    assert any(f.detector == "tool_chain" for f in by_name["adaptive agent A (chains)"].findings)


def test_false_positive_checks(demo):
    by_name = {t.name: demo["best"][ip] for ip, t in demo["truth"].items()}
    busy = by_name["busy human"]
    assert busy.label == "human" and busy.severity == "info" and len(busy.session.requests) > 150
    crawler = by_name["search-engine-style crawler"]
    assert crawler.label == "static_bot" and crawler.benign and crawler.severity == "info"
    health = by_name["monitoring health check"]
    assert health.label == "static_bot" and health.benign and health.severity == "info"
    naive = by_name["naive scraper (ignores 429)"]                     # not benign, but not an "agent"
    assert naive.label == "static_bot" and not naive.benign and naive.severity == "low"
    assert not [r for r in of(demo, "human") if r.severity != "info"]


def test_json_report_structure(demo):
    rep = build_report(demo["results"], ["a"], demo["parsed"])
    assert rep["schema"] == "agentwatch.report/1" and rep["summary"]["sessions"] == len(demo["results"])
    assert rep["summary"]["by_label"] == {"human": 6, "static_bot": 5, "agent": 9}
    s0 = rep["sessions"][0]
    for key in ("session_id", "ip", "label", "severity", "agent_score", "automation_score", "reasons", "evidence", "findings", "features"):
        assert key in s0
    json.dumps(rep)                                                     # serialisable
    text = render_text(rep, min_severity="high")
    assert "CRITICAL" in text and "top reasons" in text and "evidence:" in text and "\x1b" not in text


def test_terminal_summary_strips_control_chars_from_logs(tmp_path):
    log = tmp_path / "evil.log"
    ua = "bad\x1b[2Jua"                                              # a real ESC byte inside the log line
    lines = [f'203.0.113.9 - - [22/Oct/2026:10:00:{i:02d} +0000] "GET /healthz HTTP/1.1" 200 1 "-" "{ua}"' for i in range(30)]
    log.write_text("\n".join(lines) + "\n")
    res, parsed = run_pipeline([log], load_config())
    assert "\x1b" not in render_text(build_report(res, [str(log)], parsed), min_severity="info")


# ---- CLI ---------------------------------------------------------------------------------------------------
def test_cli_demo_command(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path), "--no-color", "--min-severity", "high"]) == 0
    out = capsys.readouterr().out
    assert "Per-class summary" in out and "NOT real-world accuracy" in out
    assert (tmp_path / "report.json").is_file() and (tmp_path / "access.log").is_file()


def test_cli_analyze_report_roundtrip_and_fail_on(demo, tmp_path, capsys):
    out_json = tmp_path / "r.json"
    art = demo["art"]
    rc = main(["analyze", str(art["access_log"]), str(art["gateway_log"]), "--leads", str(art["leads"]),
               "--json-out", str(out_json), "--no-color", "--fail-on", "critical"])
    assert rc == 1                                                      # critical sessions exist
    capsys.readouterr()
    assert main(["report", str(out_json), "--min-severity", "critical", "--no-color"]) == 0
    assert "CRITICAL" in capsys.readouterr().out
    assert main(["report", str(out_json), "--format", "json", "--top", "2"]) == 0
    assert len(json.loads(capsys.readouterr().out)["sessions"]) == 2


def test_cli_errors(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing.log")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["report", str(bad)]) == 2
    cfg = tmp_path / "c.json"
    cfg.write_text('{"nope": 1}')
    log = tmp_path / "l.log"
    log.write_text("")
    assert main(["analyze", str(log), "--config", str(cfg)]) == 2


def test_module_entrypoint_runs():
    p = subprocess.run([sys.executable, "-m", "agentwatch", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0 and "agent-watch" in p.stdout


def test_demo_is_deterministic(tmp_path):
    a = generate_demo(tmp_path / "a", seed=3)["access_log"].read_text()
    b = generate_demo(tmp_path / "b", seed=3)["access_log"].read_text()
    assert a == b


# ---- new in this version: timing variants and the logs-only view -------------------------------------------
def test_timing_signature_flags_only_the_llm_like_variant(demo):
    by_name = {t.name: demo["best"][ip] for ip, t in demo["truth"].items()}
    flagged = {n for n, r in by_name.items() if any(f.detector == "timing" for f in r.findings)}
    # the coordination-bus actors reuse the same assumed LLM delay generator, so they are flagged circularly too
    assert flagged == {"LLM-like delay-scaling agent (timing variant L)",
                       "coordination-bus agent (follows breadcrumb, registers, loops)",
                       "relay agent B (presents A's token from another IP)"}
    # a person whose reading time scales with page size has the same correlation but loads assets -> not flagged
    reader = by_name["reading human (time scales with page size)"]
    assert reader.features["ttna_spearman"] > 0.5 and reader.label == "human" and reader.severity == "info"


def test_all_timing_variants_caught_by_decoys_but_not_all_by_logs_alone(demo):
    by_name = {t.name: demo["best"][ip] for ip, t in demo["truth"].items()}
    for n in ("fast scripted agent (timing variant F)", "LLM-like delay-scaling agent (timing variant L)",
              "human-like agent (timing variant H)"):
        r = by_name[n]
        assert r.label == "agent" and r.severity == "critical" and r.honeytoken_hits
        kinds = {f.kind for f in r.honeytoken_hits}
        assert {"openapi_decoy", "error_hint_follow", "mcp_decoy_tool_call"} <= kinds
        assert any(f.detector == "multi_turn" for f in r.findings)
    cfg = load_config()
    logs_only, _ = run_pipeline([demo["art"]["access_log"], demo["art"]["gateway_log"]], cfg)
    ips = {t.name: ip for ip, t in demo["truth"].items()}
    res = {r.session.ip: r for r in logs_only}
    llm = res[ips["LLM-like delay-scaling agent (timing variant L)"]]
    human_like = res[ips["human-like agent (timing variant H)"]]
    for r in (llm, human_like):          # documented gap: without decoys these slow agents are not labelled agent
        assert r.label != "agent" and r.agent_score < cfg["thresholds"]["agent"]
        assert r.severity == "medium"
    assert any(f.detector == "timing" for f in llm.findings)
    assert res[ips["fast scripted agent (timing variant F)"]].label == "agent"


def test_demo_cli_prints_logs_only_table_and_caveats(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path), "--no-color", "--min-severity", "critical", "--top", "1"]) == 0
    out = capsys.readouterr().out
    assert "LOGS ONLY" in out and "FLAG" in out and "circular" in out and "real agent frameworks" in out
