"""Sprint evaluation aggregator, benign latency timer, and report renderer."""
from __future__ import annotations

import json
import time
from pathlib import Path

from agent_gateway import collusion_eval as ce
from agent_gateway.cli import main

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="5">
<testcase classname="tests.test_side_channel_guard" name="test_a_ok" time="0.01"/>
<testcase classname="tests.test_delegation_guard" name="test_b_bad" time="0.02"><failure message="x"/></testcase>
<testcase classname="tests.test_delegation_guard.TestDelegationDag" name="runTest" time="0.5"/>
<testcase classname="tests.test_deobfuscate" name="test_c_skip" time="0"><skipped message="s"/></testcase>
<testcase classname="tests.test_canary_watermark" name="test_c_err" time="0"><error message="e"/></testcase>
</testsuite></testsuites>
"""


def _stub_suite(passed: int = 3, failed: int = 0) -> dict:
    tests = [{"nodeid": f"tests/test_side_channel_guard.py::t{i}", "outcome": "passed", "seconds": 0.0}
             for i in range(passed)]
    tests += [{"nodeid": f"tests/test_side_channel_guard.py::f{i}", "outcome": "failed", "seconds": 0.0}
              for i in range(failed)]
    group = {"group": "A", "title": "Side-channel and timing guard", "module": "side_channel_guard.py",
             "files": ["test_side_channel_guard.py"],
             "counts": {"total": passed + failed, "passed": passed, "failed": failed, "error": 0, "skipped": 0},
             "all_passed": failed == 0, "tests": tests}
    return {"command": "python -m pytest -q tests/test_side_channel_guard.py", "returncode": 1 if failed else 0,
            "seconds": 0.1, "pytest_summary": f"{passed} passed", "missing_files": [], "groups": [group],
            "totals": dict(group["counts"])}


_STUB_COLLECTION = {"command": "python -m pytest --collect-only -q", "collected": 3, "files": 1, "returncode": 0}


def test_parse_junit_and_group(tmp_path):
    p = tmp_path / "j.xml"
    p.write_text(JUNIT, encoding="utf-8")
    cases = ce.parse_junit(p)
    by_id = {c.nodeid: c.outcome for c in cases}
    assert by_id["tests/test_side_channel_guard.py::test_a_ok"] == "passed"
    assert by_id["tests/test_delegation_guard.py::test_b_bad"] == "failed"
    assert by_id["tests/test_delegation_guard.py::TestDelegationDag::runTest"] == "passed"
    assert by_id["tests/test_deobfuscate.py::test_c_skip"] == "skipped"
    assert by_id["tests/test_canary_watermark.py::test_c_err"] == "error"
    groups = {g.group: g for g in ce.group_results(cases)}
    assert groups["A"].counts() == {"total": 1, "passed": 1, "failed": 0, "error": 0, "skipped": 0}
    assert groups["A"].ok
    assert groups["B"].counts()["failed"] == 1 and not groups["B"].ok
    assert groups["C"].counts() == {"total": 2, "passed": 0, "failed": 0, "error": 1, "skipped": 1}
    assert not groups["C"].ok


def test_empty_group_is_not_ok():
    assert not ce.GroupResult("A", "t", "m", ["x.py"]).ok


def test_run_defense_suite_counts_a_failure(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_good.py").write_text("def test_one():\n    assert True\n\ndef test_two():\n    assert 1\n")
    (tests / "test_bad.py").write_text("def test_fails():\n    assert False\n")
    groups = {"A": {"title": "good", "files": ["test_good.py"]},
              "B": {"title": "bad", "files": ["test_bad.py", "test_missing.py"]}}
    res = ce.run_defense_suite(groups=groups, tests_dir=tests)
    assert res["returncode"] != 0
    a, b = res["groups"]
    assert a["counts"]["passed"] == 2 and a["all_passed"]
    assert b["counts"]["failed"] == 1 and not b["all_passed"]
    assert res["missing_files"] == ["test_missing.py"]
    assert res["totals"]["total"] == 3


def test_percentile_nearest_rank():
    vals = [float(i) for i in range(1, 101)]
    assert ce._percentile(vals, 50) == 50.0
    assert ce._percentile(vals, 99) == 99.0
    assert ce._percentile([3.0], 95) == 3.0
    assert ce._percentile([], 50) == 0.0


def test_benign_latency_and_chain(tmp_path):
    lat = ce.run_benign_latency(iterations=2, work_dir=tmp_path)
    n_steps = sum(len(s) for s in ce.BENIGN_WORKFLOWS.values())
    assert lat["decisions"] == 2 * n_steps
    assert lat["benign_denials"] == 0, lat["benign_denial_examples"]
    assert lat["llm_calls"] == 0
    for key in ("p50_ms", "p95_ms", "p99_ms"):
        assert lat["cpu"][key] >= 0.0
    assert lat["cpu"]["p50_ms"] <= lat["cpu"]["p95_ms"] <= lat["cpu"]["p99_ms"]
    chain = ce.verify_decision_log(lat["decision_log"])
    assert chain["chain_ok"] and chain["entries"] == lat["decisions"]
    assert chain["tamper_checks"] == {"edited_line": True, "dropped_line": True}


def test_render_and_write_report(tmp_path):
    lat = ce.run_benign_latency(iterations=1, work_dir=tmp_path / "w")
    doc = ce.evaluate(iterations=1, suite=_stub_suite(), work_dir=tmp_path / "w2", collection=_STUB_COLLECTION)
    paths = ce.write_report(tmp_path / "out", doc)
    md = paths["markdown"].read_text(encoding="utf-8")
    for heading in ("## Abstract", "## Problem Statement", "## Methodology", "## Results",
                    "### Reproducible test-suite results by group", "### Benign decision latency",
                    "### Audit-chain verification", "## Defence Analysis", "## Scope and Limitations"):
        assert heading in md
    assert "2 of 13" in md and "never pooled" in md
    assert "127.0.0.1" in md and "15 minutes" in md and "approximate" in md
    assert "tests/test_side_channel_guard.py" in md
    pdf = paths["pdf"].read_bytes()
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["schema"] == ce.SCHEMA
    assert data["archive_baseline"] == {"value": "2 of 13", "pooled": False,
                                        "note": "Real-model loopback archive, non-control runs. Separate measurement."}
    assert "decision_log" not in data["benign_latency"]
    assert ce.ok(doc)
    assert lat["decisions"] > 0


def test_ok_false_on_failed_group(tmp_path):
    doc = ce.evaluate(iterations=1, suite=_stub_suite(failed=1), work_dir=tmp_path, collection=_STUB_COLLECTION)
    assert not ce.ok(doc)
    md = ce.render_markdown(doc)
    assert "Failing in group A" in md


def test_cli_end_to_end_under_ten_seconds(tmp_path, capsys):
    t0 = time.perf_counter()
    rc = main(["evaluate-collusion", "--report", str(tmp_path), "--iterations", "3"])
    elapsed = time.perf_counter() - t0
    out = json.loads(capsys.readouterr().out)
    assert rc == 0, out
    assert elapsed < 10.0, elapsed
    assert out["groups_all_passed"] == {"A": True, "B": True, "C": True}
    assert out["audit_chain_ok"] is True and out["benign_denials"] == 0
    for name in (ce.RESULTS_NAME, ce.REPORT_MD_NAME, ce.REPORT_PDF_NAME, ce.SLIDES_PDF_NAME, ce.CARD_PNG_NAME):
        assert (tmp_path / name).is_file()
    assert out["gateway_tests_collected"] >= 250
    data = json.loads((tmp_path / ce.RESULTS_NAME).read_text(encoding="utf-8"))
    total = data["defense_suite"]["totals"]
    assert total["total"] > 0 and total["passed"] == total["total"]


def test_cli_rejects_bad_iterations(capsys):
    assert main(["evaluate-collusion", "--iterations", "0"]) == 2


def test_hypothesis_settings_scan_matches_machines():
    found = {(h["file"], h["machine"]): (h["max_examples"], h["stateful_step_count"])
             for h in ce.scan_hypothesis_settings()}
    assert found[("test_delegation_guard.py", "DelegationDagMachine")] == (120, 24)
    assert found[("test_side_channel_guard.py", "SideChannelMachine")] == (60, 30)
    assert found[("test_stateful_fuzz.py", "SmugglingMachine")] == (60, 24)
    assert all(m for _f, m in found)  # every entry is attributed to a named machine


def test_collect_gateway_tests_counts_suite():
    res = ce.collect_gateway_tests()
    assert res["returncode"] == 0 and res["collected"] >= 250
