"""Tests for the three-tier benchmark toolkit (benchmark/, scripts/build_benchmark.py).

Small in-test fixtures only: independent of detector/pipeline internals and of other work in progress.  No network, no Flask,
no pydantic needed (tier-1 generators are injected or disabled).
"""
import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import build_benchmark                                                # noqa: E402
from benchmark import NOT_COMPARABLE_NOTE, TIER1, TIER2, TIER3, TIERS   # noqa: E402
from benchmark.common import BenchmarkError, SecretsFound              # noqa: E402
from benchmark.minischema import validate                              # noqa: E402
from benchmark.packer import build_bundle                              # noqa: E402
from benchmark.secrets_guard import scan_text                          # noqa: E402
from benchmark.tier2_local_real_llm import aggregate, score_run, validate_run_dir   # noqa: E402
from benchmark.tier3_wild_honeypot import build_card, collect_stats, load_slot      # noqa: E402

STUB_RUN = ROOT / "benchmark" / "tier2_local_real_llm" / "fixtures" / "stub_run"
T = "2026-10-20T10:00:00Z"
# secrets are assembled at runtime so this file itself carries no raw secret-looking literal
SK = "s" + "k-" + "A1b2C3d4E5f6G7h8I9j0"
GHP = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
AKIA = "AK" + "IA" + "ABCDEFGH12345678"
EMAIL = "alice" + "@" + "corp-example.com"
AWFAKE = "AW" + "FAKE-DO-NOT-USE-" + "AB12CD34"
SECRET_VARIANTS = {
    "sk": SK, "github": GHP, "aws": AKIA, "email": EMAIL, "awfake": AWFAKE,
    "pct_email": EMAIL.replace("@", "%40"),
    "pct_pct_email": EMAIL.replace("@", "%2540"),
    "uescape_email": EMAIL.replace("@", "\\u0040"),
    "newline_split_sk": SK[:9] + "\\n" + SK[9:],
    "real_newline_split_sk": SK[:9] + "\n" + SK[9:],
}


@pytest.fixture(autouse=True)
def _no_default_salt_dir(monkeypatch):
    monkeypatch.delenv("BENCH_GENERATED_AT", raising=False)


def jl(path: Path, recs):
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")


def prov(**kw):
    p = {"schema": "agentwatch.bench.tier3.provenance/1", "tier": TIER3, "host_label": "edge-test", "isolated_edge_host": True,
         "servers": ["nginx", "gunicorn"], "pulled_at": T, "window_start": T, "window_end": "2026-10-21T10:00:00Z"}
    p.update(kw)
    return p


def access(ip, path, ua="Mozilla/5.0", status=200, **kw):
    return {"schema": "agentwatch.access/1", "timestamp": "2026-10-20T10:00:01Z", "client_ip": ip, "method": "GET", "path": path,
            "status": status, "user_agent": ua, **kw}


def lead(ip, kind="admin_backup", **kw):
    return {"schema": "agentwatch.lead/1", "event_type": "honeytoken_hit", "timestamp": "2026-10-20T10:00:02Z", "source_ip": ip,
            "priority": "high", "decoy": {"name": "d", "kind": kind}, "decoy_kind": kind, "request": {"method": "GET", "path": "/x"},
            "tags": ["decoy"], **kw}


def make_t3(root: Path, access_recs=None, lead_recs=None, with_prov=True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if with_prov:
        (root / "provenance.json").write_text(json.dumps(prov()))
    jl(root / "edge.access.jsonl", access_recs if access_recs is not None else [
        access("198.51.100.1", "/"), access("198.51.100.1", "/about"),
        access("203.0.113.9", "/wp-login.php", ua="zgrab/0.x"), access("203.0.113.9", "/.env", ua="zgrab/0.x"),
        access("192.0.2.5", "/robots.txt"), access("192.0.2.5", "/admin-backup/")])
    jl(root / "edge.leads.jsonl", lead_recs if lead_recs is not None else [lead("192.0.2.5", harness_archetype="mcp_tool_runner")])
    return root


def empty_slot(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".gitkeep").touch()
    return root


def build(tmp_path, *, t2=None, t3=None, name="out", **kw):
    kw.setdefault("generate", False)
    return build_bundle(tmp_path / name, aw_root=tmp_path / "no_aw", pipe_root=tmp_path / "no_pipe",
                        t2_slot=t2 or empty_slot(tmp_path / "t2slot"), t3_slot=t3 or empty_slot(tmp_path / "t3slot"),
                        generated_at="2026-10-23T00:00:00Z", **kw)


def inject_fixture():
    def mk(src, seeds=(0, 1, 2, 3, 4)):
        def gen():
            recs = [{"source": src, "kind": "ground_truth_label", "seed": s, "agent": f"a{s}", "label": "positive", "group": "g"} for s in seeds]
            return recs, {str(s): {"labels": 1} for s in seeds}
        return gen
    return {"agentwatch": mk("agent-watch/synthetic"), "pipeline": mk("rogue-ai-pipeline/simulator")}


# ------------------------------------------------------------------------------------------ import / schema sanity
def test_imports_and_schema_files_parse():
    import benchmark.packer, benchmark.secrets_guard, benchmark.tier1_synthetic_regression, benchmark.tier2_local_real_llm, benchmark.tier3_wild_honeypot  # noqa: F401
    for p in (ROOT / "benchmark").rglob("*.schema.json"):
        json.loads(p.read_text())
    assert validate({"a": 1}, {"type": "object", "required": ["b"]}) == ["$: missing required field 'b'"]


# ------------------------------------------------------------------------------------------ secret gate
@pytest.mark.parametrize("name", sorted(SECRET_VARIANTS))
def test_scan_text_detects_variants(name):
    assert scan_text("note: " + SECRET_VARIANTS[name] + " end"), name


def test_scan_text_clean_and_redacted_tokens_pass():
    assert scan_text("GET /about HTTP/1.1 [REDACTED_EMAIL_SHA256:0123456789] [REDACTED_OPENAI_ANTHROPIC_KEY_SHA256:abcdef0123] task done") == []


@pytest.mark.parametrize("name", sorted(SECRET_VARIANTS))
def test_build_rejects_unscrubbed_secret_in_tier3_jsonl(tmp_path, name):
    bad = access("192.0.2.5", "/search", note=SECRET_VARIANTS[name])
    slot = make_t3(tmp_path / "s", access_recs=[access("198.51.100.1", "/"), bad])
    out = tmp_path / "out"
    with pytest.raises(SecretsFound) as ei:
        build(tmp_path, t3=slot)
    assert SECRET_VARIANTS[name] not in str(ei.value)           # the message never echoes the secret
    assert not (out / "manifest.json").exists() and not any((out / t).exists() for t in TIERS)
    # the CLI maps it to exit code 3 and leaves nothing behind
    rc = build_benchmark.main(["--out", str(out), "--no-generate", "--tier3-input", str(slot), "--tier2-input", str(empty_slot(tmp_path / "e2")),
                               "--aw-root", str(tmp_path / "x"), "--pipeline-root", str(tmp_path / "y")])
    assert rc == 3 and not (out / "manifest.json").exists()


def test_build_rejects_secret_in_leads_jsonl_and_check_jsonl_cli(tmp_path):
    slot = make_t3(tmp_path / "s", lead_recs=[lead("192.0.2.5", detail={"q": EMAIL})])
    with pytest.raises(SecretsFound):
        build(tmp_path, t3=slot)
    assert build_benchmark.main(["--check-jsonl", str(slot / "edge.leads.jsonl")]) == 3
    assert build_benchmark.main(["--check-jsonl", str(slot / "edge.access.jsonl")]) == 0


def test_build_rejects_secret_in_tier2_run(tmp_path):
    t2 = tmp_path / "t2"
    shutil.copytree(STUB_RUN, t2 / "STUB-NOT-REAL-0001")
    with open(t2 / "STUB-NOT-REAL-0001" / "leads.jsonl", "a") as fh:
        fh.write(json.dumps(lead("127.0.0.1", detail={"k": SK})) .replace("lead/1", "lead/1") + "\n")
    with pytest.raises(SecretsFound):
        build(tmp_path, t2=t2, allow_stub=True)


def test_build_rejects_secret_in_extra_eval_json(tmp_path):
    p = tmp_path / "ev.json"
    p.write_text(json.dumps({"x": GHP}))
    with pytest.raises(SecretsFound):
        build(tmp_path, eval_jsons=[p])


def test_scrub_inputs_scrubs_then_verifies(tmp_path):
    slot = make_t3(tmp_path / "s", access_recs=[access("198.51.100.1", "/", note=EMAIL), access("192.0.2.5", "/x", note=AWFAKE)])
    m = build(tmp_path, t3=slot, scrub_inputs=True)
    data = (tmp_path / "out" / TIER3 / "data" / "edge.access.jsonl").read_text()
    assert EMAIL not in data and AWFAKE not in data and "REDACTED" in data
    assert m["tiers"][TIER3]["status"] == "populated_wild_data"
    assert not list((tmp_path).glob("out/.bench-stage-*"))


def test_bundle_scan_covers_everything_clean_bundle_passes(tmp_path):
    m = build(tmp_path, t3=make_t3(tmp_path / "s"))
    assert m["secret_scan"]["result"] == "clean"


# ------------------------------------------------------------------------------------------ tier separation / manifest
def _walk(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + (str(i),))
    else:
        yield path, obj


def test_manifest_separates_tiers_no_merged_number(tmp_path):
    ev = tmp_path / "ev.json"
    ev.write_text(json.dumps({"seeds": [0, 1, 2, 3, 4], "conditions": {"v4": {"metrics": {"recall": 0.5}}}}))
    m = build(tmp_path, t2=_t2_with_stub(tmp_path), t3=make_t3(tmp_path / "s"), allow_stub=True, eval_jsons=[ev], inject=inject_fixture())
    on_disk = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert on_disk == m
    assert set(m) == {"schema", "toolkit_version", "generated_at", "network_access", "tiers", "not_comparable", "secret_scan"}
    assert list(m["tiers"]) == list(TIERS)
    assert m["not_comparable"] == NOT_COMPARABLE_NOTE and "NOT COMPARABLE" in m["not_comparable"]
    banned = ("overall", "combined", "merged", "pooled", "aggregate_score", "grand", "mean_across", "unified", "all_tiers")
    for path, val in _walk(m):
        low = [p.lower() for p in path]
        assert not any(b in p for p in low for b in banned), path
        if isinstance(val, (int, float)) and not isinstance(val, bool) and path[0] == "tiers":
            assert path[1] in TIERS                        # every number lives under exactly one tier
    # metrics blocks are distinct objects per tier, and tier2's stub numbers are NOT in its real 'metrics'
    assert m["tiers"][TIER2]["metrics"] is None and m["tiers"][TIER2]["stub_selftest_metrics"]["kind"] == "stub_fixture"
    assert m["tiers"][TIER1]["same_author_synthetic"] is True
    assert m["tiers"][TIER2]["same_author_synthetic"] is False and m["tiers"][TIER3]["same_author_synthetic"] is False
    for t in TIERS:
        assert m["tiers"][t]["can_claim"] and m["tiers"][t]["cannot_claim"]
        assert all(f["path"].startswith(t + "/") for f in m["tiers"][t]["files"])      # files never cross tiers


def _t2_with_stub(tmp_path):
    t2 = tmp_path / "t2_stub"
    shutil.copytree(STUB_RUN, t2 / "STUB-NOT-REAL-0001")
    return t2


# ------------------------------------------------------------------------------------------ tier 1
def test_tier1_records_stamped_same_author_synthetic(tmp_path):
    aw, pipe = tmp_path / "aw", tmp_path / "pipe"
    (aw / "docs").mkdir(parents=True)
    (pipe / "sample_outputs").mkdir(parents=True)
    (aw / "docs" / "eval-v3.json").write_text(json.dumps({"C4": {"mimic_n": 12, "recall": 0.5}}))
    (pipe / "sample_outputs" / "evaluation.json").write_text(json.dumps({"disclaimer": "x", "levels": {"0.0": {"seeds": [0, 1, 2, 3, 4], "events_per_run": 9}}}))
    m = build_bundle(tmp_path / "out", aw_root=aw, pipe_root=pipe, t2_slot=empty_slot(tmp_path / "a"), t3_slot=empty_slot(tmp_path / "b"),
                     inject=inject_fixture(), generated_at="2026-10-23T00:00:00Z")
    t1 = tmp_path / "out" / TIER1
    recs = [json.loads(line) for line in (t1 / "records.jsonl").read_text().splitlines()]
    assert len(recs) == 10 and all(r["same_author_synthetic"] is True and r["tier"] == TIER1 for r in recs)
    assert sorted({r["seed"] for r in recs}) == [0, 1, 2, 3, 4]
    for f in (t1 / "eval_outputs").iterdir():
        assert json.loads(f.read_text())["same_author_synthetic"] is True
    blk = m["tiers"][TIER1]
    assert blk["sources"]["agent-watch/docs/eval-v3.json"]["seeds_declared"] is None and "seeds_note" in blk["sources"]["agent-watch/docs/eval-v3.json"]
    assert blk["sources"]["rogue-ai-pipeline/sample_outputs/evaluation.json"]["seeds_declared"] == [0, 1, 2, 3, 4]
    assert "SAME-AUTHOR" in (t1 / "README.md").read_text()


def test_tier1_generator_failure_is_reported_not_faked(tmp_path):
    def boom():
        raise ModuleNotFoundError("flask")
    m = build(tmp_path, generate=True, inject={"agentwatch": boom, "pipeline": inject_fixture()["pipeline"]})
    s = m["tiers"][TIER1]["sources"]
    assert s["generated/agent-watch"]["status"] == "skipped" and s["generated/rogue-ai-pipeline"]["status"] == "generated"


# ------------------------------------------------------------------------------------------ tier 2
def test_tier2_stub_fixture_validates_only_with_allow_stub():
    ok = validate_run_dir(STUB_RUN, allow_stub=True)
    assert ok.ok and ok.stub and ok.run_id.startswith("STUB-")
    rejected = validate_run_dir(STUB_RUN, allow_stub=False)
    assert not rejected.ok and any("STUB" in e for e in rejected.errors)
    assert "NOT REAL" in json.loads((STUB_RUN / "run.json").read_text())["provenance"]["notes"]


def _mutated_run(tmp_path, mutate_run=None, mutate_lines=None, name="STUB-NOT-REAL-0002"):
    d = tmp_path / name
    shutil.copytree(STUB_RUN, d)
    run = json.loads((d / "run.json").read_text())
    run["run_id"] = name
    if mutate_run:
        mutate_run(run)
    (d / "run.json").write_text(json.dumps(run))
    if mutate_lines:
        lines = [json.loads(x) for x in (d / "transcript.jsonl").read_text().splitlines()]
        jl(d / "transcript.jsonl", mutate_lines(lines))
    return d


def test_tier2_bad_records_fail(tmp_path):
    def run_without(key):
        return lambda r: r["capture"].pop(key)
    cases = {
        "missing capture.target": dict(mutate_run=run_without("target")),
        "non-loopback target": dict(mutate_run=lambda r: r["capture"].update(target="http://example.org:8098")),
        "stub claiming real": dict(mutate_run=lambda r: r["provenance"].update(real_capture=True)),
        "stub without STUB- id": dict(mutate_run=lambda r: r.update(run_id="run-0002")),
        "wrong schema id": dict(mutate_run=lambda r: r.update(schema="nope")),
        "path traversal file": dict(mutate_run=lambda r: r["files"].update(transcript="../x.jsonl")),
        "missing file": dict(mutate_run=lambda r: r["files"].update(leads="nothere.jsonl")),
        "non-loopback transcript url": dict(mutate_lines=lambda L: L + [{**L[0], "step": 9, "url": "http://93.184.216.34/"}]),
        "url with userinfo trick": dict(mutate_lines=lambda L: L + [{**L[0], "step": 9, "url": "http://127.0.0.1@evil.example/"}]),
        "missing status": dict(mutate_lines=lambda L: [{k: v for k, v in L[0].items() if k != "status"}] + L[1:]),
        "bad method": dict(mutate_lines=lambda L: [{**L[0], "method": "TELEPORT"}] + L[1:]),
        "steps go backwards": dict(mutate_lines=lambda L: list(reversed(L))),
        "empty transcript": dict(mutate_lines=lambda L: []),
    }
    for label, kw in cases.items():
        res = validate_run_dir(_mutated_run(tmp_path / label.replace(" ", "_"), **kw), allow_stub=True)
        assert not res.ok, label
    # real runs need explicit provenance
    real = _mutated_run(tmp_path / "real", name="run-real-1", mutate_run=lambda r: r["provenance"].update(stub=False, real_capture=True, operator_attests_loopback_only=False))
    assert not validate_run_dir(real, allow_stub=True).ok
    garbage = tmp_path / "garbage" / "STUB-NOT-REAL-0003"
    shutil.copytree(STUB_RUN, garbage)
    (garbage / "transcript.jsonl").write_text("not json\n")
    assert not validate_run_dir(garbage, allow_stub=True).ok


def test_tier2_scorer_and_never_mixes_stub_with_real():
    s = score_run(STUB_RUN)
    assert s["stub"] is True and s["steps"] == 4 and s["distinct_paths"] == 4
    assert s["leads"]["honeytoken_hits"] == 2 and s["leads"]["high_priority"] == 1
    agg = aggregate([s])
    assert agg["kind"] == "stub_fixture" and agg["by_prompt"]["aggressive_audit"]["runs_with_high_priority_lead"] == 1
    with pytest.raises(BenchmarkError):
        aggregate([s, {**s, "stub": False}])


def test_tier2_real_run_accepted_and_reported_as_real(tmp_path):
    t2 = tmp_path / "t2"
    _ = _mutated_run(t2, name="run-local-0001", mutate_run=lambda r: (r["provenance"].update(stub=False, real_capture=True, operator_attests_loopback_only=True, notes="ollama run"),
                                                                    r["capture"].update(model="local-test-model")))
    m = build(tmp_path, t2=t2)                                    # no allow_stub needed
    blk = m["tiers"][TIER2]
    assert blk["status"] == "populated_real_traces" and blk["n_real_runs"] == 1 and blk["metrics"]["kind"] == "real_local"
    assert blk["stub_selftest_metrics"] is None


def test_tier2_empty_slot_is_honest(tmp_path):
    m = build(tmp_path)
    assert m["tiers"][TIER2]["status"] == "empty_slot_no_real_traces" and m["tiers"][TIER2]["metrics"] is None
    assert "EMPTY" in (tmp_path / "out" / TIER2 / "README.md").read_text()
    # the shipped slot itself holds no runs
    assert [p.name for p in (ROOT / "benchmark" / TIER2 / "slot").iterdir() if not p.name.startswith(".")] == []


def test_tier2_stub_in_bundle_is_labelled_stub(tmp_path):
    slot = _t2_with_stub(tmp_path)
    m = build(tmp_path, t2=slot, allow_stub=True)
    assert m["tiers"][TIER2]["status"] == "stub_fixture_only_NOT_REAL_DATA" and m["tiers"][TIER2]["n_real_runs"] == 0
    assert "NOT real data" in (tmp_path / "out" / TIER2 / "README.md").read_text()
    with pytest.raises(BenchmarkError):                           # without --allow-stub the packer refuses it
        build(tmp_path, t2=slot, allow_stub=False, name="out2")


# ------------------------------------------------------------------------------------------ tier 3
def test_tier3_empty_slot_card(tmp_path):
    m = build(tmp_path)
    card = (tmp_path / "out" / TIER3 / "DATASET_CARD.md").read_text()
    assert "NO WILD DATA YET" in card and "no cohort counts" in card
    assert m["tiers"][TIER3]["status"] == "empty_slot_no_wild_data_yet" and m["tiers"][TIER3]["metrics"] is None
    assert not (tmp_path / "out" / TIER3 / "data").exists()
    assert "NO WILD DATA YET" in build_card(load_slot(tmp_path / "does-not-exist"), None)
    assert [p.name for p in (ROOT / "benchmark" / TIER3 / "slot").iterdir() if not p.name.startswith(".")] == []


def test_tier3_card_counts_filter_rules_and_archetypes(tmp_path):
    inp = load_slot(make_t3(tmp_path / "s"))
    assert inp.errors == []
    st = collect_stats(inp)
    assert st["records"] == {"access": 6, "leads": 1, "report_sessions": 0} and st["clients"] == 3
    assert st["cohorts"] == {"commodity_scanner_filtered": 1, "scanner_like_kept_goal_evidence": 0, "decoy_touching": 1, "passive_visitor": 1}
    assert st["scanner_filter"]["access_requests_removed"] == 2 and st["scanner_filter"]["by_reason"] == {"scanner_ua": 1}
    assert st["rule_firing"]["decoy_kinds"] == {"admin_backup": 1} and st["rule_firing"]["lead_event_types"] == {"honeytoken_hit": 1}
    assert st["harness_archetypes"]["field_present"] is True
    assert st["harness_archetypes"]["clients_by_archetype"] == {"mcp_tool_runner": 1, "unlabelled": 2}
    card = build_card(inp, st)
    assert "Cohorts" in card and "Commodity-scanner filter" in card and "Rule firing distributions" in card and "mcp_tool_runner" in card
    assert "198.51.100.1" not in card and "192.0.2.5" not in card            # client IPs are never printed


def test_tier3_missing_archetype_field_is_unlabelled(tmp_path):
    slot = make_t3(tmp_path / "s", lead_recs=[lead("192.0.2.5")])
    st = collect_stats(load_slot(slot))
    assert st["harness_archetypes"]["field_present"] is False
    assert st["harness_archetypes"]["clients_by_archetype"] == {"unlabelled": 3}
    m = build(tmp_path, t3=slot)
    card = (tmp_path / "out" / TIER3 / "DATASET_CARD.md").read_text()
    assert "unlabelled" in card and "No record or report carries" in card
    assert m["tiers"][TIER3]["status"] == "populated_wild_data"


def test_tier3_archetype_from_report_sessions_and_scanner_with_goal_evidence(tmp_path):
    slot = make_t3(tmp_path / "s", lead_recs=[lead("203.0.113.9", matches={"credential_token_ids": ["t1"], "canary_ids": []})])
    (slot / "x.report.json").write_text(json.dumps({"schema": "agentwatch.report/1", "sessions": [
        {"ip": "198.51.100.1", "harness_archetype": "browser_driver", "findings": [{"detector": "timing", "kind": "regular"}]}]}))
    st = collect_stats(load_slot(slot))
    assert st["cohorts"]["scanner_like_kept_goal_evidence"] == 1 and st["cohorts"]["commodity_scanner_filtered"] == 0
    assert st["harness_archetypes"]["clients_by_archetype"].get("browser_driver") == 1
    assert st["rule_firing"]["detector_findings_from_reports"] == {"timing:regular": 1}


def test_tier3_validator_rejects_bad_input(tmp_path):
    assert load_slot(make_t3(tmp_path / "a", with_prov=False)).errors                       # provenance required
    bad = make_t3(tmp_path / "b", access_recs=[{"schema": "agentwatch.access/1", "client_ip": "1.2.3.4"}])
    assert load_slot(bad).errors
    wrong = make_t3(tmp_path / "c", access_recs=[{**access("1.2.3.4", "/"), "schema": "other/9"}])
    assert load_slot(wrong).errors
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "provenance.json").write_text(json.dumps(prov(isolated_edge_host=False)))
    jl(tmp_path / "d" / "e.access.jsonl", [access("1.2.3.4", "/")])
    assert load_slot(tmp_path / "d").errors
    junk = make_t3(tmp_path / "e")
    (junk / "notes.txt").write_text("hi")
    assert load_slot(junk).errors
    with pytest.raises(BenchmarkError):
        build(tmp_path, t3=bad)
    # tolerant of nginx-style field aliases
    ng = make_t3(tmp_path / "f", access_recs=[{"time_iso8601": T, "remote_addr": "192.0.2.77", "request_method": "GET", "uri": "/", "status": 200}])
    assert load_slot(ng).errors == []


def test_cli_end_to_end_and_reproducible(tmp_path):
    args = ["--no-generate", "--tier2-input", str(empty_slot(tmp_path / "e2")), "--tier3-input", str(empty_slot(tmp_path / "e3")),
            "--aw-root", str(tmp_path / "x"), "--pipeline-root", str(tmp_path / "y"), "--generated-at", "2026-10-23T00:00:00Z"]
    assert build_benchmark.main(["--out", str(tmp_path / "o1"), *args]) == 0
    assert build_benchmark.main(["--out", str(tmp_path / "o2"), *args]) == 0
    assert (tmp_path / "o1" / "manifest.json").read_bytes() == (tmp_path / "o2" / "manifest.json").read_bytes()
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_benchmark.py"), "--help"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "never opens a network connection" in r.stdout
