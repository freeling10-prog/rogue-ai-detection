"""Simulator, evaluation harness, STIX export, CLI, and the no-network guarantee."""
import json
import socket

import pytest

import run as cli
from rogue_pipeline.evaluation import Counts, aggregate, evaluate_once, format_markdown, run_evaluation, score_predictions
from rogue_pipeline.simulator import SCENARIOS, build
from rogue_pipeline.stix_export import build_bundle, validate_bundle


# ---- simulator ------------------------------------------------------------------------------------------
def test_simulator_is_deterministic_labeled_and_synthetic(sim):
    again = build(0, n_malformed=14)
    assert again.events == sim.events and again.labels == sim.labels
    assert all(e["synthetic"] is True for e in sim.events)
    groups = {g for _, g in sim.labels.values()}
    assert set(SCENARIOS) <= groups
    assert {"crawler", "cron_declared", "cron_undeclared", "orchestrator_pool", "broadcaster"} <= groups   # hard negatives
    assert len({e["event_id"] for e in sim.events}) == len(sim.events)


def test_simulator_only_uses_reserved_example_domains(sim):
    hosts = {e["dest_host"] for e in sim.events if e.get("dest_host")}
    assert all(h.endswith(".example") or ".example." in h or h.endswith(".example.net") or h.endswith(".example.org") for h in hosts), hosts


# ---- metrics --------------------------------------------------------------------------------------------
def test_metric_arithmetic():
    labels = {"p1": ("positive", "exfil"), "p2": ("positive", "exfil"), "p3": ("positive", "collusion_ring"),
              "b1": ("benign", "x"), "b2": ("benign", "x"), "b3": ("benign", "x"), "b4": ("benign", "x")}
    r = score_predictions({"p1", "p3", "b1"}, labels)
    assert (r["exfil"].tp, r["exfil"].fn, r["exfil"].fp, r["exfil"].tn) == (1, 1, 1, 3)
    assert r["exfil"].precision == 0.5 and r["exfil"].recall == 0.5 and r["exfil"].fpr == 0.25
    assert r["overall"].tp == 2 and r["overall"].fn == 1 and r["overall"].recall == pytest.approx(2 / 3)
    assert r["access_prober"].recall is None                    # no positives -> undefined, not 0 or 1
    assert Counts().precision is None


# ---- evaluation (regression checks on synthetic data) ---------------------------------------------------
@pytest.fixture(scope="module")
def evals():
    return {lv: evaluate_once(0, lv) for lv in (0.0, 1.0)}


def test_standard_run_detects_most_injected_scenarios_without_flagging_hard_negatives(evals):
    r = evals[0.0]
    fused = r.by_predictor["fused_leads"]
    assert fused["overall"].recall >= 0.8
    for sc in SCENARIOS:
        assert fused[sc].recall >= 0.5, sc
    assert fused["overall"].fpr <= 0.15
    for g in ("crawler", "cron_declared", "cron_undeclared", "orchestrator_pool", "broadcaster", "noisy_denied", "compliance_scanner", "assistant"):
        flagged, total = r.hard_negatives[g]
        assert flagged == 0, f"{g}: {flagged}/{total} produced a lead"
    assert r.guardrail_ok


def test_evasive_variants_lower_recall(evals):
    std, ev = evals[0.0].by_predictor["fused_leads"]["overall"], evals[1.0].by_predictor["fused_leads"]["overall"]
    assert ev.recall < std.recall - 0.3, (std.recall, ev.recall)


def test_ablation_isolation_forest_alone_is_weaker_and_suppression_matters(evals):
    p = evals[0.0].by_predictor
    assert p["isolation_forest_only"]["overall"].precision < p["fused_leads"]["overall"].precision
    assert p["graph_without_suppression"]["overall"].fpr > p["graph_only"]["overall"].fpr


def test_aggregate_and_markdown_render(evals):
    agg = aggregate([evals[0.0]])
    md = format_markdown({"levels": {"0.0": agg}})
    assert "precision" in md and "SYNTHETIC" in md and "collusion_ring" in md and "Hard negatives" in md


# ---- STIX -----------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def leads_json(pipeline_run):
    res, _ = pipeline_run
    return [l.to_dict() for l in res.leads]


def test_only_confirmed_leads_are_exported(leads_json):
    one = leads_json[0]["lead_id"]
    bundle = build_bundle(leads_json, [one])
    text = bundle.serialize()
    assert leads_json[0]["agent"] in text
    assert not any(l["agent"] in text for l in leads_json[1:] if l["agent"] != leads_json[0]["agent"])
    with pytest.raises(ValueError):
        build_bundle(leads_json, ["lead-doesnotexist"])


def test_stix_bundle_parses_and_passes_oasis_validator(leads_json):
    bundle = build_bundle(leads_json, [l["lead_id"] for l in leads_json])
    text = bundle.serialize(pretty=True)
    v = validate_bundle(text)
    assert v.parsed_ok, v.parse_error
    assert v.validator_available, "stix2-validator must be installed (see requirements.txt)"
    assert v.validator_ok, v.validator_messages
    types = {o["type"] for o in json.loads(text)["objects"]}
    assert {"identity", "indicator", "attack-pattern", "relationship", "note"} <= types
    for o in json.loads(text)["objects"]:
        if o["type"] == "attack-pattern":
            assert o["external_references"][0]["source_name"] == "mitre-atlas" and "approximate" in o["description"].lower()
        if o["type"] == "indicator":
            assert o["confidence"] <= 50 and "synthetic-data" in o["labels"]


def test_validator_has_teeth_negative_control(leads_json):
    text = build_bundle(leads_json, [leads_json[0]["lead_id"]]).serialize()
    bad = json.loads(text)
    next(o for o in bad["objects"] if o["type"] == "indicator")["confidence"] = 500
    v = validate_bundle(json.dumps(bad))
    assert v.validator_available and v.validator_ok is False
    assert not validate_bundle("{not json").parsed_ok


# ---- CLI ------------------------------------------------------------------------------------------------
def test_cli_missing_key_is_an_error_not_a_default(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ROGUE_PIPELINE_HMAC_KEY", raising=False)
    monkeypatch.delenv("PIPELINE_HMAC_SECRET", raising=False)
    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    assert cli.main(["demo", "--out", str(tmp_path)]) == 5
    assert "HMAC key not set" in capsys.readouterr().err


def test_cli_selftest_end_to_end(monkeypatch, capsys):
    monkeypatch.setenv("ROGUE_PIPELINE_HMAC_KEY", "cli-test-key-" + "k" * 24)
    assert cli.main(["selftest"]) == 0
    assert "SELFTEST".lower() in capsys.readouterr().out.lower()


def test_cli_verify_log_exit_codes_and_export_requires_confirmation(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ROGUE_PIPELINE_HMAC_KEY", "cli-test-key-" + "k" * 24)
    assert cli.main(["demo", "--out", str(tmp_path)]) == 0
    log = tmp_path / "audit.jsonl"
    assert cli.main(["verify-log", "--log", str(log)]) == 0
    assert cli.main(["export-stix", "--leads", str(tmp_path / "leads.json"), "--out", str(tmp_path / "b.json")]) == 1   # nothing confirmed
    lead_id = json.loads((tmp_path / "leads.json").read_text())[0]["lead_id"]
    assert cli.main(["export-stix", "--leads", str(tmp_path / "leads.json"), "--confirm", lead_id, "--out", str(tmp_path / "b.json")]) == 0
    lines = log.read_text().splitlines()
    lines[2] = lines[2].replace("lead", "leax", 1)
    log.write_text("\n".join(lines) + "\n")
    assert cli.main(["verify-log", "--log", str(log)]) == 2


def test_cli_generate_then_detect_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("ROGUE_PIPELINE_HMAC_KEY", "cli-test-key-" + "k" * 24)
    assert cli.main(["generate", "--out", str(tmp_path / "d"), "--malformed", "5"]) == 0
    assert cli.main(["detect", "--events", str(tmp_path / "d/events.jsonl"), "--policy", str(tmp_path / "d/policy.json"), "--out", str(tmp_path / "o")]) == 0
    leads = json.loads((tmp_path / "o/leads.json").read_text())
    assert leads and (tmp_path / "o/quarantine.jsonl").read_text().strip()


# ---- no network -----------------------------------------------------------------------------------------
def test_full_pipeline_and_evaluation_make_no_network_connections(monkeypatch, cfg):
    def deny(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    r = evaluate_once(1, 0.0, cfg)
    assert r.n_leads > 0
    with pytest.raises(AssertionError):                 # the guard itself works
        socket.create_connection(("203.0.113.1", 80))
