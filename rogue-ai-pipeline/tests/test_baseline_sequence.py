"""Frozen baseline (train once / save / load / score one session online), the Markov sequence model as a fusion gate,
and honest regression checks on the evasive and benign-mimicking variants (synthetic data, same author as the detectors)."""
import dataclasses
import json
import shutil

import numpy as np
import pytest

import run as cli
from rogue_pipeline.baseline import BaselineError, FrozenAnomalyScorer, load_baseline, save_baseline
from rogue_pipeline.config import Config, FusionCfg
from rogue_pipeline.features import group_events
from rogue_pipeline.fusion import fuse
from rogue_pipeline.layer1_anomaly import AgentAnomaly
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.sequence_model import SequenceResult

from conftest import KEY


def by_agent_of(res):
    return group_events(res.normalization.events)


# ---- baseline file: version, hash, round trip, tamper --------------------------------------------------
def test_save_load_roundtrip_gives_identical_scores_and_hash(ref_baseline, ext_run, tmp_path):
    res, _ = ext_run
    p = tmp_path / "b.npz"
    digest = save_baseline(ref_baseline, p)
    b2 = load_baseline(p, expect_sha256=digest)
    assert b2.content_sha256 == digest and b2.meta["baseline_version"] and b2.meta["n_reference_agents"] >= 30
    by = by_agent_of(res)
    s1 = FrozenAnomalyScorer(ref_baseline, Config()).score(by)
    s2 = FrozenAnomalyScorer(b2, Config()).score(by)
    assert {a: r.score for a, r in s1.agents.items()} == {a: r.score for a, r in s2.agents.items()}
    q1, q2 = ref_baseline.sequence.score_all(by), b2.sequence.score_all(by)
    assert {a: r.score for a, r in q1.items()} == {a: r.score for a, r in q2.items()}


def test_tampered_baseline_is_refused(ref_baseline, tmp_path):
    p = tmp_path / "b.npz"
    save_baseline(ref_baseline, p)
    raw_bytes = bytearray(p.read_bytes())
    raw_bytes[len(raw_bytes) // 2] ^= 0xFF
    bad = tmp_path / "bad.npz"
    bad.write_bytes(bytes(raw_bytes))
    with pytest.raises(BaselineError):
        load_baseline(bad)
    junk = tmp_path / "junk.npz"
    junk.write_bytes(b"not a baseline")
    with pytest.raises(BaselineError):
        load_baseline(junk)


def test_pinned_hash_mismatch_is_refused(ref_baseline, tmp_path):
    p = tmp_path / "b.npz"
    save_baseline(ref_baseline, p)
    with pytest.raises(BaselineError, match="pinned"):
        load_baseline(p, expect_sha256="0" * 64)


def test_baseline_pickle_free(ref_baseline, tmp_path):
    p = tmp_path / "b.npz"
    save_baseline(ref_baseline, p)
    with np.load(p, allow_pickle=False) as z:           # would raise if any array needed pickle
        assert "manifest" in z.files


# ---- online (single-session) scoring -------------------------------------------------------------------
def test_one_session_scores_the_same_alone_as_inside_a_population(ref_baseline, ext_run):
    res, _ = ext_run
    by = by_agent_of(res)
    scorer = FrozenAnomalyScorer(ref_baseline, Config())
    full = scorer.score(by).agents
    for a in list(full)[:15]:
        alone = scorer.score_agent(a, by[a])
        assert alone is not None and alone.score == full[a].score


def test_a_lone_session_runs_through_the_whole_pipeline_with_a_baseline(ext_sim, cfg, ref_baseline):
    one = [e for e in ext_sim.events if e["agent_id"] == "assistant-001"]
    assert len(one) >= 8
    res = Pipeline(cfg, ext_sim.policy, Pseudonymizer(KEY), baseline=ref_baseline).run(one)
    assert res.anomaly_frozen is not None and res.anomaly_frozen.agents          # scored with no population around it
    assert res.leads == [] or all(l.severity == "low" and l.recommended_action == "human_review" for l in res.leads)


def test_too_few_events_means_no_claim_not_a_guess(ref_baseline, cfg, ext_sim):
    few = [e for e in ext_sim.events if e["agent_id"] == "assistant-001"][:3]
    res = Pipeline(cfg, ext_sim.policy, Pseudonymizer(KEY), baseline=ref_baseline).run(few)
    assert res.anomaly_frozen.agents == {} and res.anomaly_frozen.insufficient
    assert res.sequence == {} and res.leads == []
    assert any("too few events" in n for n in res.notes)


def test_batch_mode_is_unchanged_without_a_baseline(ext_sim, cfg):
    res = Pipeline(cfg, ext_sim.policy, Pseudonymizer(KEY)).run(ext_sim.events)
    assert res.anomaly is not None and res.anomaly_frozen is None and res.sequence == {}
    assert any("sequence model not used" in n for n in res.notes)


# ---- sequence model ------------------------------------------------------------------------------------
def test_sequence_scores_are_timing_independent(ref_baseline, ext_run):
    res, _ = ext_run
    by = by_agent_of(res)
    a = next(a for a, evs in by.items() if len(evs) > 30)
    t0 = by[a][0].ts
    stretched = [dataclasses.replace(e, ts=t0 + (e.ts - t0) * 37.0 + 5.0) for e in by[a]]
    s1 = ref_baseline.sequence.score_agent(a, by[a])
    s2 = ref_baseline.sequence.score_agent(a, stretched)
    assert s1 is not None and s2 is not None and s1.score == s2.score and s1.worst_window_bits == s2.worst_window_bits


def test_sequence_none_when_too_short(ref_baseline, ext_run):
    res, _ = ext_run
    a, evs = next(iter(by_agent_of(res).items()))
    assert ref_baseline.sequence.score_agent(a, evs[:2]) is None


def test_sequence_model_separates_benign_from_odd_ordering(ref_baseline, ext_run, ext_sim):
    res, inv = ext_run
    gate = Config().sequence.gate
    benign = [r.score for a, r in res.sequence.items() if ext_sim.labels[inv[a]][0] == "benign"]
    pos = [r.score for a, r in res.sequence.items() if ext_sim.labels[inv[a]][0] == "positive"]
    assert benign and pos
    assert np.median(benign) < gate                        # typical benign sessions sit below the gate
    assert np.mean([s >= gate for s in pos]) > np.mean([s >= gate for s in benign])
    # a reversed benign session is ordering-odd although every individual action is ordinary
    by = by_agent_of(res)
    a = next(a for a, evs in by.items() if len(evs) > 30 and a in res.sequence and res.sequence[a].score < gate)
    ts = sorted(e.ts for e in by[a])
    rev = [dataclasses.replace(e, ts=t) for e, t in zip(reversed(sorted(by[a], key=lambda e: e.ts)), ts)]
    assert ref_baseline.sequence.score_agent(a, rev).worst_window_bits >= res.sequence[a].worst_window_bits


# ---- fusion guardrails ---------------------------------------------------------------------------------
def test_neither_anomaly_nor_sequence_alone_can_create_a_lead():
    f = FusionCfg()
    anom = {"x": AgentAnomaly("x", 0.9, 1.0, True)}
    seq = {"x": SequenceResult("x", 1.0, 9.0, 4.0, 40)}
    assert fuse(f, anom, [], [], "t") == []
    assert fuse(f, {}, [], [], "t", seq, 0.6) == []
    with pytest.raises(ValueError, match="w_sequence"):
        FusionCfg(w_sequence=0.6)
    with pytest.raises(ValueError, match="w_anomaly"):
        FusionCfg(w_anomaly=0.6)


def test_below_gate_sequence_score_is_ignored():
    seq = {"x": SequenceResult("x", 0.59, 3.0, 2.0, 40)}
    assert fuse(FusionCfg(), {}, [], [], "t", seq, 0.6) == []


def test_two_unsupervised_signals_together_can_raise_a_low_severity_lead_only():
    """Documented design choice: IF + sequence both at maximum clear the threshold, and the lead is still low severity/human review."""
    anom = {"x": AgentAnomaly("x", 0.9, 1.0, True)}
    seq = {"x": SequenceResult("x", 1.0, 9.0, 4.0, 40)}
    leads = fuse(FusionCfg(), anom, [], [], "t", seq, 0.6)
    assert len(leads) == 1 and leads[0].severity == "low" and leads[0].automatic_action == "none"
    assert leads[0].components["sequence"] == 1.0 and leads[0].sequence["score"] == 1.0


# ---- evaluation: evasive, mimic, unseen benign (honest regression checks) ---------------------------------
@pytest.fixture(scope="module")
def ev_ctx():
    from rogue_pipeline.evaluation import make_context
    return make_context()


@pytest.fixture(scope="module")
def ev_runs(ev_ctx):
    from rogue_pipeline.evaluation import evaluate_once
    return {lvl: evaluate_once(0, lvl, ctx=ev_ctx) for lvl in (0.0, 1.0)}


def test_evaluation_is_deterministic(ev_ctx, ev_runs):
    from rogue_pipeline.evaluation import evaluate_once
    again = evaluate_once(0, 1.0, ctx=ev_ctx)
    for k, v in ev_runs[1.0].by_predictor.items():
        assert {g: (c.tp, c.fp, c.fn, c.tn) for g, c in v.items()} == {g: (c.tp, c.fp, c.fn, c.tn) for g, c in again.by_predictor[k].items()}


def test_guardrails_hold_in_every_evaluation_run(ev_runs):
    assert all(r.guardrail_ok for r in ev_runs.values())


def test_sequence_gate_does_not_lose_recall_and_its_false_positives_are_reported(ev_runs):
    r = ev_runs[1.0].by_predictor
    with_seq, without = r["fused_leads"]["overall_core"], r["fused_frozen_no_sequence"]["overall_core"]
    assert with_seq.tp >= without.tp                                   # the gate only adds evidence
    assert with_seq.fp >= 0                                            # (value reported in the README table, not asserted to be zero)
    assert with_seq.fp <= without.fp + 5                               # but must not explode


def test_the_mimic_variant_still_evades_and_that_is_documented(ev_runs):
    mimic = ev_runs[0.0].by_predictor["fused_leads"].get("seq_mimic")
    seq_only = ev_runs[0.0].by_predictor["sequence_only"].get("seq_mimic")
    assert mimic is not None and seq_only is not None
    # the mimic replays benign transition statistics: the sequence model must NOT catch it (documented limitation)
    assert seq_only.tp <= max(1, (seq_only.tp + seq_only.fn) // 2)


def test_unseen_benign_behaviour_costs_false_positives(ev_runs):
    hn = ev_runs[0.0].hard_negatives
    seen = sum(f for k, (f, n) in hn.items() if k.endswith("|fused_frozen_no_sequence"))
    held = sum(f for k, (f, n) in hn.items() if k.endswith("|fused_holdout_baseline"))
    assert held >= seen                                                # a baseline missing whole benign groups is never better


# ---- CLI -----------------------------------------------------------------------------------------------
def test_cli_train_inspect_and_detect_with_baseline(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ROGUE_PIPELINE_HMAC_KEY", "cli-test-key-" + "k" * 24)
    b = tmp_path / "b.npz"
    assert cli.main(["train-baseline", "--simulate-reference", "--reference-sets", "1", "--baseline-out", str(b), "--out", str(tmp_path)]) == 0
    digest = [ln for ln in capsys.readouterr().out.splitlines() if "sha256=" in ln][0].split("sha256=")[1].strip()
    assert cli.main(["inspect-baseline", "--baseline", str(b), "--expect-sha256", digest]) == 0
    assert cli.main(["inspect-baseline", "--baseline", str(b), "--expect-sha256", "f" * 64]) == 7
    assert cli.main(["generate", "--out", str(tmp_path / "d"), "--seed", "3"]) == 0
    out = tmp_path / "o"
    assert cli.main(["detect", "--events", str(tmp_path / "d/events.jsonl"), "--policy", str(tmp_path / "d/policy.json"),
                     "--baseline", str(b), "--expect-baseline-sha256", digest, "--out", str(out)]) == 0
    leads = json.loads((out / "leads.json").read_text())
    assert leads and all(l["severity"] == "low" and l["automatic_action"] == "none" for l in leads)
    assert any("sequence" in l["components"] for l in leads)
    shutil.copy(b, tmp_path / "t.npz")
    data = bytearray((tmp_path / "t.npz").read_bytes()); data[100] ^= 0xFF
    (tmp_path / "t.npz").write_bytes(bytes(data))
    assert cli.main(["detect", "--events", str(tmp_path / "d/events.jsonl"), "--baseline", str(tmp_path / "t.npz"), "--out", str(tmp_path / "o2")]) == 7
    assert not (tmp_path / "o2" / "leads.json").exists()
