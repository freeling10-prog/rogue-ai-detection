"""Layer 1: features + Isolation Forest + explanations."""
import numpy as np
import pytest

from rogue_pipeline.config import Config, Layer1Cfg
from rogue_pipeline.features import FEATURE_NAMES, build_feature_table
from rogue_pipeline.layer1_anomaly import AnomalyScorer

from conftest import normalize, raw


def make_population(n_normal=30, seed=1):
    rng = np.random.default_rng(seed)
    evs, i = [], 0
    for a in range(n_normal):
        t = 1_770_000_000.0
        for _ in range(60):
            t += rng.uniform(40, 80)
            i += 1
            evs.append(raw(i, t, f"n{a}", "read", dest_host="api.corp.example",
                           status="denied" if rng.random() < 0.03 else "allowed"))
    # planted outlier: heavy denial on sensitive paths + lots of external traffic, fast and bursty
    t = 1_770_000_000.0
    for k in range(200):
        t += rng.uniform(0.5, 3) if k % 20 else 400
        i += 1
        evs.append(raw(i, t, "outlier", "access", status="denied" if rng.random() < 0.8 else "allowed",
                       resource=f"/secrets/k{k}", dest_host="x.example.net"))
    return normalize(evs)


def test_feature_values_on_handcrafted_agent():
    evs = normalize([raw(i, 1_770_000_000 + i * 60, "a", "read", status="denied" if i < 2 else "allowed",
                         resource="/admin/x" if i < 4 else "/docs/y", dest_host="e.example.net" if i % 2 else "api.corp.example")
                     for i in range(10)])
    t = build_feature_table(evs, min_events=8)
    f = t.row(t.agents[0])
    assert f["denied_to_allowed_ratio"] == pytest.approx(2 / 9)
    assert f["sensitive_hits"] == 4
    assert f["external_dest_ratio"] == pytest.approx(0.5)
    assert f["iet_cv"] == pytest.approx(0.0, abs=1e-6)         # perfectly regular
    assert 0 <= f["hour_entropy"] <= 1
    assert set(f) == set(FEATURE_NAMES) and len(FEATURE_NAMES) == 8


def test_new_tool_ratio_requires_baseline_and_detects_shift():
    evs = [raw(i, 1_770_000_000 + i * 60, "a", "tool_call", tool="search" if i < 30 else "upload") for i in range(60)]
    f = build_feature_table(normalize(evs)).row(build_feature_table(normalize(evs)).agents[0])
    assert f["new_tool_ratio"] == 1.0
    few = [raw(i, 1_770_000_000 + i * 60, "a", "tool_call", tool="upload") for i in range(9)]
    assert build_feature_table(normalize(few)).X[0, FEATURE_NAMES.index("new_tool_ratio")] == 0.0   # no baseline -> no claim


def test_isolation_forest_ranks_planted_outlier_first():
    table = build_feature_table(make_population())
    res = AnomalyScorer(Layer1Cfg()).score(table)
    inv_rank = sorted(res.agents.values(), key=lambda r: -r.score)
    assert len(res.agents) == 31
    assert res.agents[[a for a in table.agents if len(table.events_by_agent[a]) == 200][0]].flagged
    top = inv_rank[0]
    assert len(table.events_by_agent[top.agent]) == 200
    assert all(0.0 <= r.score <= 1.0 for r in res.agents.values())


def test_high_scores_carry_plain_language_explanations_with_baselines():
    table = build_feature_table(make_population())
    res = AnomalyScorer(Layer1Cfg()).score(table)
    flagged = [r for r in res.agents.values() if r.flagged]
    assert flagged
    for r in flagged:
        assert r.contributions, "every flagged agent needs explanations"
        for c in r.contributions:
            assert "versus a population median of" in c.text and "robust z" in c.text
    out = next(r for r in flagged if len(table.events_by_agent[r.agent]) == 200)
    named = {c.feature for c in out.contributions}
    assert named & {"denied_to_allowed_ratio", "sensitive_hits", "external_dest_ratio", "event_rate_per_min"}
    top = out.contributions[0]
    assert abs(top.robust_z) >= 2 and top.value != top.baseline_median


def test_unflagged_agents_have_no_explanations_and_scoring_is_deterministic():
    table = build_feature_table(make_population())
    a = AnomalyScorer(Layer1Cfg()).score(table)
    b = AnomalyScorer(Layer1Cfg()).score(table)
    assert {k: v.score for k, v in a.agents.items()} == {k: v.score for k, v in b.agents.items()}
    assert all(not r.contributions for r in a.agents.values() if not r.flagged)


def test_needs_a_population():
    table = build_feature_table(make_population(n_normal=4))
    with pytest.raises(ValueError):
        AnomalyScorer(Layer1Cfg()).score(table)


def test_layer1_config_validation():
    with pytest.raises(ValueError):
        Layer1Cfg(score_lo=0.7, score_hi=0.6)
