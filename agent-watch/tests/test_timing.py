"""Time-to-Next-Action vs previous-response-size feature (a weak, evadable heuristic)."""
import json
import random

import pytest

from agentwatch.detectors import detect_timing_signature, spearman, ttna_pairs, ttna_stats
from agentwatch.scoring import extract_features, score_session
from helpers import CFG, UA, mk, sess


def llm_like(n=30, seed=1, ua="agent/1", noise=0.3):
    """Gap after each response grows with its size (bytes/4 tokens), kept inside 1.5-8s."""
    rng = random.Random(seed)
    reqs, t = [], 0.0
    for i in range(n):
        size = rng.randint(1000, 8000)
        reqs.append(mk(t, f"/api/v1/items/{rng.randint(1, 900)}", ua=ua, size=size))
        t += min(8.0, max(1.5, 1.0 + size / 4 / 300 + rng.gauss(0, noise)))
    return reqs


def test_spearman_basics():
    assert spearman([1, 2, 3, 4], [10, 20, 30, 40]) == pytest.approx(1.0)
    assert spearman([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    assert spearman([1, 1, 1, 1], [1, 2, 3, 4]) == 0.0           # constant input -> undefined -> 0
    assert spearman([1, 2], [1, 2]) == 0.0                         # too few points
    assert -1 <= spearman([1, 2, 2, 3, 5], [2, 1, 4, 4, 3]) <= 1   # ties handled


def test_pairs_use_previous_size_and_skip_idle_and_zero_size():
    reqs = [mk(0, "/a", size=1000), mk(2, "/b", size=0), mk(4, "/c", size=500), mk(200, "/d", size=500), mk(203, "/e", size=1)]
    pairs = ttna_pairs(sess(reqs), CFG)
    # (a->b gap 2, size 1000) kept; (b->c) dropped (size 0); (c->d) dropped (idle >60s); (d->e) kept
    assert [(g, s) for g, s, _ in pairs] == [(2.0, 1000), (3.0, 500)]


def test_too_few_pairs_gives_no_stats_and_no_finding():
    s = sess(llm_like(n=8))
    assert ttna_stats(s, CFG) is None and detect_timing_signature(s, CFG) == []
    assert extract_features(s, CFG)["ttna_pairs"] is None


def test_llm_like_timing_is_flagged_with_heuristic_label():
    f = detect_timing_signature(sess(llm_like()), CFG)
    assert len(f) == 1 and f[0].kind == "llm_like_ttna"
    assert f[0].data["spearman"] >= CFG["ttna"]["min_spearman"] and f[0].data["band_fraction"] >= 0.6
    r = score_session(sess(llm_like()), CFG)
    assert any("HEURISTIC" in x and "LLM-like timing" in x for x in r.reasons)


def test_negative_cases_not_flagged():
    rng = random.Random(4)
    fast = [mk(i * 0.3, "/api/x", size=rng.randint(1000, 8000)) for i in range(30)]
    independent = [mk(i * 4.0 + rng.uniform(0, 3), "/api/x", size=rng.randint(1000, 8000)) for i in range(30)]
    out_of_band = []
    t = 0.0
    for i in range(30):                                     # correlated but 20-50s gaps: outside the band
        size = rng.randint(1000, 8000)
        out_of_band.append(mk(t, "/api/x", size=size))
        t += 20 + size / 8000 * 30
    const_size = [mk(i * 3.0, "/api/x", size=4000) for i in range(30)]
    for reqs in (fast, independent, out_of_band, const_size):
        assert detect_timing_signature(sess(reqs), CFG) == []


def test_asset_loading_client_is_exempt_from_timing_flag():
    reqs = []
    for r in llm_like(ua=UA):
        reqs.append(r)
        reqs += [mk((r.ts - reqs[0].ts).total_seconds() + 0.1 * k, a, size=300) for k, a in enumerate(["/s/a.css", "/s/a.js", "/s/l.png"])]
    assert detect_timing_signature(sess(reqs), CFG) == []


def test_known_false_positive_api_only_human_reader_is_flagged():
    """KNOWN LIMITATION, asserted so it stays documented: a person reading JSON/API responses without a
    browser's asset loading has the same size->delay relationship and looks 'LLM-like' to this feature."""
    assert detect_timing_signature(sess(llm_like(ua="Mozilla/5.0 (human with a JSON viewer)")), CFG)


def test_timing_alone_cannot_label_an_agent():
    r = score_session(sess(llm_like()), CFG)
    assert any(f.detector == "timing" for f in r.findings)
    assert r.agent_score < CFG["thresholds"]["agent"] and r.label != "agent" and r.severity != "critical"
    assert CFG["weights"]["agent"]["llm_timing"] <= 10


def test_timing_thresholds_are_configurable():
    cfg = json.loads(json.dumps(CFG))
    cfg["ttna"]["min_spearman"] = 0.999
    assert detect_timing_signature(sess(llm_like(), cfg), cfg) == []
    cfg = json.loads(json.dumps(CFG))
    cfg["ttna"]["enabled"] = False
    assert detect_timing_signature(sess(llm_like(), cfg), cfg) == []
    assert extract_features(sess(llm_like(), cfg), cfg)["ttna_spearman"] is None
    cfg = json.loads(json.dumps(CFG))
    cfg["ttna"]["band_lo_s"], cfg["ttna"]["band_hi_s"] = 30.0, 60.0
    assert detect_timing_signature(sess(llm_like(), cfg), cfg) == []


def test_determined_agent_can_evade_by_randomising_delays():
    rng = random.Random(9)
    evader = [mk(i * 3.0 + rng.uniform(-1, 1), "/api/x", size=rng.randint(1000, 8000)) for i in range(30)]
    assert detect_timing_signature(sess(evader), CFG) == []
