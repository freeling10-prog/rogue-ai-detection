import json
import random
from pathlib import Path

import pytest

from agentwatch.config import DEFAULTS, ConfigError, load_config
from agentwatch.scoring import (coefficient_of_variation, interval_entropy, intervals_seconds, score_session)
from helpers import CFG, UA, mk, sess

EDGES = CFG["timing"]["entropy_bin_edges_s"]


# ---- entropy / CV ------------------------------------------------------------------
def test_entropy_constant_intervals_is_zero():
    assert interval_entropy([2.0] * 30, EDGES) == 0.0


def test_entropy_spread_intervals_is_high():
    rng = random.Random(1)
    vals = [rng.lognormvariate(2, 1.2) for _ in range(300)]
    assert interval_entropy(vals, EDGES) > 0.6
    assert interval_entropy([], EDGES) == 0.0


def test_entropy_is_normalised_0_to_1():
    one_per_bin = [0.0, 0.1, 0.3, 0.7, 1.5, 3, 6, 12, 24, 48, 96, 200, 400]
    assert interval_entropy(one_per_bin, EDGES) == pytest.approx(1.0)


def test_cv():
    assert coefficient_of_variation([5, 5, 5, 5]) == 0
    assert coefficient_of_variation([0, 0, 0]) == 0
    assert coefficient_of_variation([1, 9, 1, 9]) == pytest.approx(0.8)
    assert intervals_seconds([mk(0), mk(3), mk(5)]) == [3.0, 2.0]


# ---- classification -------------------------------------------------------------------
def human_like(n=40, ip="192.0.2.50", seed=3):
    rng = random.Random(seed)
    out, t = [], 0.0
    for i in range(n):
        out.append(mk(t, f"/products/{rng.randint(1, 300)}", ip=ip, referer="https://x.invalid/"))
        for k, a in enumerate(["/s/app.css", "/s/app.js", "/s/logo.png"]):
            out.append(mk(t + 0.1 * (k + 1), a, ip=ip))
        t += rng.lognormvariate(2.0, 1.0) + 1.5
    return out


def test_human_label_with_explanations():
    r = score_session(sess(human_like()), CFG)
    assert r.label == "human" and r.severity == "info" and r.agent_score < 30
    assert any("static assets" in x for x in r.reasons)


def test_static_fixed_interval_bot():
    reqs = [mk(i * 5.0, "/api/v1/status.json", ua="curl/8.4.0") for i in range(30)]
    r = score_session(sess(reqs), CFG)
    assert r.label == "static_bot" and r.automation_score >= 80 and r.agent_score == 0
    assert any("fixed-interval" in x for x in r.reasons) and any("flat navigation" in x for x in r.reasons)
    assert r.severity == "low"


def test_goal_directed_agent():
    reqs, t, ui = [], 0.0, 0
    uas = ["python-httpx/0.27", "Mozilla/5.0 A", "Mozilla/5.0 B"]
    for c in range(6):
        for path, q in [("/api/v1/search", f"q=k{c}"), (f"/api/v1/items/{c}1", ""), (f"/api/v1/items/{c}2", ""),
                        ("/api/v1/export", "ids=1")]:
            t += 0.5
            blocked = c in (2, 4) and path == "/api/v1/export"
            reqs.append(mk(t, path, q, status=429 if blocked else 200, ua=uas[ui]))
            if blocked:
                ui += 1
                t += 1
                reqs.append(mk(t, path, q + f"&_={c}{int(t * 1000)}", ua=uas[ui]))
    r = score_session(sess(reqs), CFG)
    assert r.label == "agent" and r.agent_score >= CFG["thresholds"]["agent"]
    assert any("adapted after being blocked" in x for x in r.reasons)
    assert any("tool chain" in x for x in r.reasons)
    assert r.severity in ("high", "critical")


def test_honeytoken_canary_alone_is_agent_and_critical():
    r0 = mk(0, "/kb/page")
    r1 = mk(1, "/canary/abc")
    r1.source, r1.token_id, r1.decoy_kind = "honeypot", "cn-1", "canary_follow"
    r2 = mk(2, "/admin-backup/")
    res = score_session(sess([r0, r1, r2]), CFG)
    assert res.label == "agent" and res.severity == "critical" and len(res.honeytoken_hits) == 2


def test_single_decoy_hit_from_human_is_flagged_for_review_but_not_agent():
    # v3 change: this used to assert severity "high" for a lone passive-decoy hit; a lone robots-Disallow touch is contact,
    # not intent, so it is a "medium" lead for review and is classed as an accidental scraper / curious visitor
    reqs = human_like(10) + [mk(500, "/admin-backup/", ip="192.0.2.50")]
    res = score_session(sess(reqs), CFG)
    assert res.label == "human" and res.severity == "medium" and res.actor_type == "accidental_scraper"
    assert any("honeytoken" in x for x in res.reasons)


def test_short_sessions_report_insufficient_timing_data():
    r = score_session(sess([mk(0), mk(1)]), CFG)
    assert r.label == "human" and any("timing not scored" in x for x in r.reasons)


# ---- false-positive checks ------------------------------------------------------------
def test_busy_human_many_requests_stays_human():
    r = score_session(sess(human_like(n=150, seed=11)), CFG)
    assert r.label == "human" and r.agent_score < CFG["thresholds"]["medium"]


def test_search_engine_style_crawler_is_benign_static_bot():
    rng = random.Random(5)
    ua = "SynthBot-Search/2.1 (+http://localhost/synthbot)"
    reqs, t = [mk(0, "/robots.txt", ua=ua)], 0.0
    for _ in range(50):
        t += rng.uniform(2, 4)
        reqs.append(mk(t, f"/products/{rng.randint(1, 500)}", ua=ua))
    r = score_session(sess(reqs), CFG)
    assert r.label == "static_bot" and r.benign and r.severity == "info" and r.agent_score < 30


def test_monitoring_health_check_is_benign():
    reqs = [mk(i * 10.0, "/healthz", ua="SynthMonitor/1.0") for i in range(40)]
    r = score_session(sess(reqs), CFG)
    assert r.label == "static_bot" and r.benign and r.severity == "info"


def test_health_path_allowlist_without_known_ua():
    reqs = [mk(i * 10.0, "/health", ua="internal-lb/3") for i in range(40)]
    r = score_session(sess(reqs), CFG)
    assert r.benign and r.severity == "info"


def test_benign_allowlist_ignored_when_spoofed_ua_evades():
    ua = "Googlebot/2.1 (synthetic spoof)"
    reqs = [mk(i * 0.4, "/api/items", f"q=a&_={1700000000000 + i * 91}", ua=ua) for i in range(12)]
    reqs.append(mk(6, "/canary/xyz", ua=ua))
    r = score_session(sess(reqs), CFG)
    assert not r.benign and r.severity in ("high", "critical")


# ---- config ------------------------------------------------------------------------------
def test_threshold_file_matches_defaults():
    path = Path(__file__).resolve().parent.parent / "config" / "thresholds.json"
    assert json.loads(path.read_text()) == DEFAULTS


def test_config_override_changes_classification(tmp_path):
    cfg_file = tmp_path / "c.json"
    cfg_file.write_text(json.dumps({"thresholds": {"automation": 95}}))
    cfg = load_config(cfg_file)
    reqs = [mk(i * 5.0, "/api/v1/status.json", ua="curl/8.4.0") for i in range(30)]
    assert score_session(sess(reqs, cfg), cfg).label == "human"       # threshold raised above the score


def test_unknown_config_key_rejected(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"thresholds": {"agnet": 1}}))
    with pytest.raises(ConfigError):
        load_config(f)
    f.write_text("{not json")
    with pytest.raises(ConfigError):
        load_config(f)
