import numpy as np

from rogue_detect.detectors import (CoordinationDetector, IsolationForestDetector, normalize_template, run_rules)
from rogue_detect.features import FEATURE_NAMES, agent_features, extract_features, group_by_agent, novel_external_sequences
from rogue_detect.schema import Event


def ev(ts, a="a", kind="post", **kw):
    return Event(ts=ts, agent_id=a, kind=kind, synthetic=True, source="t", **kw)


def test_features_known_values():
    evs = [ev(0, kind="access", target="/admin/1", status="denied", in_scope=False),
           ev(10, kind="access", target="/docs/x"),
           ev(20, kind="message", target="b", text="hello"),
           ev(30, kind="tool_call", target="send", dest_external=True, payload_bytes=999)]
    f = agent_features(evs, 0, 60)
    assert f["n_events"] == 4 and abs(f["denied_ratio"] - 0.25) < 1e-9
    assert f["sensitive_hits"] == 1 and f["distinct_targets"] == 2
    assert abs(f["ext_dest_ratio"] - 0.25) < 1e-9 and f["distinct_recipients"] == 1
    assert abs(f["log_max_payload"] - np.log10(1000)) < 1e-9
    assert f["iet_cv"] == 0.0  # perfectly regular gaps


def test_extract_features_matrix_is_finite(dataset):
    ids, X, g, (t0, t1) = extract_features(dataset[0])
    assert X.shape == (len(ids), len(FEATURE_NAMES)) and np.isfinite(X).all() and t1 > t0


def test_isolation_forest_flags_planted_outlier():
    rng = np.random.default_rng(0)
    X = rng.normal(0, 1, size=(60, len(FEATURE_NAMES)))
    X[7] += 12
    ids = [f"a{i}" for i in range(60)]
    res = IsolationForestDetector(contamination=0.05).fit_score(ids, X)
    assert "a7" in res.flagged and res.scores["a7"] == max(res.scores.values())
    assert len(res.explanations["a7"]) == 3


def test_injection_sequence_requires_baseline_and_novelty():
    base = [ev(i * 120.0, kind="read", target=f"/d/{i}") for i in range(30)]
    t = 30 * 120.0
    seq = base + [ev(t, kind="read", target="http://x", ingest_external=True),
                  ev(t + 5, kind="tool_call", target="http_post", dest_external=True, payload_bytes=5000)]
    assert len(novel_external_sequences(seq)) == 1
    # same behavior but with no baseline (agent's very first events) is not flagged
    early = [ev(0, kind="read", target="http://x", ingest_external=True),
             ev(5, kind="tool_call", target="http_post", dest_external=True)]
    assert novel_external_sequences(early) == []
    # routine use of the tool beforehand -> not novel (documented evasion path)
    routine = base + [ev(100, kind="tool_call", target="http_post", dest_external=True)] + seq[-2:]
    routine.sort(key=lambda e: e.ts)
    assert novel_external_sequences(routine) == []


def test_rules_on_handcrafted_probe():
    evs = [ev(i, kind="access", target=f"/secrets/{i}", status="denied", in_scope=False) for i in range(15)]
    evs += [ev(100 + i, kind="access", target=f"/docs/{i}") for i in range(5)]
    g = {"a": sorted(evs, key=lambda e: e.ts)}
    hits = run_rules(g, {"a": {"encoded_ratio": 0.0}})
    assert [h.rule for h in hits] == ["access_probe"]


def test_normalize_template():
    assert normalize_template("Phase 12 ready http://x.y/z AAAAAAAAAAAAAAAAAAAAAAAAAAAA") == "phase # ready <url> <blob>"


def test_coordination_detects_synced_pair_and_ignores_independent():
    import random
    r = random.Random(1)
    by = {}
    bursts = [r.uniform(0, 20000) for _ in range(20)]
    for a in ("x", "y"):
        by[a] = sorted([ev(b + r.uniform(-1, 1), a=a, kind="message", target="y" if a == "x" else "x",
                           text=f"hold position {n}") for b in bursts for n in (1, 2, 3)], key=lambda e: e.ts)
    for i in range(6):
        a = f"n{i}"
        by[a] = sorted([ev(r.uniform(0, 20000), a=a, text=f"note {r.random()}") for _ in range(200)], key=lambda e: e.ts)
    res = CoordinationDetector().detect(by, 0, 20000)
    members = [set(c["members"]) for c in res.clusters]
    assert {"x", "y"} in members and all(not (m & {f"n{i}" for i in range(6)}) for m in members)
