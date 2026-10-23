"""Layer 3: bipartite coordination network, projection, clustering threshold and suppression logic."""
import random

import networkx as nx
import pytest

from rogue_pipeline.config import Config, Layer3Cfg, ResolvedPolicy
from rogue_pipeline.features import group_events
from rogue_pipeline.layer3_graph import CoordinationDetector

from conftest import normalize, raw

T = 1_770_000_000.0
SPAN = 6 * 3600.0
TEMPLATE = "relay {n} status green proceed to phase {p} confirm receipt"


class Pop:
    """Builds a background population of independent agents plus caller-supplied special agents."""

    def __init__(self, n_bg=30, seed=3):
        self.rng = random.Random(seed)
        self.evs = []
        self.i = 0
        for a in range(n_bg):
            for _ in range(60):
                self.add(f"bg{a}", self.rng.uniform(T, T + SPAN), "message", resource=f"bg{self.rng.randint(0, n_bg - 1)}",
                         text=" ".join("".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6)) for _ in range(8)))

    def add(self, agent, ts, action="message", **kw):
        self.i += 1
        kw.setdefault("dest_host", "api.corp.example")
        self.evs.append(raw(self.i, ts, agent, action, **kw))

    def detect(self, groups=None, cfg=None):
        cfg = cfg or Config().layer3
        n = normalize(self.evs)
        g = group_events(n)
        from conftest import Pseudonymizer, KEY
        p = Pseudonymizer(KEY)
        pol = ResolvedPolicy(groups={k: frozenset(p.agent(m) for m in v) for k, v in (groups or {}).items()})
        return CoordinationDetector(cfg, pol).detect(g), p


def add_ring(pop, members, rounds=25, sync=True, same_text=True):
    t = T + 3600
    for r in range(rounds):
        t += pop.rng.uniform(60, 200)
        for m in members:
            for tgt in pop.rng.sample([x for x in members if x != m], 2):
                when = t + (pop.rng.uniform(-2, 2) if sync else pop.rng.uniform(0, SPAN - 7200))
                text = TEMPLATE.format(n=pop.rng.randint(1, 99), p=pop.rng.randint(1, 9)) if same_text else \
                    " ".join("".join(pop.rng.choice("abcdefghijklmnop") for _ in range(6)) for _ in range(8))
                pop.add(m, when, resource=tgt, text=text)


def clusters_of(res, p, names):
    want = {p.agent(n) for n in names}
    return [c for c in res.clusters if set(c.members) & want]


def test_bipartite_graph_structure_and_projection_inputs():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"])
    n = normalize(pop.evs)
    det = CoordinationDetector(Config().layer3, ResolvedPolicy())
    gt, gc, span = det.build_graphs(group_events(n))
    for g in (gt, gc):
        assert nx.is_bipartite(g)
        agents = {x for x, d in g.nodes(data=True) if d["bipartite"] == 0}
        traces = {x for x, d in g.nodes(data=True) if d["bipartite"] == 1}
        assert agents and traces and all(isinstance(t, tuple) for t in traces)
        assert not any(g.has_edge(a, b) for a in agents for b in agents)
    assert span[1] > span[0]


def test_collusion_ring_is_clustered_with_timing_and_content_evidence():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"])
    res, p = pop.detect()
    cl = clusters_of(res, p, ["r1", "r2", "r3"])
    assert len(cl) == 1 and set(cl[0].members) == {p.agent(x) for x in ("r1", "r2", "r3")}
    assert not cl[0].suppressed and cl[0].score > 0.5 and cl[0].evidence_event_ids
    e = cl[0].edges[0]
    assert e.timing_nlp >= 8 and e.shared_windows >= 4 and e.content_cosine >= 0.5
    bg_only = [c for c in res.clusters if not (set(c.members) & {p.agent(x) for x in ("r1", "r2", "r3")})]
    assert bg_only == []                                       # no spurious clusters among independent agents


def test_timing_without_content_does_not_form_a_cluster():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"], same_text=False)
    res, p = pop.detect()
    assert clusters_of(res, p, ["r1", "r2", "r3"]) == []


def test_content_without_timing_does_not_form_a_cluster():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"], sync=False)
    res, p = pop.detect()
    assert clusters_of(res, p, ["r1", "r2", "r3"]) == []


def test_single_signal_cannot_cross_default_edge_threshold():
    c = Layer3Cfg()
    assert c.edge_threshold > max(c.weight_timing, c.weight_content)


def test_edge_threshold_is_configurable():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"])
    res, p = pop.detect(cfg=Config().layer3.model_copy(update={"edge_threshold": 1.01}))
    assert res.clusters == []


def add_cron(pop, members, period=600.0, jitter=1.0, template="nightly export job {n} finished rows {r} status ok"):
    for m in members:
        for k in range(int(SPAN // period)):
            pop.add(m, T + 100 + k * period + pop.rng.uniform(-jitter, jitter), resource="metrics-sink",
                    text=template.format(n=k, r=pop.rng.randint(100, 999)))


def test_known_schedule_allowlist_suppresses_declared_group():
    pop = Pop()
    members = ["c1", "c2", "c3"]
    add_cron(pop, members)
    res, p = pop.detect(groups={"schedule:nightly": members})
    cl = clusters_of(res, p, members)
    assert len(cl) == 1 and cl[0].suppressed
    assert any(r.startswith("declared_group:schedule:nightly") for r in cl[0].suppression_reasons)
    assert cl[0].score == 0.0 and res.active == []


def test_undeclared_strict_periodicity_is_suppressed_but_can_be_disabled():
    pop = Pop()
    members = ["c1", "c2", "c3"]
    add_cron(pop, members)
    res, p = pop.detect()
    cl = clusters_of(res, p, members)
    assert len(cl) == 1 and cl[0].suppressed and any(r.startswith("periodic") for r in cl[0].suppression_reasons)
    res2, p2 = pop.detect(cfg=Config().layer3.model_copy(update={"suppress_periodic": False, "suppress_fanout": False}))
    assert not clusters_of(res2, p2, members)[0].suppressed


def test_declared_orchestrator_pool_is_suppressed():
    pop = Pop()
    orch, workers = "orch", ["w1", "w2", "w3"]
    t = T + 1800
    for _ in range(40):
        t += pop.rng.uniform(60, 300)
        for w in workers:
            pop.add(orch, t + pop.rng.uniform(0, 0.4), resource=w, text=f"task {pop.rng.randint(1, 99)} assigned batch {pop.rng.randint(1, 9)} priority 2")
            pop.add(w, t + pop.rng.uniform(1, 3), resource=orch, text=f"task {pop.rng.randint(1, 99)} complete batch {pop.rng.randint(1, 9)} ok")
    res, p = pop.detect(groups={"orchestrator_pool:p1": [orch] + workers})
    cl = clusters_of(res, p, workers)
    assert cl and all(c.suppressed for c in cl)
    res2, p2 = pop.detect(cfg=Config().layer3.model_copy(update={"suppress_declared_groups": False, "suppress_fanout": False, "suppress_periodic": False}))
    assert any(not c.suppressed for c in clusters_of(res2, p2, workers))      # without the allowlist they WOULD be flagged


def test_identical_template_with_diverse_targets_is_suppressed_as_fanout():
    pop = Pop()
    bc = ["b1", "b2", "b3"]
    targets = [f"bg{i}" for i in range(30)]
    for _ in range(10):
        t = T + pop.rng.uniform(1800, SPAN - 1800)
        for b in bc:
            for k, tgt in enumerate(pop.rng.sample(targets, 25)):
                pop.add(b, t + pop.rng.uniform(-1, 1) + k * 0.3, resource=tgt,
                        text=f"maintenance notice service {pop.rng.randint(1, 9)} restarts at {pop.rng.randint(1, 24)} please save work")
    res, p = pop.detect()
    cl = clusters_of(res, p, bc)
    assert len(cl) == 1 and cl[0].suppressed and any(r.startswith("template_fanout") for r in cl[0].suppression_reasons)
    res2, p2 = pop.detect(cfg=Config().layer3.model_copy(update={"suppress_fanout": False}))
    assert not clusters_of(res2, p2, bc)[0].suppressed


def test_same_template_to_the_same_few_targets_is_not_fanout():
    """A ring talks to the same small set of peers: that must NOT be mistaken for broadcast fan-out."""
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"])
    res, p = pop.detect()
    assert not clusters_of(res, p, ["r1", "r2", "r3"])[0].suppressed


def test_agent_density_only_counts_unsuppressed_clusters():
    pop = Pop()
    add_ring(pop, ["r1", "r2", "r3"])
    add_cron(pop, ["c1", "c2", "c3"])
    res, p = pop.detect()
    dens = res.agent_density()
    assert set(dens) == {p.agent(x) for x in ("r1", "r2", "r3")}


def test_two_dense_groups_bridged_by_one_weak_edge_are_split_not_merged():
    g = nx.Graph()
    for grp in (["a1", "a2", "a3", "a4"], ["b1", "b2", "b3", "b4"]):
        g.add_weighted_edges_from((x, y, 1.0) for i, x in enumerate(grp) for y in grp[i + 1:])
    g.add_edge("a1", "b1", weight=0.6)
    det = CoordinationDetector(Config().layer3, ResolvedPolicy())
    parts = sorted(map(sorted, det.split_components(g)))
    assert parts == [["a1", "a2", "a3", "a4"], ["b1", "b2", "b3", "b4"]]
    dense = nx.complete_graph(["x1", "x2", "x3", "x4"])
    nx.set_edge_attributes(dense, 1.0, "weight")
    assert [sorted(c) for c in det.split_components(dense)] == [["x1", "x2", "x3", "x4"]]
