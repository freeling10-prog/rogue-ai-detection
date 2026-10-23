"""Detectors: Isolation Forest, transparent rules, and a coordination/collusion graph."""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Sequence, Set, Tuple

import networkx as nx
import numpy as np
from scipy.stats import hypergeom
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .features import FEATURE_NAMES, novel_external_sequences
from .schema import Event

# ----------------------------------------------------------------------------- Isolation Forest


@dataclass
class IFResult:
    scores: Dict[str, float]          # higher = more anomalous (0..1 rank-free sklearn-derived score)
    flagged: Set[str]
    explanations: Dict[str, List[Tuple[str, float, float]]]  # agent -> [(feature, value, robust_z)]


class IsolationForestDetector:
    """Unsupervised per-agent anomaly scoring (Liu, Ting, Zhou, ICDM 2008).

    Features are robust-scaled; the forest is fit on the analysed window itself (transductive), which is
    why contamination is a documented operating assumption rather than a learned property."""

    def __init__(self, contamination: float = 0.12, n_estimators: int = 300, random_state: int = 0):
        self.contamination, self.n_estimators, self.random_state = contamination, n_estimators, random_state

    def fit_score(self, ids: Sequence[str], X: np.ndarray) -> IFResult:
        if len(ids) < 10:
            raise ValueError("need at least 10 agents to profile a population")
        Xs = RobustScaler().fit_transform(X)
        Xs = np.nan_to_num(Xs, nan=0.0, posinf=0.0, neginf=0.0)
        clf = IsolationForest(n_estimators=self.n_estimators, contamination=self.contamination,
                              random_state=self.random_state).fit(Xs)
        raw = -clf.score_samples(Xs)           # larger = more isolated
        pred = clf.predict(Xs)                  # -1 = outlier
        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0)
        mad = np.where(mad < 1e-9, np.maximum(X.std(axis=0), 1e-9), mad)
        expl: Dict[str, List[Tuple[str, float, float]]] = {}
        for i, a in enumerate(ids):
            z = (X[i] - med) / (1.4826 * mad)
            top = np.argsort(-np.abs(z))[:3]
            expl[a] = [(FEATURE_NAMES[j], float(X[i][j]), float(z[j])) for j in top]
        return IFResult({a: float(s) for a, s in zip(ids, raw)},
                        {a for a, p in zip(ids, pred) if p == -1}, expl)


# ----------------------------------------------------------------------------- Rules


@dataclass
class RuleHit:
    rule: str
    agent: str
    detail: Dict
    ts: float


DEFAULT_RULES = {
    "probe_min_denied": 10,
    "probe_min_denied_ratio": 0.25,
    "probe_min_sensitive": 5,
    "hidden_min_texts": 5,
    "hidden_min_encoded_ratio": 0.2,
}


def run_rules(by_agent: Dict[str, List[Event]], feats: Dict[str, Dict[str, float]], cfg=None) -> List[RuleHit]:
    """Transparent rules. Unauthorized access is defined by technical gates (denied / out-of-scope requests),
    not inferred intent, in line with the Van Buren 'gates' framing discussed in the report."""
    cfg = {**DEFAULT_RULES, **(cfg or {})}
    hits: List[RuleHit] = []
    for a, evs in by_agent.items():
        denied = [e for e in evs if e.status == "denied" and e.kind == "access"]
        n_acc = sum(e.kind == "access" for e in evs)
        sens = sum(1 for e in evs if e.kind == "access" and not e.in_scope and re.search(
            r"/(admin|secrets?|internal|credentials?|config)/|\.env\b", e.target, re.I))
        if (len(denied) >= cfg["probe_min_denied"] and n_acc and len(denied) / n_acc >= cfg["probe_min_denied_ratio"]
                and sens >= cfg["probe_min_sensitive"]):
            hits.append(RuleHit("access_probe", a, {
                "denied": len(denied), "access_events": n_acc, "sensitive_out_of_scope": sens,
                "first_ts": denied[0].ts, "last_ts": denied[-1].ts}, denied[-1].ts))
        seqs = novel_external_sequences(evs)
        if seqs:
            hits.append(RuleHit("injection_exfil", a, {
                "sequences": len(seqs), "tool": seqs[0][1].target,
                "max_payload_bytes": max(s[1].payload_bytes for s in seqs),
                "ingest_target": seqs[0][0].target}, seqs[-1][1].ts))
        texts = [e for e in evs if e.text and e.kind in ("message", "post")]
        f = feats.get(a, {})
        if len(texts) >= cfg["hidden_min_texts"] and f.get("encoded_ratio", 0) >= cfg["hidden_min_encoded_ratio"]:
            msgs = [e for e in texts if e.kind == "message"]
            hits.append(RuleHit("hidden_channel", a, {
                "encoded_ratio": round(f["encoded_ratio"], 3), "messages": len(msgs),
                "recipients": sorted({e.target for e in msgs})[:8]}, texts[-1].ts))
    return hits


# ----------------------------------------------------------------------------- Coordination graph

_NUM = re.compile(r"\d+")
_BLOBN = re.compile(r"[A-Za-z0-9+/=]{24,}")
_URL = re.compile(r"https?://\S+")


def normalize_template(text: str) -> str:
    t = _URL.sub("<url>", text.lower())
    t = _BLOBN.sub("<blob>", t)
    t = _NUM.sub("#", t)
    return " ".join(t.split())


@dataclass
class Edge:
    a: str
    b: str
    timing: float = 0.0   # -log10 p-value of surprising shared active time bins (0 if not significant)
    content: float = 0.0  # cosine similarity on rare message templates (0 if below threshold)
    graph: int = 0        # total messages exchanged if reciprocal and dense (0 otherwise)

    def evidence(self) -> List[str]:
        return [n for n, v in (("timing", self.timing), ("content", self.content), ("graph", self.graph)) if v]


@dataclass
class CoordResult:
    edges: List[Edge] = field(default_factory=list)
    clusters: List[Dict] = field(default_factory=list)       # >= 2 independent evidence types
    scheduled: List[Dict] = field(default_factory=list)      # timing-only, periodic (shared schedule)
    watchlist: List[Dict] = field(default_factory=list)      # single-signal clusters, not alerted


class CoordinationDetector:
    """Pairwise coordination evidence combined into clusters, following the 'surprising lack of independence'
    idea of Pacheco et al. (ICWSM 2021): agents are linked only when behaviour overlaps more than chance.

    Three independent signals per pair:
      timing  - hypergeometric test on shared active time bins (bin_s seconds wide)
      content - cosine similarity over RARE message templates (common boilerplate is ignored)
      graph   - dense, reciprocal direct messaging
    A cluster needs at least two different signal types. Timing-only clusters whose members are strictly
    periodic are reported as 'scheduled_sync' (info), because shared cron schedules are common and benign.
    """

    def __init__(self, bin_s: float = 15.0, p_thresh: float = 1e-8, min_shared_bins: int = 4,
                 content_thresh: float = 0.7, rare_df_frac: float = 0.15, min_shared_templates: int = 3,
                 graph_min_msgs: int = 6, graph_min_each_way: int = 2, periodic_cv: float = 0.15):
        self.bin_s, self.p_thresh, self.min_shared_bins = bin_s, p_thresh, min_shared_bins
        self.content_thresh, self.rare_df_frac, self.min_shared_templates = content_thresh, rare_df_frac, min_shared_templates
        self.graph_min_msgs, self.graph_min_each_way, self.periodic_cv = graph_min_msgs, graph_min_each_way, periodic_cv

    # --- signals
    def _timing(self, by_agent, t_min, t_max, agents):
        nb = max(int(math.ceil((t_max - t_min) / self.bin_s)), 1)
        bins = {a: {int((e.ts - t_min) // self.bin_s) for e in by_agent[a]} for a in agents}
        out = {}
        for a, b in combinations(agents, 2):
            k = len(bins[a] & bins[b])
            if k < self.min_shared_bins:
                continue
            p = hypergeom.sf(k - 1, nb, len(bins[a]), len(bins[b]))
            if p < self.p_thresh:
                out[(a, b)] = float(min(-math.log10(max(p, 1e-300)), 300.0))
        return out

    def _content(self, by_agent, agents):
        tmpl: Dict[str, Counter] = {}
        for a in agents:
            c = Counter(normalize_template(e.text) for e in by_agent[a] if e.text and e.kind in ("message", "post"))
            tmpl[a] = c
        df = Counter(t for c in tmpl.values() for t in c)
        max_df = max(2, int(self.rare_df_frac * len(agents)))
        rare = {t for t, d in df.items() if 2 <= d <= max_df}
        vec = {}
        for a in agents:
            v = {t: c for t, c in tmpl[a].items() if t in rare}
            vec[a] = (v, math.sqrt(sum(x * x for x in v.values())))
        out = {}
        for a, b in combinations(agents, 2):
            va, na = vec[a]
            vb, nb_ = vec[b]
            if not na or not nb_:
                continue
            shared = set(va) & set(vb)
            if not shared or sum(min(va[t], vb[t]) for t in shared) < self.min_shared_templates:
                continue
            cos = sum(va[t] * vb[t] for t in shared) / (na * nb_)
            if cos >= self.content_thresh:
                out[(a, b)] = float(cos)
        return out

    def _graph(self, by_agent, agents):
        cnt: Counter = Counter()
        aset = set(agents)
        for a in agents:
            for e in by_agent[a]:
                if e.kind == "message" and e.target in aset and e.target != a:
                    cnt[(a, e.target)] += 1
        out = {}
        for a, b in combinations(agents, 2):
            ab, ba = cnt[(a, b)], cnt[(b, a)]
            if ab + ba >= self.graph_min_msgs and min(ab, ba) >= self.graph_min_each_way:
                out[(a, b)] = ab + ba
        return out

    def _is_periodic(self, evs: List[Event]) -> bool:
        ts = np.array([e.ts for e in evs])
        if len(ts) < 6:
            return False
        g = np.diff(ts)
        return g.mean() > 0 and g.std() / g.mean() <= self.periodic_cv

    # --- main
    def detect(self, by_agent: Dict[str, List[Event]], t_min: float, t_max: float) -> CoordResult:
        agents = sorted(by_agent)
        timing = self._timing(by_agent, t_min, t_max, agents)
        content = self._content(by_agent, agents)
        graph = self._graph(by_agent, agents)
        pairs = set(timing) | set(content) | set(graph)
        edges = [Edge(a, b, timing.get((a, b), 0.0), content.get((a, b), 0.0), graph.get((a, b), 0)) for a, b in sorted(pairs)]
        res = CoordResult(edges=edges)

        def components(sel):
            g = nx.Graph()
            g.add_edges_from((e.a, e.b) for e in sel)
            return [sorted(c) for c in nx.connected_components(g) if len(c) >= 2]

        multi = [e for e in edges if len(e.evidence()) >= 2]
        for comp in components(multi):
            cs = set(comp)
            ev_edges = [e for e in edges if e.a in cs and e.b in cs]
            types = sorted({t for e in ev_edges for t in e.evidence()})
            last = max(ev.ts for a in comp for ev in by_agent[a])
            res.clusters.append({"members": comp, "evidence_types": types, "edges": len(ev_edges),
                                 "mean_timing_logp": float(np.mean([e.timing for e in ev_edges if e.timing] or [0])),
                                 "mean_content_cos": float(np.mean([e.content for e in ev_edges if e.content] or [0])),
                                 "messages": int(sum(e.graph for e in ev_edges)), "ts": last})
        in_cluster = {m for c in res.clusters for m in c["members"]}
        single = [e for e in edges if len(e.evidence()) == 1 and not (e.a in in_cluster and e.b in in_cluster)]
        for comp in components(single):
            cs = set(comp)
            ev_edges = [e for e in single if e.a in cs and e.b in cs]
            etype = ev_edges[0].evidence()[0]
            last = max(ev.ts for a in comp for ev in by_agent[a])
            if etype == "timing" and all(self._is_periodic(by_agent[a]) for a in comp):
                res.scheduled.append({"members": comp, "ts": last, "edges": len(ev_edges)})
            else:
                res.watchlist.append({"members": comp, "evidence_types": [etype], "ts": last})
        return res
