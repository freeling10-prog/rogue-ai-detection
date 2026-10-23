"""Layer 3: coordination network (Pacheco-inspired) with suppression of known-benign look-alikes.

Method (after Pacheco et al., "Uncovering Coordinated Networks on Social Media", ICWSM 2021):

1. Build a bipartite graph  agent -- trace , once for TIMING traces (time windows in which the agent acted) and
   once for CONTENT traces (keyed hashes of normalized word shingles). Shingles shared by more than
   ``max_df_frac`` of agents are dropped as "popular" (boilerplate), as the paper prunes popular traces.
2. Project onto agents. Timing similarity of two agents is the hypergeometric surprise (-log10 p) of how many
   windows they share given how active each is. Content similarity is the IDF-weighted cosine of their rare
   shingle sets.
3. Edge weight = w_timing * timing_strength + w_content * content_strength. The default edge threshold (0.55) is
   ABOVE either single-signal maximum (0.5), so an edge requires BOTH timing and content agreement.
4. Connected components of the thresholded graph are candidate clusters; cluster density = mean edge weight
   x edge density.
5. Suppression - a candidate cluster is marked ``suppressed`` (kept for audit, never scored) when:
   * ``declared_group``  every member belongs to one declared schedule / orchestrator pool (Policy);
   * ``periodic``        every member has strictly periodic activity (suspected undeclared schedule);
   * ``template_fanout`` the shared content is one template sent to many DIVERSE targets (broadcast-style).

6. Semantic-state ("session stitching") edges. Events may carry tokens returned to the agent in a response
   (``response_tokens``) and a token the agent presented (``request_token``), both keyed-hashed. If agent B presents a
   token that was only ever issued to agent A, B and A share semantic state - even when they come from different IPs
   or session ids (proxy rotation). Two strengths:
   * graded: n distinct handed-over tokens give strength min(1, n / ``min_state_tokens``); it adds ``weight_state`` x
     strength to the edge weight "in addition to" timing and content (three tokens alone can cross the threshold,
     fewer need support from the other signals);
   * deterministic ``cross_ip_token_handoff``: the issuing event is flagged by the collector as a honeypot
     ``handoff_token`` / ``verification_nonce`` / ``claim_shard`` (unique per issuance, meaningless to anyone who
     was not given it), and the presenting event comes from a different IP than the issuance. ONE such token gives a
     weight-1.0 edge. Clusters containing such an edge are exempt from the suppression logic above, unless every
     such token was held by a declared orchestrator.
   Clusters with state edges are connectivity-scored (a proxy-rotation chain is a path, not a clique) and are not
   split into communities.

An attacker who spreads activity in time, varies wording, imitates a schedule, or never reuses honeypot-issued
state will evade this layer.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

import networkx as nx
import numpy as np
from networkx.algorithms import bipartite
from scipy import sparse
from scipy.stats import hypergeom

from .config import Layer3Cfg, ResolvedPolicy
from .schema import NormalizedEvent

LN10 = math.log(10.0)


CROSS_IP = "cross_ip_token_handoff"
SEMANTIC = "semantic_state"
REDACTED = "shared_redacted_token"
TIMING_CONTENT = "timing_content"
DETERMINISTIC_CLASSES = frozenset({"handoff_token", "verification_nonce", "claim_shard"})
CLUSTER_ATLAS = [{"id": "AML.T0051", "name": "LLM Prompt Injection", "url": "https://atlas.mitre.org/techniques/AML.T0051"}]


@dataclass
class EdgeInfo:
    a: str
    b: str
    timing_nlp: float
    shared_windows: int
    timing_strength: float
    content_cosine: float
    weight: float
    kind: str = TIMING_CONTENT
    state_tokens: int = 0
    state_strength: float = 0.0
    holder: Optional[str] = None            # agent that was ISSUED the handed-over token(s) (deterministic edges)
    token_class: Optional[str] = None
    holder_ip: Optional[str] = None
    presenter_ip: Optional[str] = None
    issue_event_ids: List[str] = field(default_factory=list)
    present_event_ids: List[str] = field(default_factory=list)

    def reason(self) -> str:
        """Plain-language explanation (pseudonyms only)."""
        if self.kind == CROSS_IP:
            other = self.b if self.holder == self.a else self.a
            return (f"Session {self.holder} was issued a {self.token_class} on IP {self.holder_ip}; session {other} presented "
                    f"that exact token from a different IP {self.presenter_ip}. The token was never issued to anyone else, so "
                    f"these sessions share state (deterministic cross-IP handoff, {self.state_tokens} token(s)).")
        if self.kind == REDACTED:
            return (f"{self.a} and {self.b} both presented {self.state_tokens} identical redacted secret marker(s). The markers "
                    f"are opaque hashes (never un-redacted): the same secret appeared in both sessions. Moderate confidence - "
                    f"a secret can be shared, leaked or copied (edge weight {self.weight:.2f}).")
        parts = []
        if self.state_tokens:
            parts.append(f"{self.state_tokens} token(s) issued only to one session were presented by the other")
        if self.timing_strength:
            parts.append(f"{self.shared_windows} shared activity windows (surprise -log10 p = {self.timing_nlp:.0f})")
        if self.content_cosine:
            parts.append(f"content similarity {self.content_cosine:.2f}")
        return f"{self.a} and {self.b}: " + "; ".join(parts) + f" (edge weight {self.weight:.2f})"


@dataclass
class Cluster:
    members: List[str]
    density: float
    mean_weight: float
    edges: List[EdgeInfo]
    suppressed: bool = False
    suppression_reasons: List[str] = field(default_factory=list)
    evidence_event_ids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)       # plain-language reasons for the cluster

    @property
    def kinds(self) -> List[str]:
        return sorted({e.kind for e in self.edges})

    @property
    def atlas(self) -> List[Dict[str, str]]:
        """Approximate ATLAS tag: deterministic honeypot-token handoff means agents acted on decoy instructions."""
        return CLUSTER_ATLAS if any(e.kind == CROSS_IP for e in self.edges) else []

    @property
    def score(self) -> float:
        return 0.0 if self.suppressed else self.density


@dataclass
class GraphResult:
    clusters: List[Cluster]
    n_agents: int
    n_timing_edges: int
    n_content_edges: int
    n_edges: int
    n_state_edges: int = 0

    @property
    def active(self) -> List[Cluster]:
        return [c for c in self.clusters if not c.suppressed]

    def agent_density(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for c in self.active:
            for m in c.members:
                out[m] = max(out.get(m, 0.0), c.density)
        return out


def _cv(ts: Sequence[float]) -> float:
    g = np.diff(np.sort(np.asarray(ts)))
    return float(g.std() / g.mean()) if len(g) >= 2 and g.mean() > 0 else float("inf")


class CoordinationDetector:
    def __init__(self, cfg: Layer3Cfg, policy: ResolvedPolicy) -> None:
        self.cfg = cfg
        self.policy = policy

    # -- bipartite graphs ----------------------------------------------------------------------------
    def _bipartite(self, trace_of: Dict[str, Set], kind: str) -> Tuple[nx.Graph, List[str], List]:
        g = nx.Graph()
        agents = sorted(trace_of)
        g.add_nodes_from(agents, bipartite=0)
        traces = sorted({t for s in trace_of.values() for t in s})
        g.add_nodes_from(((kind, t) for t in traces), bipartite=1)
        for a, ts in trace_of.items():
            g.add_edges_from((a, (kind, t)) for t in ts)
        return g, agents, [(kind, t) for t in traces]

    def build_graphs(self, by_agent: Dict[str, List[NormalizedEvent]]) -> Tuple[nx.Graph, nx.Graph, Tuple[float, float]]:
        c = self.cfg
        elig = {a: v for a, v in by_agent.items() if len(v) >= c.min_events}
        t0 = min(e.ts for v in elig.values() for e in v)
        t1 = max(e.ts for v in elig.values() for e in v)
        win = {a: {int(e.ts // c.window_s) for e in v} for a, v in elig.items()}
        shin = {a: set().union(*[e.shingles for e in v]) if v else set() for a, v in elig.items()}
        # prune popular shingles (appear in > max_df_frac of agents)
        df: Dict[int, int] = defaultdict(int)
        for s in shin.values():
            for x in s:
                df[x] += 1
        limit = max(2, c.max_df_frac * len(elig))
        shin = {a: {x for x in s if df[x] <= limit} for a, s in shin.items()}
        gt, _, _ = self._bipartite(win, "w")
        gc, _, _ = self._bipartite(shin, "s")
        return gt, gc, (t0, t1)

    # -- projections ---------------------------------------------------------------------------------
    def _timing_edges(self, gt: nx.Graph, span: Tuple[float, float]) -> Dict[Tuple[str, str], Tuple[float, int, float]]:
        c = self.cfg
        agents = sorted(n for n, d in gt.nodes(data=True) if d["bipartite"] == 0)
        traces = sorted((n for n, d in gt.nodes(data=True) if d["bipartite"] == 1), key=str)
        if not agents or not traces:
            return {}
        A = bipartite.biadjacency_matrix(gt, row_order=agents, column_order=traces, format="csr")
        shared = (A @ A.T).tocoo()
        n_windows = max(int((span[1] - span[0]) // c.window_s) + 1, 2)
        size = np.asarray(A.sum(axis=1)).ravel()
        out: Dict[Tuple[str, str], Tuple[float, int, float]] = {}
        for i, j, k in zip(shared.row, shared.col, shared.data):
            if i >= j or k < c.min_shared_windows:
                continue
            # P(X >= k) where X ~ Hypergeom(population=n_windows, successes=|Wi|, draws=|Wj|)
            logp = hypergeom.logsf(k - 1, n_windows, int(size[i]), int(size[j]))
            nlp = float(min(-logp / LN10, 1e4)) if np.isfinite(logp) else 1e4
            strength = 0.0 if nlp < c.min_neg_log10_p else min(1.0, nlp / c.timing_cap)
            out[(agents[i], agents[j])] = (nlp, int(k), strength)
        return out

    def _content_edges(self, gc: nx.Graph) -> Dict[Tuple[str, str], float]:
        c = self.cfg
        agents = sorted(n for n, d in gc.nodes(data=True) if d["bipartite"] == 0)
        traces = sorted((n for n, d in gc.nodes(data=True) if d["bipartite"] == 1), key=str)
        if not agents or not traces:
            return {}
        A = bipartite.biadjacency_matrix(gc, row_order=agents, column_order=traces, format="csr").astype(float)
        df = np.asarray(A.sum(axis=0)).ravel()
        idf = np.log((len(agents) + 1.0) / (df + 1.0)) + 1.0
        W = A @ sparse.diags(idf)
        norms = np.sqrt(np.asarray(W.multiply(W).sum(axis=1)).ravel())
        norms[norms == 0] = 1.0
        S = (W @ W.T).tocoo()
        out: Dict[Tuple[str, str], float] = {}
        for i, j, v in zip(S.row, S.col, S.data):
            if i >= j:
                continue
            cos = float(v / (norms[i] * norms[j]))
            if cos >= c.min_cosine:
                out[(agents[i], agents[j])] = cos
        return out

    # -- semantic state (token handoff) --------------------------------------------------------------
    def token_links(self, by_all: Dict[str, List[NormalizedEvent]]) -> Dict[Tuple[str, str], List[dict]]:
        """Handoffs of tokens that were issued to exactly ONE agent and later presented by a different agent.

        Returns {sorted agent pair: [link, ...]}; each link carries the holder, token, issuing/presenting events and
        IPs. Tokens issued to several agents (public/shared state) are ignored: they prove nothing."""
        issued: Dict[str, Dict[str, NormalizedEvent]] = defaultdict(dict)   # token -> agent -> first issuing event
        for evs in by_all.values():
            for e in evs:
                for t in e.issued:
                    if e.agent not in issued[t] or e.ts < issued[t][e.agent].ts:
                        issued[t][e.agent] = e
        links: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        seen: Set[Tuple[str, str, str]] = set()
        for evs in by_all.values():
            for e in evs:
                t = e.presented
                if t is None or t not in issued or len(issued[t]) != 1:
                    continue
                (holder, iss), = issued[t].items()
                if holder == e.agent or iss.ts > e.ts or (holder, e.agent, t) in seen:
                    continue
                seen.add((holder, e.agent, t))
                cross = bool(iss.ip and e.ip and iss.ip != e.ip)
                links[(min(holder, e.agent), max(holder, e.agent))].append({
                    "holder": holder, "token": t, "class": iss.token_class, "issue_event": iss.event_id,
                    "present_event": e.event_id, "holder_ip": iss.ip, "presenter_ip": e.ip, "cross_ip": cross})
        return links

    def redaction_links(self, by_all: Dict[str, List[NormalizedEvent]]) -> Dict[Tuple[str, str], Dict[str, str]]:
        """Pairs of agents that presented the same scrubber marker. {pair: {marker_hash: event_id of first use}}.
        Markers used by more than ``redacted_max_sessions`` agents are 'popular' (a shared service credential) and ignored."""
        users: Dict[str, Dict[str, str]] = defaultdict(dict)
        for a, evs in by_all.items():
            if len(evs) < self.cfg.state_min_events:
                continue
            for e in evs:
                for r in e.redactions:
                    users[r].setdefault(a, e.event_id)
        out: Dict[Tuple[str, str], Dict[str, str]] = defaultdict(dict)
        for r, who in users.items():
            if 2 <= len(who) <= self.cfg.redacted_max_sessions:
                agents = sorted(who)
                for i, x in enumerate(agents):
                    for y in agents[i + 1:]:
                        out[(x, y)][r] = who[x]
        return out

    # -- main ----------------------------------------------------------------------------------------
    def detect(self, by_agent: Dict[str, List[NormalizedEvent]]) -> GraphResult:
        c = self.cfg
        by_all = {a: sorted(v, key=lambda e: e.ts) for a, v in by_agent.items()}
        elig = {a: v for a, v in by_all.items() if len(v) >= c.min_events}
        timing: Dict[Tuple[str, str], Tuple[float, int, float]] = {}
        content: Dict[Tuple[str, str], float] = {}
        if len(elig) >= 2:
            gt, gc, span = self.build_graphs(elig)
            timing = self._timing_edges(gt, span)
            content = self._content_edges(gc)
        links = self.token_links(by_all) if c.use_state_edges else {}
        reds = self.redaction_links(by_all) if c.use_state_edges else {}
        proj = nx.Graph()
        edges: Dict[Tuple[str, str], EdgeInfo] = {}
        for pair in set(timing) | set(content) | set(links) | set(reds):
            nlp, k, ts_ = timing.get(pair, (0.0, 0, 0.0))
            cs = content.get(pair, 0.0)
            lk = links.get(pair, [])
            if lk and not all(len(by_all[x]) >= c.state_min_events for x in pair) \
                    and not any(l["cross_ip"] and l["class"] in DETERMINISTIC_CLASSES for l in lk):
                lk = []                                       # graded state edges need minimally active sessions
            det = [l for l in lk if l["cross_ip"] and l["class"] in DETERMINISTIC_CLASSES]
            n_tok = len({l["token"] for l in lk})
            ss = min(1.0, n_tok / c.min_state_tokens) if lk else 0.0
            if det:
                d = det[0]
                info = EdgeInfo(pair[0], pair[1], nlp, k, ts_, cs, 1.0, CROSS_IP, len({l["token"] for l in det}), 1.0,
                                d["holder"], d["class"], d["holder_ip"], d["presenter_ip"],
                                [l["issue_event"] for l in det], [l["present_event"] for l in det])
                edges[pair] = info
                proj.add_edge(pair[0], pair[1], weight=1.0, state=True)
                continue
            rd = reds.get(pair, {})
            rw = min(0.75, c.weight_redacted + 0.05 * (len(rd) - 1)) if rd else 0.0     # never reaches deterministic 1.0
            w = min(1.0, c.weight_timing * ts_ + c.weight_content * cs + c.weight_state * ss + rw)
            if w >= c.edge_threshold:
                kind = SEMANTIC if ss > 0 else REDACTED if rd else TIMING_CONTENT
                edges[pair] = EdgeInfo(pair[0], pair[1], nlp, k, ts_, cs, round(w, 4), kind, n_tok or len(rd), ss,
                                       issue_event_ids=[l["issue_event"] for l in lk] + list(rd.values()),
                                       present_event_ids=[l["present_event"] for l in lk])
                proj.add_edge(pair[0], pair[1], weight=w, state=(ss > 0 or bool(rd)))
        clusters: List[Cluster] = []
        for comp in self.split_components(proj):
            if len(comp) < c.min_cluster_size:
                continue
            members = sorted(comp)
            sub = [e for (a, b), e in edges.items() if a in comp and b in comp]
            if not sub:
                continue
            possible = len(members) * (len(members) - 1) / 2
            mean_w = float(np.mean([e.weight for e in sub]))
            if any(e.kind != TIMING_CONTENT for e in sub):    # chains (e.g. proxy rotation) are paths, not cliques
                density = mean_w * min(1.0, len(sub) / (len(members) - 1))
            else:
                density = mean_w * len(sub) / possible
            cl = Cluster(members, round(density, 4), round(mean_w, 4), sub)
            cl.evidence_event_ids = self._evidence(members, by_all, sub)
            cl.reasons = [e.reason() for e in sorted(sub, key=lambda e: (-e.weight, e.a, e.b))][:6]
            self._suppress(cl, by_all)
            clusters.append(cl)
        clusters.sort(key=lambda x: (-x.density, x.members))
        n_state = sum(e.kind != TIMING_CONTENT for e in edges.values())
        return GraphResult(clusters, len(elig), len(timing), len(content), len(edges), n_state)

    def split_components(self, proj: nx.Graph) -> List[Set[str]]:
        """Connected components, with loosely-knit components split into communities.

        Chaining a few strong groups together through one weak edge would dilute the cluster density and hide all
        of them. Components whose edge density is below ``split_below_density`` are partitioned with weighted
        Louvain communities (deterministic seed). Dense components are kept whole."""
        out: List[Set[str]] = []
        for comp in nx.connected_components(proj):
            sub = proj.subgraph(comp)
            has_state = any(d.get("state") for _, _, d in sub.edges(data=True))
            if len(comp) > 3 and not has_state and nx.density(sub) < self.cfg.split_below_density:
                out += [set(x) for x in nx.community.louvain_communities(sub, weight="weight", seed=0)]
            else:
                out.append(set(comp))
        return out

    def _evidence(self, members: List[str], elig: Dict[str, List[NormalizedEvent]], edges: Sequence[EdgeInfo] = ()) -> List[str]:
        """Token issue/presentation events first (they are the proof), then events in time windows shared by most members."""
        first = [i for e in edges for i in e.issue_event_ids + e.present_event_ids]
        wins: Dict[int, Set[str]] = defaultdict(set)
        for m in members:
            for e in elig[m]:
                wins[int(e.ts // self.cfg.window_s)].add(m)
        need = max(2, math.ceil(0.6 * len(members)))
        hot = {w for w, s in wins.items() if len(s) >= need}
        ids = first + [e.event_id for m in members for e in elig[m] if int(e.ts // self.cfg.window_s) in hot and e.event_id not in first]
        return ids[:12]

    def _suppress(self, cl: Cluster, elig: Dict[str, List[NormalizedEvent]]) -> None:
        c = self.cfg
        members = set(cl.members)
        det = [e for e in cl.edges if e.kind == CROSS_IP]
        if det and not all(e.holder in self.policy.orchestrators for e in det):
            # deterministic honeypot-token handoff is NOT excused by schedules, declared groups or fan-out shape;
            # only a declared orchestrator that holds the tokens may legitimately hand them on.
            cl.reasons.append("suppression logic not applied: a honeypot-issued token was handed to another session "
                              "and the token holder is not a declared orchestrator")
            return
        if c.suppress_declared_groups:
            for name, grp in self.policy.groups.items():
                if members <= grp:
                    cl.suppressed = True
                    cl.suppression_reasons.append(f"declared_group:{name}")
        if c.suppress_periodic and all(
            len(elig[m]) >= c.periodic_min_events and _cv([e.ts for e in elig[m]]) < c.periodic_cv for m in cl.members
        ):
            cl.suppressed = True
            cl.suppression_reasons.append("periodic: every member acts on a strict fixed schedule (suspected shared cron)")
        if c.suppress_fanout:
            shared = set.intersection(*[set().union(*[e.shingles for e in elig[m]]) for m in cl.members]) \
                if len(cl.members) > 1 else set()
            # a "burst" = one member's template-bearing outbound events inside one time window
            bursts: Dict[Tuple[str, int], List[NormalizedEvent]] = defaultdict(list)
            for m in cl.members:
                for e in elig[m]:
                    if shared and (e.shingles & shared) and e.action in ("message", "write", "tool_call"):
                        bursts[(m, int(e.ts // c.window_s))].append(e)
            total = sum(len(v) for v in bursts.values())
            diverse = 0
            max_targets = 0
            for v in bursts.values():
                t = {e.resource_key for e in v}
                if len(t) >= c.fanout_min_distinct_targets and len(t) / len(v) >= c.fanout_min_diversity:
                    diverse += len(v)
                    max_targets = max(max_targets, len(t))
            if total and diverse / total >= 0.5:
                cl.suppressed = True
                cl.suppression_reasons.append(
                    f"template_fanout: one template sent to up to {max_targets} distinct targets per burst (broadcast-style)")
