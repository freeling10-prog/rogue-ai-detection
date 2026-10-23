"""Fusion: combine Isolation Forest, rule flags and graph density into *leads for human review*.

SAFETY INVARIANTS (enforced here in code, and again in tests):
  * A ``Lead`` is always severity "low", recommended_action "human_review", automatic_action "none".
    The ``Lead`` constructor raises if anything else is attempted.
  * This package contains no code path that blocks, bans, throttles or terminates an agent.
  * A lead requires corroboration that carries EVIDENCE a reviewer can inspect: rule flags, a coordination cluster,
    or a passed sequence gate (with the specific unusual transitions). Isolation-Forest evidence alone can never
    create one (the weight check in ``FusionCfg`` plus an explicit guard below).
  * The sequence model contributes only when its calibrated score passes ``SequenceCfg.gate``; below the gate it
    is ignored, so ordinary benign variation cannot add up to a lead.
  * Scores are for ranking the review queue. They are not probabilities of wrongdoing.

Fusion rule (noisy-or):  score = 1 - prod_i (1 - w_i * s_i)  over i in {anomaly, rules, graph}.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import FusionCfg
from .layer1_anomaly import AgentAnomaly, FeatureContribution
from .layer2_rules import RuleFlag
from .layer3_graph import Cluster
from .sequence_model import SequenceResult

SEVERITY = "low"
RECOMMENDED_ACTION = "human_review"
AUTOMATIC_ACTION = "none"
DISCLAIMER = ("Lead for human review only. High score means 'worth a person looking', not 'confirmed misuse'. "
              "No automatic action is taken or recommended. ATLAS mapping is approximate. Synthetic-data prototype.")


@dataclass(frozen=True)
class Lead:
    lead_id: str
    agent: str
    score: float
    priority_band: str                      # "review_first" | "review" (ordering aid, NOT severity)
    components: Dict[str, float]
    anomaly_explanations: List[str]
    rule_flags: List[RuleFlag]
    cluster: Optional[Dict[str, Any]]
    sequence: Optional[Dict[str, Any]] = None
    severity: str = SEVERITY
    recommended_action: str = RECOMMENDED_ACTION
    automatic_action: str = AUTOMATIC_ACTION
    disclaimer: str = DISCLAIMER

    def __post_init__(self) -> None:
        if self.severity != SEVERITY or self.recommended_action != RECOMMENDED_ACTION \
                or self.automatic_action != AUTOMATIC_ACTION:
            raise ValueError("a Lead must be low severity, human_review, with no automatic action")
        if not self.rule_flags and not self.cluster and not self.sequence:
            raise ValueError("a Lead requires rule, graph or sequence-gate evidence; anomaly score alone is not enough")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lead_id": self.lead_id, "agent": self.agent, "score": self.score, "priority_band": self.priority_band,
            "severity": self.severity, "recommended_action": self.recommended_action,
            "automatic_action": self.automatic_action, "components": self.components,
            "anomaly_explanations": self.anomaly_explanations,
            "rule_flags": [{
                "rule_id": f.rule_id, "title": f.title, "atlas": f.atlas, "strength": f.strength,
                "explanation": f.explanation, "mapping_note": f.mapping_note,
                "evidence": [{"event_id": e.event_id, "ts": e.ts, "summary": e.summary} for e in f.evidence],
                "extra": f.extra,
            } for f in self.rule_flags],
            "cluster": self.cluster, "sequence": self.sequence, "disclaimer": self.disclaimer,
        }


def _lead_id(agent: str, run_tag: str) -> str:
    return "lead-" + hashlib.sha256(f"{run_tag}|{agent}".encode()).hexdigest()[:12]


def fuse(cfg: FusionCfg, anomalies: Dict[str, AgentAnomaly], flags: List[RuleFlag], clusters: List[Cluster],
         run_tag: str = "run", sequences: Optional[Dict[str, SequenceResult]] = None, seq_gate: float = 0.6) -> List[Lead]:
    """Return leads sorted by score (descending). ``sequences`` (optional) are Markov sequence scores; only those at
    or above ``seq_gate`` take part."""
    gated = {a: r for a, r in (sequences or {}).items() if r.score >= seq_gate}
    by_rule: Dict[str, List[RuleFlag]] = {}
    for f in flags:
        by_rule.setdefault(f.agent, []).append(f)
    cluster_of: Dict[str, Cluster] = {}
    for c in clusters:
        if c.suppressed:
            continue
        for m in c.members:
            if m not in cluster_of or c.density > cluster_of[m].density:
                cluster_of[m] = c
    agents = set(anomalies) | set(by_rule) | set(cluster_of) | set(gated)
    leads: List[Lead] = []
    for a in agents:
        an = anomalies.get(a)
        s_a = an.score if an else 0.0
        fl = by_rule.get(a, [])
        s_r = max((f.strength for f in fl), default=0.0)
        cl = cluster_of.get(a)
        s_g = cl.density if cl else 0.0
        sq = gated.get(a)
        s_q = sq.score if sq else 0.0
        score = 1.0 - (1 - cfg.w_anomaly * s_a) * (1 - cfg.w_rules * s_r) * (1 - cfg.w_graph * s_g) * (1 - cfg.w_sequence * s_q)
        if score < cfg.lead_threshold or (not fl and cl is None and sq is None):
            continue
        band = "review_first" if score >= cfg.band_review_first else "review"
        leads.append(Lead(
            lead_id=_lead_id(a, run_tag), agent=a, score=round(score, 4), priority_band=band,
            components={"isolation_forest": round(s_a, 4), "rules": round(s_r, 4), "graph_density": round(s_g, 4),
                        "sequence": round(s_q, 4)},
            anomaly_explanations=[c.text for c in (an.contributions if an else [])],
            rule_flags=fl,
            cluster=None if cl is None else {
                "members": cl.members, "density": cl.density, "mean_weight": cl.mean_weight,
                "evidence_event_ids": cl.evidence_event_ids, "edge_kinds": cl.kinds, "reasons": cl.reasons,
                "atlas": cl.atlas,
                "edges": [{"a": e.a, "b": e.b, "kind": e.kind, "timing_neg_log10_p": round(e.timing_nlp, 2),
                           "shared_windows": e.shared_windows, "content_cosine": round(e.content_cosine, 3),
                           "state_tokens": e.state_tokens, "weight": e.weight} for e in cl.edges]},
            sequence=None if sq is None else {
                "score": round(sq.score, 4), "worst_window_bits": round(sq.worst_window_bits, 3),
                "mean_bits": round(sq.mean_bits, 3), "n_transitions": sq.n_transitions, "explanation": sq.text,
                "evidence_event_ids": [t.event_id for t in sq.top]},
        ))
    leads.sort(key=lambda l: (-l.score, l.agent))
    return leads
