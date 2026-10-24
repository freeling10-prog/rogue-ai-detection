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

v4 addition - TWO-SIGNAL CORROBORATION GATE (``FusionCfg.corroboration_gate``): a candidate whose score passes the threshold is
emitted only if it has (a) a floor from a strong single-event rule (R10 / R11), or (b) >= 2 independent signal families (statistical
= Isolation Forest + sequence surprise counted once; rule gate; coordination graph), or (b') v6: >= 2 independent RULE families
(tool_use / probing / timing / navigation / web_interaction / session_fork / honeypot; see ``layer2_rules.RULE_FAMILY``) whose
strengths then combine by noisy-or, or (c) one deterministic family that is strong by itself (a rule of strength >= rule_solo_min
(0.65), a cluster of density >= graph_solo_min).  This removes leads made only of statistical
surprise or of a single low-weight rule; it costs recall wherever a true positive had no other family (reported by the evaluation).

v3 additions (still leads only - severity stays "low"):
  * FLOORS: a rule flag may carry ``extra["floor"]`` (R10: a single high-signal event).  After noisy-or the score is
    ``max(score, floor)``.  Nothing in the fusion is an average over the session, so unrelated benign events can never
    pull a lead with a floor below it.
  * ``actor_class`` (``goal_directed`` | ``possible_mimic`` | ``accidental_scraper`` | ``unclassified``) separates a client that
    merely touched one hidden link (an accidental scraper: lower floor, queue position "review") from one that used what a
    decoy offered or showed several corroborating web signals.  It is a triage hint derived from the flags; it is not intent.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import FusionCfg
from .layer1_anomaly import AgentAnomaly, FeatureContribution
from .layer2_rules import RuleFlag, rule_families
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
    actor_class: str = "unclassified"
    floor_applied: Optional[float] = None
    families: List[str] = field(default_factory=list)       # v4: independent signal families that were present
    gate_reason: str = ""                                    # v4: why the corroboration gate let this lead through
    harness: Optional[Dict[str, str]] = None                 # v5: descriptive harness label from the collector {archetype, confidence}; never scored
    rule_families: List[str] = field(default_factory=list)   # v6: independent RULE families present (tool_use / probing / timing / navigation ...)
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
            "cluster": self.cluster, "sequence": self.sequence, "actor_class": self.actor_class,
            "floor_applied": self.floor_applied, "families": self.families, "gate_reason": self.gate_reason, "harness": self.harness,
            "rule_families": self.rule_families,
            "disclaimer": self.disclaimer,
        }


def classify_actor(flags: List[RuleFlag]) -> str:
    """Triage hint from the web rules.  ``unclassified`` when no web rule fired (all non-web leads)."""
    by = {f.rule_id: f for f in flags}
    r10 = by.get("R10")
    r11 = by.get("R11")
    if not (r10 or r11 or "R8" in by or "R9" in by or "R14" in by):
        return "unclassified"
    if "R6" in by or "R7" in by:
        return "goal_directed"
    if r11 is not None and r11.extra.get("tier") == "strong":
        return "goal_directed"                  # webdriver/automation property, forged beacon, VLM/DOM-order click, ARIA fast-path hit
    if r10 is not None and r10.extra.get("tier") == "strong":
        return "goal_directed"
    if "R8" in by and "R9" in by:
        return "goal_directed"                  # no asset loads AND guessed URLs: two independent facts, same client
    if "R14" in by and ("R9" in by or "R11" in by or "R13" in by):
        return "goal_directed"                  # v6: a forked background sub-tree PLUS an independent web fact in the same session
    if "R8" in by or "R9" in by or r11 is not None or "R14" in by:
        return "possible_mimic"
    return "accidental_scraper"                 # R10 weak tier only: one hidden-link / decoy contact, nothing adaptive


def _families(cfg: FusionCfg, s_a: float, fl: List[RuleFlag], cl: Optional[Cluster], sq: Optional[SequenceResult]) -> List[str]:
    out: List[str] = []
    if s_a >= cfg.anomaly_min or sq is not None:
        out.append("statistical")          # Isolation Forest and the sequence model share inputs: ONE family
    if fl:
        out.append("rules")
    if cl is not None:
        out.append("graph")
    return out


def flag_families(fl: List[RuleFlag]) -> List[str]:
    """v6: the distinct rule families among an agent's flags (sorted)."""
    return sorted({x for f in fl for x in rule_families(f)})


def rules_strength(cfg: FusionCfg, fl: List[RuleFlag]) -> float:
    """Rule component of the fusion.  v3/v4: the strongest flag.  v6 (gate on + ``rule_family_corroboration``): with >= 2 independent
    rule families, the per-family maxima combine by noisy-or (capped at ``rule_family_cap``) - two different facts corroborate; several
    rules of ONE family still count as their strongest member."""
    if not fl:
        return 0.0
    best = max(f.strength for f in fl)
    if not (cfg.corroboration_gate and cfg.rule_family_corroboration):
        return best
    per: Dict[str, float] = {}
    for f in fl:
        for fam in rule_families(f):
            per[fam] = max(per.get(fam, 0.0), f.strength)
    if len(per) < 2:
        return best
    p = 1.0
    for v in per.values():
        p *= 1.0 - v
    return round(max(best, min(cfg.rule_family_cap, 1.0 - p)), 4)


def gate_decision(cfg: FusionCfg, families: List[str], s_r: float, cl: Optional[Cluster], floor: Optional[float],
                  rule_fams: Optional[List[str]] = None) -> str:
    """Return the reason a lead may be emitted, or ``""`` if the corroboration gate blocks it."""
    if not cfg.corroboration_gate:
        return "gate_off"
    if floor is not None:
        return "floor"
    if len(families) >= 2:
        return "families:" + "+".join(families)
    if cfg.rule_family_corroboration and families == ["rules"] and rule_fams and len(rule_fams) >= 2:
        return "rule_families:" + "+".join(rule_fams)
    if families == ["rules"] and s_r >= cfg.rule_solo_min:
        return "solo_rule"
    if families == ["graph"] and cl is not None and cl.density >= cfg.graph_solo_min:
        return "solo_graph"
    return ""


def _lead_id(agent: str, run_tag: str) -> str:
    return "lead-" + hashlib.sha256(f"{run_tag}|{agent}".encode()).hexdigest()[:12]


def fuse(cfg: FusionCfg, anomalies: Dict[str, AgentAnomaly], flags: List[RuleFlag], clusters: List[Cluster],
         run_tag: str = "run", sequences: Optional[Dict[str, SequenceResult]] = None, seq_gate: float = 0.6,
         gated_out: Optional[List[Dict[str, Any]]] = None, harness: Optional[Dict[str, Dict[str, str]]] = None) -> List[Lead]:
    """Return leads sorted by score (descending). ``sequences`` (optional) are Markov sequence scores; only those at
    or above ``seq_gate`` take part.  ``gated_out`` (optional list) receives one record per candidate the v4 corroboration
    gate blocked (agent, score, families, components): blocked candidates are counted and attributable, never silently lost."""
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
        s_r = rules_strength(cfg, fl)
        rfams = flag_families(fl)
        cl = cluster_of.get(a)
        s_g = cl.density if cl else 0.0
        sq = gated.get(a)
        s_q = sq.score if sq else 0.0
        score = 1.0 - (1 - cfg.w_anomaly * s_a) * (1 - cfg.w_rules * s_r) * (1 - cfg.w_graph * s_g) * (1 - cfg.w_sequence * s_q)
        floors = [float(v) for v in (f.extra.get("floor") for f in fl) if isinstance(v, (int, float))]
        floor = max(floors) if floors else None
        if floor is not None:
            score = max(score, floor)
        if score < cfg.lead_threshold or (not fl and cl is None and sq is None):
            continue
        fams = _families(cfg, s_a, fl, cl, sq)
        why = gate_decision(cfg, fams, s_r, cl, floor, rfams)
        if not why:
            if gated_out is not None:
                gated_out.append({"agent": a, "score": round(score, 4), "families": fams, "floor": floor,
                                  "components": {"isolation_forest": round(s_a, 4), "rules": round(s_r, 4), "graph_density": round(s_g, 4),
                                                 "sequence": round(s_q, 4)}, "rules": sorted(f.rule_id for f in fl),
                                  "edge_kinds": list(cl.kinds) if cl else [], "rule_families": rfams})
            continue
        band = "review_first" if score >= cfg.band_review_first else "review"
        leads.append(Lead(
            lead_id=_lead_id(a, run_tag), agent=a, score=round(score, 4), priority_band=band,
            components={"isolation_forest": round(s_a, 4), "rules": round(s_r, 4), "graph_density": round(s_g, 4),
                        "sequence": round(s_q, 4)},
            anomaly_explanations=[c.text for c in (an.contributions if an else [])],
            rule_flags=fl, actor_class=classify_actor(fl), floor_applied=floor, families=fams, gate_reason=why, harness=(harness or {}).get(a),
            rule_families=rfams,
            cluster=None if cl is None else {
                "members": cl.members, "density": cl.density, "mean_weight": cl.mean_weight,
                "evidence_event_ids": cl.evidence_event_ids, "edge_kinds": cl.kinds, "reasons": cl.reasons,
                "atlas": cl.atlas,
                "edges": [{"a": e.a, "b": e.b, "kind": e.kind, "timing_neg_log10_p": round(e.timing_nlp, 2),
                           "shared_windows": e.shared_windows, "content_cosine": round(e.content_cosine, 3),
                           "state_tokens": e.state_tokens, "weight": e.weight, **({"detail": dict(e.detail)} if e.detail else {})}
                          for e in cl.edges]},
            sequence=None if sq is None else {
                "score": round(sq.score, 4), "worst_window_bits": round(sq.worst_window_bits, 3),
                "mean_bits": round(sq.mean_bits, 3), "n_transitions": sq.n_transitions, "explanation": sq.text,
                "evidence_event_ids": [t.event_id for t in sq.top]},
        ))
    leads.sort(key=lambda l: (-l.score, l.agent))
    return leads
