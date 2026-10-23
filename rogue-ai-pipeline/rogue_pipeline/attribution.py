"""Per-layer false-positive attribution (v4).

For every lead (or gate-blocked candidate) answer "which layer made this?" by leave-one-out on the noisy-or fusion: a
component is NECESSARY if removing it drops the score below the lead threshold.  Leads held up by a score floor are
attributed to the floor rule (R10/R11).  A lead where no single component is necessary is labelled ``redundant`` (two or more
layers each sufficient on their own side of the threshold).

This is a diagnostic over synthetic data, not causal proof: it says what the fusion arithmetic needed, nothing more.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .config import FusionCfg
from .fusion import Lead

_COMPONENTS = (("isolation_forest", "w_anomaly"), ("rules", "w_rules"), ("graph_density", "w_graph"), ("sequence", "w_sequence"))
LAYERS = ("floor", "isolation_forest", "sequence_model", "rule_gate", "coordination_graph", "multi_layer")


def candidate_of_lead(lead: Lead) -> Dict[str, Any]:
    return {"agent": lead.agent, "score": lead.score, "components": dict(lead.components),
            "rules": sorted(f.rule_id for f in lead.rule_flags),
            "edge_kinds": list(lead.cluster["edge_kinds"]) if lead.cluster else [],
            "floor": lead.floor_applied, "families": list(lead.families)}


def _noisy_or(cfg: FusionCfg, comp: Dict[str, float], skip: str = "") -> float:
    p = 1.0
    for key, wname in _COMPONENTS:
        if key != skip:
            p *= 1 - getattr(cfg, wname) * comp.get(key, 0.0)
    return 1.0 - p


def attribute(cand: Dict[str, Any], cfg: FusionCfg) -> Dict[str, Any]:
    """Return ``{"layer": ..., "detail": ..., "necessary": [...]}`` for a lead / gate-blocked candidate."""
    comp = cand["components"]
    rules: List[str] = list(cand.get("rules", []))
    active = [k for k, _ in _COMPONENTS if comp.get(k, 0.0) > 0]
    floor = cand.get("floor")
    necessary = [k for k in active if _noisy_or(cfg, comp, skip=k) < cfg.lead_threshold]
    if floor is not None and floor >= cfg.lead_threshold and _noisy_or(cfg, comp) < cfg.lead_threshold:     # the floor, not the arithmetic, made it a lead
        fr = [r for r in rules if r in ("R10", "R11")]
        return {"layer": "floor", "detail": "floor:" + "+".join(fr or ["rule"]), "necessary": []}
    if len(necessary) == 1:
        k = necessary[0]
        if k == "isolation_forest":
            return {"layer": "isolation_forest", "detail": "isolation_forest", "necessary": necessary}
        if k == "sequence":
            return {"layer": "sequence_model", "detail": "sequence_model", "necessary": necessary}
        if k == "rules":
            return {"layer": "rule_gate", "detail": "rule:" + (rules[0] if rules else "?") + (f"(+{len(rules) - 1})" if len(rules) > 1 else ""),
                    "necessary": necessary}
        kinds = "+".join(cand.get("edge_kinds") or ["?"])
        return {"layer": "coordination_graph", "detail": "graph:" + kinds, "necessary": necessary}
    names = {"isolation_forest": "isolation_forest", "sequence": "sequence_model", "rules": "rule_gate", "graph_density": "coordination_graph"}
    detail = "+".join(names[k] for k in (necessary or active))
    if not necessary and len(active) == 1:
        return {"layer": names[active[0]], "detail": names[active[0]], "necessary": []}
    return {"layer": "multi_layer", "detail": detail + ("" if necessary else " (each redundant)"), "necessary": necessary}
