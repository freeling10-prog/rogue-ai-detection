"""Evaluation against the generator's ground-truth roles.

IMPORTANT: roles are planted by the same author as the detectors, on synthetic data. Perfect or near-perfect
scores here show the plumbing works; they are NOT evidence of real-world accuracy."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict

from .pipeline import Analysis
from .synthetic import ROGUE_ROLES


def evaluate(an: Analysis, roles: Dict[str, str], min_severity=("medium", "high")) -> Dict:
    truth = {a for a, r in roles.items() if r in ROGUE_ROLES}
    fused = {s for al in an.alerts if al.severity in min_severity for s in al.subjects}
    base = set(an.iforest.flagged)

    def prf(pred):
        tp = len(pred & truth)
        p = tp / len(pred) if pred else 0.0
        r = tp / len(truth) if truth else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
                "flagged": len(pred), "true_positives": tp, "false_positives": len(pred - truth),
                "missed": len(truth - pred)}

    per_role = defaultdict(lambda: {"agents": 0, "fused_flagged": 0, "iforest_flagged": 0})
    for a, r in roles.items():
        per_role[r]["agents"] += 1
        per_role[r]["fused_flagged"] += a in fused
        per_role[r]["iforest_flagged"] += a in base
    return {"rogue_agents": len(truth), "agents": len(roles),
            "fused_pipeline": prf(fused), "isolation_forest_only": prf(base),
            "per_role": dict(per_role),
            "missed": sorted((a, roles[a]) for a in truth - fused),
            "false_positives": sorted((a, roles[a]) for a in fused - truth)}


def format_eval(ev: Dict, title: str) -> str:
    lines = [title, "-" * len(title),
             f"agents: {ev['agents']}   planted rogue agents: {ev['rogue_agents']}   (SYNTHETIC; planted by this project)"]
    for name in ("fused_pipeline", "isolation_forest_only"):
        m = ev[name]
        lines.append(f"{name:24s} precision {m['precision']:.2f}  recall {m['recall']:.2f}  f1 {m['f1']:.2f}  "
                     f"(flagged {m['flagged']}, TP {m['true_positives']}, FP {m['false_positives']}, missed {m['missed']})")
    lines.append("per role (flagged / agents):")
    for r, d in sorted(ev["per_role"].items()):
        lines.append(f"  {r:28s} fused {d['fused_flagged']}/{d['agents']}   iforest-only {d['iforest_flagged']}/{d['agents']}")
    if ev["missed"]:
        lines.append("missed: " + ", ".join(f"{a} ({r})" for a, r in ev["missed"]))
    if ev["false_positives"]:
        lines.append("false positives: " + ", ".join(f"{a} ({r})" for a, r in ev["false_positives"]))
    return "\n".join(lines)
