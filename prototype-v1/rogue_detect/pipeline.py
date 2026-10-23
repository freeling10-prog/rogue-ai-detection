"""End-to-end analysis: features -> detectors -> fused, explained alerts."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .alerts import Alert, atlas_tags
from .detectors import CoordResult, CoordinationDetector, IFResult, IsolationForestDetector, RuleHit, run_rules
from .features import FEATURE_NAMES, extract_features
from .schema import Event


@dataclass
class Analysis:
    ids: List[str]
    features: Dict[str, Dict[str, float]]
    iforest: IFResult
    rule_hits: List[RuleHit]
    coord: CoordResult
    alerts: List[Alert]
    window: tuple = (0.0, 0.0)


def _aid(kind: str, subjects: Sequence[str]) -> str:
    return "AL-" + hashlib.sha1((kind + "|" + ",".join(sorted(subjects))).encode()).hexdigest()[:10]


def _fmt_expl(expl) -> str:
    return "; ".join(f"{f}={v:.3g} (robust z {z:+.1f})" for f, v, z in expl)


def analyze(events: Sequence[Event], contamination: float = 0.12, seed: int = 0) -> Analysis:
    ids, X, by_agent, (t_min, t_max) = extract_features(events)
    from .features import agent_features
    feats = {a: dict(zip(FEATURE_NAMES, X[i])) for i, a in enumerate(ids)}
    ifr = IsolationForestDetector(contamination=contamination, random_state=seed).fit_score(ids, X)
    hits = run_rules({a: by_agent[a] for a in ids}, feats)
    coord = CoordinationDetector().detect({a: by_agent[a] for a in ids}, t_min, t_max)
    alerts: List[Alert] = []
    covered = set()

    rule_info = {
        "access_probe": ("Possible unauthorized access probing", ["AML.T0075"]),
        "injection_exfil": ("Possible injection-driven exfiltration through a new tool", ["AML.T0051", "AML.T0086", "AML.T0053"]),
        "hidden_channel": ("Encoded payloads in agent-to-agent messages", ["AML.T0118"]),
    }
    for h in hits:
        title, tags = rule_info[h.rule]
        flagged = h.agent in ifr.flagged
        sev = "high" if flagged else "medium"
        d = h.detail
        if h.rule == "access_probe":
            s = (f"{title}: {d['denied']} denied of {d['access_events']} access requests, "
                 f"{d['sensitive_out_of_scope']} against sensitive out-of-scope paths.")
        elif h.rule == "injection_exfil":
            s = (f"{title}: after reading external content, used `{d['tool']}` (first use) to send data off-system "
                 f"({d['sequences']} time(s), up to {d['max_payload_bytes']} bytes).")
        else:
            s = f"{title}: {d['encoded_ratio']:.0%} of text looks encoded across {d['messages']} messages."
        alerts.append(Alert(_aid(h.rule, [h.agent]), h.ts, h.rule, sev, [h.agent],
                            round(ifr.scores[h.agent], 4), s,
                            {"rule_detail": d, "isolation_forest_flagged": flagged,
                             "top_features": ifr.explanations[h.agent]}, atlas_tags(tags)))
        covered.add(h.agent)

    for c in coord.clusters:
        types = c["evidence_types"]
        any_if = any(m in ifr.flagged for m in c["members"])
        sev = "high" if (len(types) >= 3 or any_if) else "medium"
        s = (f"Possible coordinated group of {len(c['members'])} agents; evidence: {', '.join(types)} "
             f"(timing -log10p {c['mean_timing_logp']:.1f}, content cosine {c['mean_content_cos']:.2f}, "
             f"{c['messages']} messages).")
        alerts.append(Alert(_aid("collusion_cluster", c["members"]), c["ts"], "collusion_cluster", sev, c["members"],
                            round(len(types) / 3, 3), s, {k: v for k, v in c.items() if k != "ts"},
                            atlas_tags(["AML.T0118"])))
        covered.update(c["members"])

    for c in coord.scheduled:
        alerts.append(Alert(_aid("scheduled_sync", c["members"]), c["ts"], "scheduled_sync", "info", c["members"], 0.1,
                            f"{len(c['members'])} agents act in lockstep on a strictly periodic schedule; "
                            "likely a shared scheduler, not collusion. Logged for context only.",
                            {"edges": c["edges"]}, []))
        covered.update(c["members"])  # explained: do not also raise an anomaly alert

    for a in sorted(ifr.flagged, key=lambda x: -ifr.scores[x]):
        if a in covered:
            continue
        alerts.append(Alert(_aid("behavior_anomaly", [a]), by_agent[a][-1].ts, "behavior_anomaly", "low", [a],
                            round(ifr.scores[a], 4),
                            "Statistically unusual behavior with no corroborating rule or coordination evidence. "
                            "Unsupervised evidence alone is capped at low severity until a human reviews it. "
                            f"Most unusual features: {_fmt_expl(ifr.explanations[a])}.",
                            {"top_features": ifr.explanations[a]}, []))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    alerts.sort(key=lambda al: (order[al.severity], -al.score))
    return Analysis(ids, feats, ifr, hits, coord, alerts, (t_min, t_max))
