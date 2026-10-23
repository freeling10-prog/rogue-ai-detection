"""Plain-language rendering of leads (Markdown). Output contains pseudonyms and derived text only."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .fusion import DISCLAIMER, Lead
from .normalize import NormalizationReport
from .prefilter import PrefilterReport


def leads_to_markdown(leads: List[Lead], rep: NormalizationReport, notes: List[str], prefilter: Optional[PrefilterReport] = None) -> str:
    out = ["# Leads for human review", "", f"> {DISCLAIMER}", "",
           f"Events accepted: {len(rep.events)}; quarantined: {len(rep.quarantined)}. Leads: {len(leads)}.", ""]
    out += [f"- NOTE: {n}" for n in notes]
    if prefilter is not None and (prefilter.agents or prefilter.kept_scanner_like_with_goal_evidence):
        out += [f"- Commodity-scanner pre-filter: {prefilter.agents} client(s) / {prefilter.events} events set aside before scoring "
                f"({dict(sorted(prefilter.by_reason.items()))}); {prefilter.kept_scanner_like_with_goal_evidence} scanner-looking client(s) kept "
                f"because they showed goal-directed evidence. Filtered clients are counted, not hidden."]
    for l in leads:
        out += ["", f"## {l.lead_id}  agent `{l.agent}`  (score {l.score}, queue priority: {l.priority_band})",
                f"Severity: **{l.severity}** | Recommended: **{l.recommended_action}** | Automatic action: **{l.automatic_action}**"
                + (f" | Web actor class: **{l.actor_class}**" + (f" (score floor {l.floor_applied})" if l.floor_applied else "")
                   if l.actor_class != "unclassified" else ""), "",
                f"Components (0-1): isolation forest {l.components['isolation_forest']}, rules {l.components['rules']}, "
                f"graph density {l.components['graph_density']}"]
        if l.anomaly_explanations:
            out += ["", "Why this agent looks unusual compared with its peers:"] + [f"- {t}" for t in l.anomaly_explanations]
        for f in l.rule_flags:
            out += ["", f"**{f.rule_id}: {f.title}** - ATLAS {', '.join(a['id'] + ' ' + a['name'] for a in f.atlas)}", f.explanation,
                    f"_{f.mapping_note}_", "Evidence events:"]
            out += [f"- `{e.event_id}` t={e.ts:.0f}: {e.summary}" for e in f.evidence]
        if l.cluster:
            c: Dict[str, Any] = l.cluster
            out += ["", f"**Coordination cluster** of {len(c['members'])} agents (density {c['density']}): "
                        + ", ".join(f"`{m}`" for m in c["members"]),
                    "Evidence events: " + ", ".join(f"`{e}`" for e in c["evidence_event_ids"][:8])]
    return "\n".join(out) + "\n"
