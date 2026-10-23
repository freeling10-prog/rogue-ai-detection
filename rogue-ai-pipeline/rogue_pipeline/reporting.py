"""Plain-language rendering of leads (Markdown). Output contains pseudonyms and derived text only."""
from __future__ import annotations

from typing import Any, Dict, List

from .fusion import DISCLAIMER, Lead
from .normalize import NormalizationReport


def leads_to_markdown(leads: List[Lead], rep: NormalizationReport, notes: List[str]) -> str:
    out = ["# Leads for human review", "", f"> {DISCLAIMER}", "",
           f"Events accepted: {len(rep.events)}; quarantined: {len(rep.quarantined)}. Leads: {len(leads)}.", ""]
    out += [f"- NOTE: {n}" for n in notes]
    for l in leads:
        out += ["", f"## {l.lead_id}  agent `{l.agent}`  (score {l.score}, queue priority: {l.priority_band})",
                f"Severity: **{l.severity}** | Recommended: **{l.recommended_action}** | Automatic action: **{l.automatic_action}**", "",
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
