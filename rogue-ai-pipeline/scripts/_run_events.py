#!/usr/bin/env python3
"""Helper for eval_web.py: run ONE pipeline tree (selected by PYTHONPATH) over an events JSONL, print JSON.
Works with the v2, v3 and v4 trees (it only uses APIs that exist in all three; v4-only modes are ignored by older trees).

    _run_events.py EVENTS.jsonl MODE IDS.json [POLICY.json]
    MODE: default | no_web | no_prefilter | no_gate (v4: corroboration gate off) | strict_gate (v4: every non-floor lead needs 2 families)
"""
import json
import sys

from rogue_pipeline.config import Config, Policy
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer

events_path, mode = sys.argv[1], sys.argv[2]
raw_ids = json.load(open(sys.argv[3]))                # raw agent ids to report on
policy = Policy(**json.load(open(sys.argv[4]))) if len(sys.argv) > 4 else Policy()
cfg = Config()
if mode == "no_web":
    cfg = cfg.model_copy(update={"web": cfg.web.model_copy(update={"enabled": False})})
elif mode == "no_prefilter":
    cfg = cfg.model_copy(update={"web": cfg.web.model_copy(update={"prefilter": False})})
elif mode == "no_gate":
    cfg = cfg.model_copy(update={"fusion": cfg.fusion.model_copy(update={"corroboration_gate": False})})
elif mode == "strict_gate":
    cfg = cfg.model_copy(update={"fusion": cfg.fusion.model_copy(update={"rule_solo_min": 1.01, "graph_solo_min": 1.01})})
pseudo = Pseudonymizer(b"eval-web-synthetic-key-0123456789")
items = [json.loads(x) for x in open(events_path) if x.strip()]
res = Pipeline(cfg, policy, pseudo).run(items)
inv = {pseudo.agent(a): a for a in raw_ids}
leads = {}
for l in res.leads:
    leads[inv.get(l.agent, "other:" + l.agent)] = {
        "score": l.score, "band": l.priority_band, "actor_class": getattr(l, "actor_class", None),
        "rules": sorted(f.rule_id for f in l.rule_flags), "floor": getattr(l, "floor_applied", None),
        "components": dict(l.components), "edge_kinds": list(l.cluster["edge_kinds"]) if l.cluster else [],
        "families": getattr(l, "families", None), "gate_reason": getattr(l, "gate_reason", None)}
blocked = {}
for g in getattr(res, "gated_out", []):
    blocked[inv.get(g["agent"], "other:" + g["agent"])] = {k: g[k] for k in ("score", "families", "components", "rules", "edge_kinds", "floor")}
pre = getattr(res, "prefiltered", None)
print(json.dumps({"leads": leads, "gate_blocked": blocked, "quarantined": len(res.normalization.quarantined),
                  "prefiltered": pre.as_dict() if pre is not None else None,
                  "filtered_ids": sorted(inv[a] for a in pre.filtered_agents if a in inv) if pre is not None else []}))
