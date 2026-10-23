#!/usr/bin/env python3
"""Helper for eval_web.py: run ONE pipeline tree (selected by PYTHONPATH) over an events JSONL, print JSON.
Works with both the v2 and the v3 tree (it only uses APIs that exist in both)."""
import json
import sys

from rogue_pipeline.config import Config, Policy
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer

events_path, mode = sys.argv[1], sys.argv[2]          # mode: default | no_web | no_prefilter
raw_ids = json.load(open(sys.argv[3]))                # raw agent ids to report on
cfg = Config()
if mode == "no_web":
    cfg = cfg.model_copy(update={"web": cfg.web.model_copy(update={"enabled": False})})
elif mode == "no_prefilter":
    cfg = cfg.model_copy(update={"web": cfg.web.model_copy(update={"prefilter": False})})
pseudo = Pseudonymizer(b"eval-web-synthetic-key-0123456789")
items = [json.loads(x) for x in open(events_path) if x.strip()]
res = Pipeline(cfg, Policy(), pseudo).run(items)
inv = {pseudo.agent(a): a for a in raw_ids}
leads = {}
for l in res.leads:
    leads[inv.get(l.agent, "other:" + l.agent)] = {"score": l.score, "band": l.priority_band, "actor_class": getattr(l, "actor_class", None),
                                                    "rules": [f.rule_id for f in l.rule_flags], "floor": getattr(l, "floor_applied", None)}
pre = getattr(res, "prefiltered", None)
print(json.dumps({"leads": leads, "quarantined": len(res.normalization.quarantined),
                  "prefiltered": pre.as_dict() if pre is not None else None,
                  "filtered_ids": sorted(inv[a] for a in pre.filtered_agents if a in inv) if pre is not None else []}))
