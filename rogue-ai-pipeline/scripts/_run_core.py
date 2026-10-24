#!/usr/bin/env python3
"""Helper for eval_v6.py: run ONE pipeline tree (selected by PYTHONPATH / cwd) over prepared core-simulator datasets, using THAT
tree's own frozen evaluation context (``make_context()``: its benign reference seeds 1000-1002, identity registry).  Works with the
v5 and v6 trees (only APIs present in both).

    _run_core.py MANIFEST.json        # [{"events": path, "policy": path, "ids": path, "seed": int, "out": path}, ...]
"""
import json
import sys

from rogue_pipeline.attribution import attribute, candidate_of_lead
from rogue_pipeline.config import Policy
from rogue_pipeline.evaluation import _eval_key, make_context
from rogue_pipeline.fusion import fuse
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer

ctx = make_context()
cfg = ctx.cfg_identity
for job in json.load(open(sys.argv[1])):
    items = [json.loads(x) for x in open(job["events"]) if x.strip()]
    policy = Policy(**json.load(open(job["policy"])))
    pseudo = Pseudonymizer(_eval_key(job["seed"]))
    res = Pipeline(cfg, policy, pseudo, run_tag=f"eval-{job['seed']}", baseline=ctx.baseline, identity=ctx.registry).run(items, alternatives=True)
    inv = {pseudo.agent(a): a for a in json.load(open(job["ids"]))}
    clusters = res.graph.clusters if res.graph else []
    off = fuse(cfg.fusion.model_copy(update={"corroboration_gate": False}), res.anomaly.agents if res.anomaly else {}, res.flags, clusters, "e",
               res.sequence, cfg.sequence.gate)
    strict = fuse(cfg.fusion.model_copy(update={"rule_solo_min": 1.01, "graph_solo_min": 1.01}), res.anomaly.agents if res.anomaly else {},
                  res.flags, clusters, "e", res.sequence, cfg.sequence.gate)
    kept = res.lead_agents()
    out = {"leads": {inv.get(l.agent, "other"): {"rules": sorted({f.rule_id for f in l.rule_flags}), "gate_reason": getattr(l, "gate_reason", None),
                                                  "edge_kinds": list(l.cluster["edge_kinds"]) if l.cluster else []} for l in res.leads},
           "no_gate": sorted(inv.get(l.agent, "other") for l in off),
           "strict_gate": sorted(inv.get(l.agent, "other") for l in strict),
           "attribution": [[inv.get(l.agent, "other"), attribute(candidate_of_lead(l), cfg.fusion)["detail"], l.agent not in kept] for l in off],
           "quarantined": len(res.normalization.quarantined),
           "guardrail_ok": all(l.severity == "low" and l.automatic_action == "none" and l.recommended_action == "human_review" for l in res.leads)}
    with open(job["out"], "w") as fh:
        json.dump(out, fh)
print("ok")
