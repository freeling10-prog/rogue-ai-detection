#!/usr/bin/env python3
"""Calibrate the R13 (slow_or_shielded_probing) thresholds on BENIGN data only.

Inputs (all synthetic, all benign, none of the evaluation seeds):
  * the simulator's benign-only reference sets, seeds 1000-1002 (``build(seed, extended=True, v6=True, positives=False)``) - the same
    sessions the frozen baseline is trained on; includes crawlers, cron, orchestrator pools, compliance scanners, noisy-denied
    assistants, permission-drift assistants and a declared sharded pool;
  * the BENIGN web cohorts of ``build_web(seed, v6=True)`` for seeds 1000-1002 (humans incl. js-off / beacon-blocked / no-asset,
    accessibility users, flaky-network humans, two-tab readers, slow legitimate crawlers, commodity scanners, MCP agents are
    POSITIVE and are excluded by label).  Commodity scanners are removed by the same pre-filter the pipeline applies before scoring.
No positive / attack cohort is read: the function receives only agents whose label kind is 'benign'.

    python scripts/calibrate_r13.py            # print the calibration
    python scripts/calibrate_r13.py --json     # machine-readable
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from rogue_pipeline.config import Config  # noqa: E402
from rogue_pipeline.features import group_events  # noqa: E402
from rogue_pipeline.normalize import Normalizer  # noqa: E402
from rogue_pipeline.prefilter import prefilter_by_agent  # noqa: E402
from rogue_pipeline.probing import calibrate_many  # noqa: E402
from rogue_pipeline.pseudonymize import Pseudonymizer  # noqa: E402
from rogue_pipeline.simulator import build  # noqa: E402
from rogue_pipeline.web_simulator import build_web  # noqa: E402

SEEDS = (1000, 1001, 1002)


def benign_sessions(cfg: Config, seeds=SEEDS) -> Dict[str, Any]:
    groups: Dict[str, Any] = {}
    pseudo = Pseudonymizer(b"r13-calibration-synthetic-key-0123")
    for k in seeds:
        core = build(k, 60, extended=True, v6=True, positives=False)
        web = build_web(k, v6=True)
        for name, data in (("core", core), ("web", web)):
            keep = {a for a, (kind, _) in data.labels.items() if kind == "benign"}
            items: List[Dict[str, Any]] = [e for e in data.events if e.get("agent_id") in keep]
            rep = Normalizer(cfg.normalization, pseudo, None, cfg.web).process(items)
            assert not rep.quarantined, "calibration data must normalize cleanly"
            by_agent, _ = prefilter_by_agent(group_events(rep.events), cfg.web)   # the pipeline never scores prefiltered scanners
            groups[f"{name}-{k}"] = by_agent
    return groups


def main() -> int:
    cfg = Config()
    groups = benign_sessions(cfg)
    cal = calibrate_many(groups.values(), cfg.probing, source=f"benign core+web reference, seeds {list(SEEDS)}")
    d = cal.as_dict()
    if "--json" in sys.argv:
        print(json.dumps(d, indent=2, sort_keys=True))
    else:
        for k, v in d.items():
            print(f"{k:22s} {v}")
        print("\nconfigured ProbingCfg:", {k: getattr(cfg.probing, k) for k in ("p0", "p1", "cusum_h", "p1_low", "cusum_h_low", "w3_min", "w7_min", "collapse_max_logstd", "paced_rate_min")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
