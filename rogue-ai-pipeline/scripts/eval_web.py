#!/usr/bin/env python3
"""v3 web-client evaluation, before/after.  REGRESSION CHECK ON SYNTHETIC DATA WRITTEN BY THE SAME AUTHOR - NOT A BENCHMARK.

    python scripts/eval_web.py --old-tree /path/to/v2/rogue-ai-pipeline --out eval-web-out [--seeds 0 1 2 3 4]

Per seed it builds benign background agents (the v1 simulator, positives off) + the web clients of
``rogue_pipeline/web_simulator.py`` and runs the pipeline three ways (each in its own subprocess so the v2 and v3
code never share a Python process):

  v2            the old tree on the same events with the ``web`` block stripped (v2 cannot represent it)
  v3_web_off    this tree with ``web.enabled=False`` (rules R8-R10 and the pre-filter are off): shows nothing else changed
  v3            this tree, defaults
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from rogue_pipeline.simulator import build            # noqa: E402
from rogue_pipeline.web_simulator import GROUPS, build_web   # noqa: E402

MIMICS = ("mimic_basic", "mimic_linked", "mimic_assets", "mimic_schema")
ADAPTIVE = ("mcp_agent", "decoy_explorer", "scanner_ua_spoof")


def run(tree: Path, events: Path, mode: str, ids: Path) -> dict:
    out = subprocess.run([sys.executable, str(HERE / "scripts" / "_run_events.py"), str(events), mode, str(ids)], cwd=tree,
                         env={**os.environ, "PYTHONPATH": str(tree)}, check=True, capture_output=True, text=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old-tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, nargs="*", default=[0, 1, 2, 3, 4])
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    old = Path(a.old_tree).resolve()
    agg: dict = {c: defaultdict(lambda: defaultdict(int)) for c in ("v2", "v3_web_off", "v3")}
    extra = defaultdict(int)
    for seed in a.seeds:
        web = build_web(seed)
        bg = build(seed, 40, positives=False)
        web_ids = sorted(web.labels)
        ids = out / f"ids-{seed}.json"
        ids.write_text(json.dumps(web_ids + sorted(bg.labels)))
        full = out / f"events-{seed}.jsonl"
        full.write_text("\n".join(json.dumps(e) for e in bg.events + web.events))
        stripped = out / f"events-{seed}.v2.jsonl"
        stripped.write_text("\n".join(json.dumps({k: v for k, v in e.items() if k != "web"}) for e in bg.events + web.events))
        res = {"v2": run(old, stripped, "default", ids), "v3_web_off": run(HERE, full, "no_web", ids), "v3": run(HERE, full, "default", ids)}
        res_nopre = run(HERE, full, "no_prefilter", ids)
        for cond, r in res.items():
            for agent, (kind, grp) in web.labels.items():
                d = agg[cond][grp]
                d["n"] += 1
                lead = r["leads"].get(agent)
                d["lead"] += lead is not None
                if lead:
                    d["class." + str(lead["actor_class"])] += 1
                    d["band." + lead["band"]] += 1
                d["filtered"] += agent in r["filtered_ids"]
            agg[cond]["_bg"]["leads"] += sum(1 for k in r["leads"] if k in bg.labels)
            agg[cond]["_bg"]["n"] += len(bg.labels)
            agg[cond]["_run"]["quarantined"] += r["quarantined"]
        extra["scanner_leads_if_prefilter_off"] += sum(1 for ag, (k, g) in web.labels.items() if g == "commodity_scanner" and ag in res_nopre["leads"])
        extra["bg_leads_same_v2_v3"] += set(k for k in res["v2"]["leads"] if k in bg.labels) == set(k for k in res["v3"]["leads"] if k in bg.labels)
        extra["seeds"] += 1
        extra["prefiltered_agents_v3"] += res["v3"]["prefiltered"]["agents_filtered"]
        extra["prefiltered_events_v3"] += res["v3"]["prefiltered"]["events_filtered"]
        extra["kept_scanner_like_with_goal_evidence"] += res["v3"]["prefiltered"]["kept_scanner_like_with_goal_evidence"]
    summary: dict = {"seeds": a.seeds, "extra": dict(extra), "conditions": {}}
    L = ["# v3 pipeline web-client evaluation (regression check, NOT a benchmark)", "",
         f"Seeds {a.seeds}. Groups and counts per seed: see `rogue_pipeline/web_simulator.py`. `lead` = the client produced a review lead.", ""]
    for cond in ("v2", "v3_web_off", "v3"):
        g = agg[cond]
        rows = []
        L += [f"## {cond}", "", "| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |", "|---|---|---|---|---|---|---|"]
        for grp, kind in GROUPS.items():
            d = g[grp]
            cls = ", ".join(f"{k[6:]}={v}" for k, v in sorted(d.items()) if k.startswith("class."))
            bands = ", ".join(f"{k[5:]}={v}" for k, v in sorted(d.items()) if k.startswith("band."))
            L.append(f"| {grp} | {kind} | {d['n']} | {d['lead']} | {d['filtered']} | {cls} | {bands} |")
            rows.append((grp, kind, dict(d)))
        mim_n = sum(g[m]["n"] for m in MIMICS)
        mim_l = sum(g[m]["lead"] for m in MIMICS)
        mim_n2 = sum(g[m]["n"] for m in MIMICS if m != "mimic_assets")
        mim_l2 = sum(g[m]["lead"] for m in MIMICS if m != "mimic_assets")
        ben_n = g["web_human"]["n"] + g["web_human_no_assets"]["n"]
        ben_l = g["web_human"]["lead"] + g["web_human_no_assets"]["lead"]
        acc = g["accidental_scraper"]
        m = {"mimic_lead_recall": round(mim_l / mim_n, 3), "mimic_lead_recall_excl_mimic_assets_evader": round(mim_l2 / mim_n2, 3),
             "web_benign_lead_fpr": round(ben_l / ben_n, 3), "web_benign_leads": ben_l, "web_benign_n": ben_n,
             "scanner_clients_with_a_lead": g["commodity_scanner"]["lead"], "scanner_clients": g["commodity_scanner"]["n"],
             "scanner_clients_filtered": g["commodity_scanner"]["filtered"],
             "accidental_scraper_leads": acc["lead"], "accidental_scraper_n": acc["n"],
             "accidental_scraper_class_goal_directed": acc["class.goal_directed"], "accidental_scraper_class_accidental": acc["class.accidental_scraper"],
             "adaptive_agents_lead_recall": round(sum(g[x]["lead"] for x in ADAPTIVE) / sum(g[x]["n"] for x in ADAPTIVE), 3),
             "scanner_ua_spoof_kept_with_lead": g["scanner_ua_spoof"]["lead"], "background_benign_leads": g["_bg"]["leads"],
             "background_agents": g["_bg"]["n"], "quarantined_total": g["_run"]["quarantined"]}
        summary["conditions"][cond] = {"metrics": m, "groups": {r[0]: r[2] for r in rows}}
        L += ["", "Metrics: " + json.dumps(m), ""]
    L += ["Extra:", "", "`" + json.dumps(dict(extra)) + "`", ""]
    (out / "eval-web.json").write_text(json.dumps(summary, indent=2))
    (out / "eval-web.md").write_text("\n".join(L))
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
