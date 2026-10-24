#!/usr/bin/env python3
"""Web-client evaluation, v2 vs v3 vs v4.  REGRESSION CHECK ON SYNTHETIC DATA WRITTEN BY THE SAME AUTHOR - NOT A BENCHMARK.

    python scripts/eval_web.py --v2-tree /path/to/v2 --v3-tree /path/to/v3 --out eval-web-out [--seeds 0 1 2 3 4]
    python scripts/eval_web.py --v5-tree /path/to/v5 --out eval-web-v6-out     # v6: v5 vs v6 on v6 traffic (see eval_v6.py)
    (--old-tree is accepted as a synonym of --v2-tree; without --v3-tree the v3 column is skipped)

Per seed it builds benign background agents (the v1 simulator, positives off, WITH its declared suppression policy) + the web
clients of ``rogue_pipeline/web_simulator.py`` and runs each pipeline version in its own subprocess:

  v2             old tree, ``web`` block stripped (v2 cannot represent it)
  v3             v3 tree on the SAME traffic in v3 format (no v4 fields, no beacon requests, ARIA hit = unknown URL)
  v4_no_gate     this tree with the corroboration gate OFF (what v4 rules/collector give before the gate)
  v4             this tree, defaults
  v3_nopolicy / v4_nopolicy
                 the v3 harness as it was shipped: NO declared suppression groups, which makes orchestrator-pool clusters look like
                 collusion.  Reported separately because it is a harness artifact, not a detector property.

Per-layer attribution (``rogue_pipeline/attribution.py``): leave-one-out on the noisy-or fusion says which layer was necessary
for each benign lead (Isolation Forest, sequence model, a named rule, the coordination graph and its edge kinds, or a floor).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from rogue_pipeline.attribution import attribute      # noqa: E402
from rogue_pipeline.config import FusionCfg           # noqa: E402
from rogue_pipeline.simulator import build            # noqa: E402
from rogue_pipeline.web_simulator import GROUPS, V4_GROUPS, build_web, to_v3_format   # noqa: E402

ALL_GROUPS = {**GROUPS, **V4_GROUPS}
MIMICS = ("mimic_basic", "mimic_linked", "mimic_assets", "mimic_schema")
V4_MIMICS = ("mimic_linked_nosec", "mimic_browser_webdriver", "mimic_browser_stealth", "mimic_aria", "mimic_header_forger")
HUMANS = ("web_human", "web_human_no_assets", "human_images_blocked", "human_js_off")
HARD_HUMANS = ("human_beacon_blocked", "human_no_assets_nosec")
ADAPTIVE = ("mcp_agent", "decoy_explorer", "scanner_ua_spoof")
CONDS = ("v2", "v3", "v4_no_gate", "v4", "v3_nopolicy", "v4_nopolicy")
FCFG = FusionCfg()


def run(tree: Path, events: Path, mode: str, ids: Path, policy: Optional[Path]) -> dict:
    cmd = [sys.executable, str(HERE / "scripts" / "_run_events.py"), str(events), mode, str(ids)] + ([str(policy)] if policy else [])
    out = subprocess.run(cmd, cwd=tree, env={**os.environ, "PYTHONPATH": str(tree)}, check=True, capture_output=True, text=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def _rate(n: int, d: int) -> Any:
    return round(n / d, 3) if d else None


def main() -> int:
    if "--v5-tree" in sys.argv:                         # v6: v5 vs v6 on the same v6 web traffic (scripts/eval_v6.py, web part)
        sys.path.insert(0, str(HERE / "scripts"))
        import eval_v6                                  # noqa: E402
        return int(eval_v6.main(["--only", "web"] + sys.argv[1:]))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v2-tree", "--old-tree", dest="v2", required=True)
    ap.add_argument("--v3-tree", dest="v3", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, nargs="*", default=[0, 1, 2, 3, 4])
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    trees = {"v2": Path(a.v2).resolve(), "v3": Path(a.v3).resolve() if a.v3 else None}
    conds = [c for c in CONDS if not (c.startswith("v3") and trees["v3"] is None)]
    agg: Dict[str, Any] = {c: defaultdict(lambda: defaultdict(int)) for c in conds}
    attr: Dict[str, Counter] = {c: Counter() for c in conds}            # (population, layer detail) -> n
    blocked: Counter = Counter()
    blocked_pos: Counter = Counter()
    extra: Dict[str, int] = defaultdict(int)
    for seed in a.seeds:
        web = build_web(seed, v4=True)
        bg = build(seed, 40, positives=False)
        pol = out / f"policy-{seed}.json"
        pol.write_text(json.dumps(bg.policy.model_dump()))
        ids = out / f"ids-{seed}.json"
        ids.write_text(json.dumps(sorted(web.labels) + sorted(bg.labels)))
        v4_ev = out / f"events-{seed}.jsonl"
        v4_ev.write_text("\n".join(json.dumps(e) for e in bg.events + web.events))
        v3_events = bg.events + to_v3_format(web.events)
        v3_ev = out / f"events-{seed}.v3.jsonl"
        v3_ev.write_text("\n".join(json.dumps(e) for e in v3_events))
        v2_ev = out / f"events-{seed}.v2.jsonl"
        v2_ev.write_text("\n".join(json.dumps({k: v for k, v in e.items() if k != "web"}) for e in v3_events))
        res: Dict[str, dict] = {"v2": run(trees["v2"], v2_ev, "default", ids, pol)}
        if trees["v3"]:
            res["v3"] = run(trees["v3"], v3_ev, "default", ids, pol)
            res["v3_nopolicy"] = run(trees["v3"], v3_ev, "default", ids, None)
        res["v4_no_gate"] = run(HERE, v4_ev, "no_gate", ids, pol)
        res["v4"] = run(HERE, v4_ev, "default", ids, pol)
        res["v4_nopolicy"] = run(HERE, v4_ev, "default", ids, None)
        strict = run(HERE, v4_ev, "strict_gate", ids, pol)
        nopre = run(HERE, v4_ev, "no_prefilter", ids, pol)
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
            for k, lead in r["leads"].items():
                if k in bg.labels:
                    agg[cond]["_bg"]["leads"] += 1
                    attr[cond][("background_benign", attribute(lead, FCFG)["detail"])] += 1
                elif k in web.labels and web.labels[k][0] == "benign":
                    attr[cond][("web_benign", attribute(lead, FCFG)["detail"])] += 1
            agg[cond]["_bg"]["n"] += len(bg.labels)
            agg[cond]["_run"]["quarantined"] += r["quarantined"]
        for k, g in res["v4"]["gate_blocked"].items():
            pop = "background_benign" if k in bg.labels else ("web_benign" if web.labels.get(k, ("",))[0] == "benign" else "positive_or_other")
            if pop == "positive_or_other":
                blocked_pos[(web.labels.get(k, ("", "?"))[1], attribute({**g}, FCFG)["detail"])] += 1
            else:
                blocked[(pop, attribute({**g}, FCFG)["detail"])] += 1
        for k, lead in strict["leads"].items():
            if k in web.labels:
                agg.setdefault("v4_strict_gate", defaultdict(lambda: defaultdict(int)))[web.labels[k][1]]["lead"] += 1
        for agent, (kind, grp) in web.labels.items():
            agg.setdefault("v4_strict_gate", defaultdict(lambda: defaultdict(int)))[grp]["n"] += 1
        agg["v4_strict_gate"]["_bg"]["leads"] += sum(1 for k in strict["leads"] if k in bg.labels)
        extra["scanner_leads_if_prefilter_off"] += sum(1 for ag, (k, g) in web.labels.items() if g == "commodity_scanner" and ag in nopre["leads"])
        extra["seeds"] += 1
        extra["prefiltered_agents_v4"] += res["v4"]["prefiltered"]["agents_filtered"]
        extra["kept_scanner_like_with_goal_evidence"] += res["v4"]["prefiltered"]["kept_scanner_like_with_goal_evidence"]
    all_conds = conds + ["v4_strict_gate"]
    summary: Dict[str, Any] = {"seeds": a.seeds, "extra": dict(extra), "conditions": {}, "attribution": {}, "gate_blocked": {}}

    def metrics(g: Any, cond: str) -> Dict[str, Any]:
        has4 = g["human_images_blocked"]["n"] > 0
        mims = MIMICS + (V4_MIMICS if has4 else ())
        ml = sum(g[m]["lead"] for m in mims); mn = sum(g[m]["n"] for m in mims)
        hum = [h for h in HUMANS if g[h]["n"]]
        hard = [h for h in HARD_HUMANS if g[h]["n"]]
        acc = g["accidental_scraper"]
        return {"mimic_lead_recall_all": _rate(ml, mn), "mimic_cohorts": len(mims),
                "mimic_assets_recall": _rate(g["mimic_assets"]["lead"], g["mimic_assets"]["n"]),
                "mimic_linked_recall_with_sec_fetch_absent_header": _rate(g["mimic_linked"]["lead"], g["mimic_linked"]["n"]),
                "mimic_linked_recall_collector_without_sec_fetch": _rate(g["mimic_linked_nosec"]["lead"], g["mimic_linked_nosec"]["n"]) if has4 else None,
                "images_blocked_human_leads": g["human_images_blocked"]["lead"] if has4 else None,
                "benign_web_humans_with_lead": sum(g[h]["lead"] for h in hum), "benign_web_humans_n": sum(g[h]["n"] for h in hum),
                "hard_negative_humans_with_lead": sum(g[h]["lead"] for h in hard) if hard else None,
                "hard_negative_humans_n": sum(g[h]["n"] for h in hard) if hard else None,
                "scanner_clients_with_a_lead": g["commodity_scanner"]["lead"], "scanner_clients": g["commodity_scanner"]["n"],
                "accidental_scraper_leads": acc["lead"], "accidental_scraper_n": acc["n"],
                "adaptive_agents_lead_recall": _rate(sum(g[x]["lead"] for x in ADAPTIVE), sum(g[x]["n"] for x in ADAPTIVE)),
                "background_benign_leads": g["_bg"]["leads"], "background_agents": g["_bg"]["n"]}

    L = ["# Web-client evaluation v2 / v3 / v4 (regression check on synthetic data, NOT a benchmark)", "",
         f"Seeds {a.seeds}. Groups and counts per seed: `rogue_pipeline/web_simulator.py` (v3 groups + v4 groups). Same author wrote "
         "simulator and rules; the mimic variants were written with the rules in mind. `lead` = the client produced a review lead. "
         "Contact/behaviour is not intent. v2/v3 columns see the same traffic in the format their collector could record.", ""]
    for cond in all_conds:
        g = agg[cond]
        if cond == "v4_strict_gate":
            continue
        L += [f"## {cond}", "", "| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |", "|---|---|---|---|---|---|---|"]
        rows = []
        for grp, kind in ALL_GROUPS.items():
            d = g[grp]
            if not d["n"]:
                continue
            cls = ", ".join(f"{k[6:]}={v}" for k, v in sorted(d.items()) if k.startswith("class."))
            bands = ", ".join(f"{k[5:]}={v}" for k, v in sorted(d.items()) if k.startswith("band."))
            L.append(f"| {grp} | {kind} | {d['n']} | {d['lead']} | {d['filtered']} | {cls} | {bands} |")
            rows.append((grp, dict(d)))
        m = metrics(g, cond)
        summary["conditions"][cond] = {"metrics": m, "groups": dict(rows)}
        L += ["", "Metrics: " + json.dumps(m), ""]
    sg = agg["v4_strict_gate"]
    ms = metrics(sg, "v4_strict_gate") if sg else {}
    summary["conditions"]["v4_strict_gate"] = {"metrics": {k: v for k, v in ms.items() if k in ("mimic_lead_recall_all", "mimic_assets_recall")},
                                              "background_benign_leads": sg["_bg"]["leads"]}
    L += ["## Per-layer attribution of benign leads (leave-one-out on the fusion; see rogue_pipeline/attribution.py)", "",
          "Counts pooled over seeds; `population` = what the client was.  `layer detail` = the layer(s) the lead needed.", "",
          "| condition | population | layer detail | leads |", "|---|---|---|---|"]
    for cond in conds:
        for (pop, det), n in sorted(attr[cond].items()):
            L.append(f"| {cond} | {pop} | {det} | {n} |")
            summary["attribution"].setdefault(cond, {}).setdefault(pop, {})[det] = n
    L += ["", "### Candidates the v4 corroboration gate blocked (benign)", "", "| population | layer detail | blocked |", "|---|---|---|"]
    for (pop, det), n in sorted(blocked.items()):
        L.append(f"| {pop} | {det} | {n} |")
        summary["gate_blocked"].setdefault(pop, {})[det] = n
    L += ["", "### Candidates the v4 corroboration gate blocked (web POSITIVES = recall lost to the gate)", "", "| group | layer detail | blocked |", "|---|---|---|"]
    for (grp, det), n in sorted(blocked_pos.items()):
        L.append(f"| {grp} | {det} | {n} |")
        summary["gate_blocked"].setdefault("positives", {})[f"{grp}|{det}"] = n
    L += ["", f"Strict gate (every non-floor lead needs 2 families; no solo rule/graph exception): background benign leads "
          f"{sg['_bg']['leads']}, mimic recall {ms.get('mimic_lead_recall_all')}.", "", "Extra:", "", "`" + json.dumps(dict(extra)) + "`", ""]
    (out / "eval-web.json").write_text(json.dumps(summary, indent=2))
    (out / "eval-web.md").write_text("\n".join(L))
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
