#!/usr/bin/env python3
"""v5 vs v6 on THE SAME synthetic traffic.  REGRESSION CHECK ON DATA WRITTEN BY THE SAME AUTHOR AS THE DETECTORS - NOT A BENCHMARK.

    python scripts/eval_v6.py --v5-tree /workspace/v5-snapshot/rogue-ai-pipeline --out eval-v6-out [--seeds 0 1 2 3 4] [--levels 0.0 1.0]
    python scripts/eval_v6.py ... --only web|core
    (``scripts/eval_web.py --v5-tree ...`` runs the web part of this script)

core  the core simulator with every v6 cohort (``build(seed, 60, evasive, extended=True, v6=True)``) at each evasiveness level.  Each tree
      runs with ITS OWN frozen evaluation context (v5: benign reference without the v6 benign cohorts; v6: with them); the v5 tree sees
      the events with the v6-only ``arg_entropy`` field removed (its strict schema would quarantine them otherwise).
web   per seed: 40 benign background assistants (positives off, declared suppression policy) + every web cohort of
      ``build_web(seed, v6=True)``.  v5 sees ``to_v5_format`` (3-key beacons, no v6 fields, v6-only decoys removed); v6 also runs with the
      corroboration gate OFF and in its strictest form, and every benign lead of the gate-off run is attributed to the layer that was
      necessary for it (``rogue_pipeline/attribution.py``).
Both: per-cohort lead counts pooled over seeds, FPR over ALL benign agents, per-layer attribution, guardrail check.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from rogue_pipeline.attribution import attribute      # noqa: E402
from rogue_pipeline.config import FusionCfg           # noqa: E402
from rogue_pipeline.simulator import build            # noqa: E402
from rogue_pipeline.web_simulator import build_web, to_v5_format   # noqa: E402

FCFG = FusionCfg()
V6_ONLY_CORE_KEYS = ("arg_entropy",)
CONDS = ["v5", "v5_no_gate", "v6", "v6_no_gate", "v6_strict_gate"]


def _sub(tree: Path, args: List[str]) -> str:
    r = subprocess.run([sys.executable] + args, cwd=tree, env={**os.environ, "PYTHONPATH": str(tree)}, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"{tree}: {r.stderr[-3000:]}")
    return r.stdout


def _dump(path: Path, events: List[Dict[str, Any]]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events))


def _new() -> Dict[str, Dict[str, Dict[str, int]]]:
    return {c: defaultdict(lambda: defaultdict(int)) for c in CONDS}


def _count(per: Dict[str, Any], c: str, labels: Dict[str, Tuple[str, str]], leads: Any, rename: Optional[Dict[str, str]] = None) -> None:
    for a, (k, g) in labels.items():
        grp = (rename or {}).get(a, g)
        hit = a in leads
        per[c][grp]["n"] += 1
        per[c][grp]["lead"] += hit
        pop = {"benign": "_benign", "positive": "_positive"}.get(k)    # accidental scrapers / commodity scanners are neither
        if pop:
            per[c][pop]["n"] += 1
            per[c][pop]["lead"] += hit


def core(v5: Path, out: Path, seeds: List[int], levels: List[float]) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    jobs: Dict[str, List[Dict[str, Any]]] = {"v5": [], "v6": []}
    labels: Dict[Tuple[int, float], Dict[str, Tuple[str, str]]] = {}
    for lv in levels:
        for s in seeds:
            d = build(s, 60, lv, extended=True, v6=True)
            labels[(s, lv)] = d.labels
            tag = f"core-{s}-{lv}"
            (out / f"{tag}.policy.json").write_text(json.dumps(d.policy.model_dump()))
            (out / f"{tag}.ids.json").write_text(json.dumps(sorted(d.labels)))
            _dump(out / f"{tag}.v6.jsonl", d.events)
            _dump(out / f"{tag}.v5.jsonl", [{k: v for k, v in e.items() if k not in V6_ONLY_CORE_KEYS} for e in d.events])
            for t in ("v5", "v6"):
                jobs[t].append({"events": str(out / f"{tag}.{t}.jsonl"), "policy": str(out / f"{tag}.policy.json"),
                                "ids": str(out / f"{tag}.ids.json"), "seed": s, "out": str(out / f"{tag}.{t}.result.json")})
    for t in jobs:
        (out / f"manifest-{t}.json").write_text(json.dumps(jobs[t]))
    trees = {"v5": v5, "v6": HERE}
    with ThreadPoolExecutor(2) as ex:
        list(ex.map(lambda t: _sub(trees[t], [str(HERE / "scripts" / "_run_core.py"), str(out / f"manifest-{t}.json")]), ["v5", "v6"]))
    result: Dict[str, Any] = {"levels": {}}
    kinds = {g: k for lab in labels.values() for (k, g) in lab.values()}
    for lv in levels:
        per = _new()
        att: Counter = Counter()
        guard, quar = True, 0
        for s in seeds:
            lab = labels[(s, lv)]
            r5 = json.load(open(out / f"core-{s}-{lv}.v5.result.json"))
            r6 = json.load(open(out / f"core-{s}-{lv}.v6.result.json"))
            sets = {"v5": set(r5["leads"]), "v5_no_gate": set(r5["no_gate"]), "v6": set(r6["leads"]), "v6_no_gate": set(r6["no_gate"]),
                    "v6_strict_gate": set(r6["strict_gate"])}
            guard = guard and r5["guardrail_ok"] and r6["guardrail_ok"]
            quar += r5["quarantined"] + r6["quarantined"]
            for c, st in sets.items():
                _count(per, c, lab, st)
            for a, det, blocked in r6["attribution"]:
                k, g = lab.get(a, ("?", "?"))
                if k == "benign":
                    att[f"{g} | {det}" + (" | BLOCKED by gate" if blocked else " | lead")] += 1
        result["levels"][str(lv)] = {"per_group": {c: {g: dict(v) for g, v in sorted(d.items())} for c, d in per.items()},
                                     "benign_attribution_v6_gate_off": dict(sorted(att.items())), "guardrail_ok": guard, "quarantined": quar}
    result["kinds"] = kinds
    return result


def web(v5: Path, out: Path, seeds: List[int]) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    per = _new()
    att: Counter = Counter()
    blocked_pos: Counter = Counter()
    kinds: Dict[str, str] = {"background_benign": "benign"}
    quar = 0
    for s in seeds:
        w = build_web(s, v6=True)
        bg = build(s, 40, positives=False)
        (out / f"web-{s}.policy.json").write_text(json.dumps(bg.policy.model_dump()))
        (out / f"web-{s}.ids.json").write_text(json.dumps(sorted(w.labels) + sorted(bg.labels)))
        _dump(out / f"web-{s}.v6.jsonl", bg.events + w.events)
        _dump(out / f"web-{s}.v5.jsonl", bg.events + to_v5_format(w.events))

        def args(t: str, mode: str, s: int = s) -> List[str]:
            return [str(HERE / "scripts" / "_run_events.py"), str(out / f"web-{s}.{t}.jsonl"), mode, str(out / f"web-{s}.ids.json"),
                    str(out / f"web-{s}.policy.json")]
        tasks = {"v5": (v5, args("v5", "default")), "v5_no_gate": (v5, args("v5", "no_gate")), "v6": (HERE, args("v6", "default")),
                 "v6_no_gate": (HERE, args("v6", "no_gate")), "v6_strict_gate": (HERE, args("v6", "strict_gate"))}
        with ThreadPoolExecutor(3) as ex:
            res = dict(zip(tasks, ex.map(lambda kv: json.loads(_sub(kv[0], kv[1]).strip().splitlines()[-1]), tasks.values())))
        labels = {**bg.labels, **w.labels}
        rename = {a: "background_benign" for a in bg.labels}
        for a, (k, g) in w.labels.items():
            kinds[g] = k
        for c, r in res.items():
            quar += r["quarantined"]
            _count(per, c, labels, r["leads"], rename)
        kept = set(res["v6"]["leads"])
        for a, lead in res["v6_no_gate"]["leads"].items():
            k, g = labels.get(a, ("?", "?"))
            grp = rename.get(a, g)
            if k == "benign":
                att[f"{grp} | {attribute(lead, FCFG)['detail']}" + (" | lead" if a in kept else " | BLOCKED by gate")] += 1
            elif a not in kept:
                blocked_pos[f"{grp} | {attribute(lead, FCFG)['detail']}"] += 1
    return {"per_group": {c: {g: dict(v) for g, v in sorted(d.items())} for c, d in per.items()}, "kinds": kinds,
            "benign_attribution_v6_gate_off": dict(sorted(att.items())), "positives_blocked_by_v6_gate": dict(sorted(blocked_pos.items())),
            "quarantined_total": quar}


def md_table(per: Dict[str, Any], kinds: Dict[str, str], conds: List[str] = CONDS) -> List[str]:
    lines = ["| cohort | kind | " + " | ".join(conds) + " |", "|---|---|" + "---|" * len(conds)]
    groups = sorted({g for c in conds for g in per[c] if not g.startswith("_")}, key=lambda g: (kinds.get(g, "?") != "positive", g))
    for g in groups:
        lines.append(f"| {g} | {kinds.get(g, '?')} | " + " | ".join(f"{per[c].get(g, {}).get('lead', 0)}/{per[c].get(g, {}).get('n', 0)}" for c in conds) + " |")
    for pop in ("_positive", "_benign"):
        lines.append(f"| **all {pop[1:]}** | | " + " | ".join(
            f"{per[c][pop]['lead']}/{per[c][pop]['n']} ({per[c][pop]['lead'] / max(1, per[c][pop]['n']):.3f})" for c in conds) + " |")
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v5-tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, nargs="*", default=[0, 1, 2, 3, 4])
    ap.add_argument("--levels", type=float, nargs="*", default=[0.0, 1.0])
    ap.add_argument("--only", choices=["web", "core"], default=None)
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    v5 = Path(a.v5_tree).resolve()
    summary: Dict[str, Any] = {"disclaimer": "SYNTHETIC DATA, same author as the detectors. Regression check, not a benchmark.", "seeds": a.seeds}
    md = ["# v5 vs v6 on the same synthetic traffic (regression check, NOT a benchmark)", ""]
    if a.only in (None, "web"):
        wr = web(v5, out / "web", a.seeds)
        summary["web"] = wr
        md += ["## Web cohorts (leads / agents, pooled over seeds)", ""] + md_table(wr["per_group"], wr["kinds"])
        md += ["", f"quarantined (all runs): {wr['quarantined_total']}", "", "### Benign leads of v6 with the gate OFF, attributed (necessary layer)", ""]
        md += [f"- {k}: {v}" for k, v in wr["benign_attribution_v6_gate_off"].items()]
        md += ["", "### Positives the v6 gate blocked", ""] + [f"- {k}: {v}" for k, v in wr["positives_blocked_by_v6_gate"].items()] + [""]
    if a.only in (None, "core"):
        cr = core(v5, out / "core", a.seeds, a.levels)
        summary["core"] = cr
        for lv, r in cr["levels"].items():
            md += [f"## Core simulator, evasiveness {lv} (leads / agents, pooled over seeds)", ""]
            md += md_table(r["per_group"], cr["kinds"])
            md += ["", f"guardrail ok: {r['guardrail_ok']}; quarantined: {r['quarantined']}", "", "### Benign leads of v6 with the gate OFF, attributed", ""]
            md += [f"- {k}: {v}" for k, v in r["benign_attribution_v6_gate_off"].items()] + [""]
    (out / "eval_v6.json").write_text(json.dumps(summary, indent=2))
    (out / "eval_v6.md").write_text("\n".join(md))
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
