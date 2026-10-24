#!/usr/bin/env python3
"""v5 vs v6 synthetic evaluation (REGRESSION CHECK, NOT A BENCHMARK).

    python scripts/eval_v6.py --v5-tree /path/to/v5/agent-watch --out eval-v6 [--seeds 7 8 9 10 11]

The SAME simulated client population (v3 + v4 + v6 web cohorts from THIS tree's ``agentwatch/webagents.py``, 3 copies each per seed,
plus the legacy synthetic actors) is run against each tree's OWN honeypot and analysed by that tree's own detectors.  In-process
Flask test client, fake clock, no sockets, no network.

HONEST LIMITS: the v6 cohorts and the v6 traps were written by the same author; catching them is expected by construction and is NOT
evidence of real-world efficacy against real VLM agents, patched browsers, real extensions, real device timing or accessibility tools.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
EV4 = HERE / "scripts" / "eval_v4.py"


def _ev4():
    spec = importlib.util.spec_from_file_location("eval_v4_mod", EV4)
    mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
    spec.loader.exec_module(mod)                          # type: ignore[union-attr]
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v5-tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, nargs="*", default=[7, 8, 9, 10, 11])
    args = ap.parse_args()
    os.environ.setdefault("AGENT_WATCH_SALT_FILE", str(Path(tempfile.mkdtemp(prefix="aw-eval-salt-")) / "scrub.salt"))
    ev = _ev4()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    trees = {"v5": Path(args.v5_tree).resolve(), "v6": HERE}
    pooled: dict = {t: [] for t in trees}
    for seed in args.seeds:
        for tag, tree in trees.items():
            d = out / f"seed{seed}" / tag
            subprocess.run([sys.executable, str(EV4), "--v2-tree", str(tree), "--out", str(out), "--_seed", str(seed), "--_gen", str(d),
                            "--_tree", str(tree)], check=True, env={**os.environ, "PYTHONPATH": str(tree)})
            truth = json.loads((d / "truth.json").read_text())
            files = [d / "base" / "access.log", d / "base" / "gateway.jsonl", d / "base" / "leads.jsonl", d / "web-leads.jsonl",
                     d / "base" / "leads.jsonl.access.jsonl", d / "web-leads.jsonl.access.jsonl"]
            pooled[tag].append(ev.rows_for(ev.analyze(tree, files, out / f"seed{seed}-{tag}.json"), truth))
    results = {tag: ev.pool(rows) for tag, rows in pooled.items()}
    (out / "eval-v6.json").write_text(json.dumps(results, indent=2))
    names = list(results["v6"]["variants"])
    lines = ["# agent-watch v5 vs v6 (same simulated clients, each tree's own honeypot + detectors)", "",
             f"Seeds {args.seeds}; 3 copies per cohort per seed (n=15). SAME-AUTHOR SYNTHETIC: not a benchmark.", "",
             "| cohort | truth | n | v5 alerted (>=medium) | v6 alerted | v5 label correct | v6 label correct | v5 labels | v6 labels |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name in names:
        a, b = results["v5"]["variants"].get(name, {}), results["v6"]["variants"][name]
        lines.append(f"| {name} | {b['truth']} | {b['n']} | {a.get('alerted', '-')} | {b['alerted']} | {a.get('label_correct', '-')} | "
                     f"{b['label_correct']} | {json.dumps(a.get('labels', {}))} | {json.dumps(b['labels'])} |")
    lines += ["", f"Legacy actors label accuracy: v5 {results['v5']['legacy']}, v6 {results['v6']['legacy']}", ""]
    (out / "eval-v6.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
