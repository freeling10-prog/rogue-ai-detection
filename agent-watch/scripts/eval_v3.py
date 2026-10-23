#!/usr/bin/env python3
"""v3 synthetic evaluation: before/after on the same simulated clients (REGRESSION CHECK, NOT A BENCHMARK).

    python scripts/eval_v3.py --old-tree /path/to/v2/agent-watch --out eval-out [--seed 7]

What it does (everything in-process or loopback-free: the honeypot app is driven through Flask's test client with a fake
clock, no sockets, no network):

1. For each source tree (the old v2 tree and this v3 tree) it generates the original 20 synthetic actors plus the v3 web
   clients (browsers, scrapers, four mimic variants, see ``agentwatch/webagents.py``) against THAT tree's own honeypot.
2. It analyzes the result under four conditions and scores them against the simulated ground truth.

Conditions
  C1  v2 code + v2 honeypot, logs + leads              (what the live demo saw; the mimic leaves nothing)
  C2  v3 code + v3 honeypot, logs + leads              (v3 decoys/labelling, but WITHOUT the mirrored access stream)
  C3  v3 mirror visible, new detectors + floors OFF    (passive features see every request; nothing new scores them)
  C4  v3 full                                          (mirror + asset starvation + unlinked jump + schema param + floors)

Honest limits: the simulated clients were written by the same author as the detectors; each mimic is an attempt to look
human written with the detectors in mind; n is small (1-3 copies per variant); one fixed seed; ``mimic_assets`` evades by
construction and ``human_no_assets`` is indistinguishable from ``mimic_linked`` on this evidence.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SEV = ("info", "low", "medium", "high", "critical")
T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)


def load_new_module(name: str):
    spec = importlib.util.spec_from_file_location(f"v3_{name}", HERE / "agentwatch" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
    sys.modules[spec.name] = mod                          # type: ignore[union-attr]
    spec.loader.exec_module(mod)                          # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------------------------------- generation
def gen(tree: Path, out: Path, seed: int) -> None:
    """Run in a subprocess whose sys.path starts with *tree*: generate the legacy actors + web actors against its honeypot."""
    sys.path.insert(0, str(tree))
    from agentwatch.honeypot import create_honeypot_app
    from agentwatch.synthetic import generate_demo
    web = load_new_module("webagents")
    import random
    out.mkdir(parents=True, exist_ok=True)
    art = generate_demo(out / "base", seed=seed)
    truth = [t.__dict__ for t in art["truth"]]
    state = {"t": T0}
    leads = out / "web-leads.jsonl"
    leads.write_text("")
    app = create_honeypot_app(leads, seed=f"eval-{seed}", clock=lambda: state["t"])
    client = app.test_client()
    rng = random.Random(seed)
    n = 0
    for variant, label, note, copies, benign in web.WEB_PLAN:
        for k in range(copies):
            ip = web.actor_ip(n, label)
            now = {"t": 600.0 + 40 * n}
            pace = web.pace_for(variant, rng)

            def advance(prev: int, now=now, pace=pace) -> None:
                now["t"] += pace(prev)
                state["t"] = T0 + timedelta(seconds=now["t"])

            def fetch(method, path, headers, body, ip=ip):
                r = client.open(path, method=method, headers=headers, data=body, environ_overrides={"REMOTE_ADDR": ip})
                return r.status_code, r.get_data(as_text=True)

            web.run_web_client(fetch, variant, before_step=advance)
            truth.append({"name": f"web:{variant} #{k + 1}", "label": label, "ip": ip, "note": note, "benign": benign})
            n += 1
    (out / "truth.json").write_text(json.dumps(truth, indent=2))


# ---------------------------------------------------------------------------------------------------- analysis
def analyze(tree: Path, files: list[Path], out_json: Path, config: dict | None = None) -> dict:
    cmd = [sys.executable, "-m", "agentwatch", "analyze", *map(str, files), "--json-out", str(out_json)]
    if config:
        cfg = out_json.with_suffix(".cfg.json")
        cfg.write_text(json.dumps(config))
        cmd += ["--config", str(cfg)]
    env = {**os.environ, "PYTHONPATH": str(tree), "NO_COLOR": "1"}
    subprocess.run(cmd, cwd=tree, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return json.loads(out_json.read_text())


def best_by_ip(report: dict) -> dict:
    by: dict = {}
    for s in report["sessions"]:
        if s["ip"] not in by or s["requests"] > by[s["ip"]]["requests"]:
            by[s["ip"]] = s
    return by


def metrics(report: dict, truth: list[dict]) -> dict:
    by = best_by_ip(report)
    med = SEV.index("medium")
    rows = []
    for t in truth:
        s = by.get(t["ip"])
        rows.append({"name": t["name"], "truth": t["label"], "benign": t.get("benign", False), "seen": s is not None,
                     "label": s["label"] if s else None, "severity": s["severity"] if s else None,
                     "actor": (s.get("actor_type") if s else None), "agent": s["agent_score"] if s else None})
    web = [r for r in rows if r["name"].startswith("web:")]
    legacy = [r for r in rows if not r["name"].startswith("web:")]
    alerted = lambda r: r["seen"] and SEV.index(r["severity"]) >= med                       # noqa: E731
    correct = lambda r: r["seen"] and r["label"] == r["truth"]                               # noqa: E731
    variants: dict = {}
    for r in web:
        v = variants.setdefault(r["name"].split(" #")[0], {"truth": r["truth"], "n": 0, "seen": 0, "label_correct": 0, "alerted": 0,
                                                            "labels": [], "severities": [], "actors": []})
        v["n"] += 1
        v["seen"] += bool(r["seen"])
        v["label_correct"] += bool(correct(r))
        v["alerted"] += bool(alerted(r))
        v["labels"].append(r["label"]); v["severities"].append(r["severity"]); v["actors"].append(r["actor"])
    mim = [r for r in web if r["name"].startswith("web:mimic")]
    mim_no_evader = [r for r in mim if "mimic_assets" not in r["name"]]
    humans = [r for r in rows if r["truth"] == "human"]
    benign_bots = [r for r in rows if r["truth"] == "static_bot" and r["benign"]]
    human_easy = [r for r in humans if "no_assets" not in r["name"]]
    legacy_agents = [r for r in legacy if r["truth"] == "agent"]
    frac = lambda a, b: round(a / b, 3) if b else None                                       # noqa: E731
    return {
        "mimic_n": len(mim),
        "mimic_recall_label_agent": frac(sum(map(bool, map(correct, mim))), len(mim)),
        "mimic_recall_alert_ge_medium": frac(sum(map(bool, map(alerted, mim))), len(mim)),
        "mimic_recall_alert_excluding_mimic_assets": frac(sum(map(bool, map(alerted, mim_no_evader))), len(mim_no_evader)),
        "mimic_seen": frac(sum(r["seen"] for r in mim), len(mim)),
        "human_fpr_alert_all": frac(sum(map(bool, map(alerted, humans))), len(humans)),
        "human_fpr_alert_excluding_hard_negative": frac(sum(map(bool, map(alerted, human_easy))), len(human_easy)),
        "human_n": len(humans), "human_easy_n": len(human_easy),
        "benign_declared_bot_alerted": frac(sum(map(bool, map(alerted, benign_bots))), len(benign_bots)),
        "legacy_label_accuracy": frac(sum(map(bool, map(correct, legacy))), len(legacy)),
        "legacy_agent_recall_label": frac(sum(map(bool, map(correct, legacy_agents))), len(legacy_agents)),
        "scrapers": [{k: r[k] for k in ("name", "label", "severity", "actor", "seen")} for r in web if "scraper_naive" in r["name"]],
        "variants": variants,
    }


def fmt(m: dict) -> str:
    return (f"mimic recall (label=agent) {m['mimic_recall_label_agent']}, mimic alerted>=medium {m['mimic_recall_alert_ge_medium']} "
            f"(excl. evader {m['mimic_recall_alert_excluding_mimic_assets']}), mimic seen {m['mimic_seen']}; "
            f"human alert-FPR {m['human_fpr_alert_all']} (excl. hard negative {m['human_fpr_alert_excluding_hard_negative']}); "
            f"legacy label acc {m['legacy_label_accuracy']}, legacy agent recall {m['legacy_agent_recall_label']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old-tree", required=True, help="path to the v2 agent-watch tree (the 'before' code)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--_gen", help=argparse.SUPPRESS)
    ap.add_argument("--_tree", help=argparse.SUPPRESS)
    args = ap.parse_args()
    os.environ.setdefault("AGENT_WATCH_SALT_FILE", str(Path(tempfile.mkdtemp(prefix="aw-eval-salt-")) / "scrub.salt"))
    if args._gen:
        gen(Path(args._tree), Path(args._gen), args.seed)
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    old, new = Path(args.old_tree).resolve(), HERE
    for tag, tree in (("old", old), ("new", new)):
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--old-tree", str(old), "--out", str(out),
                        "--seed", str(args.seed), "--_gen", str(out / tag), "--_tree", str(tree)],
                       check=True, env={**os.environ, "PYTHONPATH": str(tree)})
    truth_old = json.loads((out / "old" / "truth.json").read_text())
    truth_new = json.loads((out / "new" / "truth.json").read_text())
    assert [t["ip"] for t in truth_old] == [t["ip"] for t in truth_new]
    o, n = out / "old", out / "new"
    base = lambda d: [d / "base" / "access.log", d / "base" / "gateway.jsonl", d / "base" / "leads.jsonl", d / "web-leads.jsonl"]  # noqa: E731
    mirror = lambda d: [d / "base" / "leads.jsonl.access.jsonl", d / "web-leads.jsonl.access.jsonl"]                              # noqa: E731
    conds = {
        "C1 v2 as shipped (logs+leads)": metrics(analyze(old, base(o), out / "c1.json"), truth_old),
        "C2 v3 code, no mirror (logs+leads)": metrics(analyze(new, base(n), out / "c2.json"), truth_new),
        "C3 v3 mirror visible, new detectors+floors OFF": metrics(analyze(
            new, base(n) + mirror(n), out / "c3.json", {"web": {"enabled": False}, "floors": {"enabled": False}}), truth_new),
        "C4 v3 full (mirror + new detectors + floors)": metrics(analyze(new, base(n) + mirror(n), out / "c4.json"), truth_new),
    }
    (out / "eval-v3.json").write_text(json.dumps(conds, indent=2))
    lines = ["# v3 synthetic evaluation (regression check, NOT a benchmark)", ""]
    for k, m in conds.items():
        lines += [f"## {k}", "", fmt(m), ""]
        lines += ["| variant | truth | n | seen | label correct | alerted >= medium | labels | severities | actor types |", "|---|---|---|---|---|---|---|---|---|"]
        for v, d in m["variants"].items():
            lines.append(f"| {v} | {d['truth']} | {d['n']} | {d['seen']} | {d['label_correct']} | {d['alerted']} | "
                         f"{','.join(map(str, d['labels']))} | {','.join(map(str, d['severities']))} | {','.join(map(str, d['actors']))} |")
        lines.append("")
    (out / "eval-v3.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
