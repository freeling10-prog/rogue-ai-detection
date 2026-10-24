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
    spec = importlib.util.spec_from_file_location(f"v4_{name}", HERE / "agentwatch" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
    sys.modules[spec.name] = mod                          # type: ignore[union-attr]
    spec.loader.exec_module(mod)                          # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------------------------------- generation
def gen(tree: Path, out: Path, seed: int) -> None:
    """Run in a subprocess whose sys.path starts with *tree*: generate the legacy actors + web actors (v3 + v4 variants) against its honeypot."""
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
    for variant, label, note, copies, benign in web.WEB_PLAN + getattr(web, 'WEB_PLAN_V4', []) + getattr(web, 'WEB_PLAN_V6', []):
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
def analyze(tree: Path, files: list[Path], out_json: Path) -> dict:
    cmd = [sys.executable, "-m", "agentwatch", "analyze", *map(str, files), "--json-out", str(out_json)]
    env = {**os.environ, "PYTHONPATH": str(tree), "NO_COLOR": "1"}
    subprocess.run(cmd, cwd=tree, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return json.loads(out_json.read_text())


def best_by_ip(report: dict) -> dict:
    by: dict = {}
    for s in report["sessions"]:
        if s["ip"] not in by or s["requests"] > by[s["ip"]]["requests"]:
            by[s["ip"]] = s
    return by


def rows_for(report: dict, truth: list[dict]) -> list[dict]:
    by = best_by_ip(report)
    out = []
    for t in truth:
        s = by.get(t["ip"])
        out.append({"name": t["name"], "truth": t["label"], "benign": t.get("benign", False), "seen": s is not None,
                    "label": s["label"] if s else None, "severity": s["severity"] if s else None,
                    "actor": (s.get("actor_type") if s else None), "agent": s["agent_score"] if s else None})
    return out


def pool(rows_by_seed: list[list[dict]]) -> dict:
    """Per web variant, pooled over seeds."""
    med = SEV.index("medium")
    variants: dict = {}
    legacy = {"n": 0, "label_ok": 0}
    for rows in rows_by_seed:
        for r in rows:
            if not r["name"].startswith("web:"):
                legacy["n"] += 1
                legacy["label_ok"] += bool(r["seen"] and r["label"] == r["truth"])
                continue
            v = variants.setdefault(r["name"][4:].split(" #")[0], {"truth": r["truth"], "n": 0, "seen": 0, "label_correct": 0, "alerted": 0,
                                                                "labels": {}, "actors": {}, "severities": {}})
            v["n"] += 1
            v["seen"] += bool(r["seen"])
            v["label_correct"] += bool(r["seen"] and r["label"] == r["truth"])
            v["alerted"] += bool(r["seen"] and SEV.index(r["severity"]) >= med)
            for key, val in (("labels", r["label"]), ("actors", r["actor"]), ("severities", r["severity"])):
                v[key][str(val)] = v[key].get(str(val), 0) + 1
    return {"variants": variants, "legacy": legacy}


EVADERS = ("mimic_browser_stealth", "mimic_header_forger")


def summary(p: dict) -> dict:
    v = p["variants"]
    g = lambda name, key: v.get(name, {}).get(key, 0)                                                  # noqa: E731
    frac = lambda a, b: round(a / b, 3) if b else None                                                 # noqa: E731
    mims = [k for k in v if k.startswith("mimic")]
    humans = [k for k in v if v[k]["truth"] == "human"]
    easy = [k for k in humans if k in ("human", "human_images_blocked", "human_js_off")]
    return {
        "mimic_assets_recall_alerted": frac(g("mimic_assets", "alerted"), g("mimic_assets", "n")),
        "mimic_assets_recall_label_agent": frac(g("mimic_assets", "label_correct"), g("mimic_assets", "n")),
        "mimic_linked_label_agent": frac(g("mimic_linked", "label_correct"), g("mimic_linked", "n")),
        "mimic_linked_alerted": frac(g("mimic_linked", "alerted"), g("mimic_linked", "n")),
        "mimic_linked_actor_types": v.get("mimic_linked", {}).get("actors"),
        "images_blocked_human_alerted": g("human_no_assets", "alerted"), "images_blocked_human_n": g("human_no_assets", "n"),
        "images_only_blocked_human_alerted": g("human_images_blocked", "alerted"), "images_only_blocked_human_n": g("human_images_blocked", "n"),
        "mimic_recall_alerted_all": frac(sum(g(k, "alerted") for k in mims), sum(g(k, "n") for k in mims)),
        "mimic_recall_alerted_excluding_by_construction_evaders": frac(
            sum(g(k, "alerted") for k in mims if k not in EVADERS), sum(g(k, "n") for k in mims if k not in EVADERS)),
        "human_alerted_easy": sum(g(k, "alerted") for k in easy), "human_easy_n": sum(g(k, "n") for k in easy),
        "human_alerted_all": sum(g(k, "alerted") for k in humans), "human_n": sum(g(k, "n") for k in humans),
        "legacy_label_accuracy": frac(p["legacy"]["label_ok"], p["legacy"]["n"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v2-tree", "--old-tree", dest="v2", required=True, help="path to the v2 agent-watch tree")
    ap.add_argument("--v3-tree", dest="v3", default=None, help="path to the v3 agent-watch tree (optional)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, nargs="*", default=[7, 8, 9, 10, 11])
    ap.add_argument("--_gen", help=argparse.SUPPRESS)
    ap.add_argument("--_tree", help=argparse.SUPPRESS)
    ap.add_argument("--_seed", type=int, help=argparse.SUPPRESS)
    args = ap.parse_args()
    os.environ.setdefault("AGENT_WATCH_SALT_FILE", str(Path(tempfile.mkdtemp(prefix="aw-eval-salt-")) / "scrub.salt"))
    if args._gen:
        gen(Path(args._tree), Path(args._gen), args._seed)
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    trees = {"v2": Path(args.v2).resolve(), **({"v3": Path(args.v3).resolve()} if args.v3 else {}), "v4": HERE}
    pooled: dict = {c: [] for c in trees}
    for seed in args.seeds:
        truths = {}
        for tag, tree in trees.items():
            d = out / f"seed{seed}" / tag
            subprocess.run([sys.executable, str(Path(__file__).resolve()), "--v2-tree", str(trees["v2"]), "--out", str(out), "--_seed", str(seed),
                            "--_gen", str(d), "--_tree", str(tree)], check=True, env={**os.environ, "PYTHONPATH": str(tree)})
            truths[tag] = json.loads((d / "truth.json").read_text())
        base = lambda d: [d / "base" / "access.log", d / "base" / "gateway.jsonl", d / "base" / "leads.jsonl", d / "web-leads.jsonl"]  # noqa: E731
        mirror = lambda d: [d / "base" / "leads.jsonl.access.jsonl", d / "web-leads.jsonl.access.jsonl"]                              # noqa: E731
        for tag, tree in trees.items():
            d = out / f"seed{seed}" / tag
            files = base(d) + ([] if tag == "v2" else mirror(d))
            pooled[tag].append(rows_for(analyze(tree, files, out / f"seed{seed}-{tag}.json"), truths[tag]))
    results = {tag: {"summary": summary(pool(rows)), **pool(rows)} for tag, rows in pooled.items()}
    (out / "eval-v4.json").write_text(json.dumps(results, indent=2))
    lines = ["# v2 / v3 / v4 agent-watch synthetic evaluation (regression check, NOT a benchmark)", "",
             f"Seeds {args.seeds}. Same simulated client population (v3 + v4 variants, 3 copies each per seed) against each version's own honeypot "
             "and detectors.  Same author wrote clients and detectors; mimic variants were built against the rules; n is small; contact is not intent.", ""]
    for tag, res in results.items():
        lines += [f"## {tag}", "", "Summary: " + json.dumps(res["summary"]), ""]
        lines += ["| variant | truth | n | seen | label correct | alerted >= medium | labels | actor types |", "|---|---|---|---|---|---|---|---|"]
        for name, v in res["variants"].items():
            lines.append(f"| {name} | {v['truth']} | {v['n']} | {v['seen']} | {v['label_correct']} | {v['alerted']} | "
                         f"{json.dumps(v['labels'])} | {json.dumps(v['actors'])} |")
        lines.append("")
    (out / "eval-v4.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
