#!/usr/bin/env python3
"""Command line entry point for the Rogue AI Detection prototype (SYNTHETIC DATA ONLY).

  python run.py demo                 generate -> analyze -> evaluate -> sample outputs (start here)
  python run.py generate             write data/synthetic_events.jsonl (+ ground truth)
  python run.py analyze              run the pipeline on an events file, write alert log + cases
  python run.py monitor              replay the stream through a sliding window, printing alerts as they fire
  python run.py serve                local web dashboard at http://127.0.0.1:8765
  python run.py export-stix          write a STIX 2.1 bundle from the alert log
  python run.py verify-log           check the alert log hash chain
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from rogue_detect.alerts import AlertLog  # noqa: E402
from rogue_detect.cases import case_for, render_markdown  # noqa: E402
from rogue_detect.collectors import JSONLFileCollector, SyntheticCollector, write_jsonl  # noqa: E402
from rogue_detect.evaluate import evaluate, format_eval  # noqa: E402
from rogue_detect.features import group_by_agent  # noqa: E402
from rogue_detect.intel import to_stix_bundle  # noqa: E402
from rogue_detect.monitor import replay  # noqa: E402
from rogue_detect.pipeline import analyze  # noqa: E402

DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "sample_outputs")
HEADER = ("SYNTHETIC DATA. Every event in this file was fabricated by rogue_detect/synthetic.py.\n"
          "No real platform, person or message was used. Do not treat any agent here as real.")


def _paths(a):
    ev = a.events or os.path.join(DATA, "synthetic_events.jsonl")
    return {"events": ev,
            "roles": ev[:-len(".jsonl")] + ".roles.json" if ev.endswith(".jsonl") else ev + ".roles.json",
            "log": a.log or os.path.join(OUT, "alert_log.jsonl")}


def cmd_generate(a):
    os.makedirs(DATA, exist_ok=True)
    p = _paths(a)
    col = SyntheticCollector(a.seed, stealth=a.stealth)
    evs = col.collect_all()
    n = write_jsonl(evs, p["events"], HEADER)
    with open(p["roles"], "w") as fh:
        json.dump(col.roles, fh, indent=1, sort_keys=True)
    print(f"wrote {n} synthetic events -> {p['events']}\nwrote ground-truth roles -> {p['roles']}")


def _load(a):
    p = _paths(a)
    col = JSONLFileCollector(p["events"], require_synthetic=True)
    evs = col.collect_all()
    if col.rejected:
        print(f"warning: {len(col.rejected)} lines rejected, e.g. {col.rejected[0]}")
    roles = json.load(open(p["roles"])) if os.path.exists(p["roles"]) else None
    return evs, roles, p


def cmd_analyze(a, quiet=False):
    evs, roles, p = _load(a)
    an = analyze(evs)
    os.makedirs(os.path.dirname(p["log"]), exist_ok=True)
    if os.path.exists(p["log"]) and a.fresh:
        os.remove(p["log"])
    log = AlertLog(p["log"])
    new = 0
    for al in an.alerts:
        if not log.has(al):
            log.append(al)
            new += 1
    by_agent = group_by_agent(evs)
    cases = [case_for(al, an, by_agent, roles) for al in an.alerts if al.severity in ("medium", "high")]
    with open(os.path.join(OUT, "flagged_cases.json"), "w") as fh:
        json.dump(cases, fh, indent=1)
    with open(os.path.join(OUT, "flagged_cases.md"), "w") as fh:
        fh.write(render_markdown(cases))
    if not quiet:
        print(f"{len(evs)} events, {len(an.ids)} agents profiled, {len(an.alerts)} alerts ({new} newly logged)")
        for al in an.alerts:
            print(f"  [{al.severity:6s}] {al.kind:17s} {', '.join(al.subjects)[:60]}")
    if roles:
        txt = format_eval(evaluate(an, roles), f"Evaluation ({os.path.basename(p['events'])})")
        print("\n" + txt)
        with open(os.path.join(OUT, "evaluation.txt"), "a") as fh:
            fh.write(txt + "\n\n")
    return an, evs, roles


def cmd_monitor(a):
    evs, roles, p = _load(a)
    path = p["log"].replace("alert_log", "monitor_log")
    if os.path.exists(path):
        os.remove(path)
    log = AlertLog(path)

    def show(al, t):
        h = (t - evs[0].ts) / 3600
        print(f"t+{h:4.1f}h [{al.severity:6s}] {al.kind:17s} {', '.join(al.subjects)[:50]}")
    emitted = replay(evs, log, min_severity=a.min_severity, on_alert=show)
    print(f"{len(emitted)} alerts emitted; log intact: {log.verify() is None} -> {path}")


def cmd_serve(a):
    from rogue_detect.web import make_server
    evs, roles, p = _load(a)
    an = analyze(evs)
    if os.path.exists(p["log"]) and a.fresh:
        os.remove(p["log"])
    log = AlertLog(p["log"])
    for al in an.alerts:
        if not log.has(al):
            log.append(al)
    state = {"analysis": an, "roles": roles, "by_agent": group_by_agent(evs), "log": log,
             "reports_path": os.path.join(DATA, "community_reports.jsonl"), "docs_dir": os.path.join(HERE, "docs")}
    srv = make_server(state, a.host, a.port)
    print(f"Serving on http://{a.host}:{a.port}  (synthetic data only; Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


def cmd_export(a):
    p = _paths(a)
    log = AlertLog(p["log"])
    from rogue_detect.alerts import Alert
    alerts = [Alert(**rec["alert"]) for rec in log.read()]
    bundle = to_stix_bundle(alerts, a.min_severity)
    out = a.out or os.path.join(OUT, "stix_bundle.json")
    with open(out, "w") as fh:
        json.dump(bundle, fh, indent=1)
    print(f"wrote {len(bundle['objects'])} STIX objects -> {out} (synthetic; not real intelligence)")


def cmd_verify(a):
    bad = AlertLog(_paths(a)["log"]).verify()
    print("alert log intact" if bad is None else f"alert log TAMPERED at record {bad}")
    return 0 if bad is None else 1


def cmd_demo(a):
    os.makedirs(OUT, exist_ok=True)
    ev_txt = os.path.join(OUT, "evaluation.txt")
    if os.path.exists(ev_txt):
        os.remove(ev_txt)
    a.fresh, a.stealth, a.min_severity, a.out = True, False, "medium", None
    cmd_generate(a)
    cmd_analyze(a)
    # second data set: evasive variants of the SAME rogue roles, kept in separate files
    b = argparse.Namespace(**vars(a))
    b.stealth = True
    b.events = os.path.join(DATA, "synthetic_events_stealth.jsonl")
    b.log = os.path.join(OUT, "alert_log_stealth.jsonl")
    print("\n--- stealth variant (same rogue roles, evasive behavior) ---")
    cmd_generate(b)
    evs, roles, p = _load(b)
    txt = format_eval(evaluate(analyze(evs), roles), "Evaluation (stealth variant: shows what the detectors MISS)")
    print(txt)
    with open(ev_txt, "a") as fh:
        fh.write(txt + "\n")
    cmd_export(a)
    print(f"\nSample outputs in {OUT}: alert_log.jsonl, flagged_cases.md/json, evaluation.txt, stix_bundle.json")
    print("Next: python run.py serve   (dashboard) or python run.py monitor   (streaming replay)")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rogue AI Detection prototype (SYNTHETIC DATA ONLY)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    def common(p):
        p.add_argument("--events", help="events JSONL (default data/synthetic_events.jsonl)")
        p.add_argument("--log", help="alert log path (default sample_outputs/alert_log.jsonl)")
        p.add_argument("--seed", type=int, default=7)
    for name, fn in (("demo", cmd_demo), ("generate", cmd_generate), ("analyze", cmd_analyze), ("monitor", cmd_monitor),
                     ("serve", cmd_serve), ("export-stix", cmd_export), ("verify-log", cmd_verify)):
        p = sub.add_parser(name)
        common(p)
        p.set_defaults(fn=fn)
        if name in ("generate",):
            p.add_argument("--stealth", action="store_true", help="evasive variants of the rogue roles")
        if name in ("analyze", "serve"):
            p.add_argument("--fresh", action="store_true", help="start a new alert log")
        if name == "monitor":
            p.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high"])
        if name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8765)
        if name == "export-stix":
            p.add_argument("--min-severity", default="medium", choices=["info", "low", "medium", "high"])
            p.add_argument("--out")
    a = ap.parse_args(argv)
    for k, v in (("stealth", False), ("fresh", False), ("min_severity", "medium"), ("out", None)):
        if not hasattr(a, k):
            setattr(a, k, v)
    r = a.fn(a)
    return r if isinstance(r, int) else 0


if __name__ == "__main__":
    sys.exit(main())
