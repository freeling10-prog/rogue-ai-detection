"""Command line interface: analyze | serve | honeypot | demo | report | export-leads."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__
from .config import ConfigError, load_config
from .pipeline import run_pipeline
from .report import build_report, render_text, use_color
from .scoring import SEVERITIES

LABELS = ("human", "static_bot", "agent")


def _add_view_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide sessions below this severity")
    p.add_argument("--top", type=int, default=10, help="max sessions shown in the terminal summary")
    p.add_argument("--no-color", action="store_true")


def _analyze(paths: Sequence[str], cfg_path: Optional[str]) -> dict[str, Any]:
    cfg = load_config(cfg_path)
    results, parsed = run_pipeline(paths, cfg)
    return build_report(results, [str(p) for p in paths], parsed, cfg_path or "defaults")


def cmd_analyze(args: argparse.Namespace) -> int:
    paths = list(args.logfile) + list(args.leads or [])
    missing = [p for p in paths if not Path(p).is_file()]
    if missing:
        print(f"error: file not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    report = _analyze(paths, args.config)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report written to {args.json_out}")
    print(render_text(report, min_severity=args.min_severity, top=args.top, color=use_color(no_color_flag=args.no_color)))
    if args.fail_on and any(SEVERITIES.index(s["severity"]) >= SEVERITIES.index(args.fail_on) for s in report["sessions"]):
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    try:
        report = json.loads(Path(args.report_json).read_text(encoding="utf-8"))
        if report.get("schema") != "agentwatch.report/1":
            raise ValueError("not an agentwatch.report/1 file")
    except (OSError, ValueError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        floor = SEVERITIES.index(args.min_severity)
        report["sessions"] = [s for s in report["sessions"] if SEVERITIES.index(s["severity"]) >= floor][: args.top]
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report, min_severity=args.min_severity, top=args.top, color=use_color(no_color_flag=args.no_color)))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .honeytoken import check_bind, create_app, run_server
    check_bind(args.host, args.allow_nonlocal)
    app = create_app(args.log, registry_path=args.registry, seed=args.seed)
    print(f"honeytoken listener on http://{args.host}:{args.port}  ->  {args.log}")
    run_server(app, args.host, args.port, args.allow_nonlocal)
    return 0


def cmd_honeypot(args: argparse.Namespace) -> int:
    from .honeypot import create_honeypot_app
    from .honeytoken import check_bind, run_server
    check_bind(args.host, args.allow_nonlocal)
    app = create_honeypot_app(args.log, seed=args.seed, tarpit_s=args.tarpit_seconds,
                              tarpit_max_s=args.tarpit_max, registry_path=args.registry,
                              trust_forwarded_for=args.trust_forwarded_for,
                              behind_proxy=True if args.behind_proxy else None)
    if args.trust_forwarded_for:
        print("WARNING: --trust-forwarded-for makes X-Forwarded-For attacker-controllable; "
              "use ONLY for local simulation of multiple source IPs.", file=sys.stderr)
    print(f"honeypot on http://{args.host}:{args.port}  ->  leads: {args.log}  registry: {args.registry}")
    print("synthetic content only; do NOT expose publicly without isolation (see README).")
    run_server(app, args.host, args.port, args.allow_nonlocal)
    return 0


def cmd_export_leads(args: argparse.Namespace) -> int:
    from .export import export_file
    if not Path(args.leads).is_file():
        print(f"error: file not found: {args.leads}", file=sys.stderr)
        return 2
    n = export_file(args.leads, args.out, synthetic=args.label_synthetic)
    print(f"wrote {n} RawEvent record(s) to {args.out}")
    if args.coordination_out:
        from .export import export_coordination_file
        m = export_coordination_file(args.leads, args.coordination_out)
        print(f"wrote {m} coordination-event record(s) to {args.coordination_out}")
    return 0


def _demo_table(report: dict[str, Any], truth: list[Any], title: str = "Per-actor results") -> str:
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for s in report["sessions"]:
        by_ip.setdefault(s["ip"], []).append(s)
    rows, per_class = [], {k: [] for k in LABELS}
    for t in truth:
        sess = max(by_ip.get(t.ip, [{}]), key=lambda s: s.get("requests", 0))
        if not sess:
            rows.append(f"  {t.name:56} expected={t.label:10} NOT SEEN")
            continue
        per_class[t.label].append(sess)
        ok = "ok  " if sess["label"] == t.label else "MISS"
        f = sess["features"]
        flag = any(x["kind"] == "llm_like_ttna" for x in sess["findings"])
        ttna = (f"rho={f['ttna_spearman']:+.2f} band={f['ttna_band_fraction']:.0%}{' FLAG' if flag else ''}"
                if f.get("ttna_pairs") else "n/a")
        extra = " benign" if sess["benign"] else ""
        rows.append(f"  {ok} {t.name:56} exp={t.label:10} got={sess['label']:10} agent={sess['agent_score']:3d} "
                    f"auto={sess['automation_score']:3d} {sess['severity']:8} ttna[{ttna}]{extra}")
    lines = ["", f"{title} (synthetic ground truth vs. prediction):", *rows, "", "Per-class summary (synthetic demo only):"]
    for lab in LABELS:
        ss = per_class[lab]
        if not ss:
            continue
        hit = sum(1 for s in ss if s["label"] == lab)
        ag = [s["agent_score"] for s in ss]
        lines.append(f"  {lab:10} n={len(ss)}  labelled correctly={hit}/{len(ss)}  "
                     f"agent_score min/mean/max = {min(ag)}/{sum(ag) / len(ag):.0f}/{max(ag)}")
    return "\n".join(lines)


def cmd_demo(args: argparse.Namespace) -> int:
    from .synthetic import generate_demo
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="agent-watch-demo-"))
    art = generate_demo(out, seed=args.seed)
    print(f"synthetic logs written to {out}/ (access.log, gateway.jsonl, leads.jsonl, truth.json)")
    paths = [art["access_log"], art["gateway_log"], art["leads"]]
    report = _analyze([str(p) for p in paths], args.config)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"JSON report: {out / 'report.json'}\n")
    print(render_text(report, min_severity=args.min_severity, top=args.top, color=use_color(no_color_flag=args.no_color)))
    print(_demo_table(report, art["truth"], "Per-actor results: logs + honeypot leads"))
    logs_only = _analyze([str(art["access_log"]), str(art["gateway_log"])], args.config)
    print(_demo_table(logs_only, art["truth"], "Per-actor results: LOGS ONLY (honeypot leads withheld)"))
    print("\nNotes: honeypot requests are not mirrored into the synthetic access logs, so the logs-only table shows\n"
          "what ordinary API traffic alone reveals (coordination-bus agents are missed there by construction).\n"
          "The LLM-like timing variant was generated from the same hypothesis the detector tests, so its\n"
          "flag is circular; the timing feature is a weak heuristic, not an established fingerprint. These are\n"
          "results on the tool's own synthetic data, NOT real-world accuracy, and no substitute for testing\n"
          "against real agent frameworks.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agent-watch", description="Defensive detection of autonomous/rogue AI agent behaviour in logs and honeypots (local, synthetic-data tool).")
    ap.add_argument("--version", action="version", version=f"agent-watch {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyze access / API-gateway logs")
    p.add_argument("logfile", nargs="+", help="Nginx/Apache combined or JSON-lines log(s)")
    p.add_argument("--leads", nargs="*", help="honeypot lead JSONL file(s) to correlate")
    p.add_argument("--config", help="thresholds JSON (default: built-in)")
    p.add_argument("--json-out", help="write the JSON report here")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any session reaches this severity")
    _add_view_args(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("report", help="re-render a saved JSON report")
    p.add_argument("report_json")
    p.add_argument("--format", choices=("text", "json"), default="text")
    _add_view_args(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("serve", help="run the lightweight honeytoken listener (localhost)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8099)
    p.add_argument("--log", default="honeytoken-leads.jsonl")
    p.add_argument("--registry", help="write the decoy/token registry JSON here")
    p.add_argument("--seed", help="deterministic token ids (testing)")
    p.add_argument("--allow-nonlocal", action="store_true", help="allow non-loopback bind (isolated sandbox only)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("honeypot", help="run the full decoy site/API with canary pages (localhost)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8098)
    p.add_argument("--log", default="honeypot-leads.jsonl")
    p.add_argument("--registry", default="honeypot-registry.json")
    p.add_argument("--seed", help="deterministic token ids (testing)")
    p.add_argument("--tarpit-seconds", type=float, default=0.0, help="base per-IP delay on decoy hits (0=off, hard-capped at 10s)")
    p.add_argument("--tarpit-max", type=float, default=5.0, help="max delay per response (hard cap 10s)")
    p.add_argument("--allow-nonlocal", action="store_true", help="allow non-loopback bind (isolated sandbox only)")
    p.add_argument("--trust-forwarded-for", action="store_true",
                   help="TEST HOOK (off by default): take the client IP from X-Forwarded-For. Spoofable - local simulation only")
    p.add_argument("--behind-proxy", action="store_true",
                   help="one trusted reverse-proxy hop (werkzeug ProxyFix); same as AGENT_WATCH_BEHIND_PROXY=1")
    p.set_defaults(func=cmd_honeypot)

    p = sub.add_parser("export-leads", help="convert honeypot leads to rogue-ai-pipeline RawEvent JSONL")
    p.add_argument("leads")
    p.add_argument("--out", required=True)
    p.add_argument("--coordination-out", help="also write agentwatch.coordination-event/1 JSONL (issuance/use events + cognitive_capture)")
    p.add_argument("--label-synthetic", action="store_true",
                   help="mark events synthetic=true (only for your own sandbox/test traffic)")
    p.set_defaults(func=cmd_export_leads)

    p = sub.add_parser("demo", help="generate synthetic logs, run the pipeline, print results")
    p.add_argument("--out", help="output directory (default: a new temp dir)")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--config")
    _add_view_args(p)
    p.set_defaults(func=cmd_demo)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
