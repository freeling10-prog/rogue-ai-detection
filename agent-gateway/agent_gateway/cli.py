"""CLI: python -m agent_gateway serve|approve|audit|verify|evaluate-collusion|p3-calibrate|health-check

``audit`` reads an agentwatch-analyzer output directory and writes an executive
HTML report plus a pure-Python text PDF, a scrubbed ``findings.json``, an
optional hash-chained decision log, and ``audit_manifest.json``. It does not
import the PEP, bind a port, start a honeypot, or open a socket.

``verify`` recomputes the manifest digests, the manifest HMAC, and the
decision-log hash chain. It is offline too.

``evaluate-collusion`` runs the existing defence tests per carrier group,
times benign policy decisions, verifies a hash-chained benign decision log,
and with ``--report <dir>`` writes the sprint JSON, Markdown, and PDF. It
does not bind a port.

``p3-calibrate`` replays a JSONL trace of benign tool calls through the P3
leakage ledger in log-only mode and prints quarter-bit spend per session and
per coalition, the split over the cost components, and a budget with a
margin. It reads one file, holds nothing, and needs no HMAC key.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .paths import default_registry_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent-gateway",
        description="Lab insider policy-enforcement proxy (loopback). audit is offline and does not bind.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run loopback JSON-RPC PEP")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9100)
    serve.add_argument("--registry", type=Path, default=None)
    serve.add_argument("--allow-nonlocal", action="store_true", help="Permit non-loopback bind (isolated lab only)")
    serve.add_argument("--webhook-url", default=None, help="Approval webhook URL (not contacted unless --webhook-deliver)")
    serve.add_argument("--webhook-deliver", action="store_true", help="POST approval payloads (default off; no network otherwise)")

    ap = sub.add_parser("approve", help="Mint bound OOB approval token")
    ap.add_argument("session_id")
    ap.add_argument("--step", type=int, required=True, help="step_index from the policy deny response")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--args-json", default="{}", help="canonical arguments JSON matching the call")
    ap.add_argument("--taint-source", default="")
    ap.add_argument("--ttl", type=float, default=600.0)

    audit = sub.add_parser(
        "audit",
        help="Compile an executive HTML/PDF report from an agentwatch-analyzer output directory",
    )
    audit.add_argument(
        "input_dir",
        type=Path,
        help="Directory of events.scrubbed.jsonl, findings.json, leads.jsonl, replay.html, stix-bundle.json, summary.json",
    )
    audit.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Report directory (default: <input_dir>/audit-report)",
    )
    audit.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip the pure-Python text PDF (HTML is always written)",
    )
    audit.add_argument(
        "--decision-log",
        type=Path,
        default=None,
        help="Hash-chained PEP decision log (alerts.jsonl) to include "
             "(default: <input_dir>/decision-log.jsonl or alerts.jsonl if present)",
    )

    audit.add_argument(
        "--sarif",
        type=Path,
        default=None,
        help="Also write OASIS SARIF 2.1.0 (GitHub code scanning). A bare filename lands in the "
             "report directory and is covered by audit_manifest.json; a path elsewhere is written as given.",
    )
    audit.add_argument(
        "--tool-inventory",
        type=Path,
        default=None,
        help="Tool list JSON (MCP tools/list shape, optional class labels) for the toxic-combination "
             "graph (default: <input_dir>/tool-inventory.json if present). Enough on its own for a "
             "tool-list-only audit.",
    )

    verify = sub.add_parser(
        "verify",
        help="Check audit_manifest.json digests and the decision-log hash chain (offline)",
    )
    verify.add_argument("audit_dir", type=Path, help="Directory written by `audit`")

    ev = sub.add_parser(
        "evaluate-collusion",
        help="Aggregate defence tests by carrier group, time benign decisions, write the sprint report",
    )
    ev.add_argument("--report", type=Path, nargs="?", const=Path("."), default=None, metavar="OUT_DIR",
                    help="Write collusion_benchmark_results.json, collusion_sprint_report.md and "
                         "collusion_sprint_report.pdf to OUT_DIR (default: current directory)")
    ev.add_argument("--iterations", type=int, default=50, help="Benign workflow repetitions for latency")

    cal = sub.add_parser(
        "p3-calibrate",
        help="Replay a benign JSONL trace through the P3 ledger in log-only mode and size the budget",
    )
    cal.add_argument("trace", type=Path, help="JSONL trace of tool calls (see agent_gateway/p3_calibrate.py)")
    cal.add_argument("--manifest", type=Path, default=None,
                     help="JSON with eligible (destination, tool) rows, typed schemas and zdict_hex")
    cal.add_argument("--budget-qb", type=int, default=128, help="Candidate budget in quarter bits (default 128)")
    cal.add_argument("--slot-ms", type=int, default=1000, help="Slot length in milliseconds (default 1000)")
    cal.add_argument("--margin-pct", type=int, default=25,
                     help="Safety margin added to the basis, in percent (default 25)")
    cal.add_argument("--basis", choices=("peak", "p95"), default="peak",
                     help="Per-coalition figure the recommendation starts from (default peak)")
    cal.add_argument("--charge", choices=("always", "trace"), default="always",
                     help="always: charge from each session's first row. trace: from taint or a sensitive read")
    cal.add_argument("--core-server", action="append", default=None, metavar="NAME",
                     help="MCP server inside the trust boundary (repeatable; default core, internal, builtin)")
    cal.add_argument("--show-ids", action="store_true", help="Print session ids instead of their hashes")
    cal.add_argument("--json", action="store_true", help="Print the full summary as JSON")

    sub.add_parser("health-check", help="Print local health path reminder")

    args = p.parse_args(argv)
    if args.cmd in ("serve", "approve", "audit", "verify", "evaluate-collusion"):
        from .capability import hmac_key

        try:
            hmac_key()
        except RuntimeError as exc:
            print(f"agent-gateway: {exc}", file=sys.stderr)
            return 2
    if args.cmd == "serve":
        try:
            from .http_app import run_server
        except ImportError:
            print(
                "agent-gateway serve needs the optional HTTP extra: "
                "pip install 'agent-gateway[http]'",
                file=sys.stderr,
            )
            return 2
        from .pep import PepConfig

        reg = args.registry or default_registry_path()
        cfg = PepConfig(
            host=args.host, port=args.port, registry_path=reg, allow_nonlocal=args.allow_nonlocal,
            webhook_url=args.webhook_url, webhook_deliver=bool(args.webhook_deliver),
        )
        run_server(cfg)
        return 0
    if args.cmd == "approve":
        from . import approve

        try:
            arguments = json.loads(args.args_json)
        except json.JSONDecodeError as e:
            print(f"invalid --args-json: {e}", file=sys.stderr)
            return 2
        rec = approve.mint(
            args.session_id, args.step, args.tool, arguments,
            taint_source_id=args.taint_source, ttl_s=args.ttl,
        )
        print(json.dumps({"approval_token": rec["token"], "step_index": rec["step_index"],
                          "tool_name": rec["tool_name"], "args_hash": rec["args_hash"],
                          "expires_at": rec["expires_at"]}, indent=2))
        return 0
    if args.cmd == "audit":
        from .audit_report import AuditInputError, write_report

        out = args.out_dir or (args.input_dir / "audit-report")
        if args.decision_log is not None and not args.decision_log.is_file():
            print(f"error: decision log not found: {args.decision_log}", file=sys.stderr)
            return 2
        if args.tool_inventory is not None and not args.tool_inventory.is_file():
            print(f"error: tool inventory not found: {args.tool_inventory}", file=sys.stderr)
            return 2
        try:
            doc = write_report(args.input_dir, out, pdf=not args.no_pdf, decision_log=args.decision_log,
                               tool_inventory=args.tool_inventory, sarif=args.sarif)
        except AuditInputError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(doc, indent=2))
        return 0
    if args.cmd == "verify":
        from .audit_chain import verify_audit_dir

        res = verify_audit_dir(args.audit_dir)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    if args.cmd == "p3-calibrate":
        from . import p3_calibrate

        try:
            extra = {}
            if args.core_server:
                extra["core_servers"] = frozenset(name.lower() for name in args.core_server)
            cfg = p3_calibrate.CalibrationConfig(
                budget_qb=args.budget_qb, slot_ms=args.slot_ms, margin_pct=args.margin_pct,
                basis=args.basis, charge=args.charge, show_ids=bool(args.show_ids), **extra,
            )
            doc = p3_calibrate.calibrate_file(args.trace, cfg, args.manifest)
        except (OSError, p3_calibrate.TraceError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(doc, indent=2) if args.json else p3_calibrate.render_text(doc), end="\n" if args.json else "")
        return 1 if doc["rows"]["rejected"] else 0
    if args.cmd == "evaluate-collusion":
        from . import collusion_eval

        if args.iterations < 1:
            print("error: --iterations must be at least 1", file=sys.stderr)
            return 2
        doc = collusion_eval.evaluate(iterations=args.iterations)
        out = collusion_eval.summary_line(doc)
        if args.report is not None:
            paths = collusion_eval.write_report(args.report, doc)
            out["written"] = {k: str(v) for k, v in paths.items()}
        print(json.dumps(out, indent=2))
        return 0 if collusion_eval.ok(doc) else 1
    if args.cmd == "health-check":
        print("GET http://127.0.0.1:9100/health")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
