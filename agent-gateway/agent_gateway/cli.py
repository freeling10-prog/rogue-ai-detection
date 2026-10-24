"""CLI: python -m agent_gateway serve|approve|freeze-status"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import approve
from .pep import PepConfig, create_app, run_server
from .registry import Registry


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent_gateway", description="Lab insider policy-enforcement proxy (loopback)")
    sub = p.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run loopback JSON-RPC PEP")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9100)
    serve.add_argument("--registry", type=Path, default=None)
    serve.add_argument("--allow-nonlocal", action="store_true", help="Permit non-loopback bind (isolated lab only)")

    ap = sub.add_parser("approve", help="Mint bound OOB approval token")
    ap.add_argument("session_id")
    ap.add_argument("--step", type=int, required=True, help="step_index from the policy deny response")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--args-json", default="{}", help="canonical arguments JSON matching the call")
    ap.add_argument("--taint-source", default="")
    ap.add_argument("--ttl", type=float, default=600.0)

    sub.add_parser("health-check", help="Print local health path reminder")

    args = p.parse_args(argv)
    if args.cmd == "serve":
        reg = args.registry or Path(__file__).resolve().parent.parent / "config" / "agents.json"
        cfg = PepConfig(host=args.host, port=args.port, registry_path=reg, allow_nonlocal=args.allow_nonlocal)
        run_server(cfg)
        return 0
    if args.cmd == "approve":
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
    if args.cmd == "health-check":
        print("GET http://127.0.0.1:9100/health")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
