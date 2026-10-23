#!/usr/bin/env python3
"""Simulated "over-trusting AI agent" for LOCAL honeypot demos.

Start the honeypot first:   python -m agentwatch honeypot --port 8098
Then run:                   python scripts/simulated_agent.py --base-url http://127.0.0.1:8098

SAFETY: this script refuses any host that is not loopback (127.0.0.0/8, ::1,
localhost), ignores proxy environment variables, and only requests paths the
local honeypot advertises (robots.txt, /kb/, decoys).  Never point it at a
third-party system.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentwatch.simagent import run_coordination_agent, run_discovery_agent, run_obedient_agent  # noqa: E402


def assert_loopback(base_url: str) -> str:
    """Return the normalised base URL or exit if the host is not loopback."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    ok = host == "localhost"
    if not ok:
        try:
            ok = ipaddress.ip_address(host).is_loopback
        except ValueError:
            ok = False
    if parsed.scheme != "http" or not ok:
        raise SystemExit(f"refusing {base_url!r}: only http://127.0.0.1 / localhost targets are allowed")
    return base_url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # type: ignore[no-untyped-def]
        return None


def make_fetch(base: str, delay: float):
    # ProxyHandler({}) => never use HTTP(S)_PROXY from the environment
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def fetch(method: str, path: str, headers: dict[str, str], body: Optional[str]) -> tuple[int, str]:
        time.sleep(delay)
        req = urllib.request.Request(base + path, method=method, headers=headers,
                                     data=body.encode() if body else None)
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read(65536).decode("utf-8", "replace")

    return fetch


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://127.0.0.1:8098")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests")
    ap.add_argument("--user-agent", default="SimAgent/0.1 (synthetic demo)")
    ap.add_argument("--scenario", choices=("classic", "discovery", "coordination"), default="classic",
                    help="classic: robots/canary/.env; discovery: llms.txt/OpenAPI/MCP/error hints/dump; "
                         "coordination: follow the 429 breadcrumb, register on the coordination board, loop claim-shard")
    args = ap.parse_args()
    base = assert_loopback(args.base_url)
    runner = {"classic": run_obedient_agent, "discovery": run_discovery_agent,
              "coordination": run_coordination_agent}[args.scenario]
    steps = runner(make_fetch(base, args.delay), args.user_agent)
    for method, path, status in steps:
        print(f"{method:4} {path:40} -> {status}")
    print(f"\n{len(steps)} requests made; check the honeypot JSONL log for high-priority leads, then run:\n"
          "  python -m agentwatch analyze <access.log> --leads honeypot-leads.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
