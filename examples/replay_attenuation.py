"""Minimal attenuation replay (lab, loopback, in-process).

Drives the real PolicyEngine and capability code with simulated tool
backends. No network, no port, no model calls. Run from the repo root:

    AGENT_GATEWAY_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \\
        python examples/replay_attenuation.py

Exit code is 0 only if every step matches the expected outcome.
Not a benchmark, not a penetration test, not a certification.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent-gateway"))

from agent_gateway import capability  # noqa: E402
from agent_gateway.pep import PepConfig, PolicyEngine  # noqa: E402
from agent_gateway.registry import Registry  # noqa: E402
from agent_gateway.taint import SharedState  # noqa: E402

REG = ROOT / "agent-gateway" / "config" / "agents.json"
AGENT = "agk_demo_registered_0001"  # lab registry key
SESSION = "replay-session-1"

failures = 0


def show(step: str, expect: str, out: dict) -> None:
    """Print one step. ``expect`` is 'allow' or 'deny' (held/blocked)."""
    global failures
    got = "deny" if "error" in out else "allow"
    ok = got == expect
    failures += 0 if ok else 1
    detail = out.get("error", {}) if got == "deny" else ""
    if isinstance(detail, dict):
        detail = detail.get("message", detail)
    print(f"[{'ok' if ok else 'MISMATCH'}] {step}: expected {expect}, got {got} {detail}".rstrip())


def main() -> int:
    try:
        capability.hmac_key()
    except RuntimeError as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 2

    state = Path(tempfile.mkdtemp(prefix="agw-replay-"))
    os.environ["AGENT_GATEWAY_STATE_DIR"] = str(state)
    cfg = PepConfig(registry_path=REG, alert_log=state / "alerts.jsonl")
    engine = PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)

    def call(tool: str, args: dict, **kw) -> dict:
        return engine.evaluate_call(AGENT, SESSION, tool, args, **kw)

    print("Lab replay: simulated backends, in-process, loopback only.\n")

    # 0. Before any untrusted content, outbound send is not yet held for taint.
    out = call("lookup_order_status", {"order_id": "A-1001"})
    show("1. internal read before ingest", "allow", out)

    # 2. Ingest untrusted content. The session is tainted and the capability
    #    gains allow_egress=false.
    out = call("read_external_url", {"url": "https://example.test/page"})
    show("2. untrusted ingest (external read)", "allow", out)
    token = out.get("capability_token", "")
    cap = capability.verify(token)
    print(f"      capability allows_egress={cap.allows_egress if cap else 'unverifiable'}")

    # 3. DENIED: free-text send after ingest is held for one-time human approval.
    out = call("send_email", {"to": "x@example.test", "subject": "hi", "body": "summary"})
    show("3. send_email after ingest", "deny", out)

    # 4. STILL ALLOWED: an internal read, and a constrained enum status write
    #    with no free-text field. Unknown tools are classified as writes and
    #    fail closed, so only tools in the classification table qualify.
    out = call("lookup_order_status", {"order_id": "A-1001"})
    show("4a. internal read after ingest", "allow", out)
    out = call("update_ticket_status", {"ticket_id": "T-77", "status": "shipped"})
    show("4b. constrained enum status write after ingest", "allow", out)

    # 5. Holder cannot re-enable egress: appending allow_egress=true is not honored.
    if cap is not None:
        forged = capability.attenuate_token(token, "allow_egress=true")
        fcap = capability.verify(forged)
        reenabled = bool(fcap and fcap.allows_egress)
        print(f"[{'ok' if not reenabled else 'MISMATCH'}] 5. append allow_egress=true: egress re-enabled={reenabled}")
        failures_add = 1 if reenabled else 0
        globals()["failures"] += failures_add

    # 6. KNOWN LIMIT: a tool call that never goes through the gateway is not
    #    seen at all. The gateway only governs calls routed to it.
    print("[limit] 6. direct call bypassing the gateway: not observed, not blocked.")
    print("      An agent or host that can reach send_email without routing through")
    print("      the gateway is outside this boundary. The gateway is not an OS sandbox")
    print("      and not network isolation.")

    print(f"\n{'PASS' if not failures else 'FAIL'}: {failures} mismatch(es). "
          "Lab replay only; tool backends are simulated.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
