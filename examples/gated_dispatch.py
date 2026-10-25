"""Reference wrapper: route every tool call through the gateway before dispatch.

Copy and adapt. This is the boundary the gateway cannot enforce for you: the
caller's dispatch loop must call ``gated_call`` for every tool, and must not
hold a second path to the backends. Lab reference only; backends are simulated.

Run the self-test from the repo root:

    AGENT_GATEWAY_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \\
        python examples/gated_dispatch.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

# post(path, json_body) -> (status_code, response_dict). Swap in urllib/requests
# against http://127.0.0.1:9100 for a real loop.
Post = Callable[[str, dict], "tuple[int, dict]"]


class GatedDispatcher:
    def __init__(self, post: Post, agent_key: str, session_id: str, backends: dict[str, Callable[..., Any]]):
        self.post, self.agent_key, self.session_id, self.backends = post, agent_key, session_id, backends
        self.capability_token: str | None = None  # carry the latest token forward

    def gated_call(self, tool: str, arguments: dict, approval_token: str | None = None) -> dict:
        body = {"agent_key": self.agent_key, "session_id": self.session_id, "tool": tool,
                "arguments": arguments}
        if self.capability_token:
            body["capability_token"] = self.capability_token
        if approval_token:  # one-time token a person issued for this exact call
            body["approval_token"] = approval_token
        status, out = self.post("/v1/call", body)
        self.capability_token = out.get("capability_token") or self.capability_token
        if status != 200 or not out.get("ok"):
            # Held or denied: do NOT run the backend. Surface it to the person/harness.
            return {"executed": False, "reason": out.get("error") or out.get("message"), "gateway": out}
        # Fail closed on anything not explicitly registered here.
        backend = self.backends.get(tool)
        if backend is None:
            return {"executed": False, "reason": "no_backend_registered"}
        return {"executed": True, "result": backend(**arguments)}


def _selftest() -> int:
    root = Path(__file__).resolve().parents[1] / "agent-gateway"
    sys.path.insert(0, str(root))
    os.environ.setdefault("AGENT_GATEWAY_STATE_DIR", tempfile.mkdtemp(prefix="agw-gd-"))
    from agent_gateway.capability import hmac_key
    from agent_gateway.pep import PepConfig, create_app

    try:
        hmac_key()
    except RuntimeError as exc:
        print(f"gated_dispatch: {exc}", file=sys.stderr)
        return 2
    cfg = PepConfig(registry_path=root / "config" / "agents.json",
                    alert_log=Path(os.environ["AGENT_GATEWAY_STATE_DIR"]) / "alerts.jsonl")
    client = create_app(cfg).test_client()

    def post(path: str, body: dict):
        r = client.post(path, json=body)
        return r.status_code, r.get_json()

    sent: list[dict] = []
    d = GatedDispatcher(post, "agk_demo_registered_0001", "gd-1", {
        "read_external_url": lambda url: "simulated page body",
        "send_email": lambda **kw: sent.append(kw) or "sent",
    })
    first = d.gated_call("read_external_url", {"url": "https://example.test/p"})
    held = d.gated_call("send_email", {"to": "x@example.test", "subject": "s", "body": "b"})
    print("ingest executed:", first["executed"])
    print("send_email executed:", held["executed"], "-", held.get("reason"))
    ok = first["executed"] and not held["executed"] and not sent
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
