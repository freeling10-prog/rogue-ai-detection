"""The policy engine and the MCP wire proxy import and run with Flask blocked."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_SCRIPT = textwrap.dedent(
    """
    import sys
    from pathlib import Path

    sys.modules["flask"] = None
    sys.modules["werkzeug"] = None
    sys.modules["werkzeug.exceptions"] = None

    import agent_gateway.leakage_budget as leakage
    import agent_gateway.mcp_proxy as proxy
    import agent_gateway.pep as pep
    assert "hypothesis" not in sys.modules
    assert "flask" not in open(leakage.__file__, encoding="utf-8").read()
    assert "hypothesis" not in open(leakage.__file__, encoding="utf-8").read()
    from agent_gateway.registry import Registry
    from agent_gateway.taint import SharedState

    assert sys.modules["flask"] is None
    cfg = pep.PepConfig(
        registry_path=Path("config/agents.json"),
        alert_log=Path(sys.argv[1]) / "alerts.jsonl",
    )
    eng = pep.PolicyEngine(Registry.load(cfg.registry_path), shared=SharedState(), cfg=cfg)
    out = eng.evaluate_call(
        "agk_demo_registered_0001", "stdlib", "lookup_order_status", {"order_id": 1},
    )
    assert out["ok"] is True, out

    wire = proxy.McpWireProxy(eng, "agk_demo_registered_0001", "stdlib-core", "core")
    res = wire.handle(proxy.CLIENT_TO_SERVER, {
        "jsonrpc": "2.0", "id": 1, "method": "resources/read",
        "params": {"uri": "file:///lab/readme.md"},
    })
    assert res.decision == "allow" and res.forward and not res.reply, res

    try:
        import agent_gateway.http_app  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit("http_app imported while flask was blocked")
    """
)


def test_policy_engine_and_proxy_run_with_flask_blocked(tmp_path: Path) -> None:
    """Importing and calling the core must not touch Flask or Werkzeug."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["AGENT_GATEWAY_HMAC_KEY"] = "test-hmac-key-agent-gateway-lab!!"
    env["AGENT_GATEWAY_STATE_DIR"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-c", _SCRIPT, str(tmp_path)],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
