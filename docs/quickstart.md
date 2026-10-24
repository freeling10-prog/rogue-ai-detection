# AgentGate quickstart

Three minutes. One agent tool loop, evaluated in-process by `pep.py`. When the tainted `send_email` is held, the process prints the Slack Block Kit document and the generic webhook JSON from [`agent-gateway/agent_gateway/approval_webhook.py`](../agent-gateway/agent_gateway/approval_webhook.py).

**Zero network from the gateway.** `webhook_deliver` stays false, so the formatter does not POST. The only network in the Docker path is your machine pulling `python:3.12-slim` and installing the three packages in [`agent-gateway/requirements.txt`](../agent-gateway/requirements.txt). The container publishes no port and does not start the honeypot.

Lab key `agk_demo_registered_0001` is the demo entry in [`config/agents.json`](../agent-gateway/config/agents.json). Rotate it before any real use. A key that is not in that file is refused and is not frozen.

## Docker

From the repository root. Requires Docker. The script is the entire program; nothing else is written into the repo.

```bash
docker run --rm -i \
  -v "$PWD":/src:ro \
  -w /src/agent-gateway \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e PYTHONPATH=/src/agent-gateway \
  -e AGENT_GATEWAY_STATE_DIR=/tmp/agentgate-state \
  -e AGENT_GATEWAY_HMAC_KEY=lab-quickstart-not-for-production \
  -e AGENT_GATEWAY_SCRUB_SALT=lab-quickstart-salt \
  python:3.12-slim \
  bash -s <<'EOS'
set -euo pipefail
pip install -q -r requirements.txt
python - <<'PY'
import json
import os
from pathlib import Path

from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState

root = Path.cwd()
state = Path(os.environ["AGENT_GATEWAY_STATE_DIR"])
state.mkdir(parents=True, exist_ok=True)

# webhook_deliver defaults off. A URL alone does not POST.
cfg = PepConfig(
    host="127.0.0.1",
    port=9100,
    registry_path=root / "config" / "agents.json",
    alert_log=state / "alerts.jsonl",
    webhook_url=None,
    webhook_deliver=False,
)
engine = PolicyEngine(Registry.load(cfg.registry_path), shared=SharedState(), cfg=cfg)

key = "agk_demo_registered_0001"
session = "quickstart-session"
steps = [
    ("web.fetch", {"url": "http://127.0.0.1/kb/runbook"}),
    ("lookup_order_status", {"order_id": 123}),
    ("send_email", {"to": "oncall@lab.example", "body": "status from the fetched runbook"}),
]

print("webhook_deliver", engine.cfg.webhook_deliver)
held = None
for name, args in steps:
    decision = engine.evaluate_call(key, session, name, args)
    hook = decision.get("approval_webhook") or {}
    print(json.dumps({
        "tool": name,
        "ok": decision.get("ok"),
        "error": decision.get("error"),
        "step_index": decision.get("step_index"),
        "atlas": decision.get("atlas") or hook.get("atlas_id"),
        "allow_egress": decision.get("allow_egress"),
        "delivered": hook.get("delivered"),
    }))
    if hook:
        held = decision

if held is None:
    raise SystemExit("expected send_email to be held for approval")
payload = held["approval_webhook"]
if payload.get("delivered") is not False or engine.cfg.webhook_deliver:
    raise SystemExit("refusing to continue: delivery is not off")
if not str(payload["capability_state"]["token"]).startswith("agw1."):
    raise SystemExit("expected an agw1. capability token")
if payload["capability_state"]["allow_egress"] is not False:
    raise SystemExit("expected allow_egress=false after untrusted ingest")

visitor = engine.evaluate_call(
    "visitor_public", session + "-visitor", "send_email",
    {"to": "a@b.example", "body": "x"},
)
if visitor.get("error") != "unregistered_agent":
    raise SystemExit("unregistered key should be refused")
if "approval_webhook" in visitor or engine.registry.is_frozen_key("visitor_public", engine.now()):
    raise SystemExit("unregistered key must not be frozen or sent for gateway approval")

print("--- slack text ---")
print(payload["text"])
print("--- block types ---")
print([block.get("type") for block in payload["blocks"]])
print("--- webhook JSON (Slack buttons also live on payload['blocks']) ---")
print(json.dumps(payload["webhook"], indent=2))
print(
    "quickstart_ok",
    "delivered=false",
    "webhook_deliver=false",
    "atlas=" + payload["atlas_id"],
    "principal=" + payload["principal"]["agent_id"],
)
PY
EOS
```

What you should see:

- `web.fetch` allowed, then `allow_egress` false (`agw1.` attenuated on untrusted ingest).
- `lookup_order_status` allowed. The session stays tainted. An internal read does not clear it.
- `send_email` denied with `post_taint_outbound_gated`. `delivered` is false. The webhook object carries the principal, session, capability, taint source, ATLAS id, scrubbed tool name, and canonical args. The address `oncall@lab.example` is scrubbed to an email redaction token. Block types include `header`, `section`, and `actions` (Approve Once, Deny & Freeze Key 15m).
- `visitor_public` returns `unregistered_agent` and is not frozen.
- Last line: `quickstart_ok delivered=false webhook_deliver=false`.

## Same loop without Docker

```bash
cd agent-gateway
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=.
export AGENT_GATEWAY_STATE_DIR="${TMPDIR:-/tmp}/agentgate-quickstart"
export AGENT_GATEWAY_HMAC_KEY=lab-quickstart-not-for-production
export AGENT_GATEWAY_SCRUB_SALT=lab-quickstart-salt
mkdir -p "$AGENT_GATEWAY_STATE_DIR"
python - <<'PY'
import json
import os
from pathlib import Path

from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState

root = Path.cwd()
state = Path(os.environ["AGENT_GATEWAY_STATE_DIR"])
state.mkdir(parents=True, exist_ok=True)

# webhook_deliver defaults off. A URL alone does not POST.
cfg = PepConfig(
    host="127.0.0.1",
    port=9100,
    registry_path=root / "config" / "agents.json",
    alert_log=state / "alerts.jsonl",
    webhook_url=None,
    webhook_deliver=False,
)
engine = PolicyEngine(Registry.load(cfg.registry_path), shared=SharedState(), cfg=cfg)

key = "agk_demo_registered_0001"
session = "quickstart-session"
steps = [
    ("web.fetch", {"url": "http://127.0.0.1/kb/runbook"}),
    ("lookup_order_status", {"order_id": 123}),
    ("send_email", {"to": "oncall@lab.example", "body": "status from the fetched runbook"}),
]

print("webhook_deliver", engine.cfg.webhook_deliver)
held = None
for name, args in steps:
    decision = engine.evaluate_call(key, session, name, args)
    hook = decision.get("approval_webhook") or {}
    print(json.dumps({
        "tool": name,
        "ok": decision.get("ok"),
        "error": decision.get("error"),
        "step_index": decision.get("step_index"),
        "atlas": decision.get("atlas") or hook.get("atlas_id"),
        "allow_egress": decision.get("allow_egress"),
        "delivered": hook.get("delivered"),
    }))
    if hook:
        held = decision

if held is None:
    raise SystemExit("expected send_email to be held for approval")
payload = held["approval_webhook"]
if payload.get("delivered") is not False or engine.cfg.webhook_deliver:
    raise SystemExit("refusing to continue: delivery is not off")
if not str(payload["capability_state"]["token"]).startswith("agw1."):
    raise SystemExit("expected an agw1. capability token")
if payload["capability_state"]["allow_egress"] is not False:
    raise SystemExit("expected allow_egress=false after untrusted ingest")

visitor = engine.evaluate_call(
    "visitor_public", session + "-visitor", "send_email",
    {"to": "a@b.example", "body": "x"},
)
if visitor.get("error") != "unregistered_agent":
    raise SystemExit("unregistered key should be refused")
if "approval_webhook" in visitor or engine.registry.is_frozen_key("visitor_public", engine.now()):
    raise SystemExit("unregistered key must not be frozen or sent for gateway approval")

print("--- slack text ---")
print(payload["text"])
print("--- block types ---")
print([block.get("type") for block in payload["blocks"]])
print("--- webhook JSON (Slack buttons also live on payload['blocks']) ---")
print(json.dumps(payload["webhook"], indent=2))
print(
    "quickstart_ok",
    "delivered=false",
    "webhook_deliver=false",
    "atlas=" + payload["atlas_id"],
    "principal=" + payload["principal"]["agent_id"],
)
PY
```

## Opt-in delivery

Leave this off for the quickstart. When you set both, `pep.py` POSTs the same document. A failed POST does not change the allow or deny decision. Point the URL at an endpoint you control. The example host below is loopback port 9, which refuses the connection; replace it with your Slack incoming-webhook URL only if you mean to deliver.

```bash
python -m agent_gateway serve \
  --host 127.0.0.1 \
  --port 9100 \
  --webhook-url http://127.0.0.1:9/approval \
  --webhook-deliver
```

Without `--webhook-deliver`, serve stays on `127.0.0.1:9100` and the formatter only writes the local alert log.

```bash
python -m agent_gateway serve --host 127.0.0.1 --port 9100
```

Approve Once from a held call is a one-shot bypass of that exact step, tool, and canonical args. It does not clear the deny-egress caveat. Deny & Freeze Key 15m freezes the registered principal for 900 seconds. The quickstart does not exercise either button; it only prints them.

## Install the CLIs

The loop above uses `PYTHONPATH` and a read-only mount. It does not install console scripts. To put the analyzer and the audit command on `PATH`, from the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ./agentwatch-analyzer
python -m pip install -e ./agent-gateway
```

Non-editable installs use the same paths without `-e`:

```bash
python -m pip install ./agentwatch-analyzer
python -m pip install ./agent-gateway
```

Then, on a log you already have. This does not start the honeypot and does not bind a port:

```bash
agentwatch-analyzer ./access.log --format nginx --out-dir ./analyzer-out
python -m agent_gateway audit ./analyzer-out
```

`python -m agent_gateway audit` writes `audit-report.html` and `audit-report.pdf` under `./analyzer-out/audit-report`. The PDF writer is pure Python. WeasyPrint and wkhtmltopdf are not required. `agent-gateway audit ./analyzer-out` is the same command after the gateway package is installed.

Tests for the gateway package: `pip install -e "./agent-gateway[test]"` then `pytest` in `agent-gateway`. Analyzer tests need `pip install -r agentwatch-analyzer/requirements.txt` as well as the editable install (pytest is not a runtime dependency).

The gateway server, if you start it, still defaults to `127.0.0.1`. Do not pass `--allow-nonlocal` for this install check. Do not pass `--webhook-deliver`.

## What this does not do

- It does not bind a public address, and it does not pass `--allow-nonlocal`.
- It does not start `agent-watch` or deploy the honeypot.
- It does not call Slack, and it does not set `webhook_deliver`.
- It does not freeze `visitor_public`.
