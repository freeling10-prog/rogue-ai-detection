# Phase 2 — Insider Policy Gateway (lab)

Date: 2026-10-23 (America/Los_Angeles)

## Purpose

A **loopback-only** policy-enforcement proxy (PEP) for an organization's *own* registered internal AI agents. It sits between an agent harness and tools (JSON-RPC / MCP-style `tools/call`).

This is **not** a WAF, **not** malware, and **not** for blocking public web visitors. The web honeypot (`agent-watch`) stays **human-review only**. Freeze/block actions apply **only** to API keys listed in `agent-gateway/config/agents.json`.

## ATLAS map

| Defense in `pep.py` | ATLAS |
|---|---|
| Taint on untrusted ingest; restrict tool invocation while tainted | **AML.M0030** Restrict Tool Invocation on Untrusted Data |
| Bound one-time OOB HMAC over `(session_id, step_index, tool_name, sha256(canonical_args), taint_source_id)`; reject arg-swap / replay | AML.T0051 / AML.T0053 |
| `tools/list` descriptions from non-core MCP servers set TAINTED (capability pinning for core) | AML.T0051.001 |
| Scratchpad writes while TAINTED store `taint_inherited=True`; read re-taints new session | AML.T0080.000 |
| Egress classes; block external *parameter* egress when TAINTED∧SENSITIVE_READ (lethal-trifecta style gate) | AML.T0086 |
| `max_delegation_depth=1`, `max_children_per_parent=3`; bus taint propagation; R12 freeze (15 min) on Root Parent Principal; auto-lift; local alert log | AML.T0118 |
| Allowlisted constrained sinks (`update_ticket_status` int/enum/ID) without OOB; free-text still gated | usability DoS fix |
| Chained HMAC capability (macaroon-style). Untrusted ingest appends `allow_egress=false`; the caveat cannot be stripped | **AML.M0030** (attenuation) |
| Held tainted call emits a scrubbed Slack / webhook approval payload (Approve Once, or Deny & Freeze Key 15m). HTTP stays off unless opted in | commercial hook (formatter) |

## Layout

```
agent-gateway/
├── agent_gateway/
│   ├── pep.py          # PolicyEngine + Flask JSON-RPC interceptor
│   ├── capability.py   # Chained HMAC capability tokens (macaroon-style)
│   ├── approve.py      # Bound OOB HMAC mint/verify
│   ├── approval_webhook.py  # Slack / generic webhook approval formatter
│   ├── audit_report.py # Offline executive HTML + text PDF from analyzer output
│   ├── taint.py        # Session taint, egress classes, scratchpad/bus
│   ├── registry.py     # Registered keys; root-parent freeze
│   ├── scrub.py        # Deterministic log scrubbing
│   └── cli.py          # serve / approve / audit
├── config/agents.json
├── tests/
│   ├── test_basic.py
│   ├── test_pep_falsification.py   # 7 ATLAS regression cases
│   ├── test_capability_attenuation.py
│   ├── test_stateful_fuzz.py       # Hypothesis RuleBasedStateMachine
│   ├── test_approval_webhook.py    # scrub + callback tamper rejection
│   └── test_audit_report.py        # executive report from analyzer fixtures
└── README.md
```

## Safety (non-negotiable)

- Default bind `127.0.0.1`; non-loopback requires `--allow-nonlocal`.
- Actions apply only to registered keys.
- Web honeypot path untouched (no auto-block of public visitors).
- Deterministic scrubbing of logged tool args.
- No deploy / push / merge from this workstream.
- No outbound network from the gateway. The approval formatter builds JSON only. HTTP POST runs only with `--webhook-deliver` (default **off**).

## Capability tokens

Session capabilities are separate from the one-time OOB approval in `approve.py`.

```
agw1.<base64url(json)>.<hex HMAC-SHA256>

json = {"v":1,"id":"<session_id>","caveats":[...]}
sig0 = HMAC-SHA256(root_key, "agw1|" + session_id)
sig_i = HMAC-SHA256(sig_{i-1}, caveat_i)
```

Minted caveats: `bind:session=<sha256("session|"+id)[:32]>`, `bind:agent=<sha256("agent|"+key)[:32]>`, `allow_egress=true`.

On untrusted ingest the PEP appends `allow_egress=false` and `taint_source=<id>` and returns the new token (`capability_token`, `allow_egress`). Egress is monotonic: a later `allow_egress=true` does not restore it. Dropping or reordering caveats fails verification. Any worker that has `AGENT_GATEWAY_HMAC_KEY` can recompute the chain; it does not need the other worker's session table.

The root key is the trust root (a worker can mint a fresh allowing token for a session it has never seen). What a token holder cannot do is upgrade an attenuated chain. On a worker that already stored the attenuated token, replaying the earlier allowing discharge is rejected (`capability_upgrade_rejected`).

A valid hash-bound OOB token is still the only one-shot bypass of a closed egress, and it does not remove the deny caveat. Freeze still applies only to keys in `config/agents.json`. The web honeypot is unchanged (human-review only).

## Stateful fuzzing

Hypothesis `RuleBasedStateMachine` (package pin `hypothesis==6.170.9`):

| Machine | max_examples | stateful steps |
|---|---|---|
| `PepPolicyMachine` (`agent-gateway/tests/test_stateful_fuzz.py`) | 40 | 16 |
| `GatewayScrubMachine` (same file) | 80 | 8 |
| `SafelogMachine` (`agent-watch/tests/test_safelog_stateful.py`) | 80 | 8 |

Properties: blocked write/send/creds egress after taint requires a valid OOB token; fan-out stays ≤ 3 in any order; freeze does not apply to unregistered keys; scrubber outputs do not contain configured secret patterns.

## Commercial hooks

Self-serve lab hooks. They do not deploy the honeypot and they do not send traffic unless a person opts in.

### Slack / webhook approval formatter

`agent_gateway/approval_webhook.py`. When `pep.py` holds a tainted tool call for a human (`oob` / lethal-trifecta deny), it builds one JSON document:

- Slack Block Kit `text` + `blocks`, including **Approve Once** and **Deny & Freeze Key 15m**
- A generic `webhook` object for anything that is not Slack

The document carries the agent principal, session id, and `agw1.` capability state; the triggering taint source and the applicable ATLAS id (`AML.T0051`, `AML.T0080`, or `AML.T0086`); the scrubbed tool name and canonical args. Callback fields are one-time HMAC bindings over the session, step, tool, canonical args, and taint source. Changing any of those fails verification. Approve Once is the same one-shot bypass as the CLI token and does not clear the deny-egress caveat. Deny & Freeze calls `freeze_root` for **900 seconds** and only if that key is already in `config/agents.json`. A public visitor key is not frozen.

Building the payload does not open a socket. `PepConfig.webhook_deliver` defaults to false. `python -m agent_gateway serve --webhook-url … --webhook-deliver` is the opt-in. A failed POST does not change the policy decision.

### Executive audit report

`python -m agent_gateway audit <analyzer-out>` reads the directory an `agentwatch-analyzer` smoke writes and writes `audit-report.html`, `audit-report.json`, and a pure-Python text PDF (`audit-report.pdf`). HTML is the report. The PDF is a text rendering of the same figures; WeasyPrint and wkhtmltopdf are optional and are not installed here.

The executive summary counts tool calls (a record with a tool name or `tools/call`, not an access-log fetch), taint events, and ATLAS matches for `AML.T0051`, `AML.T0080`, and `AML.T0086`. Subtechniques roll up to the parent id. The STIX attack-pattern catalog is not counted, because the analyzer emits it even when a technique was not matched.

The report links and embeds the static `replay.html`. The risk matrix splits tool-call paths that can place data on an external boundary from paths whose `agw1.` capability includes `allow_egress=false`. A token that still allows egress is not treated as attenuation. Signatures are omitted. Strings pass through the gateway scrubber. The command does not bind, does not POST, and does not start the honeypot.

### Turnkey audit workflow

`.github/workflows/atlas-agent-audit.yml` runs, as separate jobs, the `agent-gateway` suite (ATLAS falsification and Hypothesis included), `agent-watch`, `rogue-ai-pipeline`, and an `agentwatch-analyzer` smoke. The smoke reads the archived Tier-2 Playwright crawler log (fixture `agentlike_nginx.log` if that archive is absent), writes `findings.json`, `replay.html`, and the validated STIX 2.1 bundle, then runs `python -m agent_gateway audit` on that directory and uploads the executive HTML and text PDF with the smoke artifacts. It does not start the honeypot.

## Test counts (this pass)

| Suite | Result |
|---|---|
| `agent-gateway` full pytest | **389 passed** on `main`: the 262 below plus 127 post-sprint v11 tests (17 schema digest + 63 GUI action + 19 schema / GUI wiring + 12 provenance / accumulator wiring + 4 memory provenance + 9 temporal accumulator, which form Group D, plus 1 SARIF and 2 Group D layout tests). **262 passed** at `cefec0d` (7 basic + **7/7 falsification** + 10 attenuation + 6 stateful + 6 approval-webhook + 5 audit-report + 12 MCP wire proxy + 21 de-obfuscation + 15 audit chain + 44 SSRF guard + 11 output scanner + 9 toxic combinations + 8 side channel + 8 delegation + 44 argument firewall + 20 canary + 7 SARIF + 4 HTTP resource limits + 11 `evaluate-collusion` + 7 sprint artifacts). The v10 pass recorded **240**, before the last three files. |
| Falsification `tests/test_pep_falsification.py` | **7/7 pass** |
| `agent-watch` full pytest (safelog machine included) | **512 passed, 2 skipped** (514 collected; re-run 25 October 2026) |

### Falsification results

1. external_read query-param egress blocked when TAINTED+SENSITIVE_READ (T0086) — **PASS**
2. cross-session scratchpad taint inheritance (T0080.000) — **PASS**
3. OOB token rejects arg-swap and replay (T0051/T0053) — **PASS**
4. post-taint routine outbound after spacer internal reads still gated (T0086) — **PASS**
5. tainted bit propagates bus→peer key; fan-out >3 refused (T0118) — **PASS**
6. tools/list description ingest taints before first tools/call (T0051.001) — **PASS**
7. allowlisted constrained `update_ticket_status` without OOB; free-text requires OOB — **PASS**

## Caveats

- **Lab-only prototype.** Not production-ready.
- **Not a WAF** and not a substitute for network egress controls.
- **No Web Bot Auth** yet.
- Tool backends are simulated echoes inside the PEP (no real external calls).
- Freeze pages humans via **local alert JSONL** plus the in-process approval payload. HTTP delivery stays off unless `webhook_deliver` is set.
- Unknown tools fail closed as `write` egress class.

## Quick start

```bash
cd /workspace/agent-gateway
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m agent_gateway serve --host 127.0.0.1 --port 9100
# OOB (use step_index + exact args from a policy deny):
python -m agent_gateway approve sess-1 --step 3 --tool send_email --args-json '{"to":"team@internal.local","body":"Status OK"}'
# offline executive report (no bind, no honeypot):
python -m agent_gateway audit ./analyzer-out --out-dir ./audit-report
```
