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

## Layout

```
agent-gateway/
├── agent_gateway/
│   ├── pep.py          # PolicyEngine + Flask JSON-RPC interceptor
│   ├── capability.py   # Chained HMAC capability tokens (macaroon-style)
│   ├── approve.py      # Bound OOB HMAC mint/verify
│   ├── taint.py        # Session taint, egress classes, scratchpad/bus
│   ├── registry.py     # Registered keys; root-parent freeze
│   ├── scrub.py        # Deterministic log scrubbing
│   └── cli.py          # serve / approve
├── config/agents.json
├── tests/
│   ├── test_basic.py
│   ├── test_pep_falsification.py   # 7 ATLAS regression cases
│   ├── test_capability_attenuation.py
│   └── test_stateful_fuzz.py       # Hypothesis RuleBasedStateMachine
└── README.md
```

## Safety (non-negotiable)

- Default bind `127.0.0.1`; non-loopback requires `--allow-nonlocal`.
- Actions apply only to registered keys.
- Web honeypot path untouched (no auto-block of public visitors).
- Deterministic scrubbing of logged tool args.
- No deploy / push / merge from this workstream.
- No outbound network from the gateway except optional webhook stub (**default OFF**).

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

## Test counts (this pass)

| Suite | Result |
|---|---|
| `agent-gateway` full pytest | **29 passed** (7 basic + **7/7 falsification** + 10 attenuation + 5 stateful) |
| Falsification `tests/test_pep_falsification.py` | **7/7 pass** |
| `agent-watch` full pytest (safelog machine included) | **512 passed, 2 skipped** |

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
- Freeze pages humans via **local alert JSONL** only unless `webhook_url` is explicitly set (still lab).
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
```
