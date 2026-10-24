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

## Layout

```
agent-gateway/
├── agent_gateway/
│   ├── pep.py          # PolicyEngine + Flask JSON-RPC interceptor
│   ├── approve.py      # Bound OOB HMAC mint/verify
│   ├── taint.py        # Session taint, egress classes, scratchpad/bus
│   ├── registry.py     # Registered keys; root-parent freeze
│   ├── scrub.py        # Deterministic log scrubbing
│   └── cli.py          # serve / approve
├── config/agents.json
├── tests/
│   ├── test_basic.py
│   └── test_pep_falsification.py   # 7 ATLAS regression cases
└── README.md
```

## Safety (non-negotiable)

- Default bind `127.0.0.1`; non-loopback requires `--allow-nonlocal`.
- Actions apply only to registered keys.
- Web honeypot path untouched (no auto-block of public visitors).
- Deterministic scrubbing of logged tool args.
- No deploy / push / merge from this workstream.
- No outbound network from the gateway except optional webhook stub (**default OFF**).

## Test counts (this pass)

| Suite | Result |
|---|---|
| `agent-gateway` full pytest | **14 passed** (7 basic + **7/7 falsification**) |
| Falsification `tests/test_pep_falsification.py` | **7/7 pass** |

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
