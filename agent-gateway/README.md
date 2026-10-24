# agent-gateway — Phase 2 Insider Gateway (lab)

A **loopback-only** policy-enforcement proxy (PEP) that sits between an *internal* agent harness and its tools (HTTP / JSON-RPC / MCP-style `tools/call`).

> **Not a production WAF.** Lab / prototype only. No Web Bot Auth. Do not expose beyond `127.0.0.1` without `--allow-nonlocal` and an isolated network.

Implements ATLAS mitigation **AML.M0030** (Restrict Tool Invocation on Untrusted Data) for registered internal agents only. See `/workspace/phase2-gateway.md`.

## How this differs from the web honeypot (agent-watch)

| | Web honeypot (`agent-watch`) | Insider gateway (this package) |
|---|---|---|
| Audience | Unknown web visitors / crawlers | **Registered internal agent API keys** |
| Action | Leads for **human review** only; never auto-block visitors | Can **hard-block** tainted tool calls and **freeze** an internal key for 15 minutes |
| Binding | `127.0.0.1` by default | `127.0.0.1` by default |
| Outbound from the service itself | None | None by default (optional webhook stub OFF) |

**Safety split:** the public honeypot path stays review-only. R12 freeze and taint blocks apply **only** to keys in `config/agents.json`.

## Defenses (policy gates)

1. **Taint tracking** — untrusted ingest sets `TAINTED`; sensitive reads set `SENSITIVE_READ`.
2. **Egress classes** — `external_read` / `internal_read` / `write` / `send` / `creds` (+ bus/spawn). When `TAINTED ∧ SENSITIVE_READ`, tools that place **parameters** on an external boundary (query/URL params) are blocked without bound OOB (AML.T0086).
3. **Bound OOB approval** — HMAC over `(session_id, step_index, tool_name, sha256(canonical_args), taint_source_id)`. CLI: `python -m agent_gateway approve ...`. Arg-swap and replay rejected.
4. **tools/list ingest** — non-core MCP server descriptions set TAINTED before any `tools/call` (capability pinning for core servers).
5. **Scratchpad provenance** — writes while TAINTED store `taint_inherited=True`; reading them taints the new session (AML.T0080.000).
6. **Delegation quotas** — `max_delegation_depth=1`, `max_children_per_parent=3`; TAINTED propagates across internal bus posts; R12-style **15 min freeze** keys to Root Parent Principal; auto-lift; local alert log.
7. **Allowlisted constrained sinks** — `update_ticket_status` with int/enum/exact ID may proceed without OOB while free-text/high-entropy sinks still need approval.
8. **Deterministic scrubbing** of logged tool args.
9. **Chained HMAC capabilities** — macaroon-style session tokens. Untrusted ingest appends `allow_egress=false`. A holder cannot strip or reorder that caveat; any worker that shares `AGENT_GATEWAY_HMAC_KEY` can verify the chain without a session table. A valid one-time OOB token is still the only bypass. See `docs/phase2-gateway.md`.

## Quick start (loopback)

```bash
cd /workspace/agent-gateway
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m agent_gateway serve --host 127.0.0.1 --port 9100
# another terminal — mint bound approval (step from deny response):
python -m agent_gateway approve sess-1 --step 3 --tool send_email \
  --args-json '{"to":"team@internal.local","body":"Status OK"}'
curl -s http://127.0.0.1:9100/health
```

## Tool API (JSON-RPC 2.0 over HTTP POST `/mcp`)

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"web.fetch","arguments":{"url":"https://example.com"},
           "agent_key":"agk_demo_registered_0001","session_id":"sess-1"}}
```

Headers: `Authorization: Bearer <agent_key>` (must match registry).

## Layout

```
agent-gateway/
├── agent_gateway/     # pep, approve, taint, registry, scrub, cli
├── config/agents.json # registered keys (lab secrets — not production)
├── tests/             # basic + 7 ATLAS falsification / regression tests
└── README.md
```

## Language

Prefer: "policy gate", "untrusted ingest", "egress class", "falsification / regression test".
Avoid framing as instructions to attack third parties.
