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
| Outbound from the service itself | None | None by default. Approval JSON is built in-process; `--webhook-deliver` is the only POST |

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
10. **Approval webhook (formatter)** — a held tainted call emits scrubbed Slack Block Kit and a generic webhook payload (principal, session, `agw1.` capability, taint source, ATLAS id, tool, canonical args, one-time Approve Once / Deny & Freeze Key 15m callbacks). No HTTP unless `--webhook-deliver`. Freeze still applies only to registered keys, for 15 minutes.
11. **Executive audit report** — `python -m agent_gateway audit <analyzer-out>` reads an `agentwatch-analyzer` output directory and writes a lab HTML report (and a pure-Python text PDF). It does not start the honeypot and does not open a socket.
12. **MCP JSON-RPC 2.0 wire proxy** (`mcp_proxy.py`) — a standard-library filter for one client/server MCP session. It gates `tools/call`, `resources/read`, and `prompts/get` through the PEP and pins `sha256(name, description, inputSchema)` for every tool on the first complete `tools/list`. A later listing that mutates or adds a pinned tool is a rug pull (`mcp_rug_pull_detected`, approximate AML.T0051): the session capability gets `allow_egress=false`, the client keeps the pinned definitions, and every later call waits for a bound one-time OOB approval (`params._meta["agentgate/approval_token"]` and `["agentgate/bound_step_index"]`, stripped before forwarding). Server-initiated `sampling/createMessage` is rejected while tainted or when the `agw1.` token has no root-keyed `grant:sampling=` caveat (`capability.mint(..., sampling=True)`). The proxy opens no sockets; the caller moves the bytes.
13. **Cross-step smuggling de-obfuscation** (`deobfuscate.py`) — sensitive-read results and registered canaries are kept only as salted SHA-256 digests of 8-character n-grams of the raw value and its Base64, hex, URL-encoded, and whitespace-stripped forms. Released outbound arguments join a per-session sliding window (one global stream and one per argument key), and each chunk is also decoded on its own. A match catches split-chunk leaks (4–6 characters per call), encode-then-split, and split-then-encode. The call is denied (`deobfuscated_exfil_detected`, approximate AML.T0086) and the registered root key is frozen for 15 minutes. Denied calls never join the window.
14. **Hash-chained audit receipts** (`audit_chain.py`) — every decision-log line carries `seq`, `prev_hash`, and `entry_hash` (SHA-256 over canonical JSON). Live approval-callback MACs are logged as a fingerprint and `agw1.` signatures are redacted, because the log can ship in an audit directory. `audit` copies the log (`--decision-log`, or `decision-log.jsonl` / `alerts.jsonl` in the input directory), a scrubbed `findings.json`, and `replay.html`, then writes `audit_manifest.json` with every file's SHA-256, the chain head, and an HMAC with `AGENT_GATEWAY_HMAC_KEY`. `python -m agent_gateway verify <audit_dir>` recomputes all of it and exits 1 on any edit, drop, reorder, insert, truncation, extra file, or re-signed manifest. A passing verify means the files match the manifest. It is not a certification and not a penetration test.

## Quick start (loopback)

From the repository root, in a virtualenv:

```bash
python -m pip install -e "./agent-gateway[test]"
cd agent-gateway
pytest -q
python -m agent_gateway serve --host 127.0.0.1 --port 9100
# another terminal — mint bound approval (step from deny response):
python -m agent_gateway approve sess-1 --step 3 --tool send_email \
  --args-json '{"to":"team@internal.local","body":"Status OK"}'
curl -s http://127.0.0.1:9100/health

# offline executive report from an analyzer smoke directory
python -m agent_gateway audit ./analyzer-out --out-dir ./audit-report \
  --decision-log ~/.local/state/agent-gateway/alerts.jsonl
python -m agent_gateway verify ./audit-report
# same command via the console script, after pip install:
agent-gateway audit ./analyzer-out --out-dir ./audit-report
```

`pip install -e ./agent-gateway` (without `[test]`) installs the runtime dependency Flask and the `agent-gateway` console script. It does not install pytest or Hypothesis. The audit PDF writer is pure Python. WeasyPrint and wkhtmltopdf are not required. Non-editable: `pip install ./agent-gateway` from the repository root. The lab registry is `config/agents.json` in a checkout, and `agent_gateway/data/agents.json` inside a wheel.

## Executive audit report

Offline. Point it at the directory `agentwatch-analyzer` writes (`events.scrubbed.jsonl`, `findings.json`, `leads.jsonl`, `replay.html`, `stix-bundle.json`, `summary.json`).

```bash
python -m agent_gateway audit ./analyzer-out --out-dir ./audit-report
```

The HTML report (`audit-report.html`) includes:

- **Executive summary** — tool-call count, taint-event count, and ATLAS matches for `AML.T0051`, `AML.T0080`, and `AML.T0086` (subtechniques roll up to the parent id).
- **Session replay** — a link and an embedded frame for the static `replay.html`. The copy written next to the report is scrubbed again.
- **Risk matrix** — tool-call paths that can place data on an external boundary, versus paths held closed by an attenuated `agw1.` capability (`allow_egress=false`). An `agw1.` token that still allows egress is not treated as protection. Access-log fetches are not counted as tool calls.

`audit-report.pdf` is a text rendering of those figures from a small pure-Python PDF writer. WeasyPrint and wkhtmltopdf are optional if you want a paginated copy of the HTML. They are not dependencies. `--no-pdf` skips the text PDF. HTML is always written.

Capability signatures are omitted. Tool arguments pass through the gateway scrubber before they are written. The command does not bind, does not deliver webhooks, and does not start the honeypot.

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
├── agent_gateway/     # pep, mcp_proxy, deobfuscate, audit_chain, capability, approve, approval_webhook, audit_report, taint, registry, scrub, cli
├── config/agents.json # registered keys (lab secrets — not production)
├── tests/             # basic + 7 ATLAS falsification + capability, Hypothesis, approval webhook, audit report, MCP proxy, de-obfuscation, audit chain
└── README.md
```

## Language

Prefer: "policy gate", "untrusted ingest", "egress class", "falsification / regression test".
Avoid framing as instructions to attack third parties.
