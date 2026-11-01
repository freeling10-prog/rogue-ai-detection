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
12. **MCP JSON-RPC 2.0 wire proxy** (`mcp_proxy.py`) — a standard-library filter for one client/server MCP session. It gates `tools/call`, `resources/read`, and `prompts/get` through the PEP and pins `sha256(name, description, inputSchema)` for every tool on the first complete `tools/list`. A later listing that mutates or adds a pinned tool is a rug pull (`mcp_rug_pull_detected`, approximate AML.T0051): the session capability gets `allow_egress=false`, the client keeps the pinned definitions, and every later call waits for a bound one-time OOB approval (`params._meta["agentgate/approval_token"]` and `["agentgate/bound_step_index"]`, stripped before forwarding). Server-initiated `sampling/createMessage` is rejected while tainted or when the `agw1.` token has no root-keyed `grant:sampling=` caveat (`capability.mint(..., sampling=True)`). Ids are null, string, or int with no coercion between them; a response whose id is not in flight is not forwarded. Batches, a BOM, duplicate keys, lone surrogates, and a reused in-flight id are rejected. Results, error bodies, resource and prompt listings, sampling, and elicitation are scanned before they can reach the model. The proxy opens no sockets; the caller moves the bytes. `handle_line` is the wire entry and uses `loads_strict`, the same parser as Flask `/mcp`: a caller that parses JSON first has already collapsed duplicate keys, and a non-integer id token such as `7.0` is rejected before an integral decimal collapses to `int`. Elicitation uses JSON-RPC -32081 so it does not share -32077 with Predicate C.
13. **Cross-step smuggling de-obfuscation** (`deobfuscate.py`) — sensitive-read results and registered canaries are kept only as salted SHA-256 digests of 8-character n-grams of the raw value and its Base64, hex, URL-encoded, and whitespace-stripped forms. Released outbound arguments join a per-session sliding window (one global stream and one per argument key), and each chunk is also decoded on its own. A match catches split-chunk leaks (4–6 characters per call), encode-then-split, and split-then-encode. The call is denied (`deobfuscated_exfil_detected`, approximate AML.T0086) and the registered root key is frozen for 15 minutes. Denied calls never join the window.
14. **Hash-chained audit receipts** (`audit_chain.py`) — every decision-log line carries `seq`, `prev_hash`, and `entry_hash` (SHA-256 over canonical JSON). Live approval-callback MACs are logged as a fingerprint and `agw1.` signatures are redacted, because the log can ship in an audit directory. `audit` copies the log (`--decision-log`, or `decision-log.jsonl` / `alerts.jsonl` in the input directory), a scrubbed `findings.json`, and `replay.html`, then writes `audit_manifest.json` with every file's SHA-256, the chain head, and an HMAC with `AGENT_GATEWAY_HMAC_KEY`. `python -m agent_gateway verify <audit_dir>` recomputes all of it and exits 1 on any edit, drop, reorder, insert, truncation, extra file, or re-signed manifest. A passing verify means the files match the manifest. It is not a certification and not a penetration test.
15. **Toxic-combination graph** (`toxic_combinations.py`) — from a tool inventory (MCP `tools/list` shape, optional `class` labels `external_read` / `internal_read` / `sensitive_read` / `write` / `send` / `credential_use`; unlabelled tools are classified from the egress table, then the name, else `write`), every 2-hop `external_read → read → sink` and 3-hop `external_read → read → read → sink` path is listed when the sink has a free-text channel and no hard `agw1.` boundary (`agw1_boundary: true` on the tool or inventory). Enum, integer, pattern, and short-`maxLength` sinks are constrained and not counted. `audit --tool-inventory tools.json` (or `tool-inventory.json` in the input directory) adds the section to `findings.json`, the HTML (table plus inline SVG), and the PDF, all covered by `audit_manifest.json`. An inventory alone is enough for a tool-list-only audit. The PEP re-runs the analysis on every `tools/list`. Static analysis of declared capabilities, approximate AML.T0086; not a penetration test.
16. **Tool-output injection scanner** (`tool_output_scanner.py`) — untrusted results (simulated `external_read` results in the PEP; every MCP `tools/call`, `resources/read`, and `prompts/get` result in the proxy) are scanned before they reach the agent loop for Unicode tag smuggling (decoded for the reviewer, and itself scanned), zero-width and BiDi override characters, delimiter / role spoofing (`</tool_result>`, `<|im_start|>`, `[INST]`, `<<SYS>>`, `\n\nHuman:`) after NFKC folding, fake JSON-RPC envelopes, and cross-tool name shadowing of the session's write / send / credential tools. A finding records `tool_output_injection` (approximate AML.T0051), taints the session, appends `allow_egress=false`, and the result is forwarded with invisible characters removed.
17. **Canonical SSRF guard** (`egress_uri_guard.py`) — every URL / URI / host argument (by key, or any embedded `scheme://`) is canonicalized: dword, hex, octal, short IPv4, IPv4-mapped / compatible / NAT64 IPv6, zone ids, percent-encoded hosts, userinfo (`https://allowed.com@169.254.169.254`), backslash parser differentials, and wildcard-DNS names such as `127.0.0.1.nip.io`. Cloud metadata and any obfuscated internal spelling are denied; plain RFC 1918, link-local, CGNAT, and `.internal` targets are held for a bound one-time OOB approval. The literal lab hosts `127.0.0.1`, `localhost`, and `::1` stay allowed (`PepConfig.ssrf_lab_allow`). Findings are `ssrf_boundary_violation` (approximate AML.T0053). No DNS lookup, so DNS rebinding is out of scope.
18. **Side-channel guard** (`side_channel_guard.py`) — after a session is both TAINTED and SENSITIVE_READ, released outbound calls are counted: more than 4 distinct argument variants (a boolean oracle's alphabet), more than 16 calls, or 5 equal intervals of 0.5 s or more in a row (a timing beacon) records `covert_side_channel_suspected` (approximate AML.T0086), denies the call, holds the session for review, and freezes the registered root key for 15 minutes. Calls a person released with a bound OOB token are not counted. Thresholds are `PepConfig.side_channel`.
19. **Delegation / confused-deputy guard** (`delegation_guard.py`) — a hand-off (`delegate_task`, or `spawn_subagent` with a child key) re-mints the recipient's session `agw1.` token carrying the sender's deny caveats (meet of the two capabilities), so a clean peer or orchestrator cannot launder a tainted parent's egress. A delegated principal that was barred upstream but presents a clean-looking session is caught at egress with `confused_deputy_delegation_blocked` (approximate AML.T0051 / AML.T0086). The meet is monotonic: re-delegation never restores egress.
20. **Argument firewall** (`arg_ast_guard.py`) — before any gate, each tool argument is checked for path traversal (`../`, `%2e%2e%2f`, double-encoded, backslash, NUL, UNC, and sensitive system paths), shell-metacharacter chaining in command arguments, CRLF splitting in header arguments, and, for `internal_read` / `sensitive_read` tools, mutating or file-exfil SQL (`INTO OUTFILE`, `COPY ... TO`, `ATTACH DATABASE`, `pg_read_file`, `xp_cmdshell`, `LOAD_FILE`, stacked mutating statements). A hit denies the call with `arg_firewall_violation` (approximate AML.T0051 / AML.T0053). No command, query, or file is executed.
21. **Canary watermarking & credential tracker** (`canary_watermark.py`) — a sensitive read's output gets a deterministic zero-width HMAC watermark bound to `(session, step, tool)`, and standard credential formats (AWS `AKIA` / `ASIA`, GitHub `ghp_` / `github_pat_`, OpenAI / Anthropic `sk-`, Google `AIza`, Slack `xox[baprs]-`, JWT, PEM) are recorded by salted digest. If a watermark or tracked credential surfaces in a later outbound call, the call is denied, the registered key is frozen for 15 minutes, and `origin_step_index` / `origin_tool_name` are written to the hash-chained decision log (`canary_watermark_exfil`, approximate AML.T0086). The registry keeps digests and tags, never the raw secret.
22. **SARIF 2.1.0 exporter** (`sarif_export.py`) — `audit --sarif <path>` writes all gateway findings, toxic tool-graph paths, and analyzer matches as OASIS SARIF 2.1.0 for GitHub code scanning. A bare filename lands in the report directory and is covered by `audit_manifest.json`. ATLAS ids ride in `properties.tags`; severities are a lab triage aid, not a certification.
23. **Cross-session file labels** (`fs_label_store.py`, Predicate T) — (confidentiality, integrity) labels committed for a workspace root are appended to a hash-chained sidecar and loaded by the next session, including shell redirections. With `real_root` bound, a regular file is keyed by dev, inode, size, mtime, and SHA-256; a post-epoch file with no record is UNTRUSTED. Reading an UNTRUSTED file taints the session so the existing egress hold applies. This does not freeze a key. The state directory is trusted storage; residuals are in the changelog and DESIGN.md section 6.

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
# tool-list-only audit: an inventory is enough
python -m agent_gateway audit ./tool-list-dir --tool-inventory ./tools.json --out-dir ./audit-report
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

## Collusion sprint evaluation

`python -m agent_gateway evaluate-collusion --report <out_dir>` is offline and binds no port. It does three things:

1. Runs the existing defence tests in a pytest subprocess and counts pass / fail per carrier group, keyed by node id. Group A is `test_side_channel_guard.py`, Group B is `test_delegation_guard.py`, and Group C is `test_deobfuscate.py` plus `test_canary_watermark.py`.
2. Times `evaluate_call` on five benign multi-agent workflows (thread CPU time, p50 / p95 / p99) against a 2 ms reference.
3. Writes each benign decision to a hash-chained log, verifies it, and checks that an edited or dropped line in a copy is detected.

It writes `collusion_benchmark_results.json`, `collusion_sprint_report.md`, `collusion_sprint_report.pdf`, a 6-slide `collusion_sprint_slides.pdf`, and a 1200x630 `collusion_project_image.png`, all with the standard library. The last generated set is in [`sprint_submission/`](../sprint_submission/). The scenarios are same-author scripted lab workflows, not a benchmark. The real-model loopback archive figure (2 of 13) is a separate measurement and is never pooled with them. The command generates no attack traffic of its own.

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
├── agent_gateway/     # pep, mcp_proxy, deobfuscate, audit_chain, toxic_combinations, tool_output_scanner, egress_uri_guard, side_channel_guard, delegation_guard, arg_ast_guard, canary_watermark, sarif_export, capability, approve, approval_webhook, audit_report, taint, registry, scrub, cli
├── config/agents.json # registered keys (lab secrets — not production)
├── tests/             # basic + 7 ATLAS falsification + capability, Hypothesis, approval webhook, audit report, MCP proxy, de-obfuscation, audit chain, SSRF guard, output scanner, toxic combinations, side channel, delegation, argument firewall, canary, SARIF
└── README.md
```

## Language

Prefer: "policy gate", "untrusted ingest", "egress class", "falsification / regression test".
Avoid framing as instructions to attack third parties.
