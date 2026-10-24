# Changelog

Release notes for the AgentGate lab stack in this repository. This file
describes the v1.0.0 snapshot. It is not a git tag and it is not a GitHub
Release.

## [Unreleased] - v8 MCP wire proxy, de-obfuscation, audit chain

All three are zero-compute (standard library plus the existing Flask
dependency; no model calls). ATLAS ids are approximate.

- `agent_gateway/mcp_proxy.py`: MCP JSON-RPC 2.0 wire interceptor around the
  PEP. Tool-schema pinning (`sha256(name, description, inputSchema)`) on the
  first complete `tools/list`. A mid-session mutation or addition records
  `mcp_rug_pull_detected` (approximate AML.T0051), appends
  `allow_egress=false` to the `agw1.` token, and holds later `tools/call`
  requests for a bound one-time OOB approval. Server-initiated
  `sampling/createMessage` is rejected while tainted or without a root-keyed
  `grant:sampling=` caveat.
- `agent_gateway/deobfuscate.py`: salted n-gram digests of sensitive reads
  and canaries (raw, Base64, hex, URL-encoded, whitespace-stripped) matched
  against a per-session window of released outbound arguments. Split-chunk
  and encoded exfiltration is denied and the registered root key is frozen
  for 15 minutes (approximate AML.T0086). New Hypothesis `SmugglingMachine`.
- `agent_gateway/audit_chain.py`: SHA-256 hash chain (`seq`, `prev_hash`,
  `entry_hash`) on every PEP decision-log line; `audit` writes
  `audit_manifest.json`; new `python -m agent_gateway verify <audit_dir>`.
  Not a certification and not a penetration test.
- `agent-gateway` tests: **89 passed** (40 before this change).

## [1.0.0] - 2026-10-24

Prepared as release-prep on the private tree. The installable packages
`agent-gateway` and `agentwatch-analyzer` are versioned 1.0.0. No tag is
created by this change.

### AgentGate Runtime Behavioral Gateway

- Policy enforcement point in `agent-gateway/agent_gateway/pep.py` for
  registered internal agent keys. The project's reading of MITRE ATLAS
  mitigation AML.M0030: taint on untrusted ingest, then restrict the tool
  call. Default bind is `127.0.0.1`.
- `agw1.` capability attenuation is macaroon-style chained HMAC. Untrusted
  ingest appends `allow_egress=false`. A holder who does not have
  `AGENT_GATEWAY_HMAC_KEY` cannot strip that caveat. This is not a full
  macaroon library: there are no third-party caveats and no discharges.
- Stateful Hypothesis checks in `agent-gateway/tests/test_stateful_fuzz.py`
  (`hypothesis==6.170.9`).
- A held call is formatted in-process as Slack Block Kit and as a generic
  webhook document. Nothing is POSTed unless `serve` is started with
  `--webhook-deliver`.
- Freeze is a temporary 15-minute (900-second) freeze of internal keys
  listed in `agent-gateway/config/agents.json`. An unregistered key is
  refused and is not frozen.

### Standalone Offline Log Analyzer

- `agentwatch-analyzer` reads static access logs offline. It does not start
  a honeypot, bind a port, or make an outbound call. Secrets are scrubbed
  before outputs are written.
- **12** Sigma rules in `agentwatch-analyzer/rules/sigma/`: R8 through R14
  (`01_R8.yml`–`07_R14.yml`) and ATLAS AML.T0051, AML.T0053, AML.T0080,
  AML.T0086, AML.T0118 (`08`–`12`). From a normal access log, R8 and R9 are
  in scope, R10 is partial, R11–R13 are not available, and R14 is partial
  and advisory without a human beacon.
- STIX 2.1 bundles. A recorded smoke on the archived Tier-2 Playwright
  crawler log reported `validator_ok=true`. Known warnings on `x_`
  properties can still appear.

### Executive Audit CLI

- `python -m agent_gateway audit` (console script: `agent-gateway audit`)
  reads an analyzer output directory and writes an HTML risk matrix and a
  text PDF (`audit-report.html`, `audit-report.pdf`).
- The PDF writer is pure Python. WeasyPrint and wkhtmltopdf are not
  dependencies and are not required. `--no-pdf` skips the text PDF. HTML
  is always written.
- The command does not start the PEP server, does not start the honeypot,
  and does not open a socket.

### Turnkey CI/CD GitHub Action

- `.github/workflows/atlas-agent-audit.yml` runs `agent-gateway`,
  `agent-watch`, and `rogue-ai-pipeline`, then an offline
  `agentwatch-analyzer` smoke. The smoke checks the STIX bundle, runs
  `python -m agent_gateway audit`, and uploads `findings.json`,
  `replay.html`, the STIX 2.1 bundle, and the executive HTML and PDF.
- The workflow does not bind a port and does not start the honeypot.

### Packaging

- Multi-package tree. From the repository root:
  `pip install -e ./agentwatch-analyzer` and
  `pip install -e ./agent-gateway` (or the same paths without `-e`).
- `agentwatch-analyzer` is the console script for the analyzer.
  `agent-gateway` is the console script for the gateway.
  `python -m agent_gateway audit` works after the gateway package is
  installed, without `PYTHONPATH`.

### Caveats

- Default bind is `127.0.0.1`. A non-loopback gateway bind needs
  `--allow-nonlocal` and an isolated lab network. This repository does not
  ship a public honeypot deploy.
- The web honeypot is human-review only. It does not automatically block
  from unverified heuristics. Honeypot contact is a lead, not intent.
- Freeze applies only to registered lab keys, for 15 minutes.
- Tier-2 catch rate is **2 of 13** non-control archived runs: one machine,
  `qwen2.5:3b`, same author. Both catches were Playwright. Nine urllib
  sessions were not caught. The scripted human control is the fourteenth
  archive and is not in the 13. Not a benchmark. Do not pool it with the
  same-author synthetic regression tables.
- ATLAS mappings are approximate. They are not a certification.
- No outbound webhook delivery by default. A failed POST does not change
  the policy decision.
- Tool backends inside the gateway are simulated echoes. There is no Web
  Bot Auth in this tree.
- The GitHub repository is still private. `LICENSE` does not make it
  public.
