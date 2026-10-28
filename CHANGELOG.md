# Changelog

Release notes for the AgentGate lab stack in this repository. This file
describes the v1.0.0 snapshot. It is not a git tag and it is not a GitHub
Release.

## [Unreleased] - v11 provenance and accumulator wiring (28 October 2026)

- `temporal_accumulator_guard.py`: U+200D (zero-width joiner) removed from
  `ZERO_WIDTH_CHARS`, so compound emoji no longer count as watermarks.
  Protected tokens are held only as per-instance salted SHA-256 digests of
  the token, its Base64 and hex spellings, and its 8-character n-grams (no
  plaintext); an n-gram match needs **2** distinct digests. The window is
  persisted only for `STREAM_CLEAN` calls, so a denied call does not poison
  later benign calls. Tokens can be scoped to one session.
- `pep.py`: `memory_provenance_guard` records scratchpad notes and
  resource-addressed writes in an HMAC-signed lineage ledger (key derived
  from `AGENT_GATEWAY_HMAC_KEY`); reads of a note, a `uri` / `path`
  resource, or an MCP `resources/read` inherit the writer's taint, and a
  record that fails its HMAC is denied (`provenance_tamper_denied`, -32042).
  `export_provenance_ledger()` / `load_provenance_ledger()` persist it.
  `temporal_accumulator_guard` runs on every released outbound call
  (`sharded_exfil_denied`, -32043); sensitive reads and canaries register
  their values with it, scoped like the de-obfuscation fingerprints.
- `mcp_proxy.py`: accumulator windows keyed `mcp:<server>`; resources/read
  goes through the lineage check before it reaches the server.
- `sarif_export.py` / `audit_report.py`: `provenance_tamper_denied`
  (AML.T0080.000, ASI06) and `sharded_exfil_denied` (AML.T0086, ASI02).
- Tests: 3 provenance unit tests (taint inheritance with the origin
  `writer_session_id` kept, `TypeError` on bool inputs, tamper deny and
  `export_ledger` / `load_ledger`), 5 accumulator tests, and
  `test_v11_provenance_accumulator_wiring.py` (12), added to Group D.
- Gateway tests 369 -> **389** (Group D 104 -> **124**, six files); CI floor
  345 -> 385. Hypothesis state machines stay at **7** and modules behind
  `pep.py` at **26**. Workspace **911** (agent-watch 512, analyzer 10).
  Groups A / B / C unchanged (57/57); 750 benign decisions, 0 denials.
- Site: trace 07 (cross-session lineage, a tampered record, sharded
  watermarks) and a re-recorded trace 08, both in-process against
  `PolicyEngine` (`examples/record_site_traces.py 7 8`); traces 01-06 and
  `sprint_submission/` / `site/sprint/` unchanged.

## [Unreleased] - v11 post-sprint guards (28 October 2026)

- `schema_integrity_guard.py`: RFC 8785-style canonical JSON, SHA-256 pin per
  `(server_id, tool_name)` across sessions. `SCHEMA_DRIFT_DENIED` without a
  manifest entry signed with the gateway HMAC key; `TOOL_SHADOWING_DENIED`
  for a normalized name within one edit of a tool pinned on another server.
  Wired into `McpWireProxy` (drifted or colliding tools are not served;
  calls to a drifted tool get `schema_drift_denied`, -32041).
- `gui_action_guard.py`: reserved screen rectangles and viewport bounds
  (`gui_region_denied`, -32038), modifier-normalized shortcut deny-list and
  raw control characters (`gui_keychord_denied`, -32039). Wired into
  `PolicyEngine.evaluate_call` for bare action names, `computer.<action>`,
  and a `computer` tool with `action` / `coordinate` / `text`.
- `memory_provenance_guard.py`: HMAC-signed cross-session resource lineage
  ledger; the taint-origin writer is kept; strict int checks;
  `MAX_TAINT_LEVEL`; `export_ledger` / `load_ledger` verify every record.
- `temporal_accumulator_guard.py`: bounded per-(session, destination) window
  validator for registered tokens and zero-width watermark counts.
- SARIF rules with approximate ATLAS ids and OWASP Agentic ASI tags for the
  four schema / GUI codes; the decision-log summary counts them.
- `collusion_eval.POST_SPRINT_GROUPS["D"]` and `run_post_sprint_suite()`.
  Groups A / B / C (57/57) and `evaluate-collusion` output are unchanged;
  `sprint_submission/` and `site/sprint/` are untouched.
- Gateway tests 262 -> **369** (Group D: 104); Hypothesis state machines
  5 -> **7**; modules behind `pep.py` 22 -> **26**; CI floor 250 -> 345.
  Workspace: **891** passing (agent-watch 512 passed, 2 skipped; analyzer 10).
- Site: trace 08 (schema drift across sessions and a cross-server name
  collision), recorded in-process by `examples/record_site_traces.py 8`;
  post-sprint figures and v11 scope notes added beside the sprint figures.

## [Unreleased] - report-style site and per-target outreach (25 October 2026)

- `site/` rebuilt as a technical report: archival palette, hairline grid,
  self-hosted Newsreader and IBM Plex (SIL OFL 1.1, `site/fonts/`), no
  gradients, shadows, or blur. Sections: empirical summary with a latency
  scale that shows the 3.84 ms maximum, architecture schematic, trace
  inspector, reproduce, scope and non-goals, and a schedule of deliverables
  with hashed sample artifacts.
- `examples/record_site_traces.py` records the six inspector traces against
  the real `PolicyEngine`, `McpWireProxy`, `toxic_combinations.analyze`, and
  `audit_chain` (median CPU of 30 fresh runs per step); `site/app.js` embeds
  its output. The trace-03 graph now counts `web.fetch` as a URL sink, so its
  totals match `analyze()` (12 paths).
- `marketing/outreach-sequence.md`: ten per-target Touch 2 payloads, each tied
  to one carrier and the matching trace.

## [Unreleased] - docs, site, and offer sync (25 October 2026)

- README: sprint-submission callout near the top (report, slides, JSON,
  reproduction command, headline figures with the 3.84 ms max and the scope
  note). Gateway count 240 -> **262** (244 before the sprint: 240 for v10
  plus 4 HTTP resource-limit tests; then 11 `evaluate-collusion` and 7
  sprint-artifact tests). agent-watch: 514 collected, 512 passed, 2 skipped.
- Site (`site/`): metrics bar synced (262 gateway, 784 passing in all,
  57/57, p50 0.126 ms / p99 0.999 ms, 0 of 750 benign denials), a "Verify in
  30 seconds" box, deliverable-backed tier names, sample-deliverable links,
  and two v10 simulator presets (confused-deputy delegation; obfuscated
  canary exfiltration). Copies of the sprint report, slides, and JSON are in
  `site/sprint/` so the Pages links resolve; `sprint_submission/` is
  unchanged.
- Whitepaper dated 25 October 2026 with a new section 6.1 on the v10
  collusion carriers and the `evaluate-collusion` results; PDF regenerated
  from the Word file.

## [Unreleased] - collusion sprint evaluation

- `agent_gateway/collusion_eval.py` and `python -m agent_gateway
  evaluate-collusion [--report OUT_DIR] [--iterations N]`: aggregates the
  existing side-channel (A), delegation (B), and de-obfuscation / canary (C)
  defence tests by group from pytest JUnit XML, times benign `evaluate_call`
  decisions (CPU p50 / p95 / p99 against a 2 ms reference), and verifies a
  hash-chained benign decision log including edit and drop detection. Writes
  `collusion_benchmark_results.json`, `collusion_sprint_report.md`, and
  `collusion_sprint_report.pdf`, a 6-slide `collusion_sprint_slides.pdf`, and
  a 1200x630 `collusion_project_image.png` (`sprint_artifacts.py`, standard
  library only). Generated set in `sprint_submission/`.
  Same-author lab scenarios; not pooled with the 2 of 13 archive figure.

## [Unreleased] - fail-closed HMAC key

- `capability.hmac_key()` now raises if `AGENT_GATEWAY_HMAC_KEY` is unset or
  shorter than 32 bytes. The built-in lab key is used only with an explicit
  `allow_default=True`. The CLI exits with code 2 and a clear message at
  startup. The test suite sets its own key.
- `examples/replay_attenuation.py`: in-process replay against the real
  `PolicyEngine` with simulated backends (one denied call, allowed calls, a
  failed re-enable of egress, and the direct-call limit).
- `docs/tool-classification.md`: egress classes, and that unknown tools fail
  closed as writes once tainted. Quickstart examples now generate a random
  32-byte key. The replay asserts the direct-bypass limit. README notes that
  key rotation is not supported.
- HTTP resource limits (`max_body_bytes`, `max_arg_bytes`, `max_sessions`,
  `max_id_len`) with tests. `docs/integration-contract.md` and
  `examples/gated_dispatch.py` state the caller's side of the boundary. Two
  more synthetic boundary notes under `docs/examples/`.
- Offer page, README, and site pricing now show the Tool Inventory Review
  ($1,800), Fixed Note ($4,500), Note + Lab Instrumentation ($6,500), and
  the add-ons. The marketing drafts (`outreach-sequence.md`, `ciso-outreach.md`,
  `marketing/README.md`, `la-targets.md`) were aligned to the same tiers.
  `show-hn.md`, `reddit-localllama.md`, and the checklist quote no prices
  and are unchanged.
- README: "What this is not" box, boundary replay command, and a "Known
  non-goals and bypasses wanted" section.

## [Unreleased] - v10 delegation guard, argument firewall, canary watermarking, SARIF

All four are zero-compute (standard library; no model calls). ATLAS ids
are approximate.

- `agent_gateway/delegation_guard.py`: monotonic capability attenuation
  across multi-agent hand-offs. The meet of two `agw1.` capabilities
  carries deny-egress, deny-sampling, and taint sources into the
  recipient, cryptographically (appended caveats the recipient cannot
  strip). A delegated agent that was barred upstream is blocked at egress
  with `confused_deputy_delegation_blocked` (approximate AML.T0051 /
  AML.T0086). New `delegate_task` tool; `spawn_subagent` with a child key
  also attenuates.
- `agent_gateway/arg_ast_guard.py`: lexical / canonical argument firewall.
  Path traversal (encoded, backslash, NUL, UNC, sensitive system paths),
  shell-metacharacter chaining, CRLF header splitting, and mutating /
  file-exfil SQL in read-classified tools are denied with
  `arg_firewall_violation` (approximate AML.T0051 / AML.T0053).
- `agent_gateway/canary_watermark.py`: zero-width HMAC watermark bound to
  `(session, step, tool)` woven into sensitive reads, plus a credential
  tracker (AWS / GitHub / OpenAI / Anthropic / Google / Slack / JWT /
  PEM). A watermark or credential in a later outbound call is denied, the
  registered key is frozen for 15 minutes, and provenance is written to
  the hash-chained log (`canary_watermark_exfil`, approximate AML.T0086).
- `agent_gateway/sarif_export.py`: OASIS SARIF 2.1.0 exporter.
  `audit --sarif <path>` emits gateway findings, toxic paths, and analyzer
  matches for GitHub code scanning; a report-dir SARIF is covered by
  `audit_manifest.json`. The workflow uploads `findings.sarif`.
- `agent-gateway` tests: **240 passed** (161 before this change).

## v9 - toxic-flow graph, ingress scanner, SSRF and side-channel guards (PR #17)

All four are zero-compute (standard library; no model calls, no DNS).
ATLAS ids are approximate.

- `agent_gateway/toxic_combinations.py`: static reachability over a tool
  inventory. Lists every 2-hop and 3-hop `external_read -> read -> sink`
  path whose sink has a free-text channel and no hard `agw1.` boundary
  (approximate AML.T0086). `audit --tool-inventory` adds it to
  `findings.json`, the HTML (table plus inline SVG), and the PDF, under
  `audit_manifest.json`. An inventory alone is enough for a
  tool-list-only audit.
- `agent_gateway/tool_output_scanner.py`: Unicode tag smuggling,
  zero-width and BiDi override characters, delimiter / role spoofing,
  fake JSON-RPC envelopes, and cross-tool name shadowing in untrusted tool
  output. Findings taint the session and attenuate the `agw1.` token
  (approximate AML.T0051); the proxy forwards the result with invisible
  characters removed.
- `agent_gateway/egress_uri_guard.py`: canonical SSRF / cloud-metadata
  guard over URI and host arguments; `ssrf_boundary_violation`
  (approximate AML.T0053). Metadata and obfuscated internal spellings are
  denied, plain private targets are held for a bound OOB approval, and
  the literal lab loopback hosts stay allowed.
- `agent_gateway/side_channel_guard.py`: post-trifecta boolean-oracle,
  cardinality, and timing-beacon detection;
  `covert_side_channel_suspected` (approximate AML.T0086) holds the
  session and freezes the registered root key for 15 minutes.
- `agent-gateway` tests: **161 passed** (89 before this change).

## v8 - MCP wire proxy, de-obfuscation, audit chain (PR #16)

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
- The repository is public under Apache 2.0. The paid audit is a separate
  written service and does not change the license.
