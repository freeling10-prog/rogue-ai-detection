# AgentGate: Runtime Behavioral Security & MITRE ATLAS Taint-and-Freeze Gateway for AI Agents & MCP

AgentGate is the lab policy gate in this repository. It sits in the tool loop of a **registered internal** agent, taints the session when untrusted content arrives, and attenuates an `agw1.` capability so that capability cannot turn egress back on. A held call is formatted for a person as Slack Block Kit and as a generic webhook document. Freeze applies only to keys listed in the lab registry, for 15 minutes. The web honeypot stays a lead for human review.

**Live interactive demo (public, no login):** <https://freeling10-prog.github.io/rogue-ai-detection/> · Source: [github.com/freeling10-prog/rogue-ai-detection](https://github.com/freeling10-prog/rogue-ai-detection) · Book: [alec@room23.net](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)

> **Apart Research collusion sprint — submission artifacts** (generated at commit `cefec0d`, 25 October 2026)
>
> - Report: [`sprint_submission/collusion_sprint_report.pdf`](sprint_submission/collusion_sprint_report.pdf) ([Markdown](sprint_submission/collusion_sprint_report.md)) · Slides: [`sprint_submission/collusion_sprint_slides.pdf`](sprint_submission/collusion_sprint_slides.pdf) · Raw data: [`sprint_submission/collusion_benchmark_results.json`](sprint_submission/collusion_benchmark_results.json)
> - Reproduce (from `agent-gateway/`, with `AGENT_GATEWAY_HMAC_KEY` set): `python -m agent_gateway evaluate-collusion --report ../sprint_submission`
> - **57/57** collusion defence tests passed: Group A side-channel / timing **8/8**, Group B delegation / confused-deputy **8/8**, Group C de-obfuscation / canary watermarking **41/41**.
> - **5** stateful Hypothesis machines in the suite, including the delegation DAG machine (`max_examples=120`, `stateful_step_count=24`).
> - **750** benign policy decisions (5 workflows × 50 runs): **0** false denials; **750/750** SHA-256 hash-chained decision-log entries verified (the audit manifest is HMAC-signed), and an edited or dropped line in a copy is detected.
>
> **Frozen snapshot vs. `main`.** The files above are the 25 October sprint snapshot at `cefec0d` (57/57 A/B/C checks) and are not regenerated. `main` has since added further guards behind `pep.py`. Their tests are reported apart from 57/57 and are never folded into that count. The test suite currently passes 1,418 tests.
>
> Scope: these are same-author, scripted lab checks of the guards against cases written for them. They are not a benchmark and not an estimate of recall against an unknown adversary. They are never pooled with the separate real-model loopback figure (**2 of 13** non-control runs, `qwen2.5:3b`, one machine).

**What this is not.** Not a production WAF. Not an injection detector. Not an OS sandbox or network isolation. Not a penetration test, a benchmark, or a certification. It governs only tool calls that are routed through it. See [Known non-goals and bypasses wanted](#known-non-goals-and-bypasses-wanted).

**Run the boundary replay** (in-process, simulated backends, no network, no port):

```bash
AGENT_GATEWAY_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" python examples/replay_attenuation.py
```

It starts a session, ingests untrusted content, then shows one denied call, two calls that stay allowed, and one known limit. The gateway refuses to start without an explicit key of at least 32 bytes. See [examples/replay_attenuation.py](examples/replay_attenuation.py).

This page is the product front door. The research write-up is the whitepaper ([PDF](docs/rogue-ai-detection-whitepaper.pdf), [Word](docs/rogue-ai-detection-whitepaper.docx)), updated 25 October 2026. Read the [lab limits](#lab-limits) before treating any number below as a deployment result.

## Choose a path

### Self-serve CI/CD and Slack sidecar

Wire the turnkey audit workflow and the in-process approval formatter. Both ship in this tree. Neither one publishes the honeypot.

- GitHub Action: [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml). On pull requests and on pushes to `main` it runs `agent-gateway`, `agent-watch`, and `rogue-ai-pipeline`, then an offline `agentwatch-analyzer` smoke. The smoke reads an archived log, checks the STIX bundle, runs `python -m agent_gateway audit`, and uploads `findings.json`, `replay.html`, the STIX 2.1 bundle, and the executive `audit-report.html` / `audit-report.pdf`. It does not bind a port.
- Slack sidecar: [`agent-gateway/agent_gateway/approval_webhook.py`](agent-gateway/agent_gateway/approval_webhook.py), called from [`pep.py`](agent-gateway/agent_gateway/pep.py) when a tainted tool call is held. The document is Slack Block Kit (`text` + `blocks`) and a generic `webhook` object. **Approve Once** authorizes that exact call. **Deny & Freeze Key 15m** freezes a registered key for 900 seconds.
- Three-minute loop, copy-paste Docker or local Python: [docs/quickstart.md](docs/quickstart.md). Building the JSON does not open a socket. HTTP runs only with `python -m agent_gateway serve --webhook-deliver` and a URL you set.

The workflow above is the free lab audit of this tree. It is not the paid review below, and it is not a claim that a public agent estate has been measured.

### How to book

The free path comes first: the GitHub Action and the offline analyzer above are free, Apache 2.0, and run on your own logs.

The paid offer is the [AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md), a written document and a person's time. It does not change the license or add a proprietary module.

| Tier | Price | What you get |
| --- | --- | --- |
| MCP Permission Quick Check | **$149** | Config and tool-manifest review of up to 5 MCP servers / 60 tools (secrets removed). Each tool classed read, write, send, or credential use. One-page PDF, top 5 fixes, in 24 hours. No code review, no runtime testing, no access to your systems |
| Starter MCP Server Build | **$450** | One system, up to 4 tools, at most 1 write tool behind confirmation, API-key auth, tests, and a README, in 4 business days. 1 revision. Add-ons on the [offer page](marketing/audit-offer.md) |
| 48-Hour Hardened MCP Server Build (Fixed-Scope Implementation) | **$750 flat** ($350 kickoff / $400 on passing acceptance tests) | A custom MCP server for one system (Postgres, Stripe, HubSpot, Slack, or an internal REST API) built on [`mcp_blueprint.py`](agent-gateway/agent_gateway/mcp_blueprint.py) and wrapped in `pep.py` allow / deny rules, sensitive-field redaction, SHA-256 hash-chained audit logging, and a `pytest` acceptance suite. Delivered as a mergeable PR in 48 hours. Nothing is deployed on your hosts by us |
| MCP Server Security Review | **$950** / **$1,500** for two | Code and tool-definition review, a loopback lab run on test data, ranked findings with fixes, SARIF 2.1.0, a 30-minute walkthrough, and one re-test, in 3 business days. Not a pentest and not an attestation |
| Agent-Gateway Guardrail Drop-In | **$1,500** | Policy proxy for up to 3 servers / 30 tools, in 5 business days. Log-only by default. Enforces only deterministic rules the client approves, and only the client switches them on. Pull request and runbook; nothing deployed on your hosts |
| Boundary Watch | **$395 / month** | Monthly re-run, up to 5 new or changed tools, one small change, a one-page summary. Month to month |
| Tier 1: MCP & Multi-Agent Exposure Diagnostic (Tool Inventory Review) | **$1,800** | Executive collusion and posture report (PDF), SARIF 2.1.0 bundle (`sarif_export.py`, approximate ATLAS ids), Sigma rules + STIX 2.1 bundle (`agentwatch-analyzer`). No lab pass |
| Tier 2: Inline PEP Hardening & CI Gate Sprint (Fixed Tool-Boundary Note) | **$4,500** | Tier 1 and the full written note, plus a loopback `pep.py` / `mcp_proxy.py` policy set for your tool list, the 13 Hypothesis regression machines in a CI workflow, and hash-chained per-run logging (`audit_chain.py`). Delivered as a pull request your team merges |
| Tier 3: Continuous Red-Team, Canary & Deception Retainer (Note + Lab Instrumentation) | **$6,500**, then $2,500 per quarter | Tier 2 plus a lab gateway pass on `127.0.0.1` (simulated backends), an offline analyzer pass on an authorized log, localhost tripwire / canary / de-obfuscation / side-channel guard configuration, and a quarterly `evaluate-collusion` re-run |

Optional add-ons: Integration Blueprint (+$2,500, code or config sketches for the top held calls, nothing deployed on your hosts), Reviewer Briefing Call (+$750), Quarterly Refresh Retainer ($2,500 per quarter). All prices are fixed. Credit toward the flagship audit, if booked within 30 days: 100% of a Quick Check fee and 50% of a Security Review or Drop-In fee. The public cards are on the [live site](https://freeling10-prog.github.io/rogue-ai-detection/#services).

Email [alec@room23.net](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit) with the subject `Book 48-Hour Agentic Tool-Boundary Audit`. You can reply in that thread with a tool inventory (names and argument shapes, no secrets). The clock starts when a usable tool list arrives. This is not a penetration test and not a certification. The honeypot stays human-review only, freeze applies only to registered lab keys for 15 minutes, and ATLAS ids in the note are approximate. See an [example note](docs/examples/sample-boundary-note.md). Sample output from our own sprint run: [report PDF](sprint_submission/collusion_sprint_report.pdf), [briefing deck](sprint_submission/collusion_sprint_slides.pdf), [JSON](sprint_submission/collusion_benchmark_results.json).

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

One-page offer: **[AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md)**

## Compliance snapshot

Labels for results **recorded in this lab tree on 25 October 2026** (the gateway count was re-run on 14 November 2026). They are not a certification, and they are not evidence of a wild deployment. The GitHub Action file is the thing you run; the shields only repeat the recorded counts.

[![GitHub Action atlas-agent-audit.yml](https://img.shields.io/badge/GitHub_Action-atlas--agent--audit.yml-3b5bdb)](.github/workflows/atlas-agent-audit.yml)
[![gateway tests 1418 passed](https://img.shields.io/badge/gateway_tests-1418_passed-2f6f4e)](agent-gateway/tests)
[![ATLAS 7/7 plus Hypothesis](https://img.shields.io/badge/ATLAS_falsification-7%2F7_%2B_Hypothesis-2f6f4e)](agent-gateway/tests/test_pep_falsification.py)
[![STIX validator_ok true](https://img.shields.io/badge/STIX_2.1-validator__ok%3Dtrue-2f6f4e)](agentwatch-analyzer/scripts/ci_smoke.py)

| Check | Where | Recorded result |
| --- | --- | --- |
| ATLAS agent audit | [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml) | Four jobs: gateway, agent-watch, pipeline, offline analyzer smoke. The smoke job fails unless the STIX bundle parses and `validator_ok` is true. It then runs `python -m agent_gateway audit` and uploads the executive HTML and text PDF with the other artifacts. No honeypot process. |
| Gateway tests | `agent-gateway` pytest | The test suite currently passes 1,418 tests (`pytest -q` in `agent-gateway`; 6 skipped without `php`). Earlier suite totals are not quoted. |
| agent-watch tests | `agent-watch` pytest | **514** collected: **512** passed, **2** skipped. |
| Collusion sprint check | `python -m agent_gateway evaluate-collusion` | **57/57** defence tests (A 8/8, B 8/8, C 41/41); 750 benign decisions, 0 denied; 750/750 chain entries verified. Same-author lab check, not a benchmark. Decision-time figures are not quoted. Artifacts in [`sprint_submission/`](sprint_submission/). |
| STIX 2.1 | [`agentwatch-analyzer/scripts/ci_smoke.py`](agentwatch-analyzer/scripts/ci_smoke.py) | Recorded smoke on the archived Tier-2 Playwright crawler log reported **`validator_ok=true`**. Known warnings on `x_` properties and approximate ATLAS tags can still appear. |

The test suite currently passes 1,418 tests. Do not quote an earlier suite total.

## What you are running

| Piece | Role | Bound |
| --- | --- | --- |
| [`agent-gateway`](agent-gateway/README.md) / `pep.py` | Policy enforcement in the agent tool loop. The project's reading of ATLAS **AML.M0030**: taint on untrusted ingest, then restrict the tool call. Chained HMAC capability (`agw1.`) attenuates with `allow_egress=false`. | Registered keys in [`agent-gateway/config/agents.json`](agent-gateway/config/agents.json). Default bind `127.0.0.1`. |
| Slack / webhook sidecar | Scrubbed approval JSON when a call is held. Callbacks are one-time and hash-bound to session, step, tool, canonical args, and taint source. | No POST unless `--webhook-deliver`. A failed POST does not change the policy decision. An unregistered key is not frozen. |
| [`agent-watch`](agent-watch/README.md) | Log detector and localhost honeypot. Leads for a person. | Default bind `127.0.0.1`. Contact with a canary is a lead, not intent, and not a block. |
| [`agentwatch-analyzer`](agentwatch-analyzer/README.md) | Offline Sigma rules, session replay, STIX 2.1. | No port and no outbound call. |
| PHP Defense Guard ([`php_defense_guard.php`](agent-gateway/agent_gateway/php_defense_guard.php), Python mirror [`php_defense_guard.py`](agent-gateway/agent_gateway/php_defense_guard.py)) | Runtime request input checks for Laravel, WordPress, or plain PHP 7.4+: `PHP_SQLI_UNION`, `PHP_SQLI_TAUTOLOGY`, `PHP_PATH_TRAVERSAL`, `PHP_DESERIALIZE_DENIED`, `PHP_RCE_EVAL`. Answers 403 with the rule code and appends a SHA-256 hash-chained log entry. | Lexical checks on `$_GET`, `$_POST`, and `$_COOKIE`. Not a WAF and not a replacement for parameterized queries or `allowed_classes => false`. |
| v12.2 reference middleware validators ([`registry_pin_validator.py`](agent-gateway/agent_gateway/registry_pin_validator.py), [`workspace_path_validator.py`](agent-gateway/agent_gateway/workspace_path_validator.py), [`lattice_flow_validator.py`](agent-gateway/agent_gateway/lattice_flow_validator.py), [`shingle_similarity_validator.py`](agent-gateway/agent_gateway/shingle_similarity_validator.py), [`common.py`](agent-gateway/agent_gateway/common.py)) | Per-provider descriptor pins with sticky revocation, alias ambiguity, and display-metadata lint; a literal-shell effect analyzer over an immutable filesystem model; a two-level contamination lattice with a precommitted single-use-step manifest; rolling shingles plus bounded bit-parallel LCS over protected strings. Five rule codes (`-32066` through `-32070`), SARIF rules with CWE and OWASP tags. | Opt-in: each validator is inert until a trusted adapter attaches pins, a filesystem snapshot, a manifest, or a matcher. The path module executes nothing and is not an OS sandbox, and unmodeled shell syntax fails closed. Benchmark figures are the reference package's, measured on Python 3.12. |
| v12.1 guards ([`interpreter_exec_guard.py`](agent-gateway/agent_gateway/interpreter_exec_guard.py), [`mcp_capability_manifest_guard.py`](agent-gateway/agent_gateway/mcp_capability_manifest_guard.py), [`cross_agent_collusion_guard.py`](agent-gateway/agent_gateway/cross_agent_collusion_guard.py)) | Inline interpreter payloads (`python -c`, `node -e`, heredocs, decoded pipes) that write protected paths or call process / network primitives; MCP tools that ask, from their first listing, for credentials or execution their server's profile does not grant, contradict their own names, or flood the namespace; taint and toxic-chain stages that cross between agents through notes, files, the bus, or delegation. Nine rule codes, SARIF rules, hash-chained logs. | Static analysis of inline code; structural schema checks; only routed reads, writes, messages, and delegations are in the graph. |
| v12 evasion guards ([`mcp_rugpull_guard.py`](agent-gateway/agent_gateway/mcp_rugpull_guard.py), [`workspace_config_guard.py`](agent-gateway/agent_gateway/workspace_config_guard.py), [`control_flow_integrity_guard.py`](agent-gateway/agent_gateway/control_flow_integrity_guard.py), [`stego_exfil_guard.py`](agent-gateway/agent_gateway/stego_exfil_guard.py)) | MCP tool-definition drift, shadowing, and hidden-instruction poisoning; writes to agent instruction, MCP / IDE config, and execution-hook files; privileged calls after untrusted reads outside a pre-taint capability manifest; secrets reshaped into branch, package, DNS, or URL identifiers. Eleven rule codes, SARIF rules with CWE and OWASP tags, hash-chained logs. | Deterministic and lexical. In `PolicyEngine` a capability manifest only narrows; MCP drift and shadowing on the proxy path stay with `schema_integrity_guard.py`. |
| [`rogue-ai-pipeline`](rogue-ai-pipeline/README.md) | Multi-layer detector (rules, Isolation Forest, coordination graph, hash-chained audit log, STIX). | Same-author synthetic checks. See the whitepaper and [docs/v6-changes.md](docs/v6-changes.md). |

Tool backends inside the gateway are simulated echoes. There is no Web Bot Auth in this tree.

## Threat coverage map

An index from threat to the modules under [`agent-gateway/agent_gateway/`](agent-gateway/agent_gateway/) that check it. Every row is a deterministic, lexical or structural check on calls routed through `pep.py` or the MCP wire proxy, and every row inherits the [lab limits](#lab-limits) and [known non-goals](#known-non-goals-and-bypasses-wanted) below; the last column repeats the one that applies most. Rule codes and JSON-RPC error codes are in the guard tables above and below.

| Threat | Modules | What the check does | Limit |
| --- | --- | --- | --- |
| MCP tool rug-pulls: definition drift, shadowing, description poisoning, over-privileged first listings | [`schema_integrity_guard.py`](agent-gateway/agent_gateway/schema_integrity_guard.py), [`mcp_rugpull_guard.py`](agent-gateway/agent_gateway/mcp_rugpull_guard.py), [`registry_pin_validator.py`](agent-gateway/agent_gateway/registry_pin_validator.py), [`mcp_capability_manifest_guard.py`](agent-gateway/agent_gateway/mcp_capability_manifest_guard.py) | Pins a SHA-256 digest of each `(server, tool)` definition at first listing; later drift needs a manifest signed with the gateway HMAC key. A name owned by another server or a core built-in, a definition carrying hidden-instruction markers, and a first listing that asks for more than its server profile grants are refused and not served | A definition that is hostile at the first pin is pinned as it is; rug-pull detection starts after that pin |
| Indirect prompt injection through tool output | [`tool_output_scanner.py`](agent-gateway/agent_gateway/tool_output_scanner.py), [`taint.py`](agent-gateway/agent_gateway/taint.py), [`control_flow_integrity_guard.py`](agent-gateway/agent_gateway/control_flow_integrity_guard.py), [`lattice_flow_validator.py`](agent-gateway/agent_gateway/lattice_flow_validator.py) | Scans `external_read` and MCP results for Unicode tag smuggling, zero-width characters, delimiter spoofing, and tool-name shadowing before the agent sees them. Any untrusted read taints the session and appends `allow_egress=false` to the `agw1.` capability, so later writes, sends, and credential calls are held for a person. A capability or workflow manifest pinned before the taint only narrows what the tainted session can still reach | Not an injection detector: taint applies whether or not the content is an attack, an injection that changes only the answer is not seen, and a source that is neither classified as untrusted ingest nor marked by the host never taints |
| Staged, encoded, or split exfiltration of a sensitive read | [`deobfuscate.py`](agent-gateway/agent_gateway/deobfuscate.py), [`canary_watermark.py`](agent-gateway/agent_gateway/canary_watermark.py), [`temporal_accumulator_guard.py`](agent-gateway/agent_gateway/temporal_accumulator_guard.py), [`stego_exfil_guard.py`](agent-gateway/agent_gateway/stego_exfil_guard.py), [`shingle_similarity_validator.py`](agent-gateway/agent_gateway/shingle_similarity_validator.py), [`dynamic_ingression_validator.py`](agent-gateway/agent_gateway/dynamic_ingression_validator.py), [`transform_invariant_validator.py`](agent-gateway/agent_gateway/transform_invariant_validator.py) | Keeps salted SHA-256 n-gram digests of sensitive reads and canaries (raw, Base64, hex, URL-encoded, whitespace-stripped), never the values, and checks outbound arguments against them across steps and per destination, so a secret split over several calls is still matched. Weaves a zero-width HMAC watermark into sensitive output and tracks standard credential formats. Matches secret shingles reshaped into branch, package, DNS, and URL identifiers, values learned from earlier tool responses, and a finite family of transforms (reversal, byte masks, Caesar shifts, acrostics, block reorderings) | Lexical: a paraphrased or encrypted secret is not caught |
| SSRF and cloud-metadata targets in tool arguments | [`egress_uri_guard.py`](agent-gateway/agent_gateway/egress_uri_guard.py) | Canonicalizes every URL, URI, and host argument before classifying it: dword, hex, and octal addresses, IPv4-mapped and NAT64 IPv6, userinfo confusion (`https://allowed.com@169.254.169.254`), percent-encoded hosts, and wildcard-DNS names that embed an address. Loopback lab fixtures pass only through `PepConfig.ssrf_lab_allow` | A policy check on arguments, not network isolation: a backend with its own network path is not confined |
| Covert channels after taint and a sensitive read | [`side_channel_guard.py`](agent-gateway/agent_gateway/side_channel_guard.py), [`leakage_budget.py`](agent-gateway/agent_gateway/leakage_budget.py), [`event_channel_capacity_validator.py`](agent-gateway/agent_gateway/event_channel_capacity_validator.py) | Holds released calls that branch over more than `max_distinct` argument variants (a boolean oracle) or beacon on timing. Charges one quarter-bit leakage budget per coalition of sessions for the selection, content, and release slot of each outbound event, and holds for a person when it would be exceeded | Bounds the modelled channel only. A budget hold is a lead for a person, not a key freeze |
| Toxic tool chains, confused-deputy delegation, cross-agent laundering | [`toxic_combinations.py`](agent-gateway/agent_gateway/toxic_combinations.py), [`delegation_guard.py`](agent-gateway/agent_gateway/delegation_guard.py), [`cross_agent_collusion_guard.py`](agent-gateway/agent_gateway/cross_agent_collusion_guard.py), [`fork_join_vector_validator.py`](agent-gateway/agent_gateway/fork_join_vector_validator.py) | Builds a static reachability graph from untrusted reads to free-text sinks over every `tools/list` inventory, with unlabelled tools classed as `write`. A hand-off can only move down the capability lattice: egress is an AND, sensitive-read history is an OR, taint sources are a union. A provenance graph across sessions denies a sink by an agent carrying a peer's taint and a toxic chain whose stages came from different agents; forked branches spend the root session's budgets | Only reads, writes, messages, and delegations routed through the gateway are in the graph |
| Filesystem and shell escape through arguments | [`arg_ast_guard.py`](agent-gateway/agent_gateway/arg_ast_guard.py), [`interpreter_exec_guard.py`](agent-gateway/agent_gateway/interpreter_exec_guard.py), [`workspace_path_validator.py`](agent-gateway/agent_gateway/workspace_path_validator.py), [`workspace_config_guard.py`](agent-gateway/agent_gateway/workspace_config_guard.py), [`canonical_argument_confinement.py`](agent-gateway/agent_gateway/canonical_argument_confinement.py) | Canonicalizes path arguments (traversal, double encoding, NUL bytes, UNC and device paths) and denies command chaining, header splitting, and a mutating SQL statement in a read-only query. Parses `python -c`, `node -e`, and heredoc payloads with `ast` for protected writes, decoded pipes, and process or network primitives. A bounded literal-shell analyzer over an immutable filesystem model fails closed on syntax it does not model. Writes to agent instruction, MCP / IDE configuration, and hook files are denied, and typed file commands compile to a fixed argv with `--` before every positional | Executes nothing and is not an OS sandbox |
| Memory and context poisoning across sessions | [`memory_provenance_guard.py`](agent-gateway/agent_gateway/memory_provenance_guard.py), [`symbolic_fs_transducer.py`](agent-gateway/agent_gateway/symbolic_fs_transducer.py), [`causality_laundering_validator.py`](agent-gateway/agent_gateway/causality_laundering_validator.py) | Records resource writes and reads in an HMAC-signed lineage ledger shared across sessions: a reader inherits the writer's taint, and a modified record is denied. Confidentiality and integrity labels follow file effects, so copying a protected file to an ordinary name does not launder it, and file create, unlink, rename, and status effects carry the label of the branch that caused them | Only writes and reads routed through the gateway are in the ledger |

## Install the CLIs

Two packages install from this tree. There is no package index and no company domain. From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ./agentwatch-analyzer
python -m pip install -e ./agent-gateway
```

The same paths work without `-e`: `pip install ./agentwatch-analyzer` and `pip install ./agent-gateway`.

Claude Code users can add the local `PreToolUse` policy hook in one command:

```bash
python -m agent_gateway.claude_code_hook --install
```

It adds one command hook to `~/.claude/settings.json` (`--settings` for another file; running it twice adds nothing). Before each tool call, [`claude_code_hook.py`](agent-gateway/agent_gateway/claude_code_hook.py) denies `CREDENTIAL_PATH_DENIED` (`.env` files except `.env.example` / `.sample` / `.template`, `~/.ssh`, `~/.aws`, `.npmrc`, `.pypirc`), `SHELL_POLICY_DENIED` (recursive root or home deletion, force push to `main` / `master`, a download piped to a shell), and `METADATA_URI_DENIED` (`169.254.169.254`, `metadata.google.internal`, `file://`). Every decision is appended to a SHA-256 hash-chained `~/.claude/agentgate_audit.jsonl`. `python -m agent_gateway.claude_code_hook --self-test` runs four validation checks and prints CPU time per decision. These are lexical configuration checks, not a sandbox.

Since v12 the hook also blocks writes to agent instruction and configuration files and to execution hooks: a `Write` / `Edit` of `CLAUDE.md`, `.claude/`, `.mcp.json`, or `.cursor/`, or a `Bash` redirection, `tee`, `cp`, `mv`, `ln -s`, `chmod`, `sed -i`, or `git config` that touches them or `.git/hooks/`, CI workflows, and shell rc files (`WORKSPACE_CONFIG_WRITE`, `WORKSPACE_HOOK_TAMPER`, `WORKSPACE_SYMLINK_ESCAPE`). Opt in for a session where you asked for such an edit with `--allow-workspace-writes config,hook` (or `AGENTGATE_ALLOW_WORKSPACE_WRITES=config,hook`); symlinks to protected paths stay denied. Since v12.1 the same applies to inline interpreters: `python -c "open('CLAUDE.md', 'w')..."` or `node -e "fs.writeFileSync('.git/hooks/pre-commit', ...)"` is blocked like a shell redirect (`INTERPRETER_PROTECTED_WRITE`), as are decoded base64 / hex payloads piped into a shell (`INTERPRETER_OBFUSCATED_PIPE`) and inline code that spawns processes or opens network connections (`INTERPRETER_DANGEROUS_PRIMITIVE`). Since v12.2 a modelled shell effect on a reserved name the v12 workspace guard does not list (`.clinerules`, `.idea/`, `.windsurf/`) is `WORKSPACE_EFFECT_DENIED`; syntax outside that literal subset is left to the rules above. A `Read` of `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, or `.cursor/rules/*` is blocked when the file on disk carries an HTML comment or invisible characters (`WORKSPACE_HIDDEN_DIRECTIVE`).

### v12 evasion guards

Four deterministic guards in `agent-gateway`, each with its own rule codes, a SHA-256 hash-chained log in the `audit_chain.py` format, and SARIF rules with CWE and OWASP (Agentic Top 10, LLM Top 10) tags:

| Guard | Rule codes | What it checks | Wired into |
| --- | --- | --- | --- |
| [`mcp_rugpull_guard.py`](agent-gateway/agent_gateway/mcp_rugpull_guard.py) | `MCP_DEFINITION_DRIFT`, `MCP_TOOL_SHADOWING`, `MCP_DESCRIPTION_POISONING` | SHA-256 fingerprint per `(server, tool)` of the normalized description and canonical schema; drift needs an HMAC re-approval token; names owned by another server or a core built-in; HTML comments, `<IMPORTANT>` / `<system>` tags, invisible characters, credential-file and "ignore previous instructions" directives, `sidenote` parameters | `PolicyEngine` / `McpWireProxy`: poisoned tools are not served and calls to them are denied (-32054) |
| [`workspace_config_guard.py`](agent-gateway/agent_gateway/workspace_config_guard.py) | `WORKSPACE_CONFIG_WRITE`, `WORKSPACE_HOOK_TAMPER`, `WORKSPACE_SYMLINK_ESCAPE`, `WORKSPACE_HIDDEN_DIRECTIVE` | Structured file tools and shell commands against `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, `.cursor/`, `.claude/`, `.mcp.json`, `.vscode/settings.json`, `.git/hooks/`, `.git/config`, CI workflows, shell rc files; `scan_workspace_instruction_file()` for hidden directives | `PolicyEngine` (-32045 / -32046 / -32047, opt-in with `PepConfig.workspace_allow`) and the Claude Code hook |
| [`control_flow_integrity_guard.py`](agent-gateway/agent_gateway/control_flow_integrity_guard.py) | `CFI_TAINTED_PRIVILEGED_SINK`, `CFI_UNENDORSED_TARGET` | CaMeL / FIDES-style integrity label per session; after an untrusted read, `write` / `delete` / `execute` / `spend` / `external_send` sinks need a grant in a (optionally HMAC-signed) `UserCapabilityManifest` pinned before the taint, and their targets must match it | `PolicyEngine.pin_capability_manifest()` (-32048 / -32049); the manifest only narrows |
| [`stego_exfil_guard.py`](agent-gateway/agent_gateway/stego_exfil_guard.py) | `STEGO_SECRET_SHINGLE_LEAK`, `STEGO_SUBSEQUENCE_EXFIL` | Salted 6-gram shingles of secrets (and their hex, base32, URL-safe base64 forms) against git branch / tag / ref names, commit titles, package installs, DNS labels, and URL parts; dense ordered-subsequence alignment with a bit-parallel LCS | `PolicyEngine` on outbound calls after a sensitive read (-32052 / -32053); free-text bodies stay with `deobfuscate.py` |

They are lexical and deterministic: a paraphrased or encrypted secret is not caught. v12.1 closes two of the gaps v12 listed: writes through an inline interpreter and MCP tools that are over-privileged from their first listing (below). No runtime dependency was added.

### Reference middleware validators (v12.2 to v14)

Fifteen rule codes on the same decision path, findings list, and SARIF export as the v12.1 guards. JSON-RPC codes are `-32066` through `-32080` because v12.1 already owns `-32055` through `-32059` and `-32062` through `-32065` (`-32060` / `-32061` stay the sampling errors). Each validator is inert until a trusted adapter attaches its state.

| Validator | Rule codes | What it checks | Wired into |
| --- | --- | --- | --- |
| [`registry_pin_validator.py`](agent-gateway/agent_gateway/registry_pin_validator.py) | `REGISTRY_PIN_DRIFT`, `REGISTRY_ALIAS_AMBIGUOUS` | Per-provider descriptor pins over inputSchema / outputSchema / description / title / annotations. The first listing seals the server; a changed, invalid, or removed descriptor stays `REVOKED`. A bare tool name claimed by two servers is an ambiguous alias and is not resolved by arrival order. Display metadata is linted before enrollment. | `PolicyEngine.pin_tool_descriptors()` (-32066 / -32067); calls to a revoked pin are denied |
| [`workspace_path_validator.py`](agent-gateway/agent_gateway/workspace_path_validator.py) | `WORKSPACE_EFFECT_DENIED` | Bounded literal-shell analyzer over an immutable filesystem model (symlink splicing before `..`, protected names, inode checks). Unmodelled syntax fails closed. | `PolicyEngine.attach_workspace_snapshot()` (-32068) and the lexical half of both Claude Code hooks |
| [`lattice_flow_validator.py`](agent-gateway/agent_gateway/lattice_flow_validator.py) | `FLOW_MANIFEST_DENIED` | Two-level contamination lattice, a precommitted manifest of single-use steps, DAG admission, path patterns, and an idempotent request ledger. | `PolicyEngine.pin_workflow_manifest()` (-32069) |
| [`shingle_similarity_validator.py`](agent-gateway/agent_gateway/shingle_similarity_validator.py) | `SIMILARITY_LEAK_DENIED` | Rolling shingles plus bounded bit-parallel LCS over two pinned normalization views. Audit records carry keyed identifier hashes only. | `PolicyEngine.configure_similarity_matcher()` on outbound string arguments (-32070) |
| [`linear_obligation_validator.py`](agent-gateway/agent_gateway/linear_obligation_validator.py) (v12.3) | `OBLIGATION_PROTOCOL_DENIED` | Bounded 16-place Petri net packed into one 64-bit marking. The manifest must pass a weighted non-minting conservation check when it is compiled. A call must be an enabled transition (input tokens present, no place above 15), and an outbound step needs every resource cleanup place settled. The marking advances only after the other validators pass. | `PolicyEngine.attach_obligation_net()` (-32071) |
| [`symbolic_fs_transducer.py`](agent-gateway/agent_gateway/symbolic_fs_transducer.py) (v12.4) | `FS_LABEL_FLOW_DENIED` | (confidentiality, integrity) labels carried from read sources to write targets in a copy-on-write overlay over the workspace model. Protected paths and inodes start PROTECTED. A non-PUBLIC file cannot feed an outbound call and an UNTRUSTED file cannot feed an execution sink, so copying a protected file to an ordinary name does not launder it. Labels only rise and are committed after the other validators pass. | `PolicyEngine.attach_fs_transducer()` (-32072) |
| [`canonical_argument_confinement.py`](agent-gateway/agent_gateway/canonical_argument_confinement.py) (v12.5) | `ARGUMENT_CONFINEMENT_DENIED` | A pinned tool's argument object is reduced to one canonical byte string (sorted keys, numbers quantized half-even at a fixed scale, sorted sets, defaults omitted), so key order, number spelling and set order cannot carry hidden bits. Duplicate keys, unknown fields, non-finite or oversized numbers and deep nesting are denied. Typed file commands compile to a fixed argv with `--` before every positional, and an operand starting with `-` is denied. | `PolicyEngine.pin_argument_policy()` and `pin_command_tool()` (-32073) |
| [`fork_join_vector_validator.py`](agent-gateway/agent_gateway/fork_join_vector_validator.py) (v12.6) | `FORK_JOIN_LEDGER_DENIED` | A root session and up to 7 forked branches share one conservation ledger of denial units, outbound bytes and 16 token places, so a child spends the root's budget instead of a fresh one. Forks move a grant, joins return it, and transitions conserve the weighted token count. Every operation is fenced on the branch's vector clock, sends need cleanup state settled across the whole ledger, and taint flows along forks and joins. | `PolicyEngine.attach_fork_join()`, `fork_branch()`, `join_branch()` and spawn auto-fork (-32074) |
| [`dynamic_ingression_validator.py`](agent-gateway/agent_gateway/dynamic_ingression_validator.py) (v12.7) | `DYNAMIC_INGRESSION_DENIED` | Every tool result is scanned before the agent sees it. Strings from a trusted credential source go into a non-evicting 8-slot hard store (a result that would overflow it is withheld); credential prefixes (`sk-`, `ghp_`, `AKIA`), `.internal` / `.corp` hosts, e-mail addresses and high-entropy tokens go into a 16-slot soft store that evicts oldest first, so an untrusted response cannot lock enrollment. Later outbound strings covering 85% of an enrolled value (bit-parallel LCS) are denied. | `PolicyEngine.attach_ingression()`, `ingest_dynamic_result()` and outbound string arguments (-32075) |
| [`transform_invariant_validator.py`](agent-gateway/agent_gateway/transform_invariant_validator.py) (v12.8) | `TRANSFORM_INVARIANT_DENIED` | Protected and learned values are matched under a finite transform family: reversal, +k and XOR-k byte masks (via difference views), Caesar shifts, word-initial acrostics, reordered 4-byte blocks and stride-2/3/4 interleavings, and inside hex and base64 runs. Work is precharged on two budgets and a query over either is denied whole. Extended atomically whenever Predicate D learns a value. | `PolicyEngine.attach_transform_index()` and outbound string arguments (-32076) |
| [`causality_laundering_validator.py`](agent-gateway/agent_gateway/causality_laundering_validator.py) (v14) | `CAUSALITY_LAUNDERING_DENIED` | Implicit-flow and absence laundering: file create / unlink / rename, directory and status effects carry the mutating branch's program-counter label (sticky tombstones included), and probing, listing or reading a status joins that label into the observer before A and E authorize the call. Bounded to 64 branches and 256 labeled paths. | `PolicyEngine.attach_causality()`, `causality_push_pc()` and typed file / status tools (-32077) |
| [`event_channel_capacity_validator.py`](agent-gateway/agent_gateway/event_channel_capacity_validator.py) (v14) | `EVENT_CHANNEL_CAPACITY_DENIED` | Hartley support budget, in exact integer quarter bits, on which eligible tool and structural choices an outbound call makes, charged only while tainted or holding live secret pins. Two-phase reserve / commit / abort. Support accounting, not KL divergence. | `PolicyEngine.attach_event_budget()` on write, send and credential calls (-32078) |
| [`blindfold_opaque_fault_validator.py`](agent-gateway/agent_gateway/blindfold_opaque_fault_validator.py) (v14) | `BLINDFOLD_PERTURBATION_DENIED` | Refusals are sealed into one constant envelope plus an HMAC-signed private receipt. A request whose exact 4-gram Jaccard with a remembered refusal is in [0.25, 1) locks its branch: the lock auto-lifts after 15 minutes and is a lead for human review. | `PolicyEngine.attach_blindfold()` (-32079, also the opaque envelope's code) |
| [`reachability_confinement_validator.py`](agent-gateway/agent_gateway/reachability_confinement_validator.py) (v14) | `REACHABILITY_CONFINEMENT_DENIED` | A call must be a successor on a workflow DAG path (at most 64 nodes, 8 obligation bits) that can still reach a terminal with every obligation discharged and, once tainted, no forbidden step. Path-qualified tables are precomputed at boot; revocation is sticky. | `PolicyEngine.attach_reachability()` and `reachability_finish()` (-32080) |

The path module executes nothing and is not an OS sandbox. These checks are deterministic and opt-in. They do not change the honeypot's human-review rule or the 15-minute registered-credential freeze.

### v12.1 interpreter, first-listing, and cross-agent guards

| Guard | Rule codes | What it checks | Wired into |
| --- | --- | --- | --- |
| [`interpreter_exec_guard.py`](agent-gateway/agent_gateway/interpreter_exec_guard.py) | `INTERPRETER_PROTECTED_WRITE`, `INTERPRETER_OBFUSCATED_PIPE`, `INTERPRETER_DANGEROUS_PRIMITIVE` | Inline payloads of `python -c` (parsed with `ast`, with constant folding of `os.path.join`, `Path(...) / ...`, f-strings, and simple assignments), `node -e`, `ruby -e`, `perl -e`, `php -r`, `bash -c` / `sh -c`, and heredocs; writes, deletes, renames, chmods, and symlinks of agent config, hook, credential, and system paths; base64 / hex decodes piped or substituted into a shell or interpreter, or executed by inline code; `subprocess`, `os.system`, `child_process`, sockets, HTTP clients, `eval` of non-literals | `PolicyEngine` before the argument firewall (-32055 / -32056 / -32057) and the Claude Code hook |
| [`mcp_capability_manifest_guard.py`](agent-gateway/agent_gateway/mcp_capability_manifest_guard.py) | `MCP_FIRST_SEEN_OVERPRIVILEGED`, `MCP_SCHEMA_PURPOSE_MISMATCH`, `MCP_TOOL_NAMESPACE_FLOOD` | Every listing, the first included, against a server profile (`PURE_TRANSFORM` < `READ_ONLY` < `LOCAL_WORKSPACE` < `EXTERNAL_NETWORK` < `PRIVILEGED`): credential parameters need `EXTERNAL_NETWORK`, execution parameters `PRIVILEGED`, unverified servers get neither; `get_` / `list_` / `format_` / `lint_` / `parse_` tools with side-effecting parameters, or an explicit wildcard schema on a privileged server; more than 32 tools in one listing | `PolicyEngine` / `McpWireProxy`: refused tools are not served (-32058 / -32059 / -32062); `PepConfig.mcp_server_profiles` assigns profiles, core servers are `PRIVILEGED` |
| [`cross_agent_collusion_guard.py`](agent-gateway/agent_gateway/cross_agent_collusion_guard.py) | `COLLUSION_CROSS_AGENT_LAUNDERING`, `COLLUSION_SPLIT_TOXIC_CHAIN`, `COLLUSION_CYCLIC_AMPLIFICATION` | A provenance graph of agents and artifacts (`file:`, `mem:`, `msg:`) with monotone `UNTRUSTED` / `SECRET_TAINTED` labels and toxic-chain stages; a sink by an agent carrying another agent's taint, a chain whose stages came from different agents, or a shared artifact passed back and forth more than `max_handoff_depth` times | `PolicyEngine` notes, bus, files, delegation, and spawn (-32063 / -32064 / -32065); a node is one session of one registered agent |

Two flows the single-session gates did not see before v12.1 are now denied: a peer sending after reading a note written by an agent that had read a secret (the note was not tainted, only its writer was), and a toxic chain split across agents. The 750-decision benign benchmark still has 0 denials. Static analysis and structural checks only: code fetched or decrypted at run time, an encrypted or paraphrased payload, and data carried between agents outside routed tools are not seen.

PHP applications (Laravel, WordPress, or plain PHP 7.4+) can add the PHP Defense Guard as a drop-in runtime input check, at the top of `index.php`, in a WordPress mu-plugin, or in a Laravel middleware:

```php
require __DIR__ . '/php_defense_guard.php';
(new \AgentGate\PhpDefenseGuard('/var/log/agentgate_php_audit.jsonl'))->inspectAndEnforce();
```

Every key and string value in `$_GET`, `$_POST`, and `$_COOKIE` is checked as received and again after URL-decoding. A match answers `403` with one of `PHP_SQLI_UNION`, `PHP_SQLI_TAUTOLOGY`, `PHP_PATH_TRAVERSAL`, `PHP_DESERIALIZE_DENIED`, or `PHP_RCE_EVAL`, and appends a SHA-256 hash-chained entry (the rule, the parameter name, and a SHA-256 of the value, never the value) that `agent_gateway.audit_chain.verify_chain_file` can check. Two optional arguments keep a site search box from being blocked: `new PhpDefenseGuard($log, ['s', 'q'])` leaves those parameters uninspected, and a third argument `true` (log-only) records the finding with verdict `LOG_ONLY` and returns it instead of answering 403. [`php_defense_guard.py`](agent-gateway/agent_gateway/php_defense_guard.py) applies the same patterns (and `excluded_keys` / `log_only`) to request dictionaries, the tests run both on the same fixtures, and `sarif_report()` turns either log into SARIF 2.1.0 rules with CWE and OWASP Top 10 tags. These are lexical input checks: keep parameterized queries, `unserialize(..., ['allowed_classes' => false])`, and `disable_functions`. A pattern list can deny unusual benign input (a search for `system()` matches `PHP_RCE_EVAL`).

On a log you already have:

```bash
agentwatch-analyzer ./access.log --format nginx --out-dir ./analyzer-out
python -m agent_gateway audit ./analyzer-out
```

`agent-gateway audit ./analyzer-out` is the same audit command. It writes `analyzer-out/audit-report/audit-report.html` and `audit-report.pdf`. The PDF writer is pure Python. WeasyPrint and wkhtmltopdf are not dependencies and are not required.

That audit command does not bind a port and does not start the honeypot. `agent-gateway serve` still defaults to `127.0.0.1` and does not POST unless you pass `--webhook-deliver`.

The Sigma pack is 12 files in [`agentwatch-analyzer/rules/sigma`](agentwatch-analyzer/rules/sigma). After install, `agentwatch_analyzer.sigma_rules_dir()` points at that directory (editable) or at the copy inside the wheel.

## Three minutes

[docs/quickstart.md](docs/quickstart.md) is a copy-paste Docker run and the same Python without Docker. The loop is: `web.fetch` (taint and attenuate) → `lookup_order_status` (still tainted) → `send_email` (held). The process prints the Slack / webhook JSON and asserts `delivered` is false.

```bash
python -m agent_gateway serve --host 127.0.0.1 --port 9100
```

That command does not deliver webhooks. Add `--webhook-url` and `--webhook-deliver` only when you intend a POST. See the quickstart for the exact flag.

## Lab limits

- **Default bind is `127.0.0.1`.** A non-loopback bind needs `--allow-nonlocal` and an isolated lab network. This repository does not ship a public honeypot deploy.
- **The web honeypot is human-review only.** It does not auto-block a public visitor. Honeypot contact is not intent.
- **Freeze only registered keys.** Deny & Freeze Key 15m calls the 900-second freeze for a key already in `config/agents.json`. A key that is not in that file is refused and is not frozen.
- **No wild deployment is claimed.** Loopback Tier-2 is one machine, one `qwen2.5:3b`, 14 archived runs. Quote **2 of 13** non-control catches. The scripted human control is the fourteenth archive and is not in that denominator. Same author, small n. Not a benchmark. Do not pool it with synthetic recall.
- **Synthetic tables are same-author regression checks.** The person who wrote the detectors wrote the simulated clients. A second, larger local model was not run (about 5 GiB free RAM and no swap). There is no mid-size multimodel result to cite.
- **Not a production WAF.** Gateway tests check the gates against cases written for them.

## Known non-goals and bypasses wanted

These are outside what the lab gateway does. Some are open design questions, and a report that breaks a stated claim below is welcome as an issue.

- **Answer-only injections.** If untrusted text only changes what the model says and triggers no gated tool call, there is nothing for the gateway to hold. Taint gates tool egress. It does not judge the answer.
- **Unlabeled or unrouted sources.** Taint starts only when a tool is classified as an untrusted ingest or the session is marked. A tool that is not in the classification table is treated as a write and held after taint, but an untrusted source that is never routed or labeled never taints the session. Direct calls that do not go through the gateway are not seen at all.
- **No injection detection.** The gateway does not decide whether content is malicious. Any external read taints the session, whether or not the content is an attack. Pattern checks on arguments and tool output are lexical and best-effort.
- **Key rotation.** Not supported or covered. There is no rotation, revocation list, or dual-key verification window. Changing `AGENT_GATEWAY_HMAC_KEY` invalidates every outstanding `agw1.` token and approval token, and the audit manifest HMAC of earlier audit directories will no longer verify under the new key.
- **Host or key compromise.** Anyone holding `AGENT_GATEWAY_HMAC_KEY` can mint and extend capabilities. A compromised gateway host, state directory, or registered agent key defeats the boundary. There is no key rotation or hardware-backed storage here.
- **Malicious tools at first pin.** Tool-schema pinning detects a change after the first pin (rug-pull). It cannot tell that the schema or behavior pinned the first time was already hostile.
- **No OS sandboxing or network isolation.** The gateway is a policy check in the tool loop. It does not confine processes, files, or sockets. A tool backend with its own network path can still reach out unless the host prevents it.
- **Tool backends in the lab pass are simulated echoes.** Nothing here shows how a real backend behaves.

Tool classification, including how unknown tools fail closed, is in [docs/tool-classification.md](docs/tool-classification.md).

Bypasses wanted: a way to restore egress on a tainted `agw1.` capability, to reach a gated tool without a hold, or to pass a free-text sink through the constrained status allowlist. Open an issue with the steps. ATLAS ids remain approximate.

## Evidence

Full narrative, methods, the 24 October 2026 update for v6 and Phases 1 to 3, and the 25 October 2026 v10 collusion-carrier section (6.1): [docs/rogue-ai-detection-whitepaper.pdf](docs/rogue-ai-detection-whitepaper.pdf) ([Word](docs/rogue-ai-detection-whitepaper.docx)). Section 4 is the loopback sample and the analyzer. Section 6 is the gateway. Section 9 is related work. Search notes for that section: [docs/prior-art.md](docs/prior-art.md) (23 October 2026; not repeated for the later update). The capability comparison that used to lead this README lives in that note and in the paper. In that search, "not found in my search" means the pages that were read did not document the capability.

Earlier research map (bot and agent detection, ATLAS, NIST AI RMF, OWASP, STIX, collection limits): [research report](https://cursor.com/canvas/store-f783d059-8304-409e-8eee-8c518ae04f8b/91900c77-b85e-45f9-b706-3b5fa0315467). Legal content there is a research summary, not legal advice.

### Loopback Tier-2 (do not quote this as a product metric)

`qwen2.5:3b` against the honeypot on `127.0.0.1`. Catch rate **2 of 13** non-control runs (headless Playwright crawler, and one LLM-driven Playwright run). Nine urllib sessions were not caught; the model usually stopped after 1 to 3 calls. The scripted human control was not caught and is not in the 13. After calibration, same-session R14 requires a schema-provenance cursor on the rider, and dwell under 12 ms is inconclusive for touch and an OS tap. Write-up: [docs/phase1-tier2-report.md](docs/phase1-tier2-report.md), [docs/phase1-fixes.md](docs/phase1-fixes.md), whitepaper section 4.

### Analyzer smoke (offline)

12 Sigma rules. **10 of 10** unit tests recorded for `agentwatch-analyzer`. Offline matrix: R8 yes, R9 yes, R10 partial, R11–R13 not available from a normal access log, R14 partial and advisory without a human beacon. Smoke matches below are from archived logs and one fixture, not from a live estate. Details: [docs/phase3-analyzer.md](docs/phase3-analyzer.md).

| Sample | Matches | Rules |
| --- | --- | --- |
| Tier-2 aggressive urllib LLM | 0 | none |
| Tier-2 Playwright LLM s100 | 1 | R9 |
| Tier-2 Playwright crawler s100 | 2 | R9 + R14 (advisory offline) |
| Fixture `agentlike_nginx.log` | 3 | R8, R9, R10 |

The advisory offline R14 on the crawler is not the live R14 false positive. Rescoring that archive after the Phase 1 calibration does not raise `parasitic_session_fork`. Playwright logs are richer than the thin urllib traces, which is why the aggressive urllib sample matched nothing. The crawler smoke is what the GitHub Action uploads, and that bundle's recorded validation is `validator_ok=true`.

### Gateway gates

[docs/phase2-gateway.md](docs/phase2-gateway.md). Falsification cases, all in the 7/7 file: external-parameter egress while tainted and sensitive (AML.T0086); scratchpad taint inheritance (AML.T0080.000); OOB token rejects arg-swap and replay (AML.T0051 / AML.T0053); post-taint outbound still gated after spacer reads (AML.T0086); bus taint and fan-out refusal (AML.T0118); `tools/list` from a non-core MCP server taints before the first `tools/call` (AML.T0051.001); constrained `update_ticket_status` without OOB, free text still gated.

### v6 synthetic regression (same author)

[docs/v6-changes.md](docs/v6-changes.md) records the paired check. Headline figures kept so they are not silently dropped: agent-watch human alerts 15/75 to **0/75** in that check; pipeline web false-positive rate 0.068 to **0.024**; all-evasive core recall 0/80 to 12/80. Two documented pipeline regressions: `mimic_assets` and `mimic_linked_nosec`, each 15 of 15 to 0 of 15. v6 numbers are not the Tier-2 2 of 13, and neither is a benchmark. Per-build notes: [docs/v3-changes.md](docs/v3-changes.md), [docs/v4-changes.md](docs/v4-changes.md), [docs/v5-changes.md](docs/v5-changes.md), [docs/v6-changes.md](docs/v6-changes.md).

### Where the rest of the tree lives

- [agent-watch/README.md](agent-watch/README.md) — v6 detector and honeypot.
- [agent-gateway/README.md](agent-gateway/README.md) — lab gateway.
- [agentwatch-analyzer/README.md](agentwatch-analyzer/README.md) — offline analyzer.
- [rogue-ai-pipeline/README.md](rogue-ai-pipeline/README.md) — v6 pipeline.
- [prototype-v1/README.md](prototype-v1/README.md) — first prototype (synthetic only).
- [docs/examples/sample-replay.html](docs/examples/sample-replay.html) — static replay example. It makes no network requests.
- [docs/examples/sample-boundary-note.md](docs/examples/sample-boundary-note.md) — anonymized example of the written tool-boundary note, built from a synthetic tool list. Two more synthetic examples: [repository-maintenance agent](docs/examples/sample-boundary-note-devops.md) and [research assistant with a third-party MCP server](docs/examples/sample-boundary-note-mcp-research.md).
- [docs/integration-contract.md](docs/integration-contract.md) — what the gateway assumes, what the caller must enforce, resource limits, and a reference dispatcher ([examples/gated_dispatch.py](examples/gated_dispatch.py)).

## License

The default license for this repository is the Apache License, Version 2.0. The full text is [LICENSE](LICENSE). [NOTICE](NOTICE) states the scope.

Apache 2.0 covers the open core in this tree: `agent-watch`, `agent-gateway` (including `pep.py`, `agw1.` attenuation, and the executive audit CLI), `agentwatch-analyzer`, [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml), `rogue-ai-pipeline`, and the documentation under `docs/` and `marketing/`. There is no separate proprietary module in the tree. Marketing drafts are documentation under the same license.

A hosted audit and paid support are commercial services. They are not granted by the Apache 2.0 license, and they are not a second codebase in this tree. The written offer is [marketing/audit-offer.md](marketing/audit-offer.md). Proprietary connectors are not in this repository. Notes for the v1.0.0 snapshot are in [CHANGELOG.md](CHANGELOG.md). The changelog line that says the GitHub remote was private describes that snapshot. Making the repository public is handled outside this tree.

Optional community posts, not yet submitted: [marketing/show-hn.md](marketing/show-hn.md) and [marketing/reddit-localllama.md](marketing/reddit-localllama.md). Post them only after this repository is public. Adding the drafts to the tree does not post them.

## Book or run it

### Self-serve CI/CD and Slack sidecar

Add [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml) and follow [docs/quickstart.md](docs/quickstart.md). The approval document is built by [`approval_webhook.py`](agent-gateway/agent_gateway/approval_webhook.py). Leave out `--webhook-deliver` until you want a POST. Serve on `127.0.0.1`.

### Book a 48-hour Agentic Tool-Boundary Audit

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

One-page offer, price, and out-of-scope list: **[AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md)**. Reply to that email with a tool inventory if you already have one. The ladder runs from a $149 config check and a $450 starter build through the $750 hardened build, a $950 / $1,500 security review, a $1,500 guardrail drop-in, and Boundary Watch at $395 a month, then the unchanged $1,800 Tool Inventory Review, $4,500 fixed note, or $6,500 with instrumentation. Not a penetration test and not a certification. The GitHub Action above is the free alternative.

## Notes for AI coding agents working in this tree

For Claude Code, Cursor, Codex, or any other assistant that edits this repository. The points below restate what the code and the test suite already enforce.

- **The core stays on the standard library.** [`agent-gateway/pyproject.toml`](agent-gateway/pyproject.toml) declares `dependencies = []`. The policy engine ([`pep.py`](agent-gateway/agent_gateway/pep.py)), the MCP wire proxy ([`mcp_proxy.py`](agent-gateway/agent_gateway/mcp_proxy.py)), and every guard and validator they import run on stdlib only. `flask` is the optional `http` extra and is imported by `http_app.py` alone; `pytest`, Hypothesis, and that extra are the `test` extra. [`tests/test_stdlib_only.py`](agent-gateway/tests/test_stdlib_only.py) imports the engine and the proxy with Flask blocked and fails if either touches it. Do not add a third-party import under `agent-gateway/agent_gateway/`.
- **Validator paths are deterministic and fail closed.** A decision is reproducible from the policy, the canonical inputs, the trusted state, and the keys ([docs/DESIGN.md](docs/DESIGN.md)): no verdict depends on randomness, hash seeds, or a network call. Per-instance salts exist to keep secret digests private, never to pick an outcome. A malformed schema, an unmodelled shell construct, an unresolvable path, missing adapter state, an exceeded budget, or a parser error is a deny or a hold for a person, never an allow, and a tool missing from `TOOL_EGRESS` is classed as `write` ([docs/tool-classification.md](docs/tool-classification.md)). Errors carry stable reason codes (`common.Denied`) and never embed caller data.
- **Every verdict stays on the audit chain and in SARIF.** A new denial appends a finding (`kind` = rule code, `session_id`, `step`, `tool`, approximate `atlas` id) to `PolicyEngine.findings` and passes through `_alert()` into the SHA-256 hash-chained log written by `ChainWriter` ([`audit_chain.py`](agent-gateway/agent_gateway/audit_chain.py)); `verify_chain_file` and `verify_audit_dir` must still verify it. Add the rule code to `RULES` in [`sarif_export.py`](agent-gateway/agent_gateway/sarif_export.py) with its CWE and OWASP tags so `build_sarif` and `validate_sarif` know it, and take a JSON-RPC error code no guard already uses (`-32083` is the highest in `pep.py`).
- **Where things are.** The engine is `PolicyEngine(registry, shared, cfg)` in [`pep.py`](agent-gateway/agent_gateway/pep.py); one tool call is `evaluate_call(agent_key, session_id, tool_name, arguments, ...)`. `PepConfig` is in the same file, `Registry.load()` in `registry.py`, and `SharedState` in `taint.py`. The MCP wire path is `McpWireProxy` in [`mcp_proxy.py`](agent-gateway/agent_gateway/mcp_proxy.py). Microbenchmarks are [`agent-gateway/benchmarks/benchmark.py`](agent-gateway/benchmarks/benchmark.py), run from `agent-gateway/` with the package installed. Tests are [`agent-gateway/tests/`](agent-gateway/tests/): `pip install -e "./agent-gateway[test]"` from the repository root, then `pytest -q` in `agent-gateway/`. A patched bypass needs an adversarial regression test there.
- **Do not edit the disclaimers.** The scope caveats ("What this is not", [Lab limits](#lab-limits), [Known non-goals](#known-non-goals-and-bypasses-wanted)), the recorded counts, and the pricing ladder are deliberate. Do not remove or soften them, and change a recorded number only after re-running the command this page names for it.
