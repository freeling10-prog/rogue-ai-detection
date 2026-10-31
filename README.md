# AgentGate: Runtime Behavioral Security & MITRE ATLAS Taint-and-Freeze Gateway for AI Agents & MCP

AgentGate is the lab policy gate in this repository. It sits in the tool loop of a **registered internal** agent, taints the session when untrusted content arrives, and attenuates an `agw1.` capability so that capability cannot turn egress back on. A held call is formatted for a person as Slack Block Kit and as a generic webhook document. Freeze applies only to keys listed in the lab registry, for 15 minutes. The web honeypot stays a lead for human review.

**Live interactive demo (public, no login):** <https://freeling10-prog.github.io/rogue-ai-detection/> · Source: [github.com/freeling10-prog/rogue-ai-detection](https://github.com/freeling10-prog/rogue-ai-detection) · Book: [alecagentboundary@gmail.com](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)

> **Apart Research collusion sprint — submission artifacts** (generated at commit `cefec0d`, 25 October 2026)
>
> - Report: [`sprint_submission/collusion_sprint_report.pdf`](sprint_submission/collusion_sprint_report.pdf) ([Markdown](sprint_submission/collusion_sprint_report.md)) · Slides: [`sprint_submission/collusion_sprint_slides.pdf`](sprint_submission/collusion_sprint_slides.pdf) · Raw data: [`sprint_submission/collusion_benchmark_results.json`](sprint_submission/collusion_benchmark_results.json)
> - Reproduce (from `agent-gateway/`, with `AGENT_GATEWAY_HMAC_KEY` set): `python -m agent_gateway evaluate-collusion --report ../sprint_submission`
> - **57/57** collusion defence tests passed: Group A side-channel / timing **8/8**, Group B delegation / confused-deputy **8/8**, Group C de-obfuscation / canary watermarking **41/41**.
> - **5** stateful Hypothesis machines in the suite, including the delegation DAG machine (`max_examples=120`, `stateful_step_count=24`).
> - **750** benign policy decisions (5 workflows × 50 runs): **0** false denials; **750/750** SHA-256 hash-chained decision-log entries verified (the audit manifest is HMAC-signed), and an edited or dropped line in a copy is detected.
> - CPU time per decision: **p50 0.126 ms · p95 0.892 ms · p99 0.999 ms** against a 2 ms reference; the slowest single decision was **3.84 ms**.
>
> **Frozen snapshot vs. `main`.** The files above are the 25 October sprint snapshot at `cefec0d` (57/57 A/B/C checks, 262 gateway tests) and are not regenerated. `main` has since added four v11 guards behind `pep.py` (`schema_integrity_guard.py`, `gui_action_guard.py`, `memory_provenance_guard.py`, `temporal_accumulator_guard.py`). Their tests are reported as a separate post-sprint **Group D** and are never folded into 57/57. On `main`: **874** gateway tests and **13** stateful Hypothesis machines (v12.2 adds the four reference middleware validators, with four Hypothesis state machines, on top of v12.1; v11.1 adds the Claude Code hook and the MCP delivery blueprint, then the PHP Defense Guard, v12 four evasion guards, and v12.1 three interpreter, first-listing, and cross-agent guards; none of them changes the sprint figures).
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
| 48-Hour Hardened MCP Server Build (Fixed-Scope Implementation) | **$750 flat** ($350 kickoff / $400 on passing acceptance tests) | A custom MCP server for one system (Postgres, Stripe, HubSpot, Slack, or an internal REST API) built on [`mcp_blueprint.py`](agent-gateway/agent_gateway/mcp_blueprint.py) and wrapped in `pep.py` allow / deny rules, sensitive-field redaction, SHA-256 hash-chained audit logging, and a `pytest` acceptance suite. Delivered as a mergeable PR in 48 hours. Nothing is deployed on your hosts by us |
| Tier 1: MCP & Multi-Agent Exposure Diagnostic (Tool Inventory Review) | **$1,800** | Executive collusion and posture report (PDF), SARIF 2.1.0 bundle (`sarif_export.py`, approximate ATLAS ids), Sigma rules + STIX 2.1 bundle (`agentwatch-analyzer`). No lab pass |
| Tier 2: Inline PEP Hardening & CI Gate Sprint (Fixed Tool-Boundary Note) | **$4,500** | Tier 1 and the full written note, plus a loopback `pep.py` / `mcp_proxy.py` policy set for your tool list, the 13 Hypothesis regression machines in a CI workflow, and hash-chained per-run logging (`audit_chain.py`). Delivered as a pull request your team merges |
| Tier 3: Continuous Red-Team, Canary & Deception Retainer (Note + Lab Instrumentation) | **$6,500**, then $2,500 per quarter | Tier 2 plus a lab gateway pass on `127.0.0.1` (simulated backends), an offline analyzer pass on an authorized log, localhost tripwire / canary / de-obfuscation / side-channel guard configuration, and a quarterly `evaluate-collusion` re-run |

Optional add-ons: Integration Blueprint (+$2,500, code or config sketches for the top held calls, nothing deployed on your hosts), Reviewer Briefing Call (+$750), Quarterly Refresh Retainer ($2,500 per quarter). All prices are fixed.

Email [alecagentboundary@gmail.com](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit) with the subject `Book 48-Hour Agentic Tool-Boundary Audit`. You can reply in that thread with a tool inventory (names and argument shapes, no secrets). The clock starts when a usable tool list arrives. This is not a penetration test and not a certification. The honeypot stays human-review only, freeze applies only to registered lab keys for 15 minutes, and ATLAS ids in the note are approximate. See an [example note](docs/examples/sample-boundary-note.md). Sample output from our own sprint run: [report PDF](sprint_submission/collusion_sprint_report.pdf), [briefing deck](sprint_submission/collusion_sprint_slides.pdf), [JSON](sprint_submission/collusion_benchmark_results.json).

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

One-page offer: **[AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md)**

## Compliance snapshot

Labels for results **recorded in this lab tree on 25 October 2026**. They are not a certification, and they are not evidence of a wild deployment. The GitHub Action file is the thing you run; the shields only repeat the recorded counts.

[![GitHub Action atlas-agent-audit.yml](https://img.shields.io/badge/GitHub_Action-atlas--agent--audit.yml-3b5bdb)](.github/workflows/atlas-agent-audit.yml)
[![gateway tests 874 passed](https://img.shields.io/badge/gateway_tests-874_passed-2f6f4e)](agent-gateway/tests)
[![ATLAS 7/7 plus Hypothesis](https://img.shields.io/badge/ATLAS_falsification-7%2F7_%2B_Hypothesis-2f6f4e)](agent-gateway/tests/test_pep_falsification.py)
[![STIX validator_ok true](https://img.shields.io/badge/STIX_2.1-validator__ok%3Dtrue-2f6f4e)](agentwatch-analyzer/scripts/ci_smoke.py)

| Check | Where | Recorded result |
| --- | --- | --- |
| ATLAS agent audit | [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml) | Four jobs: gateway, agent-watch, pipeline, offline analyzer smoke. The smoke job fails unless the STIX bundle parses and `validator_ok` is true. It then runs `python -m agent_gateway audit` and uploads the executive HTML and text PDF with the other artifacts. No honeypot process. |
| Gateway tests | `agent-gateway` pytest | **874 passed** on `main` (`pytest -q` in `agent-gateway`, 33 files). **78** of the 874 are the v12.2 reference middleware validators: **64** imported reference tests ([`test_validators.py`](agent-gateway/tests/test_validators.py), four Hypothesis state machines, oracles independent of the implementations) and **14** wiring tests ([`test_v12_2_validator_wiring.py`](agent-gateway/tests/test_v12_2_validator_wiring.py), including the JSON-RPC codes that follow v12.1). Before them, **796**. **144** of the 796 are the v12.1 tests ([`test_v12_1_guards.py`](agent-gateway/tests/test_v12_1_guards.py): inline interpreter escapes across Python (via `ast`), Node, Ruby, Perl, PHP, shells, and heredocs; first-listing MCP capability profiles; the cross-agent provenance graph with the ninth Hypothesis state machine; PEP / MCP-proxy / Claude Code hook wiring, the 750-decision benign benchmark, SARIF, and p99 latency). Before them, **652**. **146** of the 652 are the v12 evasion-guard tests ([`test_v12_guards.py`](agent-gateway/tests/test_v12_guards.py): MCP rug-pull and description poisoning, workspace config / hook persistence, control-flow integrity with one Hypothesis state machine, stego exfiltration with a bit-parallel LCS checked against dynamic programming, PEP / MCP-proxy / Claude Code hook wiring, SARIF, and p99 latency). Before them, **506**. **49** of the 506 are the PHP Defense Guard tests ([`test_php_defense.py`](agent-gateway/tests/test_php_defense.py): every rule, encoded and nested variants, benign input, excluded keys and log-only mode, the hash-chained log, SARIF export, and Python / PHP 8.3 parity; CI installs PHP 8.3 and fails if `php` is missing, a machine without PHP skips those six tests). Before them, **457**. **68** of the 457 are the v11.1 delivery additions: **48** Claude Code `PreToolUse` hook tests ([`test_claude_code_hook.py`](agent-gateway/tests/test_claude_code_hook.py), mostly parametrized policy cases) and **20** MCP blueprint tests ([`test_mcp_blueprint.py`](agent-gateway/tests/test_mcp_blueprint.py)). They are not part of Group D. Before them, **389**; **127** of the 389 are the post-sprint v11 additions: **17** schema-digest tests (two Hypothesis properties), **63** GUI-action tests (two Hypothesis properties), **19** schema / GUI PEP and MCP-proxy wiring tests, **12** memory-provenance / temporal-accumulator PEP, MCP-proxy, and SARIF wiring tests, **4** memory-provenance tests (one Hypothesis state machine), **9** temporal-accumulator tests (one Hypothesis property, one state machine), **1** SARIF test, and **2** Group D layout tests. The six new test files form Group D (**124** tests), reported apart from the sprint groups. The sprint tree collected **262** (`pytest -q` in `agent-gateway` at `cefec0d`, 20 files). **18** of the 262 are the collusion-sprint additions: **11** `evaluate-collusion` tests and **7** sprint-artifact tests. The tree before them collected **244**: the **240** recorded for v10 plus **4** HTTP resource-limit tests ([`test_resource_limits.py`](agent-gateway/tests/test_resource_limits.py)). **79** of the 240 are the v10 additions: **8** delegation / confused-deputy tests (one Hypothesis DAG machine), **44** argument-firewall tests (two Hypothesis properties), **20** canary / credential tests (two Hypothesis properties), and **7** SARIF-exporter tests (one Hypothesis property). The v9 count before them is **161**. **72** of those 161 are the v9 additions: **44** SSRF URI-guard tests (two Hypothesis properties), **11** tool-output scanner tests (two Hypothesis properties), **9** toxic-combination tests (one Hypothesis property), and **8** side-channel tests (one Hypothesis state machine). The v8 count before them is **89**. **49** of those 89 are the v8 additions: **12** MCP wire-proxy tests, **21** de-obfuscation tests, **15** hash-chain audit tests, and **1** smuggling Hypothesis machine. The v1.0.0 count before them is **40**. **5** of those 40 are executive audit-report tests. **6** are approval-webhook tests. The count before those 5 audit tests is **35**. The pre-webhook floor is **29** (the count before those 6 existed; that is the "29" figure). Inside the 40: **7/7** ATLAS falsification in [`test_pep_falsification.py`](agent-gateway/tests/test_pep_falsification.py), plus Hypothesis stateful checks. |
| agent-watch tests | `agent-watch` pytest | **514** collected: **512** passed, **2** skipped. |
| Collusion sprint check | `python -m agent_gateway evaluate-collusion` | **57/57** defence tests (A 8/8, B 8/8, C 41/41); 750 benign decisions, 0 denied; 750/750 chain entries verified; CPU p50 0.126 ms, p95 0.892 ms, p99 0.999 ms, max 3.84 ms. Same-author lab check, not a benchmark. Artifacts in [`sprint_submission/`](sprint_submission/). |
| STIX 2.1 | [`agentwatch-analyzer/scripts/ci_smoke.py`](agentwatch-analyzer/scripts/ci_smoke.py) | Recorded smoke on the archived Tier-2 Playwright crawler log reported **`validator_ok=true`**. Known warnings on `x_` properties and approximate ATLAS tags can still appear. |

Use **874** on `main` (the v12.2 reference validators on top of 796). Use **796** for v12.1 (the interpreter, first-listing, and collusion guards on top of 652). Use **652** for v12 (the evasion guards on top of 506). Use **506** for the PHP Defense Guard tree (on top of 457). Use **457** for v11.1 (the Claude Code hook and MCP blueprint on top of 389). Use **389** on the v11 tree (the v11 schema, GUI, memory-provenance, and temporal-accumulator guards and their wiring, on top of the sprint tree). Use **262** on the sprint tree `cefec0d` (the `evaluate-collusion` aggregator and sprint artifacts on top of v10 and the HTTP resource limits). Use **240** on the v10 tree (delegation guard, argument firewall, canary watermarking, and SARIF export on top of v9). Use **161** on the v9 tree (toxic-combination graph, tool-output scanner, SSRF guard, and side-channel guard on top of v8). Use **89** on the v8 tree (MCP wire proxy, de-obfuscation, and hash-chained audit receipts on top of v1.0.0). Use **40** on the v1.0.0 tree (approval webhook plus the executive audit report). Use **35** on a tree that contains [`approval_webhook.py`](agent-gateway/agent_gateway/approval_webhook.py) but not the audit-report tests. Use **29** only for the parent tree from before the webhook file.

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

Each decision stays well under the 5 ms reference (the tests assert p99 < 5 ms per guard). They are lexical and deterministic: a paraphrased or encrypted secret is not caught. v12.1 closes two of the gaps v12 listed: writes through an inline interpreter and MCP tools that are over-privileged from their first listing (below). No runtime dependency was added.

### v12.2 reference middleware validators

Five rule codes on the same decision path, findings list, and SARIF export as the v12.1 guards. JSON-RPC codes are `-32066` through `-32070` because v12.1 already owns `-32055` through `-32059` and `-32062` through `-32065` (`-32060` / `-32061` stay the sampling errors). Each validator is inert until a trusted adapter attaches its state.

| Validator | Rule codes | What it checks | Wired into |
| --- | --- | --- | --- |
| [`registry_pin_validator.py`](agent-gateway/agent_gateway/registry_pin_validator.py) | `REGISTRY_PIN_DRIFT`, `REGISTRY_ALIAS_AMBIGUOUS` | Per-provider descriptor pins over inputSchema / outputSchema / description / title / annotations. The first listing seals the server; a changed, invalid, or removed descriptor stays `REVOKED`. A bare tool name claimed by two servers is an ambiguous alias and is not resolved by arrival order. Display metadata is linted before enrollment. | `PolicyEngine.pin_tool_descriptors()` (-32066 / -32067); calls to a revoked pin are denied |
| [`workspace_path_validator.py`](agent-gateway/agent_gateway/workspace_path_validator.py) | `WORKSPACE_EFFECT_DENIED` | Bounded literal-shell analyzer over an immutable filesystem model (symlink splicing before `..`, protected names, inode checks). Unmodelled syntax fails closed. | `PolicyEngine.attach_workspace_snapshot()` (-32068) and the lexical half of both Claude Code hooks |
| [`lattice_flow_validator.py`](agent-gateway/agent_gateway/lattice_flow_validator.py) | `FLOW_MANIFEST_DENIED` | Two-level contamination lattice, a precommitted manifest of single-use steps, DAG admission, path patterns, and an idempotent request ledger. | `PolicyEngine.pin_workflow_manifest()` (-32069) |
| [`shingle_similarity_validator.py`](agent-gateway/agent_gateway/shingle_similarity_validator.py) | `SIMILARITY_LEAK_DENIED` | Rolling shingles plus bounded bit-parallel LCS over two pinned normalization views. Audit records carry keyed identifier hashes only. | `PolicyEngine.configure_similarity_matcher()` on outbound string arguments (-32070) |
| [`linear_obligation_validator.py`](agent-gateway/agent_gateway/linear_obligation_validator.py) (v12.3) | `OBLIGATION_PROTOCOL_DENIED` | Bounded 16-place Petri net packed into one 64-bit marking. The manifest must pass a weighted non-minting conservation check when it is compiled. A call must be an enabled transition (input tokens present, no place above 15), and an outbound step needs every resource cleanup place settled. The marking advances only after the other validators pass. | `PolicyEngine.attach_obligation_net()` (-32071) |
| [`symbolic_fs_transducer.py`](agent-gateway/agent_gateway/symbolic_fs_transducer.py) (v12.4) | `FS_LABEL_FLOW_DENIED` | (confidentiality, integrity) labels carried from read sources to write targets in a copy-on-write overlay over the workspace model. Protected paths and inodes start PROTECTED. A non-PUBLIC file cannot feed an outbound call and an UNTRUSTED file cannot feed an execution sink, so copying a protected file to an ordinary name does not launder it. Labels only rise and are committed after the other validators pass. | `PolicyEngine.attach_fs_transducer()` (-32072) |

The path module executes nothing and is not an OS sandbox. Benchmark figures are the reference package's, measured on Python 3.12 (combined p99 4.833856 ms, 5000 samples per case). These checks are deterministic and opt-in. They do not change the honeypot's human-review rule or the 15-minute registered-credential freeze.

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

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

One-page offer, price, and out-of-scope list: **[AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md)**. Reply to that email with a tool inventory if you already have one. $1,800 Tool Inventory Review, $4,500 fixed note, or $6,500 with instrumentation, plus optional add-ons listed on the offer page. Not a penetration test and not a certification. The GitHub Action above is the free alternative.
