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
> **Frozen snapshot vs. `main`.** The files above are the 25 October sprint snapshot at `cefec0d` (57/57 A/B/C checks, 262 gateway tests) and are not regenerated. `main` has since added four v11 guards behind `pep.py` (`schema_integrity_guard.py`, `gui_action_guard.py`, `memory_provenance_guard.py`, `temporal_accumulator_guard.py`). Their tests are reported as a separate post-sprint **Group D** and are never folded into 57/57. On `main`: **457** gateway tests and **7** stateful Hypothesis machines (v11.1 adds the Claude Code hook and the MCP delivery blueprint; neither changes the sprint figures).
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
| Tier 2: Inline PEP Hardening & CI Gate Sprint (Fixed Tool-Boundary Note) | **$4,500** | Tier 1 and the full written note, plus a loopback `pep.py` / `mcp_proxy.py` policy set for your tool list, the 7 Hypothesis regression machines in a CI workflow, and hash-chained per-run logging (`audit_chain.py`). Delivered as a pull request your team merges |
| Tier 3: Continuous Red-Team, Canary & Deception Retainer (Note + Lab Instrumentation) | **$6,500**, then $2,500 per quarter | Tier 2 plus a lab gateway pass on `127.0.0.1` (simulated backends), an offline analyzer pass on an authorized log, localhost tripwire / canary / de-obfuscation / side-channel guard configuration, and a quarterly `evaluate-collusion` re-run |

Optional add-ons: Integration Blueprint (+$2,500, code or config sketches for the top held calls, nothing deployed on your hosts), Reviewer Briefing Call (+$750), Quarterly Refresh Retainer ($2,500 per quarter). All prices are fixed.

Email [alecagentboundary@gmail.com](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit) with the subject `Book 48-Hour Agentic Tool-Boundary Audit`. You can reply in that thread with a tool inventory (names and argument shapes, no secrets). The clock starts when a usable tool list arrives. This is not a penetration test and not a certification. The honeypot stays human-review only, freeze applies only to registered lab keys for 15 minutes, and ATLAS ids in the note are approximate. See an [example note](docs/examples/sample-boundary-note.md). Sample output from our own sprint run: [report PDF](sprint_submission/collusion_sprint_report.pdf), [briefing deck](sprint_submission/collusion_sprint_slides.pdf), [JSON](sprint_submission/collusion_benchmark_results.json).

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

One-page offer: **[AgentGate — 48-Hour Agentic Tool-Boundary Audit](marketing/audit-offer.md)**

## Compliance snapshot

Labels for results **recorded in this lab tree on 25 October 2026**. They are not a certification, and they are not evidence of a wild deployment. The GitHub Action file is the thing you run; the shields only repeat the recorded counts.

[![GitHub Action atlas-agent-audit.yml](https://img.shields.io/badge/GitHub_Action-atlas--agent--audit.yml-3b5bdb)](.github/workflows/atlas-agent-audit.yml)
[![gateway tests 457 passed](https://img.shields.io/badge/gateway_tests-457_passed-2f6f4e)](agent-gateway/tests)
[![ATLAS 7/7 plus Hypothesis](https://img.shields.io/badge/ATLAS_falsification-7%2F7_%2B_Hypothesis-2f6f4e)](agent-gateway/tests/test_pep_falsification.py)
[![STIX validator_ok true](https://img.shields.io/badge/STIX_2.1-validator__ok%3Dtrue-2f6f4e)](agentwatch-analyzer/scripts/ci_smoke.py)

| Check | Where | Recorded result |
| --- | --- | --- |
| ATLAS agent audit | [`.github/workflows/atlas-agent-audit.yml`](.github/workflows/atlas-agent-audit.yml) | Four jobs: gateway, agent-watch, pipeline, offline analyzer smoke. The smoke job fails unless the STIX bundle parses and `validator_ok` is true. It then runs `python -m agent_gateway audit` and uploads the executive HTML and text PDF with the other artifacts. No honeypot process. |
| Gateway tests | `agent-gateway` pytest | **457 passed** on `main` (`pytest -q` in `agent-gateway`, 28 files). **68** of the 457 are the v11.1 delivery additions: **48** Claude Code `PreToolUse` hook tests ([`test_claude_code_hook.py`](agent-gateway/tests/test_claude_code_hook.py), mostly parametrized policy cases) and **20** MCP blueprint tests ([`test_mcp_blueprint.py`](agent-gateway/tests/test_mcp_blueprint.py)). They are not part of Group D. Before them, **389**; **127** of the 389 are the post-sprint v11 additions: **17** schema-digest tests (two Hypothesis properties), **63** GUI-action tests (two Hypothesis properties), **19** schema / GUI PEP and MCP-proxy wiring tests, **12** memory-provenance / temporal-accumulator PEP, MCP-proxy, and SARIF wiring tests, **4** memory-provenance tests (one Hypothesis state machine), **9** temporal-accumulator tests (one Hypothesis property, one state machine), **1** SARIF test, and **2** Group D layout tests. The six new test files form Group D (**124** tests), reported apart from the sprint groups. The sprint tree collected **262** (`pytest -q` in `agent-gateway` at `cefec0d`, 20 files). **18** of the 262 are the collusion-sprint additions: **11** `evaluate-collusion` tests and **7** sprint-artifact tests. The tree before them collected **244**: the **240** recorded for v10 plus **4** HTTP resource-limit tests ([`test_resource_limits.py`](agent-gateway/tests/test_resource_limits.py)). **79** of the 240 are the v10 additions: **8** delegation / confused-deputy tests (one Hypothesis DAG machine), **44** argument-firewall tests (two Hypothesis properties), **20** canary / credential tests (two Hypothesis properties), and **7** SARIF-exporter tests (one Hypothesis property). The v9 count before them is **161**. **72** of those 161 are the v9 additions: **44** SSRF URI-guard tests (two Hypothesis properties), **11** tool-output scanner tests (two Hypothesis properties), **9** toxic-combination tests (one Hypothesis property), and **8** side-channel tests (one Hypothesis state machine). The v8 count before them is **89**. **49** of those 89 are the v8 additions: **12** MCP wire-proxy tests, **21** de-obfuscation tests, **15** hash-chain audit tests, and **1** smuggling Hypothesis machine. The v1.0.0 count before them is **40**. **5** of those 40 are executive audit-report tests. **6** are approval-webhook tests. The count before those 5 audit tests is **35**. The pre-webhook floor is **29** (the count before those 6 existed; that is the "29" figure). Inside the 40: **7/7** ATLAS falsification in [`test_pep_falsification.py`](agent-gateway/tests/test_pep_falsification.py), plus Hypothesis stateful checks. |
| agent-watch tests | `agent-watch` pytest | **514** collected: **512** passed, **2** skipped. |
| Collusion sprint check | `python -m agent_gateway evaluate-collusion` | **57/57** defence tests (A 8/8, B 8/8, C 41/41); 750 benign decisions, 0 denied; 750/750 chain entries verified; CPU p50 0.126 ms, p95 0.892 ms, p99 0.999 ms, max 3.84 ms. Same-author lab check, not a benchmark. Artifacts in [`sprint_submission/`](sprint_submission/). |
| STIX 2.1 | [`agentwatch-analyzer/scripts/ci_smoke.py`](agentwatch-analyzer/scripts/ci_smoke.py) | Recorded smoke on the archived Tier-2 Playwright crawler log reported **`validator_ok=true`**. Known warnings on `x_` properties and approximate ATLAS tags can still appear. |

Use **457** on `main` (the v11.1 Claude Code hook and MCP blueprint on top of 389). Use **389** on the v11 tree (the v11 schema, GUI, memory-provenance, and temporal-accumulator guards and their wiring, on top of the sprint tree). Use **262** on the sprint tree `cefec0d` (the `evaluate-collusion` aggregator and sprint artifacts on top of v10 and the HTTP resource limits). Use **240** on the v10 tree (delegation guard, argument firewall, canary watermarking, and SARIF export on top of v9). Use **161** on the v9 tree (toxic-combination graph, tool-output scanner, SSRF guard, and side-channel guard on top of v8). Use **89** on the v8 tree (MCP wire proxy, de-obfuscation, and hash-chained audit receipts on top of v1.0.0). Use **40** on the v1.0.0 tree (approval webhook plus the executive audit report). Use **35** on a tree that contains [`approval_webhook.py`](agent-gateway/agent_gateway/approval_webhook.py) but not the audit-report tests. Use **29** only for the parent tree from before the webhook file.

## What you are running

| Piece | Role | Bound |
| --- | --- | --- |
| [`agent-gateway`](agent-gateway/README.md) / `pep.py` | Policy enforcement in the agent tool loop. The project's reading of ATLAS **AML.M0030**: taint on untrusted ingest, then restrict the tool call. Chained HMAC capability (`agw1.`) attenuates with `allow_egress=false`. | Registered keys in [`agent-gateway/config/agents.json`](agent-gateway/config/agents.json). Default bind `127.0.0.1`. |
| Slack / webhook sidecar | Scrubbed approval JSON when a call is held. Callbacks are one-time and hash-bound to session, step, tool, canonical args, and taint source. | No POST unless `--webhook-deliver`. A failed POST does not change the policy decision. An unregistered key is not frozen. |
| [`agent-watch`](agent-watch/README.md) | Log detector and localhost honeypot. Leads for a person. | Default bind `127.0.0.1`. Contact with a canary is a lead, not intent, and not a block. |
| [`agentwatch-analyzer`](agentwatch-analyzer/README.md) | Offline Sigma rules, session replay, STIX 2.1. | No port and no outbound call. |
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
