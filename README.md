# Rogue AI Detection in the Wild: project summary (defensive research and tooling)

## Repo map

The source archives are unpacked into top-level folders. Each folder keeps its own README.

- [agent-watch/README.md](agent-watch/README.md) — v6 log detector and localhost honeypot (whitepaper section 4).
- [agent-gateway/README.md](agent-gateway/README.md) — lab policy gateway for registered internal agent keys (whitepaper section 6). Not a WAF. Freeze only for keys in the lab registry.
- [agentwatch-analyzer/README.md](agentwatch-analyzer/README.md) — offline log analyzer, 12 Sigma rules, STIX 2.1 export (whitepaper section 4).
- [rogue-ai-pipeline/README.md](rogue-ai-pipeline/README.md) — v6 multi-layer detection pipeline (whitepaper section 4; summary in section 5 below).
- [prototype-v1/README.md](prototype-v1/README.md) — prototype v1, unpacked from `rogue-ai-detection` (section 2; whitepaper section 4, first version).
- [docs/rogue-ai-detection-whitepaper.pdf](docs/rogue-ai-detection-whitepaper.pdf) — whitepaper, updated 24 October 2026 for v6 and Phases 1 to 3. [Word copy](docs/rogue-ai-detection-whitepaper.docx).
- [docs/prior-art.md](docs/prior-art.md) — prior-art search behind whitepaper section 9 and the comparison below.
- [docs/v3-changes.md](docs/v3-changes.md), [docs/v4-changes.md](docs/v4-changes.md), [docs/v5-changes.md](docs/v5-changes.md), [docs/v6-changes.md](docs/v6-changes.md) — what changed in each build. v6 numbers are same-author synthetic regression checks.
- [docs/phase1-tier2-report.md](docs/phase1-tier2-report.md), [docs/phase1-fixes.md](docs/phase1-fixes.md) — loopback Tier-2 sample and the R14 / dwell calibration.
- [docs/phase2-gateway.md](docs/phase2-gateway.md), [docs/phase3-analyzer.md](docs/phase3-analyzer.md) — lab gateway and offline analyzer notes.
- [docs/examples/sample-replay.html](docs/examples/sample-replay.html) — static session-replay example. It makes no network requests.

## 1. Research report
Link: https://cursor.com/canvas/store-f783d059-8304-409e-8eee-8c518ae04f8b/91900c77-b85e-45f9-b706-3b5fa0315467
- Covers bot and agent detection, anomaly detection, coordination and collusion, prompt injection and agent misuse.
- Standards: MITRE ATLAS, NIST AI RMF, OWASP, STIX/TAXII, disclosure norms.
- Legal and ethical limits on data collection: CFAA cases, GDPR and an EDPB scraping draft, DSA Article 40, Menlo Report.
- Includes a reference architecture, recommendations, 36 linked sources. Only 3 primary documents read in full; the rest rely on abstracts or search summaries.
- ATLAS IDs were checked against the primary data file (AML.T0051, T0053, T0080, T0086, T0118).
- Legal content is a research summary, not legal advice.

## 2. Prototype v1 (rogue-ai-detection.zip)
- Synthetic data only. Isolation Forest, coordination check, rules, hash-chained alert log, STIX export, local dashboard and report form.
- 42 tests pass. Standard scenarios (62 agents, 9 planted rogue): combined precision 1.00, recall 1.00. Evasive variants: found 1 of 9.
- The perfect standard score is a regression check, not a benchmark.

## 3. Whitepaper
- PDF and Word in `docs/`. The 23 October 2026 text is kept where it still holds. The 24 October update adds v6 and Phases 1 to 3.
- Section 4: v6 synthetic regression (same author), then the loopback Tier-2 sample. Catch rate **2 of 13** on the archived non-control runs of `qwen2.5:3b`. The scripted human control is the fourteenth archive and is not in that denominator. A 3B model usually stopped after 1 to 3 steps, so `/mcp`, the coordination board, and provenance cursors rarely fired. Playwright archives are richer than the thin urllib traces for offline analysis.
- Section 4 also covers `agentwatch-analyzer`: 12 Sigma rules, STIX 2.1, **10 of 10** unit tests. Offline matrix: R8 yes, R9 yes, R10 partial, R11 to R13 not available offline, R14 partial and advisory without a human beacon. A smoke on Jordan's machine (replay.html, findings, STIX with `validator_ok` true; known `x_` / ATLAS warnings may still appear) matched: aggressive urllib LLM 0; Playwright LLM s100 R9; Playwright crawler s100 R9 plus advisory R14; fixture `agentlike_nginx.log` R8, R9, R10.
- Section 6: `agent-gateway` / `pep.py`, the project's reading of AML.M0030. Lab only. **14 of 14** tests, including **7 of 7** ATLAS falsification. Not a production WAF and not Web Bot Auth.
- Standing rules, in the paper and in the code: default bind `127.0.0.1`; the web honeypot is human-review only and does not auto-block a public visitor; gateway freeze applies only to registered internal lab keys; honeypot contact is not intent.
- No wild deployment is claimed. A second, larger local model was not run (about 5 GiB free RAM and no swap). Do not treat the synthetic tables as that missing run.
- Related work is section 9. The search notes are in [docs/prior-art.md](docs/prior-art.md). That search was not repeated for this update.

## 4. Log detector with honeypot (agent-watch)
- Python 3.10+ with Flask. v6 adds a challenge-bound beacon, provenance cursors, a DOM-visual inversion trap, and R14 parasitic-fork detection, on top of the v5 harness labels, static replay, and benchmark kit. [docs/v6-changes.md](docs/v6-changes.md) records 492 passed and 1 skipped (the 23 October v5 count was 446 passed and 1 skipped). The skip needs pydantic and the sibling `rogue-ai-pipeline` tree. This documentation change does not re-run the suite.
- Parses Nginx/Apache and JSON gateway logs, builds sessions, flags adaptive scraping, tool-chaining and rate-limit evasion.
- Rules-and-threshold scoring using timing entropy and navigation depth separates humans, static bots and goal-directed agents. Every score has plain-language reasons.
- Alerts as terminal summaries and JSON.
- Honeypot: hidden decoy links, fake admin and export endpoints, fake credentials, and canary pages carrying a harmless "AI assistants, fetch this URL" note so an agent that obeys embedded text gets logged.
- Binds to `127.0.0.1` by default, no outbound requests. Scores are leads for a person. The honeypot does not auto-block a public visitor.
- Synthetic demo: 5/5 humans, 5/5 static bots, 3/3 adaptive agents labelled correctly. Live run against the simulated agent: flagged critical, mainly for following the canary instruction. That demo is a regression check.
- Loopback Tier-2, archived, not a benchmark: `qwen2.5:3b` against the honeypot on `127.0.0.1`. Catch rate **2 of 13** non-control runs (headless Playwright crawler, and one LLM-driven Playwright run). Nine urllib sessions were not caught; the model usually quit after 1 to 3 calls. The scripted human control was not caught and is not in the 13. After calibration, same-session R14 requires a schema-provenance cursor on the rider, and dwell under 12 ms is inconclusive for touch and an OS tap. Details: whitepaper section 4, [docs/phase1-tier2-report.md](docs/phase1-tier2-report.md), [docs/phase1-fixes.md](docs/phase1-fixes.md).

## 5. Multi-layer pipeline (rogue-ai-pipeline)
- v6 accepts the v6 event contract and copies the harness-archetype label onto leads and STIX. [docs/v6-changes.md](docs/v6-changes.md) records 384 passed and clean type checks (the 23 October v5 count was 331 passed). This documentation change does not re-run pytest or mypy. STIX 2.1 export is checked with the OASIS validator in the suite.
- Layers: schema validation with keyed pseudonymization; Isolation Forest with feature explanations; rule gates mapped to ATLAS T0051, T0053, T0086 (v6 adds R12, R13, R14 and two graph edges); networkx coordination graph that suppresses cron jobs and orchestrator pools; fused scoring that only creates low-severity "human review" leads; hash-chained audit log.
- Earlier synthetic evaluation, 5 seeds (kept here so the old summary is not silently replaced):
  - Standard: precision 0.85, recall 0.97, false-positive rate 0.03
  - Half evasive: precision 0.72, recall 0.45, FPR 0.03
  - All evasive: precision 0.00, recall 0.00, FPR 0.03
- The paired v6 check is in [docs/v6-changes.md](docs/v6-changes.md), same author, not a benchmark. On that harness: standard core recall 80 of 80, FPR 21 of 605 (0.035); all-evasive core recall 12 of 80, FPR 23 of 605 (0.038). Web FPR fell from 39 of 575 (0.068) to 14 of 575 (0.024). Documented pipeline regressions: `mimic_assets` and `mimic_linked_nosec`, each 15 of 15 to 0 of 15.
- Rules alone recall 0.47; Isolation Forest alone recall 0.14; graph without suppression FPR 0.23. These three figures are from the earlier evaluation, not a new v6 ablation.
- 14 known false positives (partner integrations, agents adopting a new tool).
- Honeypot output exports in the pipeline's format, but one visitor is too little data for its anomaly layer, which needs at least 10 agents.

## 6. Lab gateway (agent-gateway)
- `pep.py` is a loopback policy proxy for **registered internal** agent keys. The project maps it to ATLAS mitigation AML.M0030 (taint on untrusted ingest, then restrict the tool call). Whitepaper section 6 and [docs/phase2-gateway.md](docs/phase2-gateway.md).
- Default bind `127.0.0.1`. Freeze and hard-block apply only to keys in `agent-gateway/config/agents.json`. They do not apply to visitors of the web honeypot.
- Recorded tests after the capability work: **29 passed**, including **7 of 7** ATLAS falsification, plus Hypothesis. The approval-webhook hook adds its own tests on that floor (see [docs/phase2-gateway.md](docs/phase2-gateway.md)). Those tests check the gates against cases written for them. Not a production evaluation.
- Commercial hooks (lab, self-serve): a Slack / generic webhook formatter for a tainted call that is waiting on a person (`agent-gateway/agent_gateway/approval_webhook.py`; no HTTP unless `--webhook-deliver`), and `.github/workflows/atlas-agent-audit.yml` for the gateway, agent-watch, the pipeline, and an offline analyzer smoke. The workflow does not deploy the honeypot. Deny & Freeze is 15 minutes and only for a registered key.
- Not a production WAF. Not Web Bot Auth. Tool backends in this prototype are simulated echoes. No wild deployment.

## 7. Offline analyzer (agentwatch-analyzer)
- Standalone CLI. It does not start the honeypot, bind a port, or call the network. It scrubs, then writes findings, `replay.html`, and a STIX 2.1 bundle. Whitepaper section 4 and [docs/phase3-analyzer.md](docs/phase3-analyzer.md).
- 12 Sigma rules. **10 of 10** unit tests recorded. Offline matrix: R8 yes; R9 yes; R10 partial; R11, R12 and R13 not available from a normal access log; R14 partial and advisory without human-beacon corroboration.
- Smoke on Jordan's machine, against archived Tier-2 logs and `agentwatch-analyzer/tests/fixtures/agentlike_nginx.log`. Outputs included `replay.html`, findings, and STIX with `validator_ok` true (known warnings on `x_` properties and approximate ATLAS tags may still appear). Matches from that smoke only:

| Sample | Matches | Rules |
| --- | --- | --- |
| Tier-2 aggressive urllib LLM | 0 | none |
| Tier-2 Playwright LLM s100 | 1 | R9 |
| Tier-2 Playwright crawler s100 | 2 | R9 + R14 (advisory offline) |
| Fixture `agentlike_nginx.log` | 3 | R8, R9, R10 |

- The advisory offline R14 on the crawler is not the live R14 false positive. After the Phase 1 calibration, rescoring that archive does not raise `parasitic_session_fork`. Playwright Tier-2 logs are richer than the thin urllib traces, which is why the aggressive urllib sample matched nothing.

## How This Project Compares to Prior Art

I did a **limited public search on 23 October 2026** (web search, then reading each README, PyPI page, vendor doc or arXiv abstract listed in
[`docs/prior-art.md`](docs/prior-art.md)). It is not a systematic review. In the table, **"not found in my search" means I did not find the
capability documented in the pages I read; it does not mean the capability does not exist.** Several of these projects are weeks or months old, and for GitHub
projects I read the README, not the code. Drosera comes closest to our web-side design (signed per-session ticket, asset-starvation signal, noisy-OR fusion, log replay, STIX report format).

| Capability | Prior art I found documented | This project (v6 stack; synthetic numbers are same-author regression checks. Loopback sample is whitepaper section 4, not this table) |
| --- | --- | --- |
| Hidden-instruction canary pages for agents | Palisade LLM Agent Honeypot; Drosera; Thinkst Canary; pihoney | Yes. Contact with a canary is a lead, not intent |
| Per-session token / nonce round trip | Drosera (HMAC-signed ticket). Others: not found in my search | Handoff token + nonce on a coordination board; a token replayed from another session/address is a separate signal (other tools: not found in my search) |
| Decoy MCP endpoint (tools/list, then tools/call) | Sundew, MCP Decoy, HoneyMCP, Thinkst MCP canarytoken | Yes, plus an `mcp_tool_runner` harness label |
| Asset-starvation signal | Drosera (`beh.no_assets`). Others: not found in my search | Yes; since v4 it separates *selective* blocking from true starvation (core CSS/JS, coherent `Sec-Fetch-*`) |
| Page move checked against the links the page actually offered | not found in my search | Yes ("unlinked jump"), with an empirical Referer-based fallback for ordinary logs (circular inside one batch) |
| Traps for browser-backed mimics | Academic work studies client-side / multi-layer fingerprints (FP-Agent, Fayolle et al.); honeypot traps for this case: not found in my search | v4/v5: ARIA canary + a beacon of three booleans (no identifiers). Catches simulated mimics that fetch our script but never run it; JS-disabled or beacon-blocking people produce no beacon (known false positive in that version). v6 narrows that false positive in the synthetic check; see section 4 of the whitepaper. The loopback sample is separate |
| Deterministic harness-archetype label with reasons | Model attribution from action traces (Lugoloobi et al.). Archetype labels for web agents: not found in my search | Six archetypes + `unclassified`; descriptive, never scored |
| Multi-layer downstream pipeline | Drosera: noisy-OR, replay, STIX report. A pipeline with anomaly + rules + graph + audit chain + STIX: not found in my search | Isolation Forest, rules, coordination graph, two-signal corroboration gate, per-layer attribution, hash-chained audit log, STIX 2.1 |
| TLS / header fingerprinting (JA3/JA4) | Documented (FoxIO, Cloudflare, academic) | **Not implemented** |
| Real-world deployment evidence | Palisade: about 8.1 million real attempts | **No wild deployment.** Loopback only: local `qwen2.5:3b` and Playwright on `127.0.0.1`; 2 of 13 non-control archives caught. Same author, tiny n. Not a benchmark |

### Where This Stack Extends

1. **Selective blocking is not starvation.** Asset starvation is typed by what was skipped (CSS/JS vs images). In the agent-watch simulation 15 of 15
   "images blocked" humans were alerted by v3 and 0 of 15 by v4.
2. **Link-graph and trap evidence against browser-backed mimics.** Moves are scored against the links the honeypot actually served, with an empirical fallback; an ARIA canary
   and a three-boolean beacon target clients that look like browsers. In the pipeline simulation (9 mimic cohorts, 135 clients, 5 seeds) the share producing a lead went
   from 0 % (v2) to 33 % (v3) to 78 % (v4, 105 of 135). The `mimic_assets` cohort went from 0 of 15 to 15 of 15, **but only because the simulated mimic fetches our script and never runs it**.
   Two evaders, a stealth browser and a header forger, were still missed in that v4 simulation (0 of 15 each). The paired v6 check is not the same result: those two cohorts are 10 of 15 pipeline leads each, and `mimic_assets` plus `mimic_linked_nosec` fall from 15 of 15 to 0 of 15. The loopback catch rate is 2 of 13 (whitepaper section 4). Do not read the v4 share as a current accuracy.
3. **Coordination and harness evidence.** A handoff token replayed from a different session or address, a capped claim loop, and a deterministic harness archetype
   (`mcp_tool_runner`, `schema_driven_api_agent`, `stateful_coordinator`, `prompt_injected_crawler`, `headless_or_http_mimic`, `commodity_or_static_scanner`) with plain-language reasons and a
   low/medium/high confidence that describes how much of the signature was seen, not a probability. Cohort accuracy is in [agent-watch/docs/fingerprint-confusion.md](agent-watch/docs/fingerprint-confusion.md) (same-author synthetic).
4. **Honest evaluation boundaries.** Synthetic numbers in this section are **same-author regression checks, not benchmarks**: the simulated clients, including each mimic, were written by the author of the
   detectors, with the rules in mind. **Honeypot or beacon contact is not intent.** Web-honeypot output is a lead for human review. The honeypot does not auto-block a public visitor. The lab gateway can freeze only a registered internal key. Costs reported for the earlier beacon rule:
   weak leads to 15 of 15 simulated beacon-blocking humans and 10 of 10 no-asset, no-`Sec-Fetch` humans. v6's paired synthetic check removes the beacon-blocked human alerts (15 of 15 to 0 of 15 in both agent-watch and the pipeline) and the pipeline's no-asset leads (10 of 10 to 0 of 10), and accepts the two pipeline regressions named above. The corroboration gate removed 11 statistical-only benign leads
   (false-positive rate 0.06 to 0.04) but also 2 injected probers and, in the all-evasive scenario set of that earlier run, all recall that rested on Isolation Forest plus the sequence model alone (core recall 0.24 to 0.00).

## Caveats
- Synthetic results were written by the same author as the detectors: regression checks, not benchmarks.
- The loopback Tier-2 archive is one machine, one 3B model, 14 runs. Quote **2 of 13** non-control catches, and do not pool that with synthetic recall. The scripted human control is not a real person.
- A second, larger local model was not run (about 5 GiB free RAM and no swap). There is no mid-size multimodel result to cite.
- No wild honeypot deployment. Do not expose the honeypot publicly without isolation. Default bind is `127.0.0.1`.
- Evasive-variant results are a worst case; those variants were written against these exact thresholds.
- Heuristics can be evaded and shared IPs cause false positives.
- Use only on systems you own or are authorized to monitor. Treat every web flag as a lead for human review, not a block. Gateway freeze is only for registered internal lab keys.
- Honeypot contact is not intent.
