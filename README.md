# Rogue AI Detection in the Wild: project summary (defensive research and tooling)

## Repo map

The source archives are unpacked into top-level folders. Each folder keeps its own README.

- [agent-watch/README.md](agent-watch/README.md) — v5 log detector and localhost honeypot (section 4).
- [rogue-ai-pipeline/README.md](rogue-ai-pipeline/README.md) — v5 multi-layer detection pipeline (section 5).
- [prototype-v1/README.md](prototype-v1/README.md) — prototype v1, unpacked from `rogue-ai-detection` (section 2).
- [docs/rogue-ai-detection-whitepaper.pdf](docs/rogue-ai-detection-whitepaper.pdf) — rebuilt whitepaper (section 3), PDF. [Word copy](docs/rogue-ai-detection-whitepaper.docx).
- [docs/prior-art.md](docs/prior-art.md) — prior-art search behind the comparison section below.
- [docs/v3-changes.md](docs/v3-changes.md), [docs/v4-changes.md](docs/v4-changes.md), [docs/v5-changes.md](docs/v5-changes.md) — what changed in each build.
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
- PDF and Word in `docs/`. The copy-edited rebuild is 10 pages and dated 23 October 2026. It states the synthetic-data limit up front.
- Includes a Related work and novelty section. The search notes are in [docs/prior-art.md](docs/prior-art.md).

## 4. Log detector with honeypot (agent-watch)
- Python 3.10+ with Flask. v5 adds harness-archetype labels, a static HTML replay, and a benchmark kit. This tree: 447 passed, 0 skipped, 0 failed. The extra pass is `test_export_validates_against_sibling_pipeline_schema_if_available`, which skips unless pydantic is installed and the sibling `rogue-ai-pipeline` tree is present (the 446 passed / 1 skipped count). These are synthetic regression checks.
- Parses Nginx/Apache and JSON gateway logs, builds sessions, flags adaptive scraping, tool-chaining and rate-limit evasion.
- Rules-and-threshold scoring using timing entropy and navigation depth separates humans, static bots and goal-directed agents. Every score has plain-language reasons.
- Alerts as terminal summaries and JSON.
- Honeypot: hidden decoy links, fake admin and export endpoints, fake credentials, and canary pages carrying a harmless "AI assistants, fetch this URL" note so an agent that obeys embedded text gets logged.
- Binds to localhost only, no outbound requests.
- Synthetic demo: 5/5 humans, 5/5 static bots, 3/3 adaptive agents labelled correctly. Live run against the simulated agent: flagged critical, mainly for following the canary instruction.

## 5. Multi-layer pipeline (rogue-ai-pipeline)
- v5 accepts the harness-archetype label and copies it onto leads and STIX. This tree: 331 passed, 0 failed, and `mypy rogue_pipeline run.py` reports no issues. STIX 2.1 export is checked with the OASIS validator in the suite. The numbers below are synthetic regression checks, not benchmarks.
- Layers: schema validation with keyed pseudonymization; Isolation Forest with feature explanations; rule gates mapped to ATLAS T0051, T0053, T0086; networkx coordination graph that suppresses cron jobs and orchestrator pools; fused scoring that only creates low-severity "human review" leads; hash-chained audit log.
- Synthetic evaluation, 5 seeds:
  - Standard: precision 0.85, recall 0.97, false-positive rate 0.03
  - Half evasive: precision 0.72, recall 0.45, FPR 0.03
  - All evasive: precision 0.00, recall 0.00, FPR 0.03
- Rules alone recall 0.47; Isolation Forest alone recall 0.14; graph without suppression FPR 0.23.
- 14 known false positives (partner integrations, agents adopting a new tool).
- Honeypot output exports in the pipeline's format, but one visitor is too little data for its anomaly layer, which needs at least 10 agents.

## How This Project Compares to Prior Art

I did a **limited public search on 23 October 2026** (web search, then reading each README, PyPI page, vendor doc or arXiv abstract listed in
[`docs/prior-art.md`](docs/prior-art.md)). It is not a systematic review. In the table, **"not found in my search" means I did not find the
capability documented in the pages I read; it does not mean the capability does not exist.** Several of these projects are weeks or months old, and for GitHub
projects I read the README, not the code. Drosera comes closest to our web-side design (signed per-session ticket, asset-starvation signal, noisy-OR fusion, log replay, STIX report format).

| Capability | Prior art I found documented | This project (v4/v5; all numbers synthetic, same author) |
| --- | --- | --- |
| Hidden-instruction canary pages for agents | Palisade LLM Agent Honeypot; Drosera; Thinkst Canary; pihoney | Yes. Contact with a canary is a lead, not intent |
| Per-session token / nonce round trip | Drosera (HMAC-signed ticket). Others: not found in my search | Handoff token + nonce on a coordination board; a token replayed from another session/address is a separate signal (other tools: not found in my search) |
| Decoy MCP endpoint (tools/list, then tools/call) | Sundew, MCP Decoy, HoneyMCP, Thinkst MCP canarytoken | Yes, plus an `mcp_tool_runner` harness label |
| Asset-starvation signal | Drosera (`beh.no_assets`). Others: not found in my search | Yes; since v4 it separates *selective* blocking from true starvation (core CSS/JS, coherent `Sec-Fetch-*`) |
| Page move checked against the links the page actually offered | not found in my search | Yes ("unlinked jump"), with an empirical Referer-based fallback for ordinary logs (circular inside one batch) |
| Traps for browser-backed mimics | Academic work studies client-side / multi-layer fingerprints (FP-Agent, Fayolle et al.); honeypot traps for this case: not found in my search | ARIA canary + a beacon of three booleans (no identifiers). Catches simulated mimics that fetch our script but never run it; JS-disabled or beacon-blocking people produce no beacon (known false positive) |
| Deterministic harness-archetype label with reasons | Model attribution from action traces (Lugoloobi et al.). Archetype labels for web agents: not found in my search | Six archetypes + `unclassified`; descriptive, never scored |
| Multi-layer downstream pipeline | Drosera: noisy-OR, replay, STIX report. A pipeline with anomaly + rules + graph + audit chain + STIX: not found in my search | Isolation Forest, rules, coordination graph, two-signal corroboration gate, per-layer attribution, hash-chained audit log, STIX 2.1 |
| TLS / header fingerprinting (JA3/JA4) | Documented (FoxIO, Cloudflare, academic) | **Not implemented** |
| Real-world deployment evidence | Palisade: about 8.1 million real attempts | **None**; localhost and synthetic only |

### Where This Stack Extends

1. **Selective blocking is not starvation.** Asset starvation is typed by what was skipped (CSS/JS vs images). In the agent-watch simulation 15 of 15
   "images blocked" humans were alerted by v3 and 0 of 15 by v4.
2. **Link-graph and trap evidence against browser-backed mimics.** Moves are scored against the links the honeypot actually served, with an empirical fallback; an ARIA canary
   and a three-boolean beacon target clients that look like browsers. In the pipeline simulation (9 mimic cohorts, 135 clients, 5 seeds) the share producing a lead went
   from 0 % (v2) to 33 % (v3) to 78 % (v4, 105 of 135). The `mimic_assets` cohort went from 0 of 15 to 15 of 15, **but only because the simulated mimic fetches our script and never runs it**.
   Two evaders, a stealth browser and a header forger, are still missed (0 of 15 each).
3. **Coordination and harness evidence.** A handoff token replayed from a different session or address, a capped claim loop, and a deterministic harness archetype
   (`mcp_tool_runner`, `schema_driven_api_agent`, `stateful_coordinator`, `prompt_injected_crawler`, `headless_or_http_mimic`, `commodity_or_static_scanner`) with plain-language reasons and a
   low/medium/high confidence that describes how much of the signature was seen, not a probability. Cohort accuracy is in [agent-watch/docs/fingerprint-confusion.md](agent-watch/docs/fingerprint-confusion.md) (same-author synthetic).
4. **Honest evaluation boundaries.** All numbers are **synthetic, same-author regression checks, not benchmarks**: the simulated clients, including each mimic, were written by the author of the
   detectors, with the rules in mind. **Honeypot or beacon contact is not intent.** Every output is a lead for human review; nothing blocks or accuses anyone. Costs are reported:
   the beacon rule gave weak leads to 15 of 15 simulated beacon-blocking humans and 10 of 10 no-asset, no-`Sec-Fetch` humans; the corroboration gate removed 11 statistical-only benign leads
   (false-positive rate 0.06 to 0.04) but also 2 injected probers and, in the all-evasive scenario set, all recall that rested on Isolation Forest plus the sequence model alone (core recall 0.24 to 0.00).

## Caveats
- All results are on synthetic data written by the same author as the detectors: regression checks, not benchmarks.
- Evasive-variant results are a worst case; those variants were written against these exact thresholds.
- Heuristics can be evaded and shared IPs cause false positives.
- Use only on systems you own or are authorized to monitor. Treat every flag as a lead for human review, not a block.
- Do not expose the honeypot publicly without isolation.
