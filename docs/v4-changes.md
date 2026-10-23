# v4 changes (agent-watch + rogue-ai-pipeline)

All numbers below are **synthetic, same-author regression checks, not benchmarks** (5 seeds; the simulated clients were written by the author of the detectors). Honeypot or beacon contact is not intent; every output is a lead for a human. Services bind to 127.0.0.1 and nothing makes an outbound request.

## What changed, in plain English
1. **"Images blocked" humans are no longer flagged.** The asset-starvation signal now looks at *which* assets were skipped. A browser-claiming client that loads core CSS/JS, or whose `Sec-Fetch-Dest: document` / `Mode: navigate` headers are coherent on >= 80% of pages, is left alone. The signal is kept for >= 5 HTML pages with no CSS/JS, or contradictory `Sec-Fetch-*` on >= 3 pages (>= 50%).
2. **Browser-backed mimics:** an ARIA "AI Assistant Fast-Path" canary and a tiny interaction beacon (three booleans only: webdriver, pointer trail, DOM automation globals; size-limited, rate-capped, no identifiers). Pipeline rule **R11** feeds the R10 floor tiers: strong (webdriver / DOM globals / ARIA hit by a client that loads our CSS/JS) -> floor 0.80; weak (loaded our script, never beaconed) -> floor 0.58 `possible_mimic`.
3. **Benign background leads:** per-layer false-positive attribution (`scripts/eval_web.py`, `run.py evaluate`) and a **two-signal corroboration gate** (a lead needs a floor, or two independent families, or one strong deterministic family). `corroboration_gate = false` restores v3.
4. **R9 fallback:** when the log has no `offered_links`, allowed links are inferred from Referer transitions of other clients (`run.py detect --link-reference`). **Scrubber parity** port: `%40`, `%20`, `%2540`, `\uXXXX`, newline/CR/TAB-split tokens become keyed `[REDACTED_<TYPE>_SHA256:<10hex>]` markers.
5. Evaluation and docs: `scripts/eval_v4.py` (agent-watch), `scripts/eval_web.py` and `run.py evaluate` (pipeline), READMEs with Before/After, limits and attribution.

## Before / After (pooled over 5 seeds)
| metric | v2 | v3 | v4 |
|---|---|---|---|
| mimic_assets recall, agent-watch (15 clients) | 0/15 | 0/15 | **15/15** alerted as `possible_mimic` (0/15 labelled `agent`) |
| mimic_assets recall, pipeline (15) | 0/15 | 0/15 | **15/15** (R11 weak tier; only because the simulated mimic never runs our script) |
| images-blocked human false positives, agent-watch | 0/15 (not seen) | **15/15** | **0/15** |
| images-blocked humans, pipeline | 0/20 | 0/20 | 0/20 |
| mimic_linked classification, agent-watch | not seen | `possible_mimic` 15/15 | `possible_mimic` 15/15 |
| mimic_linked recall without Sec-Fetch, pipeline | 0/15 | 0/15 | **15/15** `possible_mimic` |
| webdriver + ARIA mimics, pipeline / agent-watch | 0/30 | 0/30 | 30/30 `goal_directed` |
| all mimic cohorts with a lead, pipeline (135) | 0% | 33% | 78% (105/135) |
| unrelated benign background leads (380 agents, sim policy) | 14 | 14 | 14 |
| ... with no policy declared | 68 | 68 | 68 (50 are `graph:timing_content` orchestrator pools: a harness artifact) |
| **new** false positives: beacon-blocked humans / no-asset-no-Sec-Fetch humans | 0 / 0 | 0 / 0 | **15/15 and 10/10** weak leads |

Per-layer attribution of v4 benign leads: background: rule R3 x9, R1(+1) x4, R2 x1 (by-design hard negatives); web humans: floor R11 x25.

**Gate trade-off (run.py evaluate, 5 seeds):** evasiveness 0: overall recall 0.92 -> 0.91, core recall 1.00 -> 0.97, FPR 0.06 -> 0.04; evasiveness 1.0: core recall 0.24 -> **0.00**, FPR 0.06 -> 0.04. The gate removes 11 benign statistical-only leads (7 compliance_scanner, 4 noisy_denied) and 2 injected probers. The strict gate (every non-floor lead needs 2 families) cuts recall to 0.47 and is not recommended.

## Still missed / limits
`mimic_browser_stealth` (0/15) and `mimic_header_forger` (0/15). JS-disabled / beacon-blocking humans produce no beacon (false-positive class above). The R9 fallback is circular inside one batch (use `--link-reference`). Nothing was run against a real browser, automation framework or LLM agent.

## Not tested
Real browsers (the optional loopback-only Chrome smoke test was **not run**), real agents, real traffic, real nginx logs for the R9 fallback, real populations for the gate.

## Existing tests changed (deliberately)
* pipeline `tests/test_baseline_sequence.py::test_two_unsupervised_signals...` encoded the pre-gate behaviour (an IF + sequence-only lead); updated with a comment because the corroboration gate now intentionally changes that outcome.
* agent-watch `tests/test_v3_web.py` export allow-list gained `referer_path` (same-site Referer for the R9 fallback).

## Tests
agent-watch 446 passed, 1 skipped; pipeline 331 passed (slow suite run once); mypy on the pipeline clean.
