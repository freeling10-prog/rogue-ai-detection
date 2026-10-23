# v5 changes (on top of v4)

Same safety rules: 127.0.0.1 only, zero outbound requests, secrets scrubbed (scrubber / safelog) before storage or display, same-author synthetic regression numbers clearly labelled.

## Part 1: harness fingerprint
`agentwatch/fingerprint.py`: deterministic, explainable per-session `harness_archetype` (`mcp_tool_runner`, `schema_driven_api_agent`, `stateful_coordinator`, `prompt_injected_crawler`, `headless_or_http_mimic`, `commodity_or_static_scanner`, else `unclassified`) with `harness_confidence` low/medium/high (how much of the signature was seen; not a probability), plain-language reasons, `harness_also_matched`, and a `payload_structure` profile (JSON key count, objective-length bucket, retry-latency bucket after 4xx traps). It never feeds a score.
* agent-watch JSON report and the text report carry it. `export-web` writes it into the strict `web` block.
* The pipeline accepts only enumerated values, attaches it to the lead (`Lead.harness`) and to the STIX 2.1 indicator as `x_harness_archetype`; the bundle still passes the pinned `stix2-validator==3.2.0`.
* New demo cohort: `mcp:tool_runner` (extended demo only; `simagent.run_mcp_runner`).

## Part 2: static replay
`agentwatch/replay.py` + `python -m agentwatch replay leads.jsonl --access leads.jsonl.access.jsonl --out replay.html`. CSP meta `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`, no external references, fully server-rendered, every wire string sanitised -> scrubbed -> HTML-escaped; agent payloads sit in a box badged `UNTRUSTED AGENT INPUT - SCRUBBED`; the inline script only toggles filters/`hidden` (no eval, no HTML writes, no embedded JSON). Per session: summary header (id, actor type, archetype, scores, rules R8-R11, approximate ATLAS ids AML.T0051/T0053/T0080/T0086/T0118), a causal step timeline (time, +delta, method, scrubbed path, offered-by-previous-page with unlinked jumps amber/red, status, 429 peer_hint, canary, handoff-token ref, ARIA, beacon, cognitive-capture and /mcp args) and a triage checklist (human-review leads, not auto-blocks). Sample: `sample-replay.html` (extended demo, seed 7).

## Part 3 (benchmark toolkit): built by a second worker
New files only, not touched by this worker: `agent-watch/benchmark/`, `scripts/build_benchmark.py`, `docs/benchmark-protocol.md`, `tests/test_benchmark.py` (status of each is listed in the final report; they are included in the zips/upload tree as found, not overwritten).

## Part 4: tests
`tests/test_v5.py` (agent-watch, 16 tests: every cohort -> expected archetype with the known misses/false positive asserted as such; report/export carry the fields; hostile `</script><script>alert(1)</script>` in objectives, headers, paths, tool args; CSP meta; no external URLs; zero raw secrets; JS has no eval/innerHTML; CLI) and `tests/test_v5_pipeline.py` (pipeline, 4 tests: label reaches the lead, never changes the score, schema rejects invented archetypes, STIX extension validates).

## Archetype confusion table (5 seeds, same-author synthetic, NOT a benchmark)
See `agent-watch/docs/fingerprint-confusion.md` (also in the README). Overall 275/320 sessions got their intended archetype; the 45 that did not are the documented ones: `mimic_browser_stealth` (15, unclassified), `mimic_header_forger` (15, unclassified) and `human_beacon_blocked` (15, wrongly `headless_or_http_mimic`).

## Prior art and whitepaper
`README-prior-art-section.md` (a README-ready "How This Project Compares to Prior Art" section: final v4 numbers, "not found in my search" for other tools' capabilities, no page counts, honest evaluation boundaries). `docs/prior-art.md` is the search record. The whitepaper section 9 was merged into "Related work and comparative architecture" and rebuilt (`docs/rogue-ai-detection-whitepaper.docx/.pdf`).

## Existing tests changed
* agent-watch `tests/test_v3_web.py` export allow-list also gained `harness_archetype`, `harness_confidence` (deliberate, commented).
* (v4) pipeline `tests/test_baseline_sequence.py` gate-related test; agent-watch same allow-list `referer_path`.

## Not done / limits
The optional Chrome smoke test was not run. agent-watch has no mypy configuration; a plain `mypy` run shows pre-existing errors, so only the pipeline is type-checked. The fingerprint rules and the simulated harnesses share an author. Tests: agent-watch 446 passed, 1 skipped, pipeline 331 passed (slow suite run once).
