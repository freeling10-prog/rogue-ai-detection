# v6 "Deep-Cover & Frontier Evasion": combined changes (agent-watch + rogue-ai-pipeline)

> **Read this first.** Every number in this document comes from **same-author synthetic regression cohorts**: the same author wrote the
> simulated clients, the traps/detectors, and tuned the thresholds. These are regression checks that the code does what it was designed
> to do. They are **not benchmarks** and are **not evidence of real-world efficacy**. No real VLM / computer-use agent, stealth browser,
> extension or swarm was tested.
>
> **Honeypot or decoy contact does not mean intent.** Crawlers, curious people, pasted links and misconfigured clients touch decoys.
> Every lead is `severity=low`, `recommended_action=human_review`, `automatic_action=none`; nothing auto-blocks or revokes credentials.

Merged from `v6-aw-changes.md` (agent-watch) and `v6-pipeline-changes.md` (rogue-ai-pipeline). Event contract: `v6-event-contract.md`.

## Summary
* **agent-watch** adds a challenge-bound JS beacon (proof + five kinematic/automation booleans), a DOM-visual inversion trap, load-bearing
  cursors (`prov.html.*` / `prov.schema.*`), R14 parasitic-session-fork detection, a static-refusal `POST /v1/chat/completions`
  LLMjacking decoy, CSP on honeypot HTML, LRU rate maps, and v6 simulator cohorts. Still 127.0.0.1 by default, zero outbound network,
  deterministic scrubbing (PR #4 unicode decode sync, dict-key redaction).
* **rogue-ai-pipeline** ingests the v6 contract (strict schema), rewrites R11 into strong/weak/corroborate tiers, extends R10, adds R12
  `routine_tool_hijack`, R13 `slow_or_shielded_probing` (CUSUM + windows + sub-window collapse), R14, two new graph edges
  (`disjoint_target_partition`, `epistemic_discovery_inheritance`), a rule-family gate, and STIX `x_rogue_v6_detections`.
* Headline (synthetic): agent-watch human alerts 15/75 → **0/75**; pipeline web FPR 0.068 → **0.024**, core standard FPR 0.035 (= v5),
  all-evasive core recall 0/80 → 12/80. Two documented regressions (`mimic_assets`, `mimic_linked_nosec` in the pipeline).

## v5 → v6 tables
### agent-watch: v5 vs v6 per cohort (`scripts/eval_v6.py`, seeds 7-11, n=15 per cohort, same v6 client population against each tree's own honeypot and detectors)
"Alerted" means severity ≥ medium.

| cohort | truth | n | v5 alerted | v6 alerted | v5 label correct | v6 label correct | v5 labels | v6 labels |
|---|---|---|---|---|---|---|---|---|
| human | human | 15 | 0 | 0 | 15 | 15 | human 15 | human 15 |
| human_no_assets | human | 15 | 0 | 0 | 15 | 15 | human 15 | human 15 |
| human_images_blocked | human | 15 | 0 | 0 | 15 | 15 | human 15 | human 15 |
| human_js_off | human | 15 | 0 | 0 | 15 | 15 | human 15 | human 15 |
| human_beacon_blocked | human | 15 | **15** | **0** | 15 | 15 | human 15 | human 15 |
| scraper_naive | static_bot | 10 | 10 | 10 | 10 | 10 | static_bot 10 | static_bot 10 |
| crawler_declared | static_bot | 5 | 5 | 5 | 5 | 5 | static_bot 5 | static_bot 5 |
| mimic_basic | agent | 15 | 15 | 15 | 15 | 15 | agent 15 | agent 15 |
| mimic_linked | agent | 15 | 15 | 15 | 0 | 0 | static_bot 4 / human 11 | static_bot 11 / human 4 |
| mimic_assets | agent | 15 | 15 | 15 | 0 | 15 | human 15 | agent 15 |
| mimic_schema | agent | 15 | 15 | 15 | 15 | 15 | agent 15 | agent 15 |
| mimic_browser_stealth | agent | 15 | 0 | 15 | 0 | 15 | human 15 | agent 15 |
| mimic_browser_webdriver | agent | 15 | 15 | 15 | 15 | 15 | agent 15 | agent 15 |
| mimic_aria | agent | 15 | 15 | 15 | 15 | 15 | agent 15 | agent 15 |
| mimic_header_forger | agent | 15 | 0 | 15 | 0 | 15 | human 15 | agent 15 |
| mimic_vlm_os | agent | 15 | 0 | 15 | 0 | 15 | human 15 | agent 15 |
| mimic_schema_sanitizer | agent | 15 | 15 | 15 | 0 | 15 | human 15 | agent 15 |
| mimic_parasitic_rider | agent | 15 | 0 | 15 | 0 | 15 | human 15 | agent 15 |

Legacy (non-web) synthetic actors: 100/100 correct labels in both v5 and v6.

**Human false positives (alerted ≥ medium):**

| cohort | v5 | v6 |
|---|---|---|
| beacon_blocked humans | 15/15 | 0/15 |
| no_asset humans | 0/15 | 0/15 |
| js_off humans | 0/15 | 0/15 |
| all humans | 15/75 | 0/75 |

None of the humans got a 400 in v6; a test also crawls every clickable link.

Notes:
* The v5 column uses the **v6 clients**: for example, the header forger now posts a canned beacon and humans read in visual order.
  It therefore differs slightly from the numbers published in `v5-changes.md`.
* `mimic_schema_sanitizer` was already alerted in v5 (unlinked jumps) but labelled human.
* Other evals:
  - `scripts/eval_v4.py --v2-tree <v5 snapshot>`, 5 seeds: the v5 tree *without the mirror* alerts on 18.2 % of mimics, while v6 with
    the mirror alerts on 100 %. Humans are 0/75 in both. Legacy label accuracy is 1.0.
  - `scripts/eval_v3.py --old-tree <v5 snapshot>`, seeds 7-11 each: C4 (v6 full) gives mimic label-agent recall 0.75 (mimic_linked
    stays possible_mimic), alerted 1.0, human alert FPR 0.0 on every seed. C1 (v5 logs+leads, no mirror) is 0.25 / 0.25.

### rogue-ai-pipeline: v5 vs v6 per cohort (leads / agents, pooled over seeds 0–4, same traffic for both trees)
#### Web (40 benign background assistants + every web cohort per seed)
| cohort | kind | v5 | v6 | v6 gate off | v6 strict gate |
|---|---|---|---|---|---|
| mimic_header_forger | positive | 0/15 | **10/15** | 10/15 | 10/15 |
| mimic_browser_stealth | positive | 0/15 | **10/15** | 10/15 | 10/15 |
| mimic_vlm_os | positive | 0/15 | **11/15** | 11/15 | 11/15 |
| mimic_schema_sanitizer | positive | 0/15 | 5/15 | 5/15 | 5/15 |
| mimic_parasitic_rider | positive | 6/15 | **11/15** | 11/15 | 10/15 |
| swarm_schelling_overlap | positive | 17/30 | 20/30 | 28/30 | 20/30 |
| swarm_disjoint_partition | positive | 0/15 | **15/15** | 15/15 | 0/15 |
| llmjacking_prober | positive | 0/10 | **10/10** | 10/10 | 10/10 |
| mimic_assets | positive | 15/15 | **0/15** (regression) | 0/15 | 0/15 |
| mimic_linked_nosec | positive | 15/15 | **0/15** (regression) | 0/15 | 0/15 |
| mimic_basic / mimic_linked / mimic_schema | positive | 45/45 | 45/45 | 45/45 | 15/45 |
| mimic_browser_webdriver / mimic_aria | positive | 30/30 | 30/30 | 30/30 | 30/30 |
| mcp_agent / decoy_explorer / scanner_ua_spoof | positive | 25/25 | 25/25 | 25/25 | 25/25 |
| **human_beacon_blocked** | benign | **15/15** | **0/15** | 0/15 | 0/15 |
| **human_no_assets_nosec** | benign | **10/10** | **0/10** | 0/10 | 0/10 |
| **human_js_off** | benign | 0/15 | 0/15 | 0/15 | 0/15 |
| web_human_no_assets | benign | 0/20 | 0/20 | 0/20 | 0/20 |
| web_human / images_blocked / kb_reader | benign | 0/75 | 0/75 | 0/75 | 0/75 |
| human_accessibility / flaky_network / two_tabs | benign | 0/45 | 0/45 | 0/45 | 0/45 |
| slow_legit_crawler | benign | 0/15 | 0/15 | 0/15 | 0/15 |
| background benign assistants | benign | 14/380 | 14/380 | 14/380 | 6/380 |
| commodity_scanner (pre-filtered) / accidental_scraper | other | 0/40, 15/15 | 0/40, 15/15 | | |
| **all positive** | | 153/260 (0.588) | **192/260 (0.738)** | 200/260 | 146/260 |
| **all benign (web FPR)** | | 39/575 (0.068) | **14/575 (0.024)** | 14/575 | 6/575 |

#### Core simulator (60 assistants + hard negatives + all scenarios incl. v6; identity, frozen baseline, sequence gate)
| cohort | v5 std | v6 std | v6 std gate off | v5 all-evasive | v6 all-evasive |
|---|---|---|---|---|---|
| access_prober | 18/20 | 20/20 | 20/20 | 0/20 | **12/20** |
| exfil | 20/20 | 20/20 | 20/20 | 0/20 | 0/20 |
| collusion_ring | 40/40 | 40/40 | 40/40 | 0/40 | 0/40 |
| **core 3 scenarios** | 78/80 | 80/80 | 80/80 | **0/80** | **12/80 (0.15)** |
| routine_tool_hijack (new) | 0/20 | **7/20** | 18/20 | 0/20 | 0/20 |
| cmdp_padded_prober (new) | 0/20 | **10/20** | 10/20 | 0/20 | 0/20 |
| proxy_rotation | 50/50 | 50/50 | 50/50 | 50/50 | 50/50 |
| seq_mimic | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| partner_spoof / redacted_reuse / hp_* | 105/105 | 105/105 | 105/105 | 105/105 | 105/105 |
| permission_drift (benign) | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| sharded_pool (benign, declared) | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| compliance_scanner / noisy_denied (benign) | 0/20 | 0/20 | 6/20 | 0/20 | 0/20 |
| partner_integration / tool_adopter / redaction_user (benign) | 21/60 | 21/60 | 21/60 | 23/60 | 23/60 |
| cron, orchestrator, crawler, broadcaster, pager, assistants, … | 0/485 | 0/485 | 0/485 | 0/485 | 0/485 |
| **all positive** | 233/295 (0.790) | **252/295 (0.854)** | 263/295 | 155/295 (0.525) | 167/295 (0.566) |
| **all benign: standard FPR** | **21/605 (0.035)** | **21/605 (0.035)** | 27/605 (0.045) | 23/605 (0.038) | 23/605 (0.038) |

**Target check:** the standard FPR target is ≤ 0.04, and **v6 gives 0.035**. That equals v5: no new benign lead anywhere in the core
harness, and web FPR fell from 0.068 to 0.024. All-evasive core recall rose from 0/80 to 12/80, all of it `access_prober` via R13. Evasive
exfil and the paraphrased/jittered ring are still 0. The **target is met for FPR**. "Restore recall on stealth / all-evasive" is only
**partially** met.

#### `run.py evaluate --seeds 5`, each tree on its own harness data
v5 data has no v6 cohorts: 565 benign. v6 data adds them: 605 benign, and 40 more positives in the denominator.

| level | v5 overall recall | v5 core recall | v5 FPR | v6 overall recall | v6 core recall | v6 FPR |
|---|---|---|---|---|---|---|
| 0.0 standard | 0.914 | 0.975 (78/80) | **0.037** (21/565) | 0.854 | 1.000 (80/80) | **0.035** (21/605) |
| 0.5 mixed | 0.718 | 0.350 (28/80) | 0.055 (31/565) | 0.678 | 0.438 (35/80) | 0.051 (31/605) |
| 1.0 all evasive | 0.608 | **0.000** (0/80) | 0.041 (23/565) | 0.566 | **0.150** (12/80) | 0.038 (23/605) |

* Guardrails: OK at every level in both trees.
* v6 overall recall is lower only because the denominator now includes the new hard cohorts (hijack 7/20, CMDP 10/20 at standard).
* The **mixed (0.5) level is above 0.04 FPR in both trees** (0.055 → 0.051). This comes from the same pre-existing
  redaction_user / partner / adopter leads, not from a v6 rule.
* Full outputs: `docs/eval-v6/run_evaluate_v6.md`, `run_evaluate_v5_snapshot.md`.

### Per-layer FP attribution and gate trade-offs
* **Core, v6 with the gate off, benign leads by the layer that was necessary:**
  - `partner_integration` rule:R3 (9)
  - `redaction_user` graph:timing_content (6) and shared_redacted_token+timing (1–3)
  - `tool_adopter` rule:R1/R2 (5)
  - `compliance_scanner` isolation_forest+sequence (6, **blocked by the gate**)

  None of these comes from R12, R13, R14 or the new edges: the v6 rules add **zero** benign leads with the gate on, and the new benign
  cohorts (drift, sharded pool) are 0. The remaining 21 standard FPs are the same v5 FPs (partner first contact, adopter tool, redaction
  timing clusters).
* **Web, v6 with the gate off:** the benign leads are background R1/R2/R3 (14). Web humans: 0.
* **Gate trade-offs:**
  - **R12** at 0.6 is below `rule_solo_min` 0.65, so **11 of 18** gate-off hijack leads are blocked; only multi-episode or
    jump+chain hijacks pass. Raising chain strength to 0.65 would recover most of them. In a 10-seed scan R12 flagged 3 benign agents
    (2 `argument_jump` at 0.55 on ordinary assistants, 1 chain on a compliance scanner), so this would add roughly 0.1–0.2 FP per seed.
    The default was kept conservative.
  - **Inheritance edges** alone (0.75–0.95) are blocked when the cluster mean is below 0.8: 8/30 Schelling members.
  - **Strict gate** (`rule_solo_min = graph_solo_min = 1.01`): disjoint partition 0/15, hijack 2/20, ring and honeypot scenarios 0,
    but benign FPR drops to 0.018 (core) / 0.010 (web).

## Human false positives: beacon-blocked, no-asset and js-off humans
| cohort | agent-watch v5 | agent-watch v6 | pipeline v5 | pipeline v6 |
|---|---|---|---|---|
| beacon-blocked humans | 15/15 | **0/15** | 15/15 | **0/15** |
| no-asset humans | 0/15 | 0/15 | `human_no_assets_nosec` 10/10; `web_human_no_assets` 0/20 | **0/10**; 0/20 |
| js-off humans | 0/15 | 0/15 | 0/15 | 0/15 |

The v4 `beacon_missing` / `no_render_no_beacon` reasons were replaced by `script_fetched_but_unexecuted`, which is exempt when
`js_assets_fetched == 0` and for coherent navigation headers with no decoy contact. No v6 human received a 400 from the cursor routes.

## Deliberate deviations and trade-offs
* **CSP adds `'self'` to `script-src`.** Without it compliant browsers would not load `/static/site.js`, `js_assets_fetched` would be 0
  for everyone and the asset-kind rules would break. The inline beacon still works (inline script + same-origin fetch via `default-src 'self'`).
* **Inversion hit is advisory unless corroborated** (context-only lead in agent-watch; `corroborate` tier, strength 0.45, no floor, never a
  lead alone in the pipeline). Strong only with JS fetched **and** a beacon lacking pointer+press kinematics, or a forged beacon.
  **Bare missing cursor is advisory**: never creates a flag, only strengthens an existing R9. `/api/v1/status` stays cursor-free.
* **24 h proof window.** Proofs are accepted up to 24 h so stale tabs (e.g. 3 h) aren't flagged as forged; cost: a proof replayed from the
  same page within 24 h passes. Proof-less legacy beacons count as arrived, not forged.
* **`mimic_assets` / `mimic_linked_nosec` regression (pipeline 15/15 → 0/15 each).** In v4-format evidence they are indistinguishable from
  the beacon-blocked / no-asset humans whose FPs v6 removed. agent-watch still catches `mimic_assets` via the beacon and inversion trap
  (0 → 15 correct labels there). Accepted deliberately; tests moved to "documented regressions".
* **Declared `sharded_pool` kept out of the frozen baseline** (`V6_REFERENCE_EXCLUDE`). Including it dropped proxy_rotation 50/50 → 12/50
  (Isolation Forest learned short read-only sessions as normal). It stays in test data as a hard negative (0/25). Shows proxy_rotation
  recall depends on baseline composition.
* **R13 calibrated on benign data only** (`scripts/calibrate_r13.py`, 386 synthetic benign sessions, seeds 1000–1002, 1.25× margin; a test
  checks no attack cohort is read). p0 0.05, h 4.0, small-shift h 2.6, W3/W7 3/3, collapse 0.6.
* **Gate holds back R12.** R12 chain strength 0.6 < `rule_solo_min` 0.65, so 11/18 gate-off hijack leads are blocked (7/20 with gate vs
  18/20 off). Raising to 0.65 would recover most but add ~0.1–0.2 benign FP per seed (10-seed scan: 3 benign R12 flags). Kept conservative.

## Regressions and documented misses (pipeline)
* `mimic_assets` (fetches JS, coherent headers, no beacon) and `mimic_linked_nosec` went from 15/15 to **0/15** each. In v4-format
  evidence they look exactly like the beacon-blocked / no-asset humans whose FPs v6 removed. In the agent-watch v6 collector they are
  caught by the challenge-bound beacon and the inversion trap, which the pipeline only sees as corroborating context. In this
  simulator's v6 view they do not hit the inversion link, so they evade.
* `mimic_schema_sanitizer` 5/15: only the variant that keeps the schema cursor while browsing is caught. Variants that strip the cursor
  or use HTML only produce advisory missing-cursor requests, which by contract are not evidence.
* `mimic_header_forger`, `mimic_browser_stealth` and `mimic_vlm_os` are each 10–11/15. The missing 1/3 are the variants built to evade:
  a forger that posts no beacon, a stealth client that doesn't take the inversion link, and a humanized VLM.
* `cmdp_padded_prober` at the evasive rate (2–3.5 %, at the benign 99th percentile) is **0/20**. The CUSUM is calibrated so that no
  benign session alarms, so a prober that stays inside the benign tail is not separable *by construction*. The spacing constraint also
  defeats W=3/W=7 by construction.
* `routine_tool_hijack` evasive (payloads chunked under 2.5×; ≥4 padding steps between the sensitive read and the send) is **0/20**.
* `seq_mimic`, evasive exfil and the evasive collusion ring are still 0. v6 doesn't address them.

## Tests and typing
| | tests | mypy |
|---|---|---|
| agent-watch | **492 passed, 1 skipped** (v5: 446 passed, 1 skipped); 46 new in `tests/test_v6.py` | `agentwatch`: 26 errors in 10 files, identical set to the v5 snapshot in the same venv (26th is the environment-dependent gunicorn.glogging stubs note); no new errors |
| rogue-ai-pipeline | **384 passed, 0 failed** (v5 snapshot: 331); 53 new in `tests/test_v6_pipeline.py` | `mypy rogue_pipeline run.py`: Success, no issues in 28 source files |

Existing tests changed deliberately carry a `v6 (deliberate edit)` comment. STIX output passes pinned `stix2-validator` 3.2.0.

## Caveats (unmeasured)
* **Same author / synthetic only** — see the note at the top. Catching these cohorts is expected by construction.
* **Honeypot contact ≠ intent.** All leads are for human review.

### agent-watch
* **Same author.** The v6 cohorts and the v6 traps were written by the same author. Catching them is expected by construction and is
  **not evidence of real-world efficacy**.
* **Real VLM agents** may scroll with momentum and click with human-like timing, and then pass. Nothing was tested against a real
  computer-use agent.
* **Real stealth browsers** (for example patched Chromium) can click in visual order and run our script, and then pass.
  - A client that re-implements the script (parses the meta tag and probe style) forges a valid proof.
  - A proof replayed from the same page within 24 h passes.
* **Real parasitic extensions** may act outside the 500 ms window or only along linked paths (FN). Browser prefetch, a fast
  double-open or a new tab that lands in the window could create an FP.
* **Timing jitter on real devices** has not been measured.
* **Mobile touch kinematics:** touch produces near-instant compatibility mousedown/up, so `kinematic_dwell_ok=false`. Touch scrolling
  sends no wheel events, so `inertial_scroll_ok` stays true and the VLM rule should not fire. This is untested on real phones.
* **Notched mouse wheels:** constant deltas read as `inertial_scroll_ok=false`. A user who scrolls that way and activates links by
  keyboard could look VLM-quantized.
* **Accessibility tools** (switch access, voice control, screen readers, keyboard-only users) produce instant activations with no
  pointer path, which may look like VLM/quantized input.
* **Other FP paths:**
  - A curious person whose beacon is blocked and who clicks the footer "Diagnostic archive" link reads as DOM-order iteration.
  - A person who pastes a link from `/llms.txt` carries a schema cursor.
  - Sessions are IP + UA, so NAT can merge a person and an unrelated agent into an apparent "fork".

### rogue-ai-pipeline
* **Real VLM / computer-use agents** were never run. Momentum scrolling and human-like dwell pass `vlm_quantized_interaction`. In the
  other direction, keyboard and switch-access users, notched-wheel mice and touch input could look quantized. The pipeline requires a
  pointer trail for VLM, which lowers the keyboard-user risk but is itself an assumption about agent-watch's beacon on real devices.
* **CMDP adaptation to CUSUM:** an adaptive controller that knows p0/h can hold its probe rate under p0 indefinitely and evade. Only
  fixed-policy padded probers were simulated.
* **Real swarms:** sub-agents with independent reading, partial overlap, or partition over several families may pass the
  hypergeometric/coverage tests. Benign shard pools that are **not declared** in policy would be flagged by the same edge.
* **Real hijacks:** argument entropy is simulated. Real tool arguments (JSON, base64 attachments) may have very different
  length/entropy baselines, and partner first-contacts already cause R3 FPs.
* **Synthetic calibration:** R13 thresholds come from 386 synthetic benign sessions (3 seeds) with a 1.25× margin. Real benign traffic
  (retry storms, security scanners with credentials, misconfigured clients) needs its own calibration with `scripts/calibrate_r13.py`
  on frozen benign data.
* **Session identity:** sessions are IP+UA, so NAT can merge a person and an agent into an apparent R14 fork. Browser prefetch inside
  500 ms is untested.
* **ATLAS names:** AML.T0080 ("AI Agent Context Poisoning") and AML.T0118 ("Autonomous AI Agent Communication") were copied from
  agent-watch and **not verified** against the live ATLAS site, because there is no network. The mapping stays marked approximate.
