# Evaluation (SYNTHETIC data - a regression check, not a benchmark)

Same author wrote the simulator and the detectors; thresholds were set while looking at this simulator. Nothing here is evidence about real-world performance. 'Recall' for the honeypot/state-edge scenarios is a regression check on deterministic logic.

## Evasiveness 0.0: standard injected scenarios
Seeds [0, 1, 2, 3, 4], ~52027 events per run. Fused overall recall range across seeds [0.902, 0.922], FPR range [0.018, 0.053].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 18 | 21 | 2 | 544 | 0.46 | 0.90 | 0.04 |
| exfil | 20 | 21 | 0 | 544 | 0.49 | 1.00 | 0.04 |
| collusion_ring | 40 | 21 | 0 | 544 | 0.66 | 1.00 | 0.04 |
| seq_mimic | 0 | 21 | 20 | 544 | 0.00 | 0.00 | 0.04 |
| proxy_rotation | 50 | 21 | 0 | 544 | 0.70 | 1.00 | 0.04 |
| partner_spoof | 15 | 21 | 0 | 544 | 0.42 | 1.00 | 0.04 |
| redacted_reuse | 20 | 21 | 0 | 544 | 0.49 | 1.00 | 0.04 |
| hp_single | 10 | 21 | 0 | 544 | 0.32 | 1.00 | 0.04 |
| hp_handoff | 30 | 21 | 0 | 544 | 0.59 | 1.00 | 0.04 |
| hp_nolink | 30 | 21 | 0 | 544 | 0.59 | 1.00 | 0.04 |
| overall_core | 78 | 21 | 2 | 544 | 0.79 | 0.97 | 0.04 |
| overall | 233 | 21 | 22 | 544 | 0.92 | 0.91 | 0.04 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.90 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.72 | 0.04 |
| B. frozen baseline IF, no sequence | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.91 | 0.04 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.91 | 0.04 |
| D. = C with identity/allow-listing OFF | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.91 | 0.07 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.91 | 0.04 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.92 | 0.06 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 0.90 | 0.75 | 0.00 | 0.00 | 1.00 | 0.40 | 0.00 | 0.00 | 1.00 | 0.00 | 0.41 | 0.47 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.90 | 0.72 | 0.04 |
| fused_frozen_no_sequence | 0.92 | 0.91 | 0.04 |
| fused_holdout_baseline | 0.92 | 0.91 | 0.04 |
| fused_leads | 0.92 | 0.91 | 0.04 |
| fused_no_gate | 0.88 | 0.92 | 0.06 |
| fused_no_identity | 0.85 | 0.91 | 0.07 |
| fused_strict_gate | 0.92 | 0.47 | 0.02 |
| graph_only | 0.95 | 0.55 | 0.01 |
| graph_without_suppression | 0.54 | 0.55 | 0.21 |
| isolation_forest_batch_only | 0.30 | 0.05 | 0.06 |
| isolation_forest_only | 0.33 | 0.13 | 0.12 |
| rules_only | 0.90 | 0.48 | 0.02 |
| sequence_only | 0.63 | 0.13 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 7 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 4 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 6 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 14 / 15 | 0 / 15 |
| redaction_user | 7 / 40 | 7 / 40 | 0 / 40 | 7 / 40 | 7 / 40 | 7 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 7 | 7 |
| benign | noisy_denied | isolation_forest+sequence_model | 4 | 4 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 1 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | isolation_forest+rule_gate+sequence_model (each redundant) | 18 | 0 |
| positive | access_prober | isolation_forest+sequence_model | 2 | 2 |
| positive | collusion_ring | graph:timing_content | 40 | 0 |
| positive | exfil | isolation_forest+rule_gate+sequence_model (each redundant) | 3 | 0 |
| positive | exfil | rule:R1(+2) | 3 | 0 |
| positive | exfil | rule:R1(+3) | 6 | 0 |
| positive | exfil | rule:R2 | 6 | 0 |
| positive | exfil | rule:R2(+1) | 2 | 0 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | isolation_forest+rule_gate+sequence_model (each redundant) | 1 | 0 |
| positive | partner_spoof | rule:R1(+2) | 2 | 0 |
| positive | partner_spoof | rule:R2 | 3 | 0 |
| positive | partner_spoof | rule:R2(+1) | 9 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 14 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 6 | 0 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 565 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 20 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 12 / 15 |

## Evasiveness 0.5: mixed: half of injected scenarios use evasive forms
Seeds [0, 1, 2, 3, 4], ~52289 events per run. Fused overall recall range across seeds [0.667, 0.745], FPR range [0.035, 0.088].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 7 | 31 | 13 | 534 | 0.18 | 0.35 | 0.05 |
| exfil | 9 | 31 | 11 | 534 | 0.23 | 0.45 | 0.05 |
| collusion_ring | 12 | 31 | 28 | 534 | 0.28 | 0.30 | 0.05 |
| seq_mimic | 0 | 31 | 20 | 534 | 0.00 | 0.00 | 0.05 |
| proxy_rotation | 50 | 31 | 0 | 534 | 0.62 | 1.00 | 0.05 |
| partner_spoof | 15 | 31 | 0 | 534 | 0.33 | 1.00 | 0.05 |
| redacted_reuse | 20 | 31 | 0 | 534 | 0.39 | 1.00 | 0.05 |
| hp_single | 10 | 31 | 0 | 534 | 0.24 | 1.00 | 0.05 |
| hp_handoff | 30 | 31 | 0 | 534 | 0.49 | 1.00 | 0.05 |
| hp_nolink | 30 | 31 | 0 | 534 | 0.49 | 1.00 | 0.05 |
| overall_core | 28 | 31 | 52 | 534 | 0.47 | 0.35 | 0.05 |
| overall | 183 | 31 | 72 | 534 | 0.86 | 0.72 | 0.05 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.35 | 0.45 | 0.30 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.52 | 0.05 |
| B. frozen baseline IF, no sequence | 0.35 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.72 | 0.05 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.35 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.72 | 0.05 |
| D. = C with identity/allow-listing OFF | 0.35 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.72 | 0.10 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.35 | 0.45 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.45 | 0.75 | 0.05 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 0.50 | 0.75 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.56 | 0.78 | 0.07 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 0.35 | 0.40 | 0.00 | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | 0.00 | 0.19 | 0.42 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.81 | 0.52 | 0.05 |
| fused_frozen_no_sequence | 0.86 | 0.72 | 0.05 |
| fused_holdout_baseline | 0.86 | 0.75 | 0.05 |
| fused_leads | 0.86 | 0.72 | 0.05 |
| fused_no_gate | 0.83 | 0.78 | 0.07 |
| fused_no_identity | 0.77 | 0.72 | 0.10 |
| fused_strict_gate | 0.91 | 0.42 | 0.02 |
| graph_only | 0.88 | 0.47 | 0.03 |
| graph_without_suppression | 0.49 | 0.47 | 0.22 |
| isolation_forest_batch_only | 0.25 | 0.04 | 0.05 |
| isolation_forest_only | 0.24 | 0.09 | 0.13 |
| rules_only | 0.88 | 0.40 | 0.02 |
| sequence_only | 0.73 | 0.18 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 7 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 4 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 14 / 15 | 0 / 15 |
| redaction_user | 17 / 40 | 17 / 40 | 0 / 40 | 17 / 40 | 17 / 40 | 17 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 7 | 7 |
| benign | noisy_denied | isolation_forest+sequence_model | 4 | 4 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 11 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | isolation_forest+rule_gate+sequence_model (each redundant) | 7 | 0 |
| positive | access_prober | isolation_forest+sequence_model | 3 | 3 |
| positive | collusion_ring | graph:timing_content | 20 | 8 |
| positive | exfil | isolation_forest+rule_gate+sequence_model (each redundant) | 3 | 0 |
| positive | exfil | isolation_forest+sequence_model | 6 | 6 |
| positive | exfil | rule:R1(+3) | 3 | 0 |
| positive | exfil | rule:R2 | 1 | 0 |
| positive | exfil | rule:R2(+1) | 2 | 0 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | isolation_forest+rule_gate+sequence_model (each redundant) | 1 | 0 |
| positive | partner_spoof | rule:R1(+2) | 2 | 0 |
| positive | partner_spoof | rule:R2 | 2 | 0 |
| positive | partner_spoof | rule:R2(+1) | 10 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 8 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 12 | 0 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 565 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 23 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 13 / 15 |

## Evasiveness 1.0: evasive: all injected scenarios use evasive forms (timing-throttled, jittered, baseline-seeded)
Seeds [0, 1, 2, 3, 4], ~51220 events per run. Fused overall recall range across seeds [0.608, 0.608], FPR range [0.027, 0.071].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 0 | 23 | 20 | 542 | 0.00 | 0.00 | 0.04 |
| exfil | 0 | 23 | 20 | 542 | 0.00 | 0.00 | 0.04 |
| collusion_ring | 0 | 23 | 40 | 542 | 0.00 | 0.00 | 0.04 |
| seq_mimic | 0 | 23 | 20 | 542 | 0.00 | 0.00 | 0.04 |
| proxy_rotation | 50 | 23 | 0 | 542 | 0.68 | 1.00 | 0.04 |
| partner_spoof | 15 | 23 | 0 | 542 | 0.39 | 1.00 | 0.04 |
| redacted_reuse | 20 | 23 | 0 | 542 | 0.47 | 1.00 | 0.04 |
| hp_single | 10 | 23 | 0 | 542 | 0.30 | 1.00 | 0.04 |
| hp_handoff | 30 | 23 | 0 | 542 | 0.57 | 1.00 | 0.04 |
| hp_nolink | 30 | 23 | 0 | 542 | 0.57 | 1.00 | 0.04 |
| overall_core | 0 | 23 | 80 | 542 | 0.00 | 0.00 | 0.04 |
| overall | 155 | 23 | 100 | 542 | 0.87 | 0.61 | 0.04 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.00 | 0.00 | 0.00 | 0.00 | 0.02 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.42 | 0.04 |
| B. frozen baseline IF, no sequence | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.61 | 0.04 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.61 | 0.04 |
| D. = C with identity/allow-listing OFF | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.61 | 0.08 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.61 | 0.04 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 0.25 | 0.70 | 0.00 | 0.05 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.24 | 0.69 | 0.06 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.67 | 0.05 | 0.00 | 1.00 | 0.00 | 0.00 | 0.36 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.82 | 0.42 | 0.04 |
| fused_frozen_no_sequence | 0.87 | 0.61 | 0.04 |
| fused_holdout_baseline | 0.87 | 0.61 | 0.04 |
| fused_leads | 0.87 | 0.61 | 0.04 |
| fused_no_gate | 0.84 | 0.69 | 0.06 |
| fused_no_identity | 0.78 | 0.61 | 0.08 |
| fused_strict_gate | 0.89 | 0.36 | 0.02 |
| graph_only | 0.92 | 0.39 | 0.02 |
| graph_without_suppression | 0.46 | 0.39 | 0.21 |
| isolation_forest_batch_only | 0.11 | 0.02 | 0.06 |
| isolation_forest_only | 0.10 | 0.03 | 0.13 |
| rules_only | 0.86 | 0.33 | 0.02 |
| sequence_only | 0.75 | 0.20 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 7 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 4 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 12 / 15 | 0 / 15 |
| redaction_user | 9 / 40 | 9 / 40 | 0 / 40 | 9 / 40 | 9 / 40 | 9 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 7 | 7 |
| benign | noisy_denied | isolation_forest+sequence_model | 4 | 4 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 3 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | isolation_forest+sequence_model | 5 | 5 |
| positive | exfil | isolation_forest+sequence_model | 14 | 14 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | isolation_forest+rule_gate+sequence_model (each redundant) | 3 | 0 |
| positive | partner_spoof | rule:R1(+2) | 3 | 0 |
| positive | partner_spoof | rule:R2 | 1 | 0 |
| positive | partner_spoof | rule:R2(+1) | 8 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 16 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 4 | 0 |
| positive | seq_mimic | isolation_forest+sequence_model | 1 | 1 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 565 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 21 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 14 / 15 |
