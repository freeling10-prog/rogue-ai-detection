# Evaluation (SYNTHETIC data - a regression check, not a benchmark)

Same author wrote the simulator and the detectors; thresholds were set while looking at this simulator. Nothing here is evidence about real-world performance. 'Recall' for the honeypot/state-edge scenarios is a regression check on deterministic logic.

## Evasiveness 0.0: standard injected scenarios
Seeds [0, 1, 2, 3, 4], ~55377 events per run. Fused overall recall range across seeds [0.831, 0.881], FPR range [0.017, 0.05].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 20 | 21 | 0 | 584 | 0.49 | 1.00 | 0.03 |
| exfil | 20 | 21 | 0 | 584 | 0.49 | 1.00 | 0.03 |
| collusion_ring | 40 | 21 | 0 | 584 | 0.66 | 1.00 | 0.03 |
| seq_mimic | 0 | 21 | 20 | 584 | 0.00 | 0.00 | 0.03 |
| proxy_rotation | 50 | 21 | 0 | 584 | 0.70 | 1.00 | 0.03 |
| partner_spoof | 15 | 21 | 0 | 584 | 0.42 | 1.00 | 0.03 |
| redacted_reuse | 20 | 21 | 0 | 584 | 0.49 | 1.00 | 0.03 |
| hp_single | 10 | 21 | 0 | 584 | 0.32 | 1.00 | 0.03 |
| hp_handoff | 30 | 21 | 0 | 584 | 0.59 | 1.00 | 0.03 |
| hp_nolink | 30 | 21 | 0 | 584 | 0.59 | 1.00 | 0.03 |
| routine_tool_hijack | 7 | 21 | 13 | 584 | 0.25 | 0.35 | 0.03 |
| cmdp_padded_prober | 10 | 21 | 10 | 584 | 0.32 | 0.50 | 0.03 |
| overall_core | 80 | 21 | 0 | 584 | 0.79 | 1.00 | 0.03 |
| overall | 252 | 21 | 43 | 584 | 0.92 | 0.85 | 0.03 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | routine_tool_hijack | cmdp_padded_prober | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.30 | 0.40 | 1.00 | 0.67 | 0.03 |
| B. frozen baseline IF, no sequence | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.30 | 0.40 | 1.00 | 0.84 | 0.03 |
| C. frozen baseline + sequence gate (v1.1 default) | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.50 | 1.00 | 0.85 | 0.03 |
| D. = C with identity/allow-listing OFF | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.50 | 1.00 | 0.85 | 0.07 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.90 | 0.50 | 1.00 | 0.89 | 0.03 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.90 | 0.50 | 1.00 | 0.89 | 0.04 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 1.00 | 0.75 | 0.00 | 0.00 | 1.00 | 0.33 | 0.00 | 0.00 | 1.00 | 0.00 | 0.10 | 0.50 | 0.44 | 0.45 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.90 | 0.67 | 0.03 |
| fused_frozen_no_sequence | 0.92 | 0.84 | 0.03 |
| fused_holdout_baseline | 0.93 | 0.89 | 0.03 |
| fused_leads | 0.92 | 0.85 | 0.03 |
| fused_no_gate | 0.91 | 0.89 | 0.04 |
| fused_no_identity | 0.86 | 0.85 | 0.07 |
| fused_strict_gate | 0.92 | 0.45 | 0.02 |
| graph_only | 0.95 | 0.47 | 0.01 |
| graph_without_suppression | 0.54 | 0.47 | 0.19 |
| isolation_forest_batch_only | 0.30 | 0.05 | 0.05 |
| isolation_forest_only | 0.33 | 0.12 | 0.11 |
| rules_only | 0.91 | 0.52 | 0.02 |
| sequence_only | 0.78 | 0.16 | 0.02 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 6 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 6 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 14 / 15 | 0 / 15 |
| permission_drift | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| redaction_user | 7 / 40 | 7 / 40 | 0 / 40 | 7 / 40 | 7 / 40 | 7 / 40 |
| sharded_pool | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 6 | 6 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 1 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | isolation_forest+rule_gate+sequence_model (each redundant) | 20 | 0 |
| positive | cmdp_padded_prober | rule_gate+sequence_model | 8 | 0 |
| positive | cmdp_padded_prober | sequence_model | 2 | 0 |
| positive | collusion_ring | graph:timing_content | 40 | 0 |
| positive | exfil | isolation_forest+rule_gate+sequence_model (each redundant) | 1 | 0 |
| positive | exfil | rule:R1(+2) | 3 | 0 |
| positive | exfil | rule:R1(+3) | 8 | 0 |
| positive | exfil | rule:R2 | 6 | 0 |
| positive | exfil | rule:R2(+1) | 2 | 0 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | rule:R1(+2) | 3 | 0 |
| positive | partner_spoof | rule:R12(+1) | 1 | 0 |
| positive | partner_spoof | rule:R2 | 2 | 0 |
| positive | partner_spoof | rule:R2(+1) | 9 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 14 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 6 | 0 |
| positive | routine_tool_hijack | isolation_forest+rule_gate | 11 | 11 |
| positive | routine_tool_hijack | rule:R12 | 7 | 0 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 605 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 20 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 12 / 15 |

## Evasiveness 0.5: mixed: half of injected scenarios use evasive forms
Seeds [0, 1, 2, 3, 4], ~55715 events per run. Fused overall recall range across seeds [0.593, 0.729], FPR range [0.033, 0.083].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 14 | 31 | 6 | 574 | 0.31 | 0.70 | 0.05 |
| exfil | 9 | 31 | 11 | 574 | 0.23 | 0.45 | 0.05 |
| collusion_ring | 12 | 31 | 28 | 574 | 0.28 | 0.30 | 0.05 |
| seq_mimic | 0 | 31 | 20 | 574 | 0.00 | 0.00 | 0.05 |
| proxy_rotation | 50 | 31 | 0 | 574 | 0.62 | 1.00 | 0.05 |
| partner_spoof | 15 | 31 | 0 | 574 | 0.33 | 1.00 | 0.05 |
| redacted_reuse | 20 | 31 | 0 | 574 | 0.39 | 1.00 | 0.05 |
| hp_single | 10 | 31 | 0 | 574 | 0.24 | 1.00 | 0.05 |
| hp_handoff | 30 | 31 | 0 | 574 | 0.49 | 1.00 | 0.05 |
| hp_nolink | 30 | 31 | 0 | 574 | 0.49 | 1.00 | 0.05 |
| routine_tool_hijack | 3 | 31 | 17 | 574 | 0.09 | 0.15 | 0.05 |
| cmdp_padded_prober | 7 | 31 | 13 | 574 | 0.18 | 0.35 | 0.05 |
| overall_core | 35 | 31 | 45 | 574 | 0.53 | 0.44 | 0.05 |
| overall | 200 | 31 | 95 | 574 | 0.87 | 0.68 | 0.05 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | routine_tool_hijack | cmdp_padded_prober | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.45 | 0.45 | 0.30 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.10 | 0.10 | 0.38 | 0.47 | 0.05 |
| B. frozen baseline IF, no sequence | 0.45 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.10 | 0.10 | 0.38 | 0.64 | 0.05 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.70 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.15 | 0.35 | 0.44 | 0.68 | 0.05 |
| D. = C with identity/allow-listing OFF | 0.70 | 0.45 | 0.30 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.15 | 0.35 | 0.44 | 0.68 | 0.09 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.70 | 0.45 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.30 | 0.35 | 0.54 | 0.72 | 0.05 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 0.70 | 0.45 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.35 | 0.35 | 0.54 | 0.72 | 0.06 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 0.70 | 0.40 | 0.00 | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | 0.00 | 0.05 | 0.35 | 0.28 | 0.41 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.82 | 0.47 | 0.05 |
| fused_frozen_no_sequence | 0.86 | 0.64 | 0.05 |
| fused_holdout_baseline | 0.87 | 0.72 | 0.05 |
| fused_leads | 0.87 | 0.68 | 0.05 |
| fused_no_gate | 0.85 | 0.72 | 0.06 |
| fused_no_identity | 0.79 | 0.68 | 0.09 |
| fused_strict_gate | 0.92 | 0.41 | 0.02 |
| graph_only | 0.88 | 0.41 | 0.03 |
| graph_without_suppression | 0.49 | 0.41 | 0.21 |
| isolation_forest_batch_only | 0.26 | 0.04 | 0.05 |
| isolation_forest_only | 0.24 | 0.07 | 0.12 |
| rules_only | 0.89 | 0.42 | 0.02 |
| sequence_only | 0.75 | 0.14 | 0.02 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 6 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 14 / 15 | 0 / 15 |
| permission_drift | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| redaction_user | 17 / 40 | 17 / 40 | 0 / 40 | 17 / 40 | 17 / 40 | 17 / 40 |
| sharded_pool | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 6 | 6 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 11 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | isolation_forest+rule_gate+sequence_model (each redundant) | 6 | 0 |
| positive | access_prober | rule:R13 | 3 | 0 |
| positive | access_prober | rule:R13(+1) | 1 | 0 |
| positive | access_prober | rule_gate+sequence_model | 4 | 0 |
| positive | cmdp_padded_prober | rule_gate+sequence_model | 6 | 0 |
| positive | cmdp_padded_prober | sequence_model | 1 | 0 |
| positive | collusion_ring | graph:timing_content | 20 | 8 |
| positive | exfil | isolation_forest+rule_gate+sequence_model (each redundant) | 2 | 0 |
| positive | exfil | rule:R1(+3) | 3 | 0 |
| positive | exfil | rule:R2 | 1 | 0 |
| positive | exfil | rule:R2(+1) | 3 | 0 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | rule:R1(+2) | 2 | 0 |
| positive | partner_spoof | rule:R2 | 2 | 0 |
| positive | partner_spoof | rule:R2(+1) | 11 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 8 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 12 | 0 |
| positive | routine_tool_hijack | isolation_forest+rule_gate | 4 | 4 |
| positive | routine_tool_hijack | rule:R12 | 3 | 0 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 605 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 23 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 13 / 15 |

## Evasiveness 1.0: evasive: all injected scenarios use evasive forms (timing-throttled, jittered, baseline-seeded)
Seeds [0, 1, 2, 3, 4], ~54595 events per run. Fused overall recall range across seeds [0.542, 0.593], FPR range [0.025, 0.066].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 12 | 23 | 8 | 582 | 0.34 | 0.60 | 0.04 |
| exfil | 0 | 23 | 20 | 582 | 0.00 | 0.00 | 0.04 |
| collusion_ring | 0 | 23 | 40 | 582 | 0.00 | 0.00 | 0.04 |
| seq_mimic | 0 | 23 | 20 | 582 | 0.00 | 0.00 | 0.04 |
| proxy_rotation | 50 | 23 | 0 | 582 | 0.68 | 1.00 | 0.04 |
| partner_spoof | 15 | 23 | 0 | 582 | 0.39 | 1.00 | 0.04 |
| redacted_reuse | 20 | 23 | 0 | 582 | 0.47 | 1.00 | 0.04 |
| hp_single | 10 | 23 | 0 | 582 | 0.30 | 1.00 | 0.04 |
| hp_handoff | 30 | 23 | 0 | 582 | 0.57 | 1.00 | 0.04 |
| hp_nolink | 30 | 23 | 0 | 582 | 0.57 | 1.00 | 0.04 |
| routine_tool_hijack | 0 | 23 | 20 | 582 | 0.00 | 0.00 | 0.04 |
| cmdp_padded_prober | 0 | 23 | 20 | 582 | 0.00 | 0.00 | 0.04 |
| overall_core | 12 | 23 | 68 | 582 | 0.34 | 0.15 | 0.04 |
| overall | 167 | 23 | 128 | 582 | 0.88 | 0.57 | 0.04 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | routine_tool_hijack | cmdp_padded_prober | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.05 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.01 | 0.36 | 0.04 |
| B. frozen baseline IF, no sequence | 0.05 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.01 | 0.53 | 0.04 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.60 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.15 | 0.57 | 0.04 |
| D. = C with identity/allow-listing OFF | 0.60 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.15 | 0.57 | 0.07 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.60 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.15 | 0.57 | 0.04 |
| F. = C with the v4 corroboration gate OFF (v3 fusion) | 0.60 | 0.05 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0.16 | 0.57 | 0.05 |
| G. = C with the STRICTEST gate (every non-floor lead needs 2 families) | 0.60 | 0.00 | 0.00 | 0.00 | 1.00 | 0.60 | 0.05 | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 0.15 | 0.35 | 0.02 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.82 | 0.36 | 0.04 |
| fused_frozen_no_sequence | 0.87 | 0.53 | 0.04 |
| fused_holdout_baseline | 0.88 | 0.57 | 0.04 |
| fused_leads | 0.88 | 0.57 | 0.04 |
| fused_no_gate | 0.85 | 0.57 | 0.05 |
| fused_no_identity | 0.79 | 0.57 | 0.07 |
| fused_strict_gate | 0.90 | 0.35 | 0.02 |
| graph_only | 0.92 | 0.34 | 0.01 |
| graph_without_suppression | 0.46 | 0.34 | 0.20 |
| isolation_forest_batch_only | 0.11 | 0.01 | 0.06 |
| isolation_forest_only | 0.10 | 0.03 | 0.12 |
| rules_only | 0.87 | 0.33 | 0.02 |
| sequence_only | 0.78 | 0.16 | 0.02 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default (v4 gate) | F gate off (v3) | G strict gate | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| compliance_scanner | 0 / 10 | 6 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| noisy_denied | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 | 0 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 12 / 15 | 0 / 15 |
| permission_drift | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 | 0 / 15 |
| redaction_user | 9 / 40 | 9 / 40 | 0 / 40 | 9 / 40 | 9 / 40 | 9 / 40 |
| sharded_pool | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 | 0 / 25 |
| tool_adopter | 5 / 10 | 5 / 10 | 2 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

### Per-layer attribution of leads (v4; leave-one-out on the fusion, gate-off leads, pooled over seeds)

`layer` = the layer(s) the lead NEEDED (see rogue_pipeline/attribution.py).  'blocked' = the v4 corroboration gate removes it (for benign agents: a false positive removed; for injected scenarios: RECALL LOST).

| population | scenario / benign group | layer | leads without gate | blocked by gate |
|---|---|---|---|---|
| benign | compliance_scanner | isolation_forest+sequence_model | 6 | 6 |
| benign | partner_integration | rule:R3 | 8 | 0 |
| benign | partner_integration | rule:R3(+1) | 1 | 0 |
| benign | redaction_user | graph:shared_redacted_token+timing_content | 3 | 0 |
| benign | redaction_user | graph:timing_content | 6 | 0 |
| benign | tool_adopter | rule:R1(+1) | 3 | 0 |
| benign | tool_adopter | rule:R2 | 2 | 0 |
| positive | access_prober | rule:R13 | 2 | 0 |
| positive | access_prober | rule_gate+sequence_model | 9 | 0 |
| positive | access_prober | sequence_model | 1 | 0 |
| positive | exfil | isolation_forest+sequence_model | 1 | 1 |
| positive | hp_handoff | rule_gate+coordination_graph (each redundant) | 30 | 0 |
| positive | hp_nolink | rule:R6 | 30 | 0 |
| positive | hp_single | rule:R6 | 5 | 0 |
| positive | hp_single | rule:R6(+1) | 5 | 0 |
| positive | partner_spoof | rule:R1(+2) | 4 | 0 |
| positive | partner_spoof | rule:R1(+3) | 1 | 0 |
| positive | partner_spoof | rule:R2 | 1 | 0 |
| positive | partner_spoof | rule:R2(+1) | 9 | 0 |
| positive | proxy_rotation | isolation_forest+coordination_graph | 50 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token | 16 | 0 |
| positive | redacted_reuse | graph:shared_redacted_token+timing_content | 4 | 0 |

### Regression checks (hits / trials, pooled over seeds)

| check | hits / trials |
|---|---|
| hp_handoff pairs joined by a cross_ip_token_handoff edge | 15 / 15 |
| hp_nolink pairs (B did NOT reuse A's token) wrongly joined | 0 / 15 |
| hp_single agents that produced a lead (R6/R7) | 10 / 10 |
| benign agents (ignoring the honeypot protocol) with an R6/R7 flag | 0 / 605 |
| proxy_rotation consecutive session pairs stitched by a shared-state edge | 40 / 40 |
| benign pagination clients (own cursor tokens) wrongly joined | 0 / 30 |
| redacted_reuse pairs joined by a moderate shared_redacted_token edge | 10 / 10 |
| benign agents sharing only a POPULAR redacted marker wrongly joined | 0 / 140 |
| verified/allow-listed partner agents with R3/R4 flag: identity ON | 0 / 25 |
| verified/allow-listed partner agents with R3/R4 flag: identity OFF | 21 / 25 |
| spoofed-identity agents with R3/R4 flag: identity ON (should stay scored) | 14 / 15 |
