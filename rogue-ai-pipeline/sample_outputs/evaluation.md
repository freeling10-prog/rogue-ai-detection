# Evaluation (SYNTHETIC data - a regression check, not a benchmark)

Same author wrote the simulator and the detectors; thresholds were set while looking at this simulator. Nothing here is evidence about real-world performance. 'Recall' for the honeypot/state-edge scenarios is a regression check on deterministic logic.

## Evasiveness 0.0: standard injected scenarios
Seeds [0, 1, 2, 3, 4], ~52027 events per run. Fused overall recall range across seeds [0.922, 0.922], FPR range [0.035, 0.071].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 20 | 32 | 0 | 533 | 0.38 | 1.00 | 0.06 |
| exfil | 20 | 32 | 0 | 533 | 0.38 | 1.00 | 0.06 |
| collusion_ring | 40 | 32 | 0 | 533 | 0.56 | 1.00 | 0.06 |
| seq_mimic | 0 | 32 | 20 | 533 | 0.00 | 0.00 | 0.06 |
| proxy_rotation | 50 | 32 | 0 | 533 | 0.61 | 1.00 | 0.06 |
| partner_spoof | 15 | 32 | 0 | 533 | 0.32 | 1.00 | 0.06 |
| redacted_reuse | 20 | 32 | 0 | 533 | 0.38 | 1.00 | 0.06 |
| hp_single | 10 | 32 | 0 | 533 | 0.24 | 1.00 | 0.06 |
| hp_handoff | 30 | 32 | 0 | 533 | 0.48 | 1.00 | 0.06 |
| hp_nolink | 30 | 32 | 0 | 533 | 0.48 | 1.00 | 0.06 |
| overall_core | 80 | 32 | 0 | 533 | 0.71 | 1.00 | 0.06 |
| overall | 235 | 32 | 20 | 533 | 0.88 | 0.92 | 0.06 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.90 | 1.00 | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.72 | 0.04 |
| B. frozen baseline IF, no sequence | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.97 | 0.91 | 0.04 |
| C. frozen baseline + sequence gate (v1.1 default) | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.92 | 0.06 |
| D. = C with identity/allow-listing OFF | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.92 | 0.09 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.92 | 0.32 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.90 | 0.72 | 0.04 |
| fused_frozen_no_sequence | 0.92 | 0.91 | 0.04 |
| fused_holdout_baseline | 0.56 | 0.92 | 0.32 |
| fused_leads | 0.88 | 0.92 | 0.06 |
| fused_no_identity | 0.82 | 0.92 | 0.09 |
| graph_only | 0.95 | 0.55 | 0.01 |
| graph_without_suppression | 0.54 | 0.55 | 0.21 |
| isolation_forest_batch_only | 0.30 | 0.05 | 0.06 |
| isolation_forest_only | 0.33 | 0.13 | 0.12 |
| rules_only | 0.90 | 0.48 | 0.02 |
| sequence_only | 0.63 | 0.13 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 15 / 15 |
| compliance_scanner | 7 / 10 | 0 / 10 | 7 / 10 | 10 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 25 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| noisy_denied | 4 / 10 | 0 / 10 | 4 / 10 | 8 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 60 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 6 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 14 / 15 | 2 / 15 |
| redaction_user | 7 / 40 | 7 / 40 | 7 / 40 | 7 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

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
Seeds [0, 1, 2, 3, 4], ~52289 events per run. Fused overall recall range across seeds [0.725, 0.863], FPR range [0.053, 0.115].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 10 | 42 | 10 | 523 | 0.19 | 0.50 | 0.07 |
| exfil | 15 | 42 | 5 | 523 | 0.26 | 0.75 | 0.07 |
| collusion_ring | 20 | 42 | 20 | 523 | 0.32 | 0.50 | 0.07 |
| seq_mimic | 0 | 42 | 20 | 523 | 0.00 | 0.00 | 0.07 |
| proxy_rotation | 50 | 42 | 0 | 523 | 0.54 | 1.00 | 0.07 |
| partner_spoof | 15 | 42 | 0 | 523 | 0.26 | 1.00 | 0.07 |
| redacted_reuse | 20 | 42 | 0 | 523 | 0.32 | 1.00 | 0.07 |
| hp_single | 10 | 42 | 0 | 523 | 0.19 | 1.00 | 0.07 |
| hp_handoff | 30 | 42 | 0 | 523 | 0.42 | 1.00 | 0.07 |
| hp_nolink | 30 | 42 | 0 | 523 | 0.42 | 1.00 | 0.07 |
| overall_core | 45 | 42 | 35 | 523 | 0.52 | 0.56 | 0.07 |
| overall | 200 | 42 | 55 | 523 | 0.83 | 0.78 | 0.07 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.35 | 0.45 | 0.50 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.45 | 0.55 | 0.05 |
| B. frozen baseline IF, no sequence | 0.35 | 0.45 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.45 | 0.75 | 0.05 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.50 | 0.75 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.56 | 0.78 | 0.07 |
| D. = C with identity/allow-listing OFF | 0.50 | 0.75 | 0.50 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.56 | 0.78 | 0.12 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.60 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.90 | 0.89 | 0.34 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.82 | 0.55 | 0.05 |
| fused_frozen_no_sequence | 0.86 | 0.75 | 0.05 |
| fused_holdout_baseline | 0.54 | 0.89 | 0.34 |
| fused_leads | 0.83 | 0.78 | 0.07 |
| fused_no_identity | 0.75 | 0.78 | 0.12 |
| graph_only | 0.88 | 0.47 | 0.03 |
| graph_without_suppression | 0.49 | 0.47 | 0.22 |
| isolation_forest_batch_only | 0.25 | 0.04 | 0.05 |
| isolation_forest_only | 0.24 | 0.09 | 0.13 |
| rules_only | 0.88 | 0.40 | 0.02 |
| sequence_only | 0.73 | 0.18 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 15 / 15 |
| compliance_scanner | 7 / 10 | 0 / 10 | 7 / 10 | 10 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 25 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| noisy_denied | 4 / 10 | 0 / 10 | 4 / 10 | 8 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 60 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 14 / 15 | 1 / 15 |
| redaction_user | 17 / 40 | 17 / 40 | 17 / 40 | 17 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

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
Seeds [0, 1, 2, 3, 4], ~51220 events per run. Fused overall recall range across seeds [0.647, 0.725], FPR range [0.044, 0.088].

### Fused pipeline (leads), pooled over seeds

| scenario | TP | FP | FN | TN | precision | recall | FPR |
|---|---|---|---|---|---|---|---|
| access_prober | 5 | 34 | 15 | 531 | 0.13 | 0.25 | 0.06 |
| exfil | 14 | 34 | 6 | 531 | 0.29 | 0.70 | 0.06 |
| collusion_ring | 0 | 34 | 40 | 531 | 0.00 | 0.00 | 0.06 |
| seq_mimic | 1 | 34 | 19 | 531 | 0.03 | 0.05 | 0.06 |
| proxy_rotation | 50 | 34 | 0 | 531 | 0.60 | 1.00 | 0.06 |
| partner_spoof | 15 | 34 | 0 | 531 | 0.31 | 1.00 | 0.06 |
| redacted_reuse | 20 | 34 | 0 | 531 | 0.37 | 1.00 | 0.06 |
| hp_single | 10 | 34 | 0 | 531 | 0.23 | 1.00 | 0.06 |
| hp_handoff | 30 | 34 | 0 | 531 | 0.47 | 1.00 | 0.06 |
| hp_nolink | 30 | 34 | 0 | 531 | 0.47 | 1.00 | 0.06 |
| overall_core | 19 | 34 | 61 | 531 | 0.36 | 0.24 | 0.06 |
| overall | 175 | 34 | 80 | 531 | 0.84 | 0.69 | 0.06 |

### Before / after (recall per scenario; FPR over ALL benign agents)

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | partner_spoof | redacted_reuse | hp_single | hp_handoff | hp_nolink | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style fusion) | 0.00 | 0.00 | 0.00 | 0.00 | 0.02 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.42 | 0.04 |
| B. frozen baseline IF, no sequence | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.61 | 0.04 |
| C. frozen baseline + sequence gate (v1.1 default) | 0.25 | 0.70 | 0.00 | 0.05 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.24 | 0.69 | 0.06 |
| D. = C with identity/allow-listing OFF | 0.25 | 0.70 | 0.00 | 0.05 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.24 | 0.69 | 0.10 |
| E. = C but baseline trained WITHOUT crawlers/scanners/cron/orchestrators/broadcasters | 0.40 | 1.00 | 1.00 | 0.15 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.85 | 0.89 | 0.32 |

### Ablation (overall, agent-level)

| predictor | precision | recall | FPR |
|---|---|---|---|
| fused_batch_no_sequence | 0.82 | 0.42 | 0.04 |
| fused_frozen_no_sequence | 0.87 | 0.61 | 0.04 |
| fused_holdout_baseline | 0.56 | 0.89 | 0.32 |
| fused_leads | 0.84 | 0.69 | 0.06 |
| fused_no_identity | 0.76 | 0.69 | 0.10 |
| graph_only | 0.92 | 0.39 | 0.02 |
| graph_without_suppression | 0.46 | 0.39 | 0.21 |
| isolation_forest_batch_only | 0.11 | 0.02 | 0.06 |
| isolation_forest_only | 0.10 | 0.03 | 0.13 |
| rules_only | 0.86 | 0.33 | 0.02 |
| sequence_only | 0.75 | 0.20 | 0.03 |

### Hard negatives: benign groups that produced a lead (leads / agents)

| benign group | C default | B no sequence | D no identity | E held-out baseline |
|---|---|---|---|---|
| assistant | 0 / 300 | 0 / 300 | 0 / 300 | 0 / 300 |
| broadcaster | 0 / 15 | 0 / 15 | 0 / 15 | 15 / 15 |
| compliance_scanner | 7 / 10 | 0 / 10 | 7 / 10 | 10 / 10 |
| crawler | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| cron_declared | 0 / 25 | 0 / 25 | 0 / 25 | 25 / 25 |
| cron_undeclared | 0 / 20 | 0 / 20 | 0 / 20 | 20 / 20 |
| noisy_denied | 4 / 10 | 0 / 10 | 4 / 10 | 8 / 10 |
| orchestrator_pool | 0 / 60 | 0 / 60 | 0 / 60 | 60 / 60 |
| pagination_client | 0 / 20 | 0 / 20 | 0 / 20 | 0 / 20 |
| partner_integration | 9 / 10 | 9 / 10 | 9 / 10 | 9 / 10 |
| partner_ipallow | 0 / 10 | 0 / 10 | 9 / 10 | 0 / 10 |
| partner_verified | 0 / 15 | 0 / 15 | 12 / 15 | 0 / 15 |
| redaction_user | 9 / 40 | 9 / 40 | 9 / 40 | 9 / 40 |
| tool_adopter | 5 / 10 | 5 / 10 | 5 / 10 | 5 / 10 |

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
