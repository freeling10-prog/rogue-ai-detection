# v5 vs v6 on the same synthetic traffic (regression check, NOT a benchmark)

## Core simulator, evasiveness 0.0 (leads / agents, pooled over seeds)

| cohort | kind | v5 | v5_no_gate | v6 | v6_no_gate | v6_strict_gate |
|---|---|---|---|---|---|---|
| access_prober | positive | 18/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| cmdp_padded_prober | positive | 0/20 | 6/20 | 10/20 | 10/20 | 10/20 |
| collusion_ring | positive | 40/40 | 40/40 | 40/40 | 40/40 | 0/40 |
| exfil | positive | 20/20 | 20/20 | 20/20 | 20/20 | 15/20 |
| hp_handoff | positive | 30/30 | 30/30 | 30/30 | 30/30 | 30/30 |
| hp_nolink | positive | 30/30 | 30/30 | 30/30 | 30/30 | 0/30 |
| hp_single | positive | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 |
| partner_spoof | positive | 15/15 | 15/15 | 15/15 | 15/15 | 5/15 |
| proxy_rotation | positive | 50/50 | 50/50 | 50/50 | 50/50 | 50/50 |
| redacted_reuse | positive | 20/20 | 20/20 | 20/20 | 20/20 | 0/20 |
| routine_tool_hijack | positive | 0/20 | 0/20 | 7/20 | 18/20 | 2/20 |
| seq_mimic | positive | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| assistant | benign | 0/300 | 0/300 | 0/300 | 0/300 | 0/300 |
| broadcaster | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| compliance_scanner | benign | 0/10 | 7/10 | 0/10 | 6/10 | 0/10 |
| crawler | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| cron_declared | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| cron_undeclared | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| noisy_denied | benign | 0/10 | 4/10 | 0/10 | 0/10 | 0/10 |
| orchestrator_pool | benign | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 |
| pagination_client | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| partner_integration | benign | 9/10 | 9/10 | 9/10 | 9/10 | 9/10 |
| partner_ipallow | benign | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| partner_verified | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| permission_drift | benign | 0/15 | 2/15 | 0/15 | 0/15 | 0/15 |
| redaction_user | benign | 7/40 | 7/40 | 7/40 | 7/40 | 0/40 |
| sharded_pool | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| tool_adopter | benign | 5/10 | 5/10 | 5/10 | 5/10 | 2/10 |
| **all positive** | | 233/295 (0.790) | 241/295 (0.817) | 252/295 (0.854) | 263/295 (0.892) | 132/295 (0.447) |
| **all benign** | | 21/605 (0.035) | 34/605 (0.056) | 21/605 (0.035) | 27/605 (0.045) | 11/605 (0.018) |

guardrail ok: True; quarantined: 0

### Benign leads of v6 with the gate OFF, attributed

- compliance_scanner | isolation_forest+sequence_model | BLOCKED by gate: 6
- partner_integration | rule:R3 | lead: 8
- partner_integration | rule:R3(+1) | lead: 1
- redaction_user | graph:shared_redacted_token+timing_content | lead: 1
- redaction_user | graph:timing_content | lead: 6
- tool_adopter | rule:R1(+1) | lead: 3
- tool_adopter | rule:R2 | lead: 2

## Core simulator, evasiveness 1.0 (leads / agents, pooled over seeds)

| cohort | kind | v5 | v5_no_gate | v6 | v6_no_gate | v6_strict_gate |
|---|---|---|---|---|---|---|
| access_prober | positive | 0/20 | 5/20 | 12/20 | 12/20 | 12/20 |
| cmdp_padded_prober | positive | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| collusion_ring | positive | 0/40 | 0/40 | 0/40 | 0/40 | 0/40 |
| exfil | positive | 0/20 | 14/20 | 0/20 | 1/20 | 0/20 |
| hp_handoff | positive | 30/30 | 30/30 | 30/30 | 30/30 | 30/30 |
| hp_nolink | positive | 30/30 | 30/30 | 30/30 | 30/30 | 0/30 |
| hp_single | positive | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 |
| partner_spoof | positive | 15/15 | 15/15 | 15/15 | 15/15 | 9/15 |
| proxy_rotation | positive | 50/50 | 50/50 | 50/50 | 50/50 | 50/50 |
| redacted_reuse | positive | 20/20 | 20/20 | 20/20 | 20/20 | 1/20 |
| routine_tool_hijack | positive | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| seq_mimic | positive | 0/20 | 1/20 | 0/20 | 0/20 | 0/20 |
| assistant | benign | 0/300 | 0/300 | 0/300 | 0/300 | 0/300 |
| broadcaster | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| compliance_scanner | benign | 0/10 | 7/10 | 0/10 | 6/10 | 0/10 |
| crawler | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| cron_declared | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| cron_undeclared | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| noisy_denied | benign | 0/10 | 4/10 | 0/10 | 0/10 | 0/10 |
| orchestrator_pool | benign | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 |
| pagination_client | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| partner_integration | benign | 9/10 | 9/10 | 9/10 | 9/10 | 9/10 |
| partner_ipallow | benign | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| partner_verified | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| permission_drift | benign | 0/15 | 2/15 | 0/15 | 0/15 | 0/15 |
| redaction_user | benign | 9/40 | 9/40 | 9/40 | 9/40 | 0/40 |
| sharded_pool | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| tool_adopter | benign | 5/10 | 5/10 | 5/10 | 5/10 | 2/10 |
| **all positive** | | 155/295 (0.525) | 175/295 (0.593) | 167/295 (0.566) | 168/295 (0.569) | 102/295 (0.346) |
| **all benign** | | 23/605 (0.038) | 36/605 (0.060) | 23/605 (0.038) | 29/605 (0.048) | 11/605 (0.018) |

guardrail ok: True; quarantined: 0

### Benign leads of v6 with the gate OFF, attributed

- compliance_scanner | isolation_forest+sequence_model | BLOCKED by gate: 6
- partner_integration | rule:R3 | lead: 8
- partner_integration | rule:R3(+1) | lead: 1
- redaction_user | graph:shared_redacted_token+timing_content | lead: 3
- redaction_user | graph:timing_content | lead: 6
- tool_adopter | rule:R1(+1) | lead: 3
- tool_adopter | rule:R2 | lead: 2
