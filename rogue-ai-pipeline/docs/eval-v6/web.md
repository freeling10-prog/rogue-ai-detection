# v5 vs v6 on the same synthetic traffic (regression check, NOT a benchmark)

## Web cohorts (leads / agents, pooled over seeds)

| cohort | kind | v5 | v5_no_gate | v6 | v6_no_gate | v6_strict_gate |
|---|---|---|---|---|---|---|
| decoy_explorer | positive | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 |
| llmjacking_prober | positive | 0/10 | 0/10 | 10/10 | 10/10 | 10/10 |
| mcp_agent | positive | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 |
| mimic_aria | positive | 15/15 | 15/15 | 15/15 | 15/15 | 15/15 |
| mimic_assets | positive | 15/15 | 15/15 | 0/15 | 0/15 | 0/15 |
| mimic_basic | positive | 15/15 | 15/15 | 15/15 | 15/15 | 0/15 |
| mimic_browser_stealth | positive | 0/15 | 0/15 | 10/15 | 10/15 | 10/15 |
| mimic_browser_webdriver | positive | 15/15 | 15/15 | 15/15 | 15/15 | 15/15 |
| mimic_header_forger | positive | 0/15 | 0/15 | 10/15 | 10/15 | 10/15 |
| mimic_linked | positive | 15/15 | 15/15 | 15/15 | 15/15 | 0/15 |
| mimic_linked_nosec | positive | 15/15 | 15/15 | 0/15 | 0/15 | 0/15 |
| mimic_parasitic_rider | positive | 6/15 | 6/15 | 11/15 | 11/15 | 10/15 |
| mimic_schema | positive | 15/15 | 15/15 | 15/15 | 15/15 | 15/15 |
| mimic_schema_sanitizer | positive | 0/15 | 0/15 | 5/15 | 5/15 | 5/15 |
| mimic_vlm_os | positive | 0/15 | 0/15 | 11/15 | 11/15 | 11/15 |
| scanner_ua_spoof | positive | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| swarm_disjoint_partition | positive | 0/15 | 0/15 | 15/15 | 15/15 | 0/15 |
| swarm_schelling_overlap | positive | 17/30 | 17/30 | 20/30 | 28/30 | 20/30 |
| accidental_scraper | accidental | 15/15 | 15/15 | 15/15 | 15/15 | 15/15 |
| background_benign | benign | 14/380 | 14/380 | 14/380 | 14/380 | 6/380 |
| commodity_scanner | scanner | 0/40 | 0/40 | 0/40 | 0/40 | 0/40 |
| human_accessibility | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| human_beacon_blocked | benign | 15/15 | 15/15 | 0/15 | 0/15 | 0/15 |
| human_flaky_network | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| human_images_blocked | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| human_js_off | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| human_kb_reader | benign | 0/30 | 0/30 | 0/30 | 0/30 | 0/30 |
| human_no_assets_nosec | benign | 10/10 | 10/10 | 0/10 | 0/10 | 0/10 |
| human_two_tabs | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| slow_legit_crawler | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| web_human | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| web_human_no_assets | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| **all positive** | | 153/260 (0.588) | 153/260 (0.588) | 192/260 (0.738) | 200/260 (0.769) | 146/260 (0.562) |
| **all benign** | | 39/575 (0.068) | 39/575 (0.068) | 14/575 (0.024) | 14/575 (0.024) | 6/575 (0.010) |

quarantined (all runs): 0

### Benign leads of v6 with the gate OFF, attributed (necessary layer)

- background_benign | rule:R1(+1) | lead: 4
- background_benign | rule:R2 | lead: 1
- background_benign | rule:R3 | lead: 9

### Positives the v6 gate blocked

- swarm_schelling_overlap | graph:epistemic_discovery_inheritance: 8

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
| proxy_rotation | positive | 50/50 | 50/50 | 12/50 | 22/50 | 12/50 |
| redacted_reuse | positive | 20/20 | 20/20 | 20/20 | 20/20 | 0/20 |
| routine_tool_hijack | positive | 0/20 | 0/20 | 10/20 | 19/20 | 5/20 |
| seq_mimic | positive | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| assistant | benign | 0/300 | 0/300 | 0/300 | 0/300 | 0/300 |
| broadcaster | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| compliance_scanner | benign | 0/10 | 7/10 | 0/10 | 7/10 | 0/10 |
| crawler | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| cron_declared | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| cron_undeclared | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| noisy_denied | benign | 0/10 | 4/10 | 0/10 | 3/10 | 0/10 |
| orchestrator_pool | benign | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 |
| pagination_client | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| partner_integration | benign | 9/10 | 9/10 | 9/10 | 9/10 | 9/10 |
| partner_ipallow | benign | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| partner_verified | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| permission_drift | benign | 0/15 | 2/15 | 0/15 | 0/15 | 0/15 |
| redaction_user | benign | 7/40 | 7/40 | 7/40 | 7/40 | 0/40 |
| sharded_pool | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| tool_adopter | benign | 5/10 | 5/10 | 5/10 | 5/10 | 2/10 |
| **all positive** | | 233/295 (0.790) | 241/295 (0.817) | 217/295 (0.736) | 236/295 (0.800) | 97/295 (0.329) |
| **all benign** | | 21/605 (0.035) | 34/605 (0.056) | 21/605 (0.035) | 31/605 (0.051) | 11/605 (0.018) |

guardrail ok: True; quarantined: 0

### Benign leads of v6 with the gate OFF, attributed

- compliance_scanner | isolation_forest+sequence_model | BLOCKED by gate: 7
- noisy_denied | isolation_forest+sequence_model | BLOCKED by gate: 3
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
| exfil | positive | 0/20 | 14/20 | 0/20 | 8/20 | 0/20 |
| hp_handoff | positive | 30/30 | 30/30 | 30/30 | 30/30 | 30/30 |
| hp_nolink | positive | 30/30 | 30/30 | 30/30 | 30/30 | 0/30 |
| hp_single | positive | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 |
| partner_spoof | positive | 15/15 | 15/15 | 15/15 | 15/15 | 9/15 |
| proxy_rotation | positive | 50/50 | 50/50 | 13/50 | 24/50 | 13/50 |
| redacted_reuse | positive | 20/20 | 20/20 | 20/20 | 20/20 | 1/20 |
| routine_tool_hijack | positive | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| seq_mimic | positive | 0/20 | 1/20 | 0/20 | 0/20 | 0/20 |
| assistant | benign | 0/300 | 0/300 | 0/300 | 0/300 | 0/300 |
| broadcaster | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| compliance_scanner | benign | 0/10 | 7/10 | 0/10 | 7/10 | 0/10 |
| crawler | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| cron_declared | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| cron_undeclared | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| noisy_denied | benign | 0/10 | 4/10 | 0/10 | 3/10 | 0/10 |
| orchestrator_pool | benign | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 |
| pagination_client | benign | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| partner_integration | benign | 9/10 | 9/10 | 9/10 | 9/10 | 9/10 |
| partner_ipallow | benign | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| partner_verified | benign | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| permission_drift | benign | 0/15 | 2/15 | 0/15 | 0/15 | 0/15 |
| redaction_user | benign | 9/40 | 9/40 | 9/40 | 9/40 | 0/40 |
| sharded_pool | benign | 0/25 | 0/25 | 0/25 | 0/25 | 0/25 |
| tool_adopter | benign | 5/10 | 5/10 | 5/10 | 5/10 | 2/10 |
| **all positive** | | 155/295 (0.525) | 175/295 (0.593) | 130/295 (0.441) | 149/295 (0.505) | 65/295 (0.220) |
| **all benign** | | 23/605 (0.038) | 36/605 (0.060) | 23/605 (0.038) | 33/605 (0.055) | 11/605 (0.018) |

guardrail ok: True; quarantined: 0

### Benign leads of v6 with the gate OFF, attributed

- compliance_scanner | isolation_forest+sequence_model | BLOCKED by gate: 7
- noisy_denied | isolation_forest+sequence_model | BLOCKED by gate: 3
- partner_integration | rule:R3 | lead: 8
- partner_integration | rule:R3(+1) | lead: 1
- redaction_user | graph:shared_redacted_token+timing_content | lead: 3
- redaction_user | graph:timing_content | lead: 6
- tool_adopter | rule:R1(+1) | lead: 3
- tool_adopter | rule:R2 | lead: 2
