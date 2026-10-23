# Web-client evaluation v2 / v3 / v4 (regression check on synthetic data, NOT a benchmark)

Seeds [0, 1, 2, 3, 4]. Groups and counts per seed: `rogue_pipeline/web_simulator.py` (v3 groups + v4 groups). Same author wrote simulator and rules; the mimic variants were written with the rules in mind. `lead` = the client produced a review lead. Contact/behaviour is not intent. v2/v3 columns see the same traffic in the format their collector could record.

## v2

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 33 | 0 | None=33 | review=24, review_first=9 |
| accidental_scraper | accidental | 15 | 0 | 0 |  |  |
| mimic_basic | positive | 15 | 0 | 0 |  |  |
| mimic_linked | positive | 15 | 0 | 0 |  |  |
| mimic_assets | positive | 15 | 0 | 0 |  |  |
| mimic_schema | positive | 15 | 0 | 0 |  |  |
| mcp_agent | positive | 10 | 0 | 0 |  |  |
| decoy_explorer | positive | 10 | 0 | 0 |  |  |
| scanner_ua_spoof | positive | 5 | 0 | 0 |  |  |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 0 | 0 |  |  |
| human_no_assets_nosec | benign | 10 | 0 | 0 |  |  |
| mimic_linked_nosec | positive | 15 | 0 | 0 |  |  |
| mimic_browser_webdriver | positive | 15 | 0 | 0 |  |  |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 0 | 0 |  |  |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.0, "mimic_cohorts": 9, "mimic_assets_recall": 0.0, "mimic_linked_recall_with_sec_fetch_absent_header": 0.0, "mimic_linked_recall_collector_without_sec_fetch": 0.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 0, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 33, "scanner_clients": 40, "accidental_scraper_leads": 0, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 0.0, "background_benign_leads": 14, "background_agents": 380}

## v3

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 0 | 40 |  |  |
| accidental_scraper | accidental | 15 | 15 | 0 | accidental_scraper=15 | review=15 |
| mimic_basic | positive | 15 | 15 | 0 | goal_directed=15 | review=15 |
| mimic_linked | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_assets | positive | 15 | 0 | 0 |  |  |
| mimic_schema | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mcp_agent | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| decoy_explorer | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| scanner_ua_spoof | positive | 5 | 5 | 0 | goal_directed=5 | review_first=5 |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 0 | 0 |  |  |
| human_no_assets_nosec | benign | 10 | 0 | 0 |  |  |
| mimic_linked_nosec | positive | 15 | 0 | 0 |  |  |
| mimic_browser_webdriver | positive | 15 | 0 | 0 |  |  |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 0 | 0 |  |  |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.333, "mimic_cohorts": 9, "mimic_assets_recall": 0.0, "mimic_linked_recall_with_sec_fetch_absent_header": 1.0, "mimic_linked_recall_collector_without_sec_fetch": 0.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 0, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 1.0, "background_benign_leads": 14, "background_agents": 380}

## v4_no_gate

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 0 | 40 |  |  |
| accidental_scraper | accidental | 15 | 15 | 0 | accidental_scraper=15 | review=15 |
| mimic_basic | positive | 15 | 15 | 0 | goal_directed=15 | review=15 |
| mimic_linked | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_assets | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_schema | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mcp_agent | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| decoy_explorer | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| scanner_ua_spoof | positive | 5 | 5 | 0 | goal_directed=5 | review_first=5 |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| human_no_assets_nosec | benign | 10 | 10 | 0 | possible_mimic=10 | review=10 |
| mimic_linked_nosec | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_browser_webdriver | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.778, "mimic_cohorts": 9, "mimic_assets_recall": 1.0, "mimic_linked_recall_with_sec_fetch_absent_header": 1.0, "mimic_linked_recall_collector_without_sec_fetch": 1.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 25, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 1.0, "background_benign_leads": 14, "background_agents": 380}

## v4

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 0 | 40 |  |  |
| accidental_scraper | accidental | 15 | 15 | 0 | accidental_scraper=15 | review=15 |
| mimic_basic | positive | 15 | 15 | 0 | goal_directed=15 | review=15 |
| mimic_linked | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_assets | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_schema | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mcp_agent | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| decoy_explorer | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| scanner_ua_spoof | positive | 5 | 5 | 0 | goal_directed=5 | review_first=5 |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| human_no_assets_nosec | benign | 10 | 10 | 0 | possible_mimic=10 | review=10 |
| mimic_linked_nosec | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_browser_webdriver | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.778, "mimic_cohorts": 9, "mimic_assets_recall": 1.0, "mimic_linked_recall_with_sec_fetch_absent_header": 1.0, "mimic_linked_recall_collector_without_sec_fetch": 1.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 25, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 1.0, "background_benign_leads": 14, "background_agents": 380}

## v3_nopolicy

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 0 | 40 |  |  |
| accidental_scraper | accidental | 15 | 15 | 0 | accidental_scraper=15 | review=15 |
| mimic_basic | positive | 15 | 15 | 0 | goal_directed=15 | review=15 |
| mimic_linked | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_assets | positive | 15 | 0 | 0 |  |  |
| mimic_schema | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mcp_agent | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| decoy_explorer | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| scanner_ua_spoof | positive | 5 | 5 | 0 | goal_directed=5 | review_first=5 |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 0 | 0 |  |  |
| human_no_assets_nosec | benign | 10 | 0 | 0 |  |  |
| mimic_linked_nosec | positive | 15 | 0 | 0 |  |  |
| mimic_browser_webdriver | positive | 15 | 0 | 0 |  |  |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 0 | 0 |  |  |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.333, "mimic_cohorts": 9, "mimic_assets_recall": 0.0, "mimic_linked_recall_with_sec_fetch_absent_header": 1.0, "mimic_linked_recall_collector_without_sec_fetch": 0.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 0, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 1.0, "background_benign_leads": 68, "background_agents": 380}

## v4_nopolicy

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 0 | 40 |  |  |
| accidental_scraper | accidental | 15 | 15 | 0 | accidental_scraper=15 | review=15 |
| mimic_basic | positive | 15 | 15 | 0 | goal_directed=15 | review=15 |
| mimic_linked | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_assets | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_schema | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mcp_agent | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| decoy_explorer | positive | 10 | 10 | 0 | goal_directed=10 | review_first=10 |
| scanner_ua_spoof | positive | 5 | 5 | 0 | goal_directed=5 | review_first=5 |
| human_images_blocked | benign | 20 | 0 | 0 |  |  |
| human_js_off | benign | 15 | 0 | 0 |  |  |
| human_beacon_blocked | benign | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| human_no_assets_nosec | benign | 10 | 10 | 0 | possible_mimic=10 | review=10 |
| mimic_linked_nosec | positive | 15 | 15 | 0 | possible_mimic=15 | review=15 |
| mimic_browser_webdriver | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_browser_stealth | positive | 15 | 0 | 0 |  |  |
| mimic_aria | positive | 15 | 15 | 0 | goal_directed=15 | review_first=15 |
| mimic_header_forger | positive | 15 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall_all": 0.778, "mimic_cohorts": 9, "mimic_assets_recall": 1.0, "mimic_linked_recall_with_sec_fetch_absent_header": 1.0, "mimic_linked_recall_collector_without_sec_fetch": 1.0, "images_blocked_human_leads": 0, "benign_web_humans_with_lead": 0, "benign_web_humans_n": 80, "hard_negative_humans_with_lead": 25, "hard_negative_humans_n": 25, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "adaptive_agents_lead_recall": 1.0, "background_benign_leads": 68, "background_agents": 380}

## Per-layer attribution of benign leads (leave-one-out on the fusion; see rogue_pipeline/attribution.py)

Counts pooled over seeds; `population` = what the client was.  `layer detail` = the layer(s) the lead needed.

| condition | population | layer detail | leads |
|---|---|---|---|
| v2 | background_benign | rule:R1(+1) | 4 |
| v2 | background_benign | rule:R2 | 1 |
| v2 | background_benign | rule:R3 | 9 |
| v3 | background_benign | rule:R1(+1) | 4 |
| v3 | background_benign | rule:R2 | 1 |
| v3 | background_benign | rule:R3 | 9 |
| v4_no_gate | background_benign | rule:R1(+1) | 4 |
| v4_no_gate | background_benign | rule:R2 | 1 |
| v4_no_gate | background_benign | rule:R3 | 9 |
| v4_no_gate | web_benign | floor:R11 | 25 |
| v4 | background_benign | rule:R1(+1) | 4 |
| v4 | background_benign | rule:R2 | 1 |
| v4 | background_benign | rule:R3 | 9 |
| v4 | web_benign | floor:R11 | 25 |
| v3_nopolicy | background_benign | graph:timing_content | 50 |
| v3_nopolicy | background_benign | rule:R1 | 9 |
| v3_nopolicy | background_benign | rule:R3 | 9 |
| v4_nopolicy | background_benign | graph:timing_content | 50 |
| v4_nopolicy | background_benign | rule:R1 | 9 |
| v4_nopolicy | background_benign | rule:R3 | 9 |
| v4_nopolicy | web_benign | floor:R11 | 25 |

### Candidates the v4 corroboration gate blocked (benign)

| population | layer detail | blocked |
|---|---|---|

### Candidates the v4 corroboration gate blocked (web POSITIVES = recall lost to the gate)

| group | layer detail | blocked |
|---|---|---|

Strict gate (every non-floor lead needs 2 families; no solo rule/graph exception): background benign leads 6, mimic recall 0.778.

Extra:

`{"scanner_leads_if_prefilter_off": 33, "seeds": 5, "prefiltered_agents_v4": 40, "kept_scanner_like_with_goal_evidence": 5}`
