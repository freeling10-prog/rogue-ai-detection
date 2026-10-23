# v3 pipeline web-client evaluation (regression check, NOT a benchmark)

Seeds [0, 1, 2, 3, 4]. Groups and counts per seed: see `rogue_pipeline/web_simulator.py`. `lead` = the client produced a review lead.

## v2

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 33 | 0 | None=33 | review=25, review_first=8 |
| accidental_scraper | accidental | 15 | 0 | 0 |  |  |
| mimic_basic | positive | 15 | 0 | 0 |  |  |
| mimic_linked | positive | 15 | 0 | 0 |  |  |
| mimic_assets | positive | 15 | 0 | 0 |  |  |
| mimic_schema | positive | 15 | 0 | 0 |  |  |
| mcp_agent | positive | 10 | 0 | 0 |  |  |
| decoy_explorer | positive | 10 | 0 | 0 |  |  |
| scanner_ua_spoof | positive | 5 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall": 0.0, "mimic_lead_recall_excl_mimic_assets_evader": 0.0, "web_benign_lead_fpr": 0.0, "web_benign_leads": 0, "web_benign_n": 45, "scanner_clients_with_a_lead": 33, "scanner_clients": 40, "scanner_clients_filtered": 0, "accidental_scraper_leads": 0, "accidental_scraper_n": 15, "accidental_scraper_class_goal_directed": 0, "accidental_scraper_class_accidental": 0, "adaptive_agents_lead_recall": 0.0, "scanner_ua_spoof_kept_with_lead": 0, "background_benign_leads": 68, "background_agents": 380, "quarantined_total": 0}

## v3_web_off

| group | kind | n | leads | filtered as scanner | actor_class of leads | bands |
|---|---|---|---|---|---|---|
| web_human | benign | 25 | 0 | 0 |  |  |
| web_human_no_assets | benign | 20 | 0 | 0 |  |  |
| commodity_scanner | scanner | 40 | 33 | 0 | unclassified=33 | review=25, review_first=8 |
| accidental_scraper | accidental | 15 | 0 | 0 |  |  |
| mimic_basic | positive | 15 | 0 | 0 |  |  |
| mimic_linked | positive | 15 | 0 | 0 |  |  |
| mimic_assets | positive | 15 | 0 | 0 |  |  |
| mimic_schema | positive | 15 | 0 | 0 |  |  |
| mcp_agent | positive | 10 | 0 | 0 |  |  |
| decoy_explorer | positive | 10 | 0 | 0 |  |  |
| scanner_ua_spoof | positive | 5 | 0 | 0 |  |  |

Metrics: {"mimic_lead_recall": 0.0, "mimic_lead_recall_excl_mimic_assets_evader": 0.0, "web_benign_lead_fpr": 0.0, "web_benign_leads": 0, "web_benign_n": 45, "scanner_clients_with_a_lead": 33, "scanner_clients": 40, "scanner_clients_filtered": 0, "accidental_scraper_leads": 0, "accidental_scraper_n": 15, "accidental_scraper_class_goal_directed": 0, "accidental_scraper_class_accidental": 0, "adaptive_agents_lead_recall": 0.0, "scanner_ua_spoof_kept_with_lead": 0, "background_benign_leads": 68, "background_agents": 380, "quarantined_total": 0}

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

Metrics: {"mimic_lead_recall": 0.75, "mimic_lead_recall_excl_mimic_assets_evader": 1.0, "web_benign_lead_fpr": 0.0, "web_benign_leads": 0, "web_benign_n": 45, "scanner_clients_with_a_lead": 0, "scanner_clients": 40, "scanner_clients_filtered": 40, "accidental_scraper_leads": 15, "accidental_scraper_n": 15, "accidental_scraper_class_goal_directed": 0, "accidental_scraper_class_accidental": 15, "adaptive_agents_lead_recall": 1.0, "scanner_ua_spoof_kept_with_lead": 5, "background_benign_leads": 68, "background_agents": 380, "quarantined_total": 0}

Extra:

`{"scanner_leads_if_prefilter_off": 33, "bg_leads_same_v2_v3": 5, "seeds": 5, "prefiltered_agents_v3": 40, "prefiltered_events_v3": 560, "kept_scanner_like_with_goal_evidence": 5}`
