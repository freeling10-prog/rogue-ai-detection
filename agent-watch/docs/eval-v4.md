# v2 / v3 / v4 agent-watch synthetic evaluation (regression check, NOT a benchmark)

Seeds [7, 8, 9, 10, 11]. Same simulated client population (v3 + v4 variants, 3 copies each per seed) against each version's own honeypot and detectors.  Same author wrote clients and detectors; mimic variants were built against the rules; n is small; contact is not intent.

## v2

Summary: {"mimic_assets_recall_alerted": 0.0, "mimic_assets_recall_label_agent": 0.0, "mimic_linked_label_agent": 0.0, "mimic_linked_alerted": 0.0, "mimic_linked_actor_types": {"None": 15}, "images_blocked_human_alerted": 0, "images_blocked_human_n": 15, "images_only_blocked_human_alerted": 0, "images_only_blocked_human_n": 15, "mimic_recall_alerted_all": 0.0, "mimic_recall_alerted_excluding_by_construction_evaders": 0.0, "human_alerted_easy": 0, "human_easy_n": 45, "human_alerted_all": 0, "human_n": 75, "legacy_label_accuracy": 1.0}

| variant | truth | n | seen | label correct | alerted >= medium | labels | actor types |
|---|---|---|---|---|---|---|---|
| human | human | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| human_no_assets | human | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| scraper_naive | static_bot | 10 | 10 | 0 | 10 | {"human": 10} | {"None": 10} |
| crawler_declared | static_bot | 5 | 5 | 5 | 5 | {"static_bot": 5} | {"None": 5} |
| mimic_basic | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_linked | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_assets | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_schema | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| human_images_blocked | human | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| human_js_off | human | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| human_beacon_blocked | human | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_browser_stealth | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_browser_webdriver | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_aria | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |
| mimic_header_forger | agent | 15 | 0 | 0 | 0 | {"None": 15} | {"None": 15} |

## v3

Summary: {"mimic_assets_recall_alerted": 0.0, "mimic_assets_recall_label_agent": 0.0, "mimic_linked_label_agent": 0.0, "mimic_linked_alerted": 1.0, "mimic_linked_actor_types": {"possible_mimic": 15}, "images_blocked_human_alerted": 15, "images_blocked_human_n": 15, "images_only_blocked_human_alerted": 0, "images_only_blocked_human_n": 15, "mimic_recall_alerted_all": 0.5, "mimic_recall_alerted_excluding_by_construction_evaders": 0.5, "human_alerted_easy": 0, "human_easy_n": 45, "human_alerted_all": 15, "human_n": 75, "legacy_label_accuracy": 1.0}

| variant | truth | n | seen | label correct | alerted >= medium | labels | actor types |
|---|---|---|---|---|---|---|---|
| human | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_no_assets | human | 15 | 15 | 15 | 15 | {"human": 15} | {"possible_mimic": 15} |
| scraper_naive | static_bot | 10 | 10 | 10 | 10 | {"static_bot": 10} | {"accidental_scraper": 10} |
| crawler_declared | static_bot | 5 | 5 | 5 | 5 | {"static_bot": 5} | {"accidental_scraper": 5} |
| mimic_basic | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| mimic_linked | agent | 15 | 15 | 0 | 15 | {"static_bot": 4, "human": 11} | {"possible_mimic": 15} |
| mimic_assets | agent | 15 | 15 | 0 | 0 | {"human": 15} | {"human": 15} |
| mimic_schema | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| human_images_blocked | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_js_off | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_beacon_blocked | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| mimic_browser_stealth | agent | 15 | 15 | 0 | 0 | {"human": 15} | {"human": 15} |
| mimic_browser_webdriver | agent | 15 | 15 | 0 | 0 | {"human": 15} | {"human": 15} |
| mimic_aria | agent | 15 | 15 | 0 | 0 | {"human": 15} | {"human": 15} |
| mimic_header_forger | agent | 15 | 15 | 0 | 15 | {"human": 10, "static_bot": 5} | {"possible_mimic": 15} |

## v4

Summary: {"mimic_assets_recall_alerted": 1.0, "mimic_assets_recall_label_agent": 0.0, "mimic_linked_label_agent": 0.0, "mimic_linked_alerted": 1.0, "mimic_linked_actor_types": {"possible_mimic": 15}, "images_blocked_human_alerted": 0, "images_blocked_human_n": 15, "images_only_blocked_human_alerted": 0, "images_only_blocked_human_n": 15, "mimic_recall_alerted_all": 0.75, "mimic_recall_alerted_excluding_by_construction_evaders": 1.0, "human_alerted_easy": 0, "human_easy_n": 45, "human_alerted_all": 15, "human_n": 75, "legacy_label_accuracy": 1.0}

| variant | truth | n | seen | label correct | alerted >= medium | labels | actor types |
|---|---|---|---|---|---|---|---|
| human | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_no_assets | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| scraper_naive | static_bot | 10 | 10 | 10 | 10 | {"static_bot": 10} | {"accidental_scraper": 10} |
| crawler_declared | static_bot | 5 | 5 | 5 | 5 | {"static_bot": 5} | {"accidental_scraper": 5} |
| mimic_basic | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| mimic_linked | agent | 15 | 15 | 0 | 15 | {"static_bot": 4, "human": 11} | {"possible_mimic": 15} |
| mimic_assets | agent | 15 | 15 | 0 | 15 | {"human": 15} | {"possible_mimic": 15} |
| mimic_schema | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| human_images_blocked | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_js_off | human | 15 | 15 | 15 | 0 | {"human": 15} | {"human": 15} |
| human_beacon_blocked | human | 15 | 15 | 15 | 15 | {"human": 15} | {"possible_mimic": 15} |
| mimic_browser_stealth | agent | 15 | 15 | 0 | 0 | {"human": 15} | {"human": 15} |
| mimic_browser_webdriver | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| mimic_aria | agent | 15 | 15 | 15 | 15 | {"agent": 15} | {"goal_directed_agent": 15} |
| mimic_header_forger | agent | 15 | 15 | 0 | 0 | {"human": 10, "static_bot": 5} | {"human": 10, "static_bot": 5} |
