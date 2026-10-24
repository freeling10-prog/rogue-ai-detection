# agent-watch v5 vs v6 (same simulated clients, each tree's own honeypot + detectors)

Seeds [7, 8, 9, 10, 11]; 3 copies per cohort per seed (n=15). SAME-AUTHOR SYNTHETIC: not a benchmark.

| cohort | truth | n | v5 alerted (>=medium) | v6 alerted | v5 label correct | v6 label correct | v5 labels | v6 labels |
|---|---|---|---|---|---|---|---|---|
| human | human | 15 | 0 | 0 | 15 | 15 | {"human": 15} | {"human": 15} |
| human_no_assets | human | 15 | 0 | 0 | 15 | 15 | {"human": 15} | {"human": 15} |
| scraper_naive | static_bot | 10 | 10 | 10 | 10 | 10 | {"static_bot": 10} | {"static_bot": 10} |
| crawler_declared | static_bot | 5 | 5 | 5 | 5 | 5 | {"static_bot": 5} | {"static_bot": 5} |
| mimic_basic | agent | 15 | 15 | 15 | 15 | 15 | {"agent": 15} | {"agent": 15} |
| mimic_linked | agent | 15 | 15 | 15 | 0 | 0 | {"static_bot": 4, "human": 11} | {"static_bot": 11, "human": 4} |
| mimic_assets | agent | 15 | 15 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |
| mimic_schema | agent | 15 | 15 | 15 | 15 | 15 | {"agent": 15} | {"agent": 15} |
| human_images_blocked | human | 15 | 0 | 0 | 15 | 15 | {"human": 15} | {"human": 15} |
| human_js_off | human | 15 | 0 | 0 | 15 | 15 | {"human": 15} | {"human": 15} |
| human_beacon_blocked | human | 15 | 15 | 0 | 15 | 15 | {"human": 15} | {"human": 15} |
| mimic_browser_stealth | agent | 15 | 0 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |
| mimic_browser_webdriver | agent | 15 | 15 | 15 | 15 | 15 | {"agent": 15} | {"agent": 15} |
| mimic_aria | agent | 15 | 15 | 15 | 15 | 15 | {"agent": 15} | {"agent": 15} |
| mimic_header_forger | agent | 15 | 0 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |
| mimic_vlm_os | agent | 15 | 0 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |
| mimic_schema_sanitizer | agent | 15 | 15 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |
| mimic_parasitic_rider | agent | 15 | 0 | 15 | 0 | 15 | {"human": 15} | {"agent": 15} |

Legacy actors label accuracy: v5 {'n': 100, 'label_ok': 100}, v6 {'n': 100, 'label_ok': 100}
