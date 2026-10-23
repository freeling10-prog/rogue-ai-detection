# Harness fingerprint: cohort x archetype confusion table

Seeds 0..4, `demo --extended` cohorts, counts pooled over seeds.  SAME-AUTHOR SYNTHETIC: rules and simulated harnesses share an author; this is a regression check, not a benchmark of real frameworks.  Labels describe a harness, not intent.

| cohort | expected | n | commodity_or_static_scanner | headless_or_http_mimic | mcp_tool_runner | prompt_injected_crawler | schema_driven_api_agent | stateful_coordinator | unclassified | correct | note |
|---|---|---|---|---|---|---|---|---|---|---|---|
| human | unclassified | 45 | . | . | . | . | . | . | 45 | 45/45 |  |
| human_no_assets/images_blocked/js_off | unclassified | 45 | . | . | . | . | . | . | 45 | 45/45 |  |
| human_beacon_blocked | unclassified | 15 | . | 15 | . | . | . | . | . | 0/15 | KNOWN false positive: ad-blocked beacon looks like a missing beacon |
| static scanners / crawlers | commodity_or_static_scanner | 20 | 20 | . | . | . | . | . | . | 20/20 |  |
| naive_scraper | commodity_or_static_scanner | 20 | 20 | . | . | . | . | . | . | 20/20 |  |
| classic agents C/F/L/H (canary, creds) | prompt_injected_crawler | 20 | . | . | . | 20 | . | . | . | 20/20 |  |
| classic adaptive A/B (chains, enumeration) | unclassified | 10 | . | . | . | . | . | . | 10 | 10/10 | no distinctive harness signature exists for these |
| coordination | stateful_coordinator | 15 | . | . | . | . | . | 15 | . | 15/15 |  |
| mcp tool runner | mcp_tool_runner | 10 | . | . | 10 | . | . | . | . | 10/10 |  |
| mimic_basic | headless_or_http_mimic | 15 | . | 15 | . | . | . | . | . | 15/15 |  |
| mimic_linked | headless_or_http_mimic | 15 | . | 15 | . | . | . | . | . | 15/15 |  |
| mimic_assets | headless_or_http_mimic | 15 | . | 15 | . | . | . | . | . | 15/15 |  |
| mimic_schema | schema_driven_api_agent | 15 | . | . | . | . | 15 | . | . | 15/15 |  |
| mimic_aria / webdriver | headless_or_http_mimic | 30 | . | 30 | . | . | . | . | . | 30/30 |  |
| mimic_browser_stealth | headless_or_http_mimic | 15 | . | . | . | . | . | . | 15 | 0/15 | KNOWN miss: nothing observable distinguishes it |
| mimic_header_forger | headless_or_http_mimic | 15 | . | . | . | . | . | . | 15 | 0/15 | KNOWN miss: forged coherent Sec-Fetch is trusted |

Overall 275/320 sessions got their intended archetype.  Same-author synthetic cohorts; not a benchmark.
