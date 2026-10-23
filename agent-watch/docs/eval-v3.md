# v3 synthetic evaluation (regression check, NOT a benchmark)

## C1 v2 as shipped (logs+leads)

mimic recall (label=agent) 0.0, mimic alerted>=medium 0.0 (excl. evader 0.0), mimic seen 0.0; human alert-FPR 0.0 (excl. hard negative 0.0); legacy label acc 1.0, legacy agent recall 1.0

| variant | truth | n | seen | label correct | alerted >= medium | labels | severities | actor types |
|---|---|---|---|---|---|---|---|---|
| web:human | human | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:human_no_assets | human | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:scraper_naive | static_bot | 2 | 2 | 0 | 2 | human,human | high,high | None,None |
| web:crawler_declared | static_bot | 1 | 1 | 1 | 1 | static_bot | high | None |
| web:mimic_basic | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_linked | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_assets | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_schema | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |

## C2 v3 code, no mirror (logs+leads)

mimic recall (label=agent) 0.25, mimic alerted>=medium 0.25 (excl. evader 0.333), mimic seen 0.25; human alert-FPR 0.0 (excl. hard negative 0.0); legacy label acc 1.0, legacy agent recall 1.0

| variant | truth | n | seen | label correct | alerted >= medium | labels | severities | actor types |
|---|---|---|---|---|---|---|---|---|
| web:human | human | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:human_no_assets | human | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:scraper_naive | static_bot | 2 | 2 | 2 | 2 | static_bot,static_bot | medium,medium | accidental_scraper,accidental_scraper |
| web:crawler_declared | static_bot | 1 | 1 | 1 | 1 | static_bot | medium | accidental_scraper |
| web:mimic_basic | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_linked | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_assets | agent | 3 | 0 | 0 | 0 | None,None,None | None,None,None | None,None,None |
| web:mimic_schema | agent | 3 | 3 | 3 | 3 | agent,agent,agent | critical,critical,critical | goal_directed_agent,goal_directed_agent,goal_directed_agent |

## C3 v3 mirror visible, new detectors+floors OFF

mimic recall (label=agent) 0.0, mimic alerted>=medium 0.0 (excl. evader 0.0), mimic seen 1.0; human alert-FPR 0.0 (excl. hard negative 0.0); legacy label acc 1.0, legacy agent recall 1.0

| variant | truth | n | seen | label correct | alerted >= medium | labels | severities | actor types |
|---|---|---|---|---|---|---|---|---|
| web:human | human | 3 | 3 | 3 | 0 | human,human,human | info,info,info | human,human,human |
| web:human_no_assets | human | 3 | 3 | 3 | 0 | human,human,human | info,info,info | human,human,human |
| web:scraper_naive | static_bot | 2 | 2 | 2 | 2 | static_bot,static_bot | medium,medium | accidental_scraper,accidental_scraper |
| web:crawler_declared | static_bot | 1 | 1 | 1 | 1 | static_bot | medium | accidental_scraper |
| web:mimic_basic | agent | 3 | 3 | 0 | 0 | human,human,human | info,info,info | human,human,human |
| web:mimic_linked | agent | 3 | 3 | 0 | 0 | static_bot,human,human | low,info,info | static_bot,human,human |
| web:mimic_assets | agent | 3 | 3 | 0 | 0 | human,human,human | info,info,info | human,human,human |
| web:mimic_schema | agent | 3 | 3 | 0 | 0 | human,static_bot,static_bot | info,low,low | human,static_bot,static_bot |

## C4 v3 full (mirror + new detectors + floors)

mimic recall (label=agent) 0.5, mimic alerted>=medium 0.75 (excl. evader 1.0), mimic seen 1.0; human alert-FPR 0.25 (excl. hard negative 0.0); legacy label acc 1.0, legacy agent recall 1.0

| variant | truth | n | seen | label correct | alerted >= medium | labels | severities | actor types |
|---|---|---|---|---|---|---|---|---|
| web:human | human | 3 | 3 | 3 | 0 | human,human,human | info,info,info | human,human,human |
| web:human_no_assets | human | 3 | 3 | 3 | 3 | human,human,human | medium,medium,medium | possible_mimic,possible_mimic,possible_mimic |
| web:scraper_naive | static_bot | 2 | 2 | 2 | 2 | static_bot,static_bot | medium,medium | accidental_scraper,accidental_scraper |
| web:crawler_declared | static_bot | 1 | 1 | 1 | 1 | static_bot | medium | accidental_scraper |
| web:mimic_basic | agent | 3 | 3 | 3 | 3 | agent,agent,agent | critical,critical,critical | goal_directed_agent,goal_directed_agent,goal_directed_agent |
| web:mimic_linked | agent | 3 | 3 | 0 | 3 | static_bot,human,human | medium,medium,medium | possible_mimic,possible_mimic,possible_mimic |
| web:mimic_assets | agent | 3 | 3 | 0 | 0 | human,human,human | info,info,info | human,human,human |
| web:mimic_schema | agent | 3 | 3 | 3 | 3 | agent,agent,agent | critical,critical,critical | goal_directed_agent,goal_directed_agent,goal_directed_agent |
