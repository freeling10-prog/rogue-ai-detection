# Rogue AI Detection in the Wild: project summary (defensive research and tooling)

## Repo map

The source archives are unpacked into top-level folders. Each folder keeps its own README.

- [agent-watch/README.md](agent-watch/README.md) — log detector and localhost honeypot (section 4).
- [rogue-ai-pipeline/README.md](rogue-ai-pipeline/README.md) — multi-layer detection pipeline (section 5).
- [prototype-v1/README.md](prototype-v1/README.md) — prototype v1, unpacked from `rogue-ai-detection` (section 2).
- [docs/rogue-ai-detection-whitepaper.pdf](docs/rogue-ai-detection-whitepaper.pdf) — 7-page whitepaper (section 3).

## 1. Research report
Link: https://cursor.com/canvas/store-f783d059-8304-409e-8eee-8c518ae04f8b/91900c77-b85e-45f9-b706-3b5fa0315467
- Covers bot and agent detection, anomaly detection, coordination and collusion, prompt injection and agent misuse.
- Standards: MITRE ATLAS, NIST AI RMF, OWASP, STIX/TAXII, disclosure norms.
- Legal and ethical limits on data collection: CFAA cases, GDPR and an EDPB scraping draft, DSA Article 40, Menlo Report.
- Includes a reference architecture, recommendations, 36 linked sources. Only 3 primary documents read in full; the rest rely on abstracts or search summaries.
- ATLAS IDs were checked against the primary data file (AML.T0051, T0053, T0080, T0086, T0118).
- Legal content is a research summary, not legal advice.

## 2. Prototype v1 (rogue-ai-detection.zip)
- Synthetic data only. Isolation Forest, coordination check, rules, hash-chained alert log, STIX export, local dashboard and report form.
- 42 tests pass. Standard scenarios (62 agents, 9 planted rogue): combined precision 1.00, recall 1.00. Evasive variants: found 1 of 9.
- The perfect standard score is a regression check, not a benchmark.

## 3. Whitepaper
- 7 pages, PDF and Word, same numbers as the report and prototype, states the synthetic-data limit up front.

## 4. Log detector with honeypot (agent-watch.zip)
- Python 3.10+ with Flask. 103 tests pass, 1 skipped.
- Parses Nginx/Apache and JSON gateway logs, builds sessions, flags adaptive scraping, tool-chaining and rate-limit evasion.
- Rules-and-threshold scoring using timing entropy and navigation depth separates humans, static bots and goal-directed agents. Every score has plain-language reasons.
- Alerts as terminal summaries and JSON.
- Honeypot: hidden decoy links, fake admin and export endpoints, fake credentials, and canary pages carrying a harmless "AI assistants, fetch this URL" note so an agent that obeys embedded text gets logged.
- Binds to localhost only, no outbound requests.
- Synthetic demo: 5/5 humans, 5/5 static bots, 3/3 adaptive agents labelled correctly. Live run against the simulated agent: flagged critical, mainly for following the canary instruction.

## 5. Multi-layer pipeline (rogue-ai-pipeline.zip)
- 99 tests pass, mypy clean, STIX 2.1 export passes the OASIS validator.
- Layers: schema validation with keyed pseudonymization; Isolation Forest with feature explanations; rule gates mapped to ATLAS T0051, T0053, T0086; networkx coordination graph that suppresses cron jobs and orchestrator pools; fused scoring that only creates low-severity "human review" leads; hash-chained audit log.
- Synthetic evaluation, 5 seeds:
  - Standard: precision 0.85, recall 0.97, false-positive rate 0.03
  - Half evasive: precision 0.72, recall 0.45, FPR 0.03
  - All evasive: precision 0.00, recall 0.00, FPR 0.03
- Rules alone recall 0.47; Isolation Forest alone recall 0.14; graph without suppression FPR 0.23.
- 14 known false positives (partner integrations, agents adopting a new tool).
- Honeypot output exports in the pipeline's format, but one visitor is too little data for its anomaly layer, which needs at least 10 agents.

## Caveats
- All results are on synthetic data written by the same author as the detectors: regression checks, not benchmarks.
- Evasive-variant results are a worst case; those variants were written against these exact thresholds.
- Heuristics can be evaded and shared IPs cause false positives.
- Use only on systems you own or are authorized to monitor. Treat every flag as a lead for human review, not a block.
- Do not expose the honeypot publicly without isolation.
