# Rogue AI Detection prototype

> **SYNTHETIC DATA ONLY.** Every agent, message and event in this project is fabricated by `rogue_detect/synthetic.py`. Nothing here scrapes, contacts or collects data about any real platform or person. The network collector is a deliberately disabled stub. Results on synthetic data show that the pipeline works. They are not evidence of real-world accuracy.

Part of the project "Rogue AI Detection in the Wild". It demonstrates, end to end and at small scale, the pipeline described in the accompanying report and whitepaper: a collector interface, feature extraction, anomaly detection, coordination analysis, an alert log, flagged cases, intel-sharing export, and a small community report form.

## What it does

| Brief component | In this prototype |
|---|---|
| Data collection | `Collector` interface; `SyntheticCollector` (default), `JSONLFileCollector` (community contributions: schema validation, PII redaction, optional pseudonymization), `LiveNetworkCollectorStub` (disabled) |
| Anomaly detection | Per-agent features (timing, access, tool use, content, network), Isolation Forest, transparent rules, and a coordination graph |
| Collusion / coordination | Pairwise timing synchrony (hypergeometric test), rare-template content similarity, reciprocal messaging; clusters need at least two independent signals |
| Real-time monitoring | `python run.py monitor` replays the stream through a sliding window and logs new alerts as they appear (deduplicated) |
| Alerting | Hash-chained, append-only alert log with severity, explanation and approximate MITRE ATLAS tags |
| Intel sharing | STIX 2.1 export, labeled synthetic |
| Ethics and disclosure | `docs/ethics_and_compliance.md`, `docs/responsible_disclosure.md` |
| Community and developers | Local web dashboard with a report form and developer docs |

Planted synthetic scenarios: an access prober, a five-agent collusion ring, two injection-driven hijacks, plus benign look-alikes that should NOT be escalated (scheduled jobs, a heavy crawler, an orchestrator with workers, routine users of an external tool).

## Run it

Requires Python 3.10 or newer (developed on 3.13).

```bash
cd rogue-ai-detection
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python run.py demo              # generate data, analyze, evaluate, write sample outputs (about 30 seconds)
python run.py serve             # dashboard at http://127.0.0.1:8765 (Ctrl+C to stop)
python run.py monitor           # streaming replay; prints alerts as they fire
python -m pytest -q             # 42 tests
```

Other commands: `generate`, `analyze`, `export-stix`, `verify-log` (see `python run.py --help`). To analyze your own file of events, use `python run.py analyze --events yourfile.jsonl --log out_alert_log.jsonl`. The file must follow the schema in `docs/developer_guide.md`. Only contribute data you are allowed to share, with personal data removed.

## Outputs (written by `demo` into `sample_outputs/`)
- `alert_log.jsonl`: hash-chained alerts (`python run.py verify-log` checks integrity)
- `flagged_cases.md` and `.json`: evidence packages for medium and high alerts
- `evaluation.txt`: comparison against the generator's planted roles, including the evasive "stealth" variant
- `stix_bundle.json`: STIX 2.1 indicators for medium and high alerts (synthetic, not real intelligence)

## How detection works
1. Features per agent over the analysis window: rate, inter-event variation, burstiness, activity entropy, denied and out-of-scope ratios, sensitive-path hits, external-destination ratio, new-tool use, messaging breadth, text entropy, encoded-looking payload share, largest payload.
2. Isolation Forest (Liu, Ting and Zhou, 2008) on robust-scaled features gives an unsupervised ranking and a per-agent explanation (most extreme features).
3. Rules key on technical gates, not inferred intent: many denied or out-of-scope requests to sensitive paths; new external-destination tool use soon after ingesting external content (after a baseline period); encoded payloads in messages.
4. Coordination: pairs of agents are linked only if their behavior overlaps more than chance (in the spirit of Pacheco et al., 2021). Timing-only clusters that are strictly periodic are reported as an informational shared-schedule note.
5. Fusion: rule hits are medium, or high if the forest also flags the agent. Collusion clusters are high with three evidence types, or two plus a flagged member. Isolation Forest evidence alone is capped at low until a human reviews it.

## Test results
Recorded in this build (Python 3.13.5, scikit-learn 1.9.1, numpy 2.5.4, networkx 3.7):
- `python -m pytest -q`: 42 passed.
- `python run.py demo` (seed 7, 62 agents, 9 planted rogue agents): fused pipeline precision 1.00, recall 1.00 at medium or higher; Isolation Forest alone, precision 0.62 and recall 0.56. Benign look-alikes: none escalated above info or low.
- Stealth variant (same roles, evasive behavior): fused recall 0.11 (1 of 9). Slow low-denial probing, de-synchronized ring without reused templates, and abuse of an already-used tool all evade the current detectors. This is expected and is shown on purpose.

The roles are planted by the same author as the detectors, so the perfect standard-case score reflects that. It is a regression check, not a benchmark.

## Limitations
- Synthetic data only. Real traffic is messier; no claim is made about real-world precision or recall.
- Detectors fit the analysis window itself (transductive Isolation Forest, fixed contamination assumption). No drift handling.
- Evasion is easy, as the stealth variant shows. An agent that already uses a tool routinely will not trigger the new-tool rule.
- Fan-out workloads where many workers react to one trigger can look like coordination. The synthetic orchestrator is deliberately jittered and does not test this fully.
- ATLAS tags are an approximate mapping for triage. IDs and names were checked against the ATLAS v2026.09 data file.
- Content analysis does not detect real steganography. Encoded-looking text is a crude proxy.
- The STIX export has not been run through the OASIS validator. The hash-chained log is tamper-evident, not tamper-proof.
- The web UI is for local use only: no login, no CSRF protection, and no rate limiting. Do not expose it to a network.
- The community report form stores reports in `data/community_reports.jsonl` locally and sends nothing anywhere.

## Layout
```
run.py                 command line entry point
rogue_detect/          schema, synthetic, collectors, features, detectors, pipeline, alerts, monitor, intel, cases, evaluate, web
docs/                  ethics and compliance, responsible disclosure, developer guide
tests/                 42 pytest tests
data/                  generated synthetic events (re-created by `demo`)
sample_outputs/        example alert log, flagged cases, evaluation, STIX bundle
```
