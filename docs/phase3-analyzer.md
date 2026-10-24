# Phase 3 — Offline log analyzer + Sigma/STIX pack

Date: 2026-10-23 (America/Los_Angeles)

## Deliverable

Standalone installable package: `/workspace/agentwatch-analyzer/`

Does **not** import Flask honeypot runtime. Vendors scrubbing + link-graph logic for offline use.

## Files

```
agentwatch-analyzer/
├── agentwatch_analyzer/
│   ├── cli.py parse.py scrub.py prefilter.py linkgraph.py
│   ├── detect.py replay.py stix_bundle.py
├── rules/sigma/          # 12 valid Sigma YAML rules
├── tests/ + fixtures/    # nginx + json logs (benign / agent-like / scanner)
├── README.md
└── requirements.txt      # pytest, PyYAML, stix2, stix2-validator==3.2.0
```

## Offline-capable matrix

| Rule | Offline | Needs honeypot/gateway |
|---|---|---|
| R8 | Yes | — |
| R9 | Yes (stronger w/ sitemap) | — |
| R10 | Partial | decoy/canary kinds |
| R11 | No | beacons / VLM / inversion |
| R12 | No | agent-gateway |
| R13 | No | honeypot timing |
| R14 | Partial | human-beacon corroboration |
| AML.T0051 canary | No (Sigma for leads JSONL) | honeypot |
| AML.T0053 | Partial via machine-doc paths | full decoy tool call |
| AML.T0080 / T0086 / T0118 | No | agent-gateway |

OWASP ASI01–ASI10 noted on Sigma `agentwatch.owasp_asi` / references where mapped (orientation, not a compliance claim).

## Test counts

Run: `cd /workspace/agentwatch-analyzer && pytest -q`

Expected: **10 passed** (`tests/test_analyzer.py`).

## Safety

Offline only; scrub before write; no honeypot deploy; no push/merge from this task.


## Test results (this pass)

- `cd /workspace/agentwatch-analyzer && pytest -q` → **10 passed**
- Sigma rules: **12** YAML files under `rules/sigma/`
- STIX: `stix2` parse OK with `allow_custom=True`; `stix2-validator==3.2.0` pinned (same as pipeline)
