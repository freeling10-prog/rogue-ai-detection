# agentwatch-analyzer — offline static web-log analyzer (Phase 3)

SOC-facing **sibling package** to `agent-watch`. Analyzes *your own* static access logs offline.

## Zero-exposure promise

- **Never** starts a honeypot
- **Never** binds a port for analysis
- **Never** makes outbound network calls
- Scrubs secrets (2-round percent-decode + dict-key redaction) **before** writing outputs
- No deploy / push required to use

This is **not** a WAF and **not** a substitute for the live honeypot. Beacon booleans, VLM scroll/dwell, and insider R12 tool-chain gates are **N/A offline**.

## Install

```bash
cd /workspace/agentwatch-analyzer
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install -e .
pytest -q
```

## Run on your logs

```bash
agentwatch-analyzer /var/log/nginx/access.log --format nginx --sitemap /path/to/sitemap.xml --out-dir ./out
# formats: auto|nginx|caddy|cloudflare|json
```

Outputs in `--out-dir`:

| file | contents |
|---|---|
| `events.scrubbed.jsonl` | scrubbed normalized events |
| `findings.json` / `leads.jsonl` | R8–R14 offline-capable leads + matrix |
| `replay.html` | CSP-safe static session replay (no network) |
| `stix-bundle.json` | STIX 2.1 indicators (validate with `stix2-validator==3.2.0`) |
| `summary.json` | counts |

## Offline-capable rule matrix

| Rule | Offline? | Notes |
|---|---|---|
| R8 asset starvation | **Yes** | Browser UA + HTML without css/js in the log |
| R9 unlinked jump | **Yes** | Referer link-graph; stronger with `--sitemap` or JSON `links[]` |
| R10 schema/machine-doc | **Partial** | cursor/query + openapi/llms paths; decoy kinds need honeypot |
| R11 beacon/mimic | **No** | honeypot beacons only |
| R12 tool hijack | **No** | agent-gateway / API telemetry |
| R13 timing/adaptation | **No** | honeypot instrumentation |
| R14 session fork | **Partial** | interleaved disjoint Referer trees; human-beacon N/A |

Sigma pack: `rules/sigma/` (R8–R14 + ATLAS AML.T0051, T0053, T0080, T0086, T0118; OWASP ASI01–ASI10 noted where mapped).

## Honest limits / FP caveats

- Typed URLs, bookmarks, and Referer-stripping proxies inflate R9/R14 offline.
- Commodity scanners are pre-filtered (UA / 404 fan-out) but sensitive-path probes are kept.
- STIX confidence is capped (lab/heuristic). ATLAS mappings are **approximate**.
- Custom STIX properties use `x_` prefix; validator SHOULD warnings may appear.

See `/workspace/phase3-analyzer.md` for file inventory and test counts.
