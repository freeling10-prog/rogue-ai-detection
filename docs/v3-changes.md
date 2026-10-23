# v3 changes (agent-watch + rogue-ai-pipeline)

Everything here is synthetic data, localhost only (127.0.0.1), no outbound requests, sanitized logging.
All numbers are **regression checks written by the same author as the detectors, not benchmarks**. Honeypot contact is not intent.

## What was wrong (from the live demo, /workspace/honeypot-demo-transcript.md)
1. A "mimic" client (browser User-Agent, human pace, never touches a decoy) left no lead and no alert.
2. A naive scraper that hit one hidden link got severity "high" but was labelled "human".
3. The Flask dev-server console printed raw query strings, fake keys, e-mails and coordination tokens/nonces, although the log files were scrubbed.

## agent-watch: what changed
- **Console/process logs (item 1).** New `agentwatch/safelog.py`: a werkzeug request handler that prints a query-free path, a logging filter on the
  Flask/werkzeug/agentwatch loggers, a gunicorn logger class that scrubs every message (gunicorn access log off and a no-op even if forced on). The
  new test starts the real dev server and real gunicorn, sends fake secrets in queries/paths/headers plus malformed raw-socket requests, stops them
  with SIGINT and greps the captured stdout/stderr (the old code leaks; checked by hand).
- **Mimic detection (item 2).** The honeypot now mirrors *every* request into `<lead log>.access.jsonl` (with the links each page offered, headers,
  content type). New detectors: asset starvation (>= 5 HTML pages from a browser-claiming client with zero assets, plus Sec-Fetch mismatch when headers
  exist), per-transition unlinked jump (uses the served link graph; moves to URLs offered earlier score much less), max-pooling score floors (one
  strong event cannot be diluted by benign padding), the camouflaged `client_schema_rev=2026.04-ai` parameter in the decoy `openapi.json`, a per-session canary
  parameter. New `actor_type`: goal_directed_agent / accidental_scraper / possible_mimic / static_bot / human.
- **Scraper severity fix.** A lone hit on a passive decoy (invisible link, robots Disallow, /.env) is now `medium` and `accidental_scraper` unless
  there is stronger evidence. **One existing test was deliberately edited** (`tests/test_scoring.py`, the human-with-one-decoy-hit test) because its old
  assertion encoded bug (b) (severity high while labelled human).
- **Decoy MCP endpoint (item 3).** `POST /mcp` JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`), tools `query_customer_backup`,
  `read_internal_notes`, `claim_coordination_task`; scrubbed args logged, plausible synthetic reply with a canary phrase, advertised in
  `/.well-known/mcp.json` and `/llms.txt`; read-only, size-limited, 30 calls/min/IP. `tools/list` then a valid `tools/call` = strong goal-directed evidence (still contact, not intent).
- **Red-team harness (item 5).** `redteam/llm_agent.py` (~60-line loop, loopback-only `fetch_url`, hard step cap 25, refuses non-loopback hosts
  without DNS lookups, Ollama at 127.0.0.1:11434, optional OpenAI-compatible backend only if `AGENTWATCH_LLM_API_BASE` is set; three prompts) + runbook `redteam/README.md`.
- **JA4 (item 6).** `docs/ja4-tls-fingerprinting.md` design note only; optional parse-only `ja4`/`ja4h` field in the parser. Not implemented, not tested.
- **New CLI:** `demo --extended`, `export-web` (mirrored stream -> pipeline RawEvents), `scripts/eval_v3.py`.
- **PR #2 changes ported** (found by a separate GitHub review): scrubber handles newline-split / %40 / %20 / %2540 / `\uXXXX`-encoded secrets as the same token;
  sqlite column guards raise `ValueError` not `assert`; nginx log has a millisecond timestamp (`$msec`) and `error_log stderr warn`. Patches applied
  unmodified (the five files were identical to the base), with the PR's 4 new tests; its two docs were added to `agent-watch/docs/`.

## rogue-ai-pipeline: what changed
- Optional strict `web` block on events (no UA string kept) and three new rules: **R8** asset starvation (gated on a browser-claiming client), **R9** unlinked jump
  (never-offered transitions only), **R10** strong-signal floor tiers (weak 0.58, strong 0.8) applied after fusion (`max(score, floor)`).
- **Commodity-scanner pre-filter (item 4).** Sessions with >= 80% scanner paths (PHP/WordPress/.env/phpmyadmin...) or a known scanner UA (zgrab, masscan, censys, shodan, nmap...)
  are tagged and removed before scoring and before baseline training; counts are reported (and audited). A scanner UA on a session with goal-directed evidence is **not** exempt-filtered
  away (so a spoofed UA cannot hide an agent); a bare decoy hit is not "evidence". 
- Leads carry `actor_class` (goal_directed / possible_mimic / accidental_scraper / unclassified), `floor_applied`; leads stay severity "low" with human review, never automatic action.
- New synthetic web simulator (`web_simulator.py`), `demo --web`, `generate --web`, `scripts/eval_web.py`, sample export from agent-watch in `tests/data/`.

## Before / after
### agent-watch (seed 7, `scripts/eval_v3.py`; also `agent-watch/docs/eval-v3.md`)
| | v2 as shipped | v3 |
|---|---|---|
| mimic clients seen at all (12) | 0 / 12 | 12 / 12 |
| mimic recall, label `agent` | 0 / 12 | 6 / 12 (0.50) |
| mimic alerted (>= medium) | 0 / 12 | 9 / 12 (0.75); 9 / 9 excluding the evader `mimic_assets` |
| `mimic_assets` (evader) | invisible | still undetected (0 / 3) |
| `mimic_linked` | invisible | alerted medium (`possible_mimic`) 3 / 3, but labelled `agent` 0 / 3 |
| humans alerted (of 12) | 0 (vacuous: web humans weren't even visible) | 3 / 12 = 0.25 - all three are "images blocked" humans (a false positive of asset starvation); 0 / 9 otherwise |
| naive scraper (hidden link) | label human, severity high (bug) | static_bot, medium, accidental_scraper |
| original 20 actors labelled correctly | 20 / 20 | 20 / 20 |
Ablation: with the mirror visible but the new detectors/floors off, nothing is alerted (0 / 12): the mirror gives visibility, the detectors give the alerts.

### rogue-ai-pipeline (5 seeds, `scripts/eval_web.py`; `sample_outputs/web_evaluation.md`)
| | v2 | v3 |
|---|---|---|
| mimic clients (60) producing a lead | 0 / 60 | 45 / 60 (0.75); 45 / 45 excluding `mimic_assets`; `mimic_assets` 0 / 15 |
| benign web clients (45) producing a lead | 0 / 45 | 0 / 45 (only because the sim sends correct Sec-Fetch for "images blocked" humans) |
| commodity scanners (40) with a lead | 33 / 40 (noise) | 0 / 40; 40 filtered (560 events), 33 would be leads with the filter off |
| accidental scrapers (15) | 0 / 15 visible | 15 / 15 leads, all `accidental_scraper`, review queue |
| goal-directed MCP/decoy agents (25, 5 with a zgrab UA) | 0 / 25 | 25 / 25 `goal_directed`, review_first |
| unrelated benign background leads (380 agents) | 68 | 68 (unchanged) |
The existing standard evaluation (`run.py evaluate --seeds 5`) was re-run and its output is **identical** to the checked-in `sample_outputs/evaluation.json`.

## Test results (final fresh venvs)
- agent-watch: **339 passed, 1 skipped** (the skip needs pydantic + sibling pipeline; run separately with the pipeline venv: passes).
- rogue-ai-pipeline: **258 passed** (203 pre-existing + 55 new; pytest.ini uses -q so the summary line is hidden, counted from the progress dots, 0 failures) in a fresh venv; `mypy rogue_pipeline run.py`: no issues in 25 files.

## What remains untested / not done
- **Real LLM never run.** No Ollama on the box (`which ollama` empty, nothing on 11434); no model downloaded, no external API called. The harness is tested with a stub model only.
- **JA4/JA4H: design note only**, no TLS capture, nothing tested.
- **No Docker or nginx run here**; the nginx change (PR #2 port) is checked by text/parse tests. The PR author's `nginx -t` result is theirs.
- `mimic_assets` evades by design; a careful real agent in a real browser looks like it.
- "Images blocked" humans are false positives of asset starvation in agent-watch (medium); the pipeline avoids them only because the simulator sends Sec-Fetch.
- R8 alone is below the lead threshold, so the pipeline would miss `mimic_linked` on logs without Sec-Fetch; link-graph rules (R9) abstain on ordinary logs; scanner path/UA lists are examples.
- Tiny n (1-5 per group), one or five seeds, same-author simulation: nothing here measures real-world recall/FPR.
- Duplicate robots.txt entries in the pre-existing legacy generator were not fixed.
- The PR #2 scrubber fix was ported to agent-watch only (that is all the PR touched); the pipeline's own HMAC pseudonymiser was not changed.

## Files
- /workspace/agent-watch, /workspace/agent-watch.zip; /workspace/rogue-ai-pipeline, /workspace/rogue-ai-pipeline.zip
- /workspace/github-upload-v3/agent-watch/, /workspace/github-upload-v3/rogue-ai-pipeline/ (unzipped, no venvs/caches)
- Docs: agent-watch/redteam/README.md, agent-watch/docs/{ja4-tls-fingerprinting,eval-v3,security-review,docker-smoke-test}.md
