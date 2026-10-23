# Rogue-AI Detection Pipeline (multi-layer, defensive, synthetic data only)

A modular Python 3 pipeline that looks for AI agents behaving outside their remit, and turns what it finds into
**leads for human review**. It is a research prototype built on the earlier `rogue-ai-detection` prototype, but it is
standalone: nothing in this directory imports from it.

> **Scope and safety, in four lines**
> 1. **Defensive use only.** The pipeline can only *rank things for a person to look at*. It has no code path that
>    blocks, bans, throttles or terminates an agent (enforced in code and in tests, see "Guardrails").
> 2. **Synthetic data only (by default).** The default config refuses any event not labeled `synthetic=true`. Real traffic needs
>    a deliberate operator decision (`normalization.require_synthetic = false`, see `config/production-example.toml`).
> 3. **No network access.** No module opens a socket; a test fails if any import or call would.
> 4. **Not a benchmark.** Evaluation numbers come from a simulator written by the same author as the detectors.

## Project layout

```
rogue-ai-pipeline/
  run.py                      CLI: demo | generate | detect | train-baseline | inspect-baseline | ingest-coordination |
                              evaluate | verify-log | export-stix | check-atlas | selftest      (--production on most)
  requirements.txt            minimum versions (stix2-validator is pinned, see note); shellcheck-py is dev-only
  config/default.toml         every threshold, strictly validated (unknown keys are rejected)
  config/production-example.toml   the deliberate `require_synthetic = false` override for real traffic
  deploy/sync_and_score.sh    Zone B pull -> score -> verify -> STIX -> anchor workflow (see "Zone A / Zone B")
  rogue_pipeline/
    config.py                 pydantic config + Policy (declared tools, schedules, orchestrator pools)
    schema.py                 RawEvent (strict, extra=forbid), NormalizedEvent (pseudonyms only), redaction-marker regex
    pseudonymize.py           keyed HMAC-SHA256 pseudonyms; dev/production key policy (resolve_key, check_production_secret)
    normalize.py              validation + quarantine + pseudonymization + shingling + capture sanitization + marker extraction
    identity.py               simulated HTTP Message Signatures (RFC 9421-shaped, HMAC) + IP/ASN allowlists, per event
    features.py               per-agent / per-session features
    layer1_anomaly.py         Layer 1 (batch): IsolationForest + plain-language explanations
    baseline.py               Layer 1 (frozen): own Isolation Forest, versioned + hashed .npz, online scoring
    sequence_model.py         first-order Markov action-order model (timing-independent), fusion gate
    layer2_rules.py           Layer 2: deterministic rules R1-R7 (+ v3 web rules R8-R10) with ATLAS ids and evidence
    prefilter.py              v3: commodity-scanner pre-filter (before scoring AND before baseline training; counts reported)
    web_simulator.py          v3: synthetic web clients (browsers, scanners, accidental scraper, mimics, MCP agents)
    layer3_graph.py           Layer 3: bipartite coordination graph, edge kinds, suppression
    fusion.py                 noisy-or fusion into Lead objects (invariants enforced in the constructor)
    audit.py                  hash-chained audit log (persisted across runs) + verifier + anchor check
    atlas.py                  ATLAS technique table (+ offline verifier against a local ATLAS YAML)
    ingest.py                 agent-watch coordination-event JSONL -> RawEvent
    simulator.py              synthetic telemetry: hard negatives + injected scenarios (+ evasive variants)
    evaluation.py             precision / recall / FPR per scenario, before/after variants, ablations, checks
    stix_export.py            STIX 2.1 export of human-confirmed leads, validated with stix2 + OASIS validator
    reporting.py, pipeline.py
  scripts/eval_web.py         v3 before/after web-client evaluation (needs the old tree for the "before" column)
  tests/                      pytest suite (see "Tests")
  sample_outputs/             evaluation.md/json (v1.1) and a demo run (leads, audit log, quarantine, STIX bundle)
```

## How the layers fit

```
raw events ──► normalize ──► features ──► Layer 1  IsolationForest (population-relative anomaly + explanations)
 (JSONL)      validate        per agent ─► Layer 2  rule gates R1-R5 (ATLAS-tagged, evidence events)
              quarantine                 Layer 3  coordination graph (timing + content), suppression
              pseudonymize ─────────────────────► fusion ──► Leads (low severity, human_review, no automatic action)
              (HMAC, BEFORE features)                        └──► hash-chained audit log ──► verify-log
                                                  confirmed by a human ──► export-stix (STIX 2.1)
```

**1. Normalization.** `RawEvent` is strict (no unknown fields, no silent type coercion, valid IPs/hostnames/timestamps,
control characters rejected). Anything invalid, unlabeled-synthetic, over-long or duplicated goes to **quarantine** with
machine-readable reasons; quarantine records hold a SHA-256 of the input and field *names* only, never raw values.
Agent IDs, IPs, user IDs and resource names are replaced by **keyed HMAC pseudonyms** *before* feature extraction; the
feature code accepts only `NormalizedEvent` and raises `TypeError` otherwise. Free text is reduced to keyed hashes of
word shingles (numbers, URLs, e-mails and long blobs masked first) and then discarded.

**2. Layer 1 (Isolation Forest).** Eight per-agent features: event rate, inter-event variation, hour-of-day entropy
(timing); denied-to-allowed ratio, sensitive-resource hits (access); external-destination ratio, new-tool ratio,
new-external-host ratio (tool use). Scores are population-relative (fit on the batch). Every agent above the flag
threshold gets up to three explanations such as *"Denied-to-allowed request ratio: 0.49 versus a population median of
0.02 (about 21.4x the typical value) - many more refused requests than peers (robust z=+19.9)"*, ranked by how much the
score drops when that feature is replaced by the population median.

**3. Layer 2 (rules).** Deterministic; R3/R4 are exemptable per event by verified identity (see below); each flag lists evidence events and the note *"The MITRE ATLAS mapping is
approximate"*.

| Rule | ATLAS | Fires when |
|---|---|---|
| R1 | AML.T0051 LLM Prompt Injection | untrusted content is read, then within 300 s a tool is invoked that is neither in the agent's baseline nor its declared list |
| R2 | AML.T0053 AI Agent Tool Invocation | a tool call is outside the agent's declared purpose (Policy) |
| R3 | AML.T0086 Exfiltration via AI Agent Tool Invocation | a write-capable tool sends >= 1000 bytes to an external host never contacted before |
| R4 | AML.T0051 (approx.) | an outbound call to a new external host occurs within 60 s of reading untrusted text |
| R5 | AML.T0075 Enterprise Resource Discovery (approx.) | many denied requests concentrated on sensitive resources. *Extra rule: R1-R4 cannot see pure access probing.* |

| R6 | AML.T0051 (+ T0053/T0086 as evidence dictates; approx.) | agent engaged the decoy coordination-board / claim-shard protocol of the honeypot (legitimate agents are never sent there) |
| R7 | AML.T0051 (+ T0053/T0086; approx.) | agent disclosed its own system-prompt summary / declared tools to a decoy ("cognitive capture") |

R1/R3/R4 compare with the agent's own baseline (first hour, >= 20 events) and **abstain** without one. ATLAS IDs/names
were checked against `ATLAS-2026.09` (`run.py check-atlas --yaml <local file>` re-checks offline).

**4. Layer 3 (coordination graph, Pacheco-inspired).** Bipartite graphs agent-to-time-window and agent-to-content-shingle
(`networkx`), projected onto agents: timing similarity = hypergeometric surprise of shared 15 s windows, content
similarity = IDF-weighted cosine over rare shingles (shingles used by >15 % of agents are pruned as popular). Edge weight
= 0.5 x timing + 0.5 x content with threshold 0.55, which is **above either signal's maximum, so an edge needs both
timing and content agreement** (tests prove timing-only and content-only groups form no cluster). Connected components
are clusters; loosely-knit components are split into Louvain communities (found during evaluation: two rings bridged by
one chance edge were diluted below the lead threshold). Cluster density = mean edge weight x edge density.
**Suppression** (suppressed clusters are kept in the audit log but contribute nothing):
* `declared_group` - every member belongs to a declared schedule allowlist or orchestrator pool (`Policy`);
* `periodic` - every member runs on a strict fixed schedule (undeclared cron);
* `template_fanout` - one identical template sent to many *diverse* targets in a burst (broadcast notices).

**Graph edge kinds (v1.1).** `timing_content` (above); `semantic_state` (sessions on different IPs that hand the same opaque
state tokens - cursors, request ids - to each other; graded, needs >= 3 distinct tokens for weight 0.6; used to stitch
proxy-rotated sessions); `cross_ip_token_handoff` (agent-watch honeypot: session B *presents* a one-time handoff token that
the decoy issued to session A on another IP; deterministic, weight 1.0, **exempt from suppression** unless the token holder is a
*declared orchestrator*); `shared_redacted_token` (see below; moderate, weight 0.6, capped at 0.75, subject to suppression).

**5. Fusion.** `score = 1 - (1 - 0.5*anomaly)(1 - 0.9*rules)(1 - 0.8*graph)(1 - 0.5*sequence)`; a lead needs score >= 0.55.
`FusionCfg` *refuses to load* if `w_anomaly` **or** `w_sequence` is >= `lead_threshold`, so neither the forest nor the sequence
model alone can create a lead. **Design consequence you should know about:** both at maximum together give 0.75, so
*Isolation Forest + sequence model with no rule and no graph evidence* can still produce a (low-severity, human-review) lead.
The sequence score only counts when it passes a gate (0.6).

**6. Audit log.** JSONL, each record carries the previous record's hash. `verify-log` detects modification, deletion,
insertion and reordering and says which line. A chain alone cannot detect truncation of the *tail* if the attacker also
deletes the sidecar `.head` file; store the printed head hash elsewhere and pass `--anchor <hash>` for a real guarantee.

### Guardrails ("leads for human review, never block triggers")
* `Lead.__post_init__` raises unless `severity == "low"`, `recommended_action == "human_review"`,
  `automatic_action == "none"`, and there is rule, graph or sequence-gate evidence (Isolation Forest alone is never enough). `Lead` is frozen.
* `priority_band` (`review_first` / `review`) only orders the queue; it is not a severity.
* Tests: construction with other values fails; maximal anomaly score alone yields no lead; a static AST scan of the
  package fails on names like `block`, `ban`, `terminate`, `throttle`, `revoke`; another scan fails on network imports.
* STIX export only includes leads a human explicitly confirms (`--confirm LEAD_ID`).

## v1.1 additions

### Frozen baseline and online scoring
`python run.py train-baseline --events benign.jsonl --baseline-out baseline.npz` (or `--simulate-reference` for synthetic
benign data) fits **once** on benign reference data and saves a versioned `.npz` (no pickle) with a SHA-256 content hash over
the manifest and every array. `detect --baseline baseline.npz [--expect-baseline-sha256 H]` then scores **each agent/session
alone** against the frozen model: no population needed; a session with < 8 events gets "insufficient evidence", never a guess.
Any corruption, hash mismatch, wrong format version or different feature set is refused (exit 7). The batch Isolation
Forest still runs when no baseline is given. The frozen forest is our own numpy implementation of the Isolation Forest
scoring rule, calibrated by k-fold cross-fitting on held-out *reference* agents (so reference agents are not scored by a
forest that saw them). **If the reference set contains malicious agents the baseline learns them as normal.**
`river` (0.26.1) installs cleanly here but is **not integrated**: a quick HalfSpaceTrees trial on the same synthetic agents gave
AUC 0.66-0.68 and varied with the seed, so it was not worth a dependency.

### Sequence model (fusion gate)
A first-order Markov model of action *categories* (read / write-external / denied-sensitive / ...), fit on the same benign
reference. A session's score is its worst 30-transition window of surprisal (bits per transition), calibrated to 0..1 on
held-out reference agents; **timing is deliberately ignored**, so throttling a probe does not hide it (tested: stretching timestamps
37x leaves the score identical). It adds evidence only above a 0.6 gate. It is blind to an attacker who *replays benign
transition statistics* - the `seq_mimic` scenario exists to show that, and it still evades (recall 0.00, see below).

### Verified identity and allowlists (applied before scoring)
Events may carry a simulated RFC 9421-shaped HTTP Message Signature (HMAC-SHA256 over a canonical signature base, key looked
up in a local registry by `keyid`; fresh within 300 s). A *verified* partner is exempted from the rules its registry entry lists
(R3/R4), only for destinations the entry covers, **per event**: a spoofer cannot hide behind a verified stream, and an event
that fails verification **vetoes every allowlist for that event**. IP/ASN allowlists (CIDR / ASN + destination suffixes) work
the same way. Unknown keyid, bad signature, stale `created` and unreadable registry all fail closed (the event stays scored).
Exemptions are counted and written to the audit log. It is a **simulation** of the mechanism, not an implementation of any
partner's real signing scheme or key distribution.

### Honeypot coordination events and redacted tokens
`ingest-coordination` / `detect --coordination` convert agent-watch `agentwatch.coordination-event/1` records (handoff / nonce
issued and presented, cognitive capture) into RawEvents; invalid or other-schema records are skipped and counted. Captured
agent text is **untrusted data**: control characters stripped, per-field length caps (truncate), hard oversize -> quarantine,
audit log stores only a hash of capture text, STIX carries truncated copies in `x_untrusted_agent_capture`.
agent-watch's scrubber replaces secrets with `[REDACTED_<TYPE>_SHA256:<10 hex>]`. The pipeline treats a marker as an
**opaque, correlatable token**: it is re-hashed with the keyed HMAC, masked in text before shingling, never parsed and never
"unredacted". Two sessions presenting the same marker get a **moderate** `shared_redacted_token` edge (distinct from the
deterministic handoff edge; a marker shared by more than 6 sessions is "popular" and ignored). Same-marker is weak evidence: it
may be one shared service credential, so this edge alone stays below the lead threshold.

### Production key enforcement
| mode | how selected | key used | behaviour |
|---|---|---|---|
| dev (default) | nothing set | `ROGUE_PIPELINE_HMAC_KEY` (>= 16 bytes); if unset, `PIPELINE_HMAC_SECRET` as a length-checked fallback | `--ephemeral-key` allowed (demos) |
| production | `--production` flag **or** `PIPELINE_ENV=production` | **only** `PIPELINE_HMAC_SECRET` | strong secret required, no fallback, `--ephemeral-key` refused, exit code **6** before any processing |

If **both** variables are set: dev mode uses `ROGUE_PIPELINE_HMAC_KEY`; production mode **ignores** it (it is an error if it equals the
secret, so the dev key cannot be reused as the production key). A strong secret is >= 32 bytes after decoding (>= 64 hex chars, a
strict base64 string of >= 44 chars) or >= 32 chars of text, with basic entropy checks (>= 12 distinct bytes, >= 3.3 bits/byte, no repeated
blocks or sequential runs) and a refusal of obvious defaults (`test`, `changeme`, `password`, `secret`, `demo`, `ephemeral`, all-same
characters, ...). The error names the reason and **never echoes the secret**. This is a sanity check against accidents, not proof of
randomness: generate it with `python -c 'import secrets;print(secrets.token_hex(32))'`. Pseudonyms (and therefore lead ids) depend on the secret, so
keep the same secret across runs or STIX confirmation by lead id will not find old leads.

### Zone A / Zone B (deploy/sync_and_score.sh)
```
 Zone A (sacrificial honeypot host)            Zone B (analysis host)
 agent-watch decoys + logs, exports to  <---- one-way PULL over ssh (read-only rrsync, restrict, from=) ----  this script
 a read-only export dir; no credentials                                   spool -> agentwatch analyze -> export-leads ->
 for B; no outbound connection to B                                       run.py detect --production --baseline ... ->
                                                                          verify-log -> STIX (human-confirmed only) ->
                                         off-host append-only anchor  <-- audit head hash
```
Zone A is assumed compromisable; everything pulled is untrusted. The script uses `set -euo pipefail`, takes hosts/keys/secrets
**only from environment variables**, never pushes to A, never uses `--delete`, defaults to `rsync --ignore-existing`
(`SYNC_MODE=append` uses `--append-verify`), unsets the dev key and exports `PIPELINE_ENV=production`, verifies the audit
log against the previous anchor before and after each run (the log persists across runs via `--append-log`; `verify-log
--anchor` requires the log to *end* at the anchored head), exports STIX only for lead ids a human listed in `CONFIRMED_LEADS_FILE`, and
appends `timestamp head-hash` to a local anchor file and to an off-host anchor store via an ssh forced command. `--dry-run`
prints every command and touches nothing. The `authorized_keys` options for both keys are documented in the script header
(they cannot be enforced from B). Shellcheck-clean (checked with `shellcheck-py`).

## v3: web-collector evidence, commodity-scanner pre-filter, floors

> Added after a live demo of the sibling `agent-watch` honeypot found that a browser-UA, human-paced client that never touched a
> decoy left zero leads, and that a naive scraper that hit one hidden link was ranked "high" but labelled human.
> **Everything below was tested on synthetic clients written by the same author as the rules (see "What v3 does NOT show").**

**Input.** `RawEvent` gained an optional strict `web` block (`WebMeta`, unknown fields forbidden): `content_kind`, `referer_valid`,
`linked_from_prev`, `offered_earlier`, `sec_fetch_mismatch`, `strong_signal`, `decoy_kind`, `mcp`, optional `ja4` and the raw
`user_agent`. agent-watch produces it with `python -m agentwatch export-web leads.jsonl leads.jsonl.access.jsonl --out web.jsonl
--label-synthetic` (`tests/data/agentwatch_web_export_sample.jsonl` is a checked-in sample that the tests validate). The
normalizer reduces the User-Agent to `ua_class` (browser / scanner / declared_bot / other) and **discards it**; resource paths
become flags (`scanner_path`), never stored. Events without a `web` block behave exactly as in v1.1 (the existing 203 tests and the
evaluation tables are unchanged by construction).

**Rules** (no session averages; each looks at single facts):

| rule | fires when | strength |
| --- | --- | --- |
| R8 asset starvation | >= 5 successful HTML page loads, a browser-claiming UA, **zero** CSS/JS/image/favicon fetches (abstains for declared bots/scripts) | 0.50; 0.65 if >= half the page loads also lack browser `Sec-Fetch-*` |
| R9 unlinked jump | >= 2 transitions to a URL **no page ever offered this client**, without a valid Referer (breadth-first queue moves to earlier-offered URLs are *not* counted) | 0.55 + 0.05 per extra, cap 0.80 |
| R10 strong-signal floor | one high-signal event: decoy contact, session canary, schema parameter, error-hint follow, MCP `tools/call` | sets a **fusion floor**: 0.80 if the client *used* something a decoy offered (or touched >= 3 decoy kinds), 0.58 for a lone hidden-link/decoy contact |

R8 alone is deliberately **below the lead threshold** (0.9 x 0.5 = 0.45; a person with images blocked looks identical); it becomes
a lead only with the `Sec-Fetch-*` mismatch (0.585) or with R9/R10. **Floors** are applied after noisy-or as `max(score, floor)`:
nothing in fusion averages over a session, so any amount of benign padding cannot pull a flagged client below its floor (tested
with 0 / 50 / 500 padding pages).

**Accidental scraper vs goal-directed agent.** `Lead.actor_class` is a triage hint derived from the flags:
`goal_directed` (R10 strong tier, R6/R7, or R8 + R9 together), `possible_mimic` (R8 or R9 alone), `accidental_scraper` (only a weak
R10: one hidden-link/decoy contact, no adaptive behaviour), `unclassified` (every non-web lead). A lone hidden-link hit lands in the
normal `review` queue (score 0.58 < 0.75), a client that parsed a schema or called an MCP tool lands in `review_first`.
It is a label for the reviewer, not a statement about intent. Leads are still always severity `low`, `human_review`, no automatic action.

**Commodity-scanner pre-filter** (`prefilter.py`, `[web]` config). Before scoring *and before baseline training*, a client whose events
are all web events is set aside when >= 80% of its requests are scanner paths (`*.php`, `/wp-login`, `/wp-admin`, `/xmlrpc`, `/.env`,
`/.git`, `/phpmyadmin`, `/cgi-bin`, `/actuator`, ...) or when any request carries a scanner User-Agent (zgrab, masscan, censys, shodan,
nmap, nikto, sqlmap, nuclei, wpscan, ...). **A scanner UA or path is not a hiding place:** a client that also shows goal-directed
evidence (schema parameter, MCP `tools/call`, session canary, error-hint follow, fake-credential use) is kept and counted separately; a
bare decoy touch is *not* exempting, because scanners hit the `/.env` and `/wp-login` decoys all day. Counts are reported, not hidden:
`PipelineResult.prefiltered`, a run note, an `audit.jsonl` `prefilter` record, the `leads.md` header, the CLI line
`[prefilter] set aside N ...`, and the baseline metadata (`n_prefiltered_scanner_agents`). Non-web events are never filtered
(your `/config/.env` access prober is still scored). Run `python run.py demo --web --out out_web` to see it.

### v3 before/after (5 seeds; synthetic web clients; regression check, NOT a benchmark)
`python scripts/eval_web.py --old-tree <pristine v2 tree> --out eval_web_out`; full tables in `sample_outputs/web_evaluation.md/.json`.
Per seed: the standard simulator's ~76 benign background agents (380 over 5 seeds) + 8 scanner clients, 9 human browsers (5 normal, 4 with images blocked), 3 accidental scrapers, 12
mimics (basic / linked / assets / schema) and 5 MCP / decoy-exploring agents (incl. one with a zgrab UA). "v2" = the previous code on the
same events with the `web` block stripped (v2 cannot represent it).

| metric (pooled over 5 seeds) | v2 | v3 |
| --- | --- | --- |
| mimic clients (60) that produce a lead | 0 / 60 (0%) | 45 / 60 (75%) |
| ... excluding `mimic_assets`, the variant built to evade | 0 / 45 | 45 / 45 |
| `mimic_assets` (loads assets, sends Sec-Fetch-*) | 0 / 15 | **0 / 15 - still invisible, on purpose** |
| benign web clients (45) that produce a lead | 0 / 45 | 0 / 45 (incl. 20 "images blocked" humans, **but only because the sim sends correct Sec-Fetch-* for them**) |
| commodity scanners (40) that produce a lead | **33 / 40 (noise leads from R5)** | 0 / 40 (40 set aside and counted; 33 would be leads with the filter off) |
| accidental scrapers (15): lead / class | 0 / 15 (not visible) | 15 / 15, all `accidental_scraper`, queue `review` |
| goal-directed MCP/decoy agents (25, incl. 5 with a zgrab UA) | 0 / 25 | 25 / 25, all `goal_directed`, queue `review_first`; the 5 zgrab-UA agents were *kept* by the exemption |
| non-web benign background leads (380 agents over 5 seeds) | 68 | 68 (same agents in 5 / 5 seeds) |

### What v3 does NOT show
* The simulated clients and the rules share an author, and each mimic was written to look human *with these rules in mind*.
  `mimic_assets` evades by construction (it loads assets and sends proper headers) and a careful real agent would too.
* The `web_human_no_assets` result (0 false positives) depends on the simulator sending correct `Sec-Fetch-*` for those humans.
  Without those headers (a log format that lacks them) R8 alone is below the lead threshold by design - which also means **R8 alone
  would miss `mimic_linked`**. Real browsers/extensions/proxies strip or alter these headers in ways not simulated here.
* Everything depends on the honeypot's link graph: R9 and the `linked_from_prev` flags exist only for traffic to a site that records
  what it served. On ordinary access logs they are absent and the rules abstain.
* Scanner path/UA lists are examples; a scanner with a browser UA whose requests are < 80% scanner paths is not filtered.
* No real traffic, no real agents, no real LLM was involved. Counts are tiny (1-5 clients per group per seed, 5 seeds).

## Quick start

```bash
cd rogue-ai-pipeline
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export ROGUE_PIPELINE_HMAC_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))')   # never commit this

python run.py demo --out out                       # simulate synthetic data, run all layers, write out/
python run.py verify-log --log out/audit.jsonl     # exit 0 = intact, 2 = tampering detected
python run.py export-stix --leads out/leads.json --confirm-all-synthetic --out out/bundle.json   # DEMO ONLY confirmation
python run.py demo --extended --frozen --out out2  # v1.1 scenarios, in-memory frozen baseline + sequence model
python run.py train-baseline --simulate-reference --baseline-out baseline.npz      # prints version + sha256
python run.py generate --extended --out data && python run.py detect --events data/events.jsonl --policy data/policy.json --baseline baseline.npz --out out3
python run.py evaluate --seeds 5 --ephemeral-key --out eval_out   # ~10 min; before/after tables, ablations, evasive runs (--v1: old tables)
export PIPELINE_HMAC_SECRET=$(python -c 'import secrets;print(secrets.token_hex(32))')
python run.py detect --production --events data/events.jsonl --baseline baseline.npz --out out4   # production key policy
python run.py selftest --ephemeral-key             # end-to-end smoke test incl. tamper check
python -m pytest -q                                # tests
```

Other commands: `generate` (writes `events.jsonl`, `policy.json`, `labels.json`), `detect --events FILE --policy FILE
[--identity-registry FILE] [--coordination FILE...] [--append-log]`, `inspect-baseline`, `ingest-coordination`,
`verify-log --log F [--anchor HASH]`, `check-atlas --yaml FILE`. Exit codes: 0 ok, 2 audit tampering, 3 STIX invalid,
4 ATLAS mismatch, 5 dev key missing/short, 6 production key refused, 7 baseline/registry error. Use `--ephemeral-key` for demos (random in-memory key, pseudonyms differ per run); without
it a missing key is an error, never a default.

Input format: one JSON object per line (`schema.py` lists fields). Example:
`{"event_id":"e1","ts":1772409600,"source":"api_gateway","agent_id":"agent-7","action":"tool_call","tool":"http_post","dest_host":"hooks.example.net","payload_bytes":4096,"synthetic":true}`.
Policy file: `{"declared_tools": {"agent-7": ["search_docs","http_post"]}, "suppression_groups": [{"kind":"schedule","name":"nightly","members":["cron-1","cron-2"]}]}`.

## Safely testing in a local sandbox
* Use a throwaway virtualenv in a scratch directory; the code only reads files you give it and writes under `--out`.
* Keep the sandbox offline if you like - nothing needs the network after `pip install`. (`pip install` itself does.)
* Never feed real telemetry: the default config quarantines everything not labeled `synthetic=true`. Turning that off
  (`require_synthetic = false`) is a decision for a separate, reviewed deployment: you would need a lawful basis, data
  minimization and retention rules, key management, a disclosure process and review of the legal limits (ToS, privacy
  law, computer-misuse law) - none of which this prototype provides.
* Do not point it at systems or agents you do not own or are not authorized to monitor.
* To see tamper detection: `cp out/audit.jsonl /tmp/a.jsonl && sed -i '3s/lead/leax/' /tmp/a.jsonl && python run.py verify-log --log /tmp/a.jsonl`.
* The HMAC key is the secret that protects people: whoever holds it can re-link pseudonyms. Rotate it to unlink old data.

## Tests
`python -m pytest -q` runs 258 tests (about 4-5 minutes), grouped by topic: **v3 web evidence** (strict `web` block, UA discarded, R8/R9/R10 positives and near-misses, floors vs padding, scanner pre-filter incl. spoofed-UA exemption and baseline hygiene, accidental vs goal-directed labels, a checked-in agent-watch export sample, `demo --web`), normalization (schema, quarantine, HMAC),
Layer 1, Layer 2 (each rule: positive, near-miss negative, evidence, ATLAS), Layer 3 (both-signals requirement, each suppression
with an off-switch counter-test), fusion/audit (guardrails, tamper detection), evaluation/STIX/CLI, **baseline + sequence**
(round trip, tamper, online == in-population score, timing independence, guardrails, evasive/mimic/holdout checks),
**identity + allowlists** (per-event exemption, spoof stays scored, fail-closed registry), **honeypot + redaction + state
edges** (benign agents ignoring the protocol, single follower, two-IP handoff edge and lead, sanitization/oversize,
no-reuse not linked, redacted marker edge distinct from handoff edge, popular markers ignored, proxy-rotation stitching,
never "unredacted"), and **production + deploy** (production refused without / with short / default-looking / ephemeral /
dev-key-equal secrets, accepted with a strong one; the deploy script in `--dry-run`, with no secrets in its text, strict mode,
shellcheck, and a stubbed end-to-end run including audit tamper detection).

## Evaluation (synthetic; regression check, not a benchmark)
**v3 web evaluation** (mimics, scanner pre-filter, accidental scrapers; v2 vs v3 on identical web clients over 5 seeds):
`sample_outputs/web_evaluation.md` / `.json`, regenerated with `python scripts/eval_web.py --old-tree <pristine v2 tree> --out DIR`.
Summarised in "v3 before/after" above. The standard-scenario tables below are unchanged by v3 and were re-run (see `sample_outputs/evaluation.json`).

Full tables (all scenarios, three evasiveness levels, regression checks): `sample_outputs/evaluation.md` / `.json`
(regenerate: `python run.py evaluate --seeds 5 --ephemeral-key --out eval_out`; keys are fixed per seed so numbers are
reproducible). 5 seeds, ~52k events per run, 565 benign and 255 positive agents pooled. Unit = agent. Frozen baselines are trained on
**separate benign reference seeds** (1000-1002), never on the run being scored.

**Before / after, standard (non-evasive) scenarios** - recall per scenario, FPR over all benign agents:

| variant | access_prober | exfil | collusion_ring | seq_mimic | proxy_rotation | overall_core recall | overall recall | FPR |
|---|---|---|---|---|---|---|---|---|
| A. batch IF, no sequence (v1.0-style) | 0.90 | 1.00 | 1.00 | 0.00 | 0.00 | 0.97 | 0.72 | 0.04 |
| B. frozen baseline, no sequence | 0.90 | 1.00 | 1.00 | 0.00 | 1.00 | 0.97 | 0.91 | 0.04 |
| C. frozen + sequence gate (v1.1 default) | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 0.92 | 0.06 |
| D. = C with identity/allowlists OFF | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 0.92 | 0.09 |
| E. = C, baseline trained WITHOUT 6 benign groups | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.00 | 0.92 | **0.32** |

**Evasive variants** (all injected scenarios regenerated in forms written with knowledge of these heuristics: throttled, jittered, baseline-seeded):

| variant | access_prober | exfil | collusion_ring | seq_mimic | overall_core recall | FPR |
|---|---|---|---|---|---|---|
| A. batch IF, no sequence | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.04 |
| B. frozen baseline, no sequence | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.04 |
| C. frozen + sequence gate | 0.25 | 0.70 | 0.00 | 0.05 | 0.24 | 0.06 |
| E. baseline missing 6 benign groups | 0.40 | 1.00 | 1.00 | 0.15 | 0.85 | 0.32 |

Reading it honestly:
* **The sequence gate helps against throttled evasion (core recall 0.00 -> 0.24 when all scenarios are evasive) and costs false
  positives**: FPR 0.04 -> 0.06 on standard runs. The new false positives are `compliance_scanner` (0 -> 7 of 10 agents pooled) and
  `noisy_denied` (0 -> 4 of 10): benign agents whose action *order* is unusual. `collusion_ring` evasion (jitter + paraphrase) is
  not helped by it (0.00).
* **The mimic still evades** (`seq_mimic` recall 0.00 standard, 0.05 evasive). It replays benign transition statistics, so a
  Markov model of action order has nothing to see. That is the documented limit of this gate, kept in the suite on purpose.
* **Unseen benign behaviour is the real risk**: a baseline trained without crawlers, scanners, cron jobs, orchestrator pools
  and broadcasters (E) puts FPR at 0.32 - those groups all get leads. "Recall went up" in column E is *not* a win; it is the
  detectors firing on everything unfamiliar. Baseline coverage of legitimate behaviour matters more than any threshold here.
* `proxy_rotation` recall is 0.00 under A and 1.00 under B/C. The graded `semantic_state` edges alone give weight 0.6 and **do
  not clear the lead threshold by themselves** (benign cross-IP session continuity such as mobile roaming would look the same);
  leads appear because the frozen Isolation Forest adds a thin margin of corroboration. The stitching itself works
  (40/40 consecutive session pairs joined) but the margin to a lead is thin.
* **Identity**: partner agents trip R3 without identity handling (20/25 verified/allow-listed partner agents flagged) and 0/25 with
  it, FPR 0.09 -> 0.06. Spoofers stay scored: 12/15 still carry an R3/R4 flag, 15/15 still produce a lead - **but 3 of 15 spoofers carried no R3/R4 flag** (the
  lead came from other evidence), so a spoofer is not guaranteed an R3 flag.
* **Known benign false-positive sources, kept in**: `partner_integration` 9/10 and `tool_adopter` 5/10 (legitimate change looks like
  an attack; that is what human review is for), `redaction_user` 7/40 (standard) up to 17/40 (mixed run). The `redaction_user` leads
  come from chance timing+content (`timing_content`) edges between agents sharing the simulator's peer-message templates,
  *not* from the redaction edge (0/140 agents sharing only a popular marker were joined). I did not resolve why this group is
  more affected than ordinary assistants (0/300); treat it as an unexplained simulator/graph interaction, not a result.
* **Honeypot checks (hp_handoff, hp_single, hp_nolink, redacted_reuse, partner_spoof) all score 1.00 because the logic is
  deterministic and the simulator was written by the same author as the detectors.** They test that the code does what it was
  written to do; they say nothing about real hostile agents. The hp_handoff edge is trivially caught by construction.

Regression checks (pooled, standard run): handoff pairs joined by `cross_ip_token_handoff` 15/15; no-reuse pairs wrongly joined 0/15;
benign agents ignoring the protocol with an R6/R7 flag 0/565; proxy-rotation pairs stitched 40/40; benign pagination clients wrongly
joined 0/30; redacted-reuse pairs joined by the moderate edge 10/10.

## STIX 2.1 export
Only human-confirmed leads. Contents: Identity (producer), Attack-Pattern objects referencing ATLAS (marked approximate),
Indicators (`user-account:account_login` = agent pseudonym; `domain-name:value` for new external hosts seen in R3/R4
evidence), `indicates` Relationships, one Note per indicator with the caveats, TLP:CLEAR marking (appropriate only because
the data is synthetic), confidence 40. The bundle is re-parsed with `stix2.parse` and checked by the OASIS `stix2-validator`.
**Dependency note:** `stix2-validator` 3.3.1 (latest) and 3.1.0 on PyPI ship *without* the STIX 2.1 JSON schemas and then
fail every object with "Cannot locate a schema"; `requirements.txt` therefore pins `stix2-validator==3.2.0`, which includes
them. The export command and tests report honestly if the validator is missing (`NOT RUN`), and a negative-control test
proves the validator rejects an invalid bundle.

## Limitations (read before relying on anything)
* **v3 limits** (details under "What v3 does NOT show"): the web simulator shares an author with the rules; `mimic_assets` evades by
  design; R8 depends on `Sec-Fetch-*` being logged and truthful; R9/`linked_from_prev` exist only for a site that records its link graph;
  scanner lists are examples (a scanner with a browser UA and < 80% scanner paths is not filtered; a spoofed scanner UA on a session with
  goal-directed evidence is deliberately not filtered); floors let one flagged event decide a lead; leads stay severity `low`
  / human review, never automatic action; ATLAS ids for R8-R10 are an approximate mapping.
* **Feeding it agent-watch output:** `python -m agentwatch export-web leads.jsonl leads.jsonl.access.jsonl --out web.jsonl --label-synthetic`, then
  `python run.py detect --events web.jsonl --out out_web --ephemeral-key`. Only for sandbox traffic you generated yourself; the
  `--label-synthetic` flag asserts that.
* **What remains unproven.** Everything above is on synthetic data from a simulator written by the same author as the detectors, with
  thresholds tuned while looking at it. The v1.1 numbers do not show the pipeline works on real agents; real agents have
  not been tested. The sequence model, the allowlists and the honeypot edges were each shown to do what they were coded to do.
* **Frozen baseline quality = reference quality.** Benign behaviour missing from the reference becomes a false positive
  (variant E: FPR 0.32); malicious behaviour inside it becomes "normal".
* **The sequence-model mimic evades**; IF + sequence together can raise a lead with no rule/graph evidence (see Fusion).
* **Simulated identity.** The signature scheme is an RFC 9421-shaped simulation with locally held HMAC keys, not real partner
  signing, key distribution or revocation. A stolen partner key would be accepted as that partner.
* **ATLAS mapping is approximate** (also for R6/R7 and the honeypot / coordination-board / cognitive-capture alerts: they are
  mapped to T0051/T0053/T0086 as the closest behavioural fits, not as findings). `check-atlas --yaml <local ATLAS file>` verifies ids and
  names only (last run against ATLAS 2026.09: match).
* **Synthetic data.** The simulator and the detectors share an author, and thresholds were tuned while looking at the
  simulator. Metrics are a regression check for the code. They say nothing reliable about real agents or real traffic.
* **ATLAS mapping is approximate.** ATLAS describes adversary techniques; rules observe behaviors consistent with them.
  R4 and R5 are looser fits than R1-R3. Tags are triage hints, never findings.
* **Heuristics can be evaded.** Slow, small, declared-tool, baseline-seeded, jittered or paraphrased activity defeats the
  rules and the graph (see the evasive run). Isolation Forest is relative to the batch: if many agents misbehave alike,
  none looks unusual. Suppressions are themselves an attack surface (an attacker who copies a declared schedule, or
  periodic timing, is suppressed).
* **Baselines.** Rules need ~1 hour / 20 events of history per agent and abstain otherwise; an agent compromised from
  its first minute has no clean baseline.
* **Content features are simple.** Word-shingle templates only; no semantic similarity; the simulator's benign text is
  random words, so benign content overlap is unrealistically low.
* **Batch, in memory.** No streaming or scaling work (the audit log persists across runs; nothing else does) (graph projection is O(agents^2) in the worst case).
* **Pseudonymization is not anonymization.** Behavioural profiles can still identify an agent's owner to someone who can
  correlate other data; HMAC protects against casual re-identification only while the key stays secret.
* **Audit log.** Tail truncation needs an external anchor; the log is not encrypted or access-controlled.
* **No legal or ethical review is embedded.** A real deployment needs authorization, lawful basis, privacy and
  disclosure processes that this repository does not supply.

## What was NOT tested
* **v3 web evidence**: only synthetic clients written by the same author as the rules; the agent-watch export was exercised on a checked-in sample and on an in-process demo, never on real web traffic, a real LLM agent or a real scanner population. `ja4` is parsed and validated only; no TLS fingerprint capture exists (see agent-watch `docs/ja4-tls-fingerprinting.md`).
* **No real remote host.** `deploy/sync_and_score.sh` was run end to end only with **stub `rsync`/`ssh` executables** against a local
  directory (plus `--dry-run`). Real rsync was **not installed** on the build machine, so rsync flag behaviour (`--ignore-existing`,
  `--append-verify`, `--safe-links`, `--max-size`) and the `rrsync -ro` / `restrict` / `from=` `authorized_keys` setup were
  **not exercised**; they were written from the rsync/OpenSSH documentation and are unverified here. Run `--dry-run` and a first real pull in a
  disposable environment before trusting it.
* **No Docker / containers / network isolation.** Zone A/B separation here is a *design and a script*; no firewall rules, host
  hardening or container sandbox was built or tested.
* **agent-watch** was used only as a local demo (its real `analyze` / `export-leads` output fed through the script, with
  stubbed transport). Its code was read, not modified.
* **No real traffic and no real secrets.** The production key check was tested with generated strings only.
* The off-host anchor store, the append-only forced command, and concurrent runs (two scorers appending to one audit log) were not tested.
* Scaling, streaming, and large populations (graph projection is O(agents^2)) were not tested.

## References used in the design
Liu, Ting & Zhou, "Isolation Forest" (ICDM 2008); Pacheco et al., "Uncovering Coordinated Networks on Social Media" (ICWSM 2021);
MITRE ATLAS (atlas.mitre.org, data release 2026.09); OASIS STIX 2.1 and the `stix2` / `stix2-validator` libraries; NIST AI RMF 1.0.
