# Benchmark protocol: three tiers, never merged

The toolkit (`benchmark/`, `scripts/build_benchmark.py`) packages traces into three **strictly separated** tiers so that a synthetic
regression check is never mistaken for a real-world benchmark. It makes **no network connection** (honeypot targets are 127.0.0.1 only;
nothing is downloaded, pulled or uploaded by the toolkit), and it refuses to package anything containing a raw secret.

```
python scripts/build_benchmark.py --out benchmark_out            # all tiers; tier1 re-generates seeds 0-4 (~25 s with Flask, ~3 s without)
python scripts/build_benchmark.py --out benchmark_out --no-generate   # tier1 from existing eval JSON only
python scripts/build_benchmark.py --check-jsonl some.jsonl       # just verify a file is secret-free
python -m pytest tests/test_benchmark.py -q                      # tests (fast, no Flask/pydantic needed)
```

Exit codes: 0 ok, 2 validation failed, 3 secrets found (nothing packaged), 4 usage. Output: `<out>/tier1_synthetic_regression/`,
`tier2_local_real_llm/`, `tier3_wild_honeypot/` and `manifest.json` (per-tier metrics listed separately + an explicit NOT COMPARABLE note;
`--generated-at` or `BENCH_GENERATED_AT` makes it byte-reproducible).

## What each tier is, and can / cannot claim

| | Tier 1 `tier1_synthetic_regression` | Tier 2 `tier2_local_real_llm` | Tier 3 `tier3_wild_honeypot` |
|---|---|---|---|
| Data | simulators written by the detector author (agent-watch `synthetic.py`/`webagents.py`, pipeline `simulator.py`/`web_simulator.py`) | real local models (Ollama/API via `redteam/llm_agent.py`) or headless browsers against a loopback honeypot | live nginx/gunicorn honeypot logs from an isolated edge host |
| Status today | populated (regression only) | **EMPTY** - never run against a real model | **EMPTY** - no wild data yet |
| Stamp | every record `"same_author_synthetic": true` | `provenance.real_capture: true`; `stub: false` | `provenance.json` (operator assertions) |
| CAN claim | "this change did / did not alter behaviour on our fixed scenarios" | "against *these* models and prompts the honeypot/detectors did X" (descriptive, small n) | "this is what reaches a public honeypot": volumes, scanner share, which decoys/rules fire |
| CANNOT claim | real-world detection, generalisation, fair comparison | population performance, unlisted models, wild behaviour | detector accuracy (no ground truth), that anyone is an AI agent |

**Never** average, pool, rank or compare numbers across tiers. The manifest keeps each tier's metrics in its own block; tier-2 stub numbers go
under `stub_selftest_metrics` and never under `metrics`.

## Labelling rules

1. Anything produced by our own generators is `same_author_synthetic: true`, and says so in README, record, and manifest.
2. Tier 2 requires a human to have actually run the model/browser. Hand-written fixtures must be `stub: true`, `real_capture: false`,
   `run_id` starting `STUB-`, and are rejected unless `--allow-stub` (tests only). The shipped stub is `STUB-NOT-REAL-0001`.
3. The operator's prompt is an *intent* (`benign_control`, `aggressive_audit`, `stealth_mimic`), not ground truth about what a detector should say.
4. Tier 3 has no labels. `harness_archetype` (key on log records, `detail`, or a bundled report's sessions) is a descriptive signature: when
   absent, clients are `unlabelled`. State who assigned labels in `provenance.archetype_labels`.
5. An eval output that does not declare 5 seeds (e.g. `eval_v3.py`, default seed 7) is reported with `seeds_declared: null` and a note; it is not 5-seed data.

## How to capture

### Tier 1 (automatic)
Regenerate eval JSON with the existing scripts (they need an old source tree): `scripts/eval_v3.py --old-tree ... --out ...`,
`rogue-ai-pipeline/scripts/eval_web.py --v2-tree ... --out ...` or `run.py evaluate`, then pass `--eval-json <file>`. The builder also
re-runs the generators for seeds 0-4 and records ground-truth labels plus event counts and sha256 digests (so a silent change in generator
output shows up as a hash diff). If Flask (agent-watch) or pydantic (pipeline) is missing that source is reported `skipped` - never faked.

### Tier 2 (manual, local)
See `benchmark/tier2_local_real_llm/README.md`. Short form: run the honeypot on 127.0.0.1, run `redteam/llm_agent.py` (or a headless browser)
against it, save the transcript and the honeypot's leads/access streams, write `run.json`, drop the directory in
`benchmark/tier2_local_real_llm/slot/<run_id>/`. The validator enforces: schema-valid files, loopback-only target/URLs/client IPs, step order,
plain file names, no secrets, and honest provenance. The scorer reports steps, distinct paths, honeytoken hits and (if a report is attached)
max severity, per prompt and per model. No accuracy is computed.

### Tier 3 (manual, isolated edge host)
Pull `*.access.jsonl` / `*.leads.jsonl` (and optionally `agentwatch analyze --json-out` reports) from an isolated edge host (no credentials,
no private network, nothing of value) into `benchmark/tier3_wild_honeypot/slot/` with a `provenance.json`. **Before packaging** every file is
scanned for sk- API keys, GitHub tokens, AWS access keys, JWTs, Bearer tokens, emails and the honeypot's fake-credential tokens (AWFAKE),
including encoded variants (`%40`, double percent-encoding, `\uXXXX`, literal and real newline-split). One hit refuses the whole bundle
(exit 3, nothing written). Fix at the source or use `--scrub-inputs` (project scrubber + decoy redaction, then re-verify). The final bundle,
manifest and dataset card are scanned again. `DATASET_CARD.md` reports cohort counts, commodity-scanner filter stats, rule firing
distributions and harness-archetype breakdowns; with an empty slot it says "NO WILD DATA YET". Client IPs are never printed in the card, but
raw logs in the bundle can contain them (they are not treated as secrets): review before sharing.

## Leakage and same-author caveats

- Tier 1: detector thresholds were tuned while looking at these same simulators (each mimic variant was written with the detectors in mind). Scores are
  *expected* to be high; a drop is informative, a high value is not evidence. Do not tune on tier 2/3 and then report on the same traces.
- Tier 2: the same person wrote the prompts, the honeypot decoys and the detectors. Models can also have seen public descriptions of
  honeypots. Keep a held-out set of runs that were never used for tuning, and record model name/version and prompt text name.
- Tier 3: the scanner filter in the dataset card is a local mirror of `rogue_pipeline/prefilter.py`; it can drift and is also written by us. The lack of
  labels means rules can be described, not scored.
- Archetype labels produced by `fingerprint.py` are tool-assigned; do not use them both as the label and as the thing being evaluated.
- The decoy documents served by the honeypot are synthetic; the traffic hitting them is real in tiers 2/3.

## Adding new traces

1. Tier 2: create `slot/<run_id>/run.json` + `transcript.jsonl` (+ `leads.jsonl`, `access.jsonl`, `report.json`), `run_id` unique, matching
   `^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`. Run `python scripts/build_benchmark.py --out /tmp/check`; fix whatever the validator reports.
2. Tier 3: add files to `slot/` (flat directory, `provenance.json` required); rebuild.
3. Tier 1: new generator? add it to `benchmark/tier1_synthetic_regression/export.py` and stamp its records with `stamp()`.
4. Never add real traces to tier 1, and never relabel a stub as real. Add a test for any new validator rule.

## Files

`benchmark/{common,secrets_guard,minischema,packer}.py`, `benchmark/tier1_synthetic_regression/export.py`,
`benchmark/tier2_local_real_llm/{validator,scorer}.py` + `schema/*.json` + `fixtures/stub_run/` (stub, test-only) + `slot/`,
`benchmark/tier3_wild_honeypot/{validator,dataset_card}.py` + `schema/provenance.schema.json` + `slot/`, `scripts/build_benchmark.py`, `tests/test_benchmark.py`.
