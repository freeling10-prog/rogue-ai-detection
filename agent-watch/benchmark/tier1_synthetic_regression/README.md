# Tier 1 - synthetic regression (SAME-AUTHOR SYNTHETIC)

Everything here comes from simulators written by the same author as the detectors. It answers "did my change break something I already
handle?" and nothing else. Every exported record carries `"same_author_synthetic": true`.

- Exporter: `export.py` (`export_tier1`). Reads existing eval JSON (`docs/eval-*.json`, the pipeline's `sample_outputs/*evaluation.json`)
  and, unless `--no-generate`, re-runs the generators for seeds 0-4 in-process (agent-watch needs Flask; if it is missing that source
  is reported `skipped`, not faked).
- The heavyweight eval scripts (`scripts/eval_v3.py`, the pipeline's `scripts/eval_web.py`) need old source trees; run them yourself and
  pass the resulting JSON with `--eval-json`.
- Do not put real or LLM-produced traces here. Use tier 2 / tier 3.
