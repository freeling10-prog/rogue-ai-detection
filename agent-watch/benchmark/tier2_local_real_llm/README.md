# Tier 2 - local real-LLM traces

**STATUS: EMPTY. No real trace has been captured yet.** `slot/` is intentionally empty (only a `.gitkeep`).
`fixtures/stub_run/` is a hand-written STUB (run_id `STUB-NOT-REAL-0001`, `stub: true`, `real_capture: false`). It exists only so the tests
can exercise the validator and scorer; the packer rejects it unless `--allow-stub` is passed and reports any stub numbers separately
as `stub_selftest_metrics`. It is never a result.

## Capture (all on 127.0.0.1, no outbound traffic from the honeypot side)

1. Start the honeypot: `python -m agentwatch honeypot --port 8098 --log run/leads.jsonl --registry run/registry.json`
2. Run the agent, e.g. `python redteam/llm_agent.py --target http://127.0.0.1:8098 --prompt aggressive_audit --model <local-model> --transcript run/transcript.jsonl`
   (Ollama on 127.0.0.1 by default; the API backend is OFF unless you opt in and then sends prompts to that third party). Or drive a
   headless browser at the loopback honeypot and write the same transcript lines.
3. Stop the honeypot, then create `slot/<run_id>/` containing `run.json` (schema `schema/run.schema.json`), `transcript.jsonl`
   (one line per tool call: step, tool, url, method, status), and optionally `leads.jsonl`, `access.jsonl` (the honeypot's mirrored stream)
   and `report.json` (`agentwatch analyze ... --json-out`). One run per directory, one prompt/model per run.
4. `python scripts/build_benchmark.py --out benchmark_out` validates, scores and packs. Real runs must say `real_capture: true` and
   `operator_attests_loopback_only: true`.

The scorer is descriptive (steps, paths, honeytoken hits, report severity per prompt/model). It reports no accuracy: the prompt is the
operator's intent, not detector ground truth.
