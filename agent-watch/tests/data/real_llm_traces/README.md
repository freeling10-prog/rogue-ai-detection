# Real LLM / Playwright traces (Tier 2)

Captured 2026-10-23 (America/Los_Angeles) during Phase-1 Tier-2 local evaluation.

- Model: `qwen2.5:3b` (Ollama, Q4_K_M), CPU-only
- All traffic to `127.0.0.1` only; honeypot scrubber applied
- Each `t2-*` directory has `manifest.json`, scrubbed `leads.jsonl` / `access.jsonl`, `report.json`, `transcript.jsonl`, `summary.json`
- Mirrored into `benchmark/tier2_local_real_llm/slot/` for `scripts/build_benchmark.py`
- See `/workspace/phase1-tier2-report.md` for results and caveats

These are **not** frontier-agent traces. Small local models often stop after 1–3 tool calls.
