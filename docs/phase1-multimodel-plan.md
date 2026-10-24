# Phase 1 — Multi-model loopback eval plan (prep)

Date: 2026-10-23 (America/Los_Angeles)

Runner: `agent-watch/scripts/run_multimodel_tier2.py`

**Safety:** loopback honeypot only; `fetch_url` refuses non-loopback; step cap; **you must supply** any frontier API base URL + key. The runner **never scrapes keys** from the browser, vault files, or env files other than the variables you export yourself. It **does not** `ollama pull` or download models.

## (a) Another local Ollama mid-size model (when present)

```bash
# See what is already installed (no pull):
curl -s http://127.0.0.1:11434/api/tags | jq .
python /workspace/agent-watch/scripts/run_multimodel_tier2.py --list-local

# Dry-run plan only:
python /workspace/agent-watch/scripts/run_multimodel_tier2.py \
  --models qwen2.5:3b --dry-run --only llm

# Full local run for models already on disk:
python /workspace/agent-watch/scripts/run_multimodel_tier2.py \
  --discover-ollama --only all --max-steps 15 --port-base 18100
```

Traces: `agent-watch/tests/data/real_llm_traces/multimodel/<model-id>/`  
Comparison: `.../multimodel/_comparison/comparison.md` (+ `.json`)

If you install a mid-size model yourself (example — **you** run pull; not this task):

```bash
ollama pull qwen2.5:7b   # optional; not run by the agent in this prep
python /workspace/agent-watch/scripts/run_multimodel_tier2.py --models qwen2.5:7b --only all
```

## (b) Frontier / OpenAI-compatible API

```bash
export AGENTWATCH_LLM_API_BASE="https://api.example.com/v1"   # you supply
export AGENTWATCH_LLM_API_KEY="..."                            # you supply
# Never commit the key. Runner does not read keys from the vault or browser.

python /workspace/agent-watch/scripts/run_multimodel_tier2.py \
  --models openai:your-model-name --only llm --max-steps 15 --dry-run

# When ready (sends prompts + synthetic honeypot text to that API):
python /workspace/agent-watch/scripts/run_multimodel_tier2.py \
  --models openai:your-model-name --only llm --max-steps 15
```

Note: `run_tier2_eval.py` historically shells `llm_agent` with Ollama defaults. For OpenAI backend, also run `redteam/llm_agent.py --backend openai ...` directly if tier2 has not yet wired `TIER2_LLM_BACKEND`. The multimodel runner records the intended env (`AGENTWATCH_LLM_API_*`) and model id for that path.

## Cheap smoke (no LLM)

```bash
python /workspace/agent-watch/scripts/run_multimodel_tier2.py --playwright-only --dry-run
# Live (starts loopback honeypot + scripted human_control):
python /workspace/agent-watch/scripts/run_multimodel_tier2.py --playwright-only --port-base 18200
```

## Currently on this box

- Ollama has `qwen2.5:3b` (already used for Phase-1 Tier-2). No additional large models were downloaded in this prep task.
