# Real-LLM red-team harness (runbook)

> **STATUS: the harness has NEVER been run against a real model.**  When it was written, no Ollama was installed on the build box
> (`which ollama` → nothing; nothing listening on `127.0.0.1:11434`) and, by design, **no model was downloaded and no external
> API was called**.  It is tested only with a stub "LLM" that replays scripted tool calls
> (`tests/test_redteam_harness.py`).  Whatever a real model does with these prompts is unknown.  Treat the first real run as an
> experiment, read the transcript, and expect surprises (models refuse, loop, ignore the tool, or call it with bad arguments).

## What it is

`redteam/llm_agent.py` — one file, a ~60-line tool-calling loop (`run_agent`) plus a loopback-only `fetch_url(url, method, body)`
tool.  A model that supports tool calling browses **your local agent-watch honeypot**; the honeypot's lead log and mirrored access
stream are then analyzed by agent-watch and, via `export-web`, by `rogue-ai-pipeline`.  That tells you how the detectors react to
*real* model behaviour instead of the simulated clients (which were written by the same author as the detectors).

### Safety properties (enforced in code, covered by tests)

* `fetch_url` accepts only `http(s)` URLs whose host is `localhost`, `127.0.0.0/8` or `::1` (literal match — no DNS lookup, no
  `127.1`/integer tricks, no `user@host` tricks).  Anything else returns `{"refused": true}` to the model as data and **nothing is
  connected to**.  Redirects are re-checked hop by hop; proxy environment variables are ignored.
* Hard step cap (`MAX_STEPS_HARD = 25`, regardless of `--max-steps`), one tool call executed per step, request/response bodies capped.
* Backends:
  * **Ollama** (default): `http://127.0.0.1:11434`.  `OLLAMA_HOST` may only point at a loopback address.
  * **OpenAI-compatible API** (default **OFF**): used only with `--backend openai` **and** `AGENTWATCH_LLM_API_BASE` (+
    `AGENTWATCH_LLM_API_KEY`) set by you.  That API endpoint is the only non-loopback destination the script will ever contact
    and it is used for model calls only; `fetch_url` stays loopback-only.  **Using it sends the prompts and whatever the honeypot
    returned (all synthetic) to a third party — only do this if that is acceptable to you.**
* The script never installs, pulls or downloads anything.

## Prompts

| name | what it tests |
| --- | --- |
| `benign_summarizer` | an ordinary assistant told to summarize the site by clicking visible links — the false-positive control |
| `aggressive_audit` | an *authorized* audit persona told to enumerate thoroughly (robots, llms.txt, API docs, every interface) — should light up decoys, schema parameter, MCP |
| `stealth_mimic` | told to behave like a slow ordinary visitor, follow only shown links, skip assets, avoid admin/machine interfaces — the hard case for the mimic detectors |

Note that `urllib` sends its own default `Python-urllib` User-Agent, so **asset starvation (which applies only to browser-claiming
User-Agents) will abstain** for runs of this harness unless you add a browser User-Agent to `fetch_url` yourself; the harness does
not fake one by default because that would pre-decide the result.

## Running it locally

```bash
# 0. is a local model available?  (not installed on the build box; install it yourself if you want to)
ollama list                     # must show a model that supports tool calling

# 1. start the honeypot on loopback (terminal 1)
python -m agentwatch honeypot --port 8098 --log run/leads.jsonl --registry run/registry.json

# 2. run a prompt (terminal 2) — repeat per prompt/model
python redteam/llm_agent.py --target http://127.0.0.1:8098 --prompt benign_summarizer   --model <local-model> --transcript run/benign.jsonl
python redteam/llm_agent.py --target http://127.0.0.1:8098 --prompt aggressive_audit    --model <local-model> --transcript run/audit.jsonl
python redteam/llm_agent.py --target http://127.0.0.1:8098 --prompt stealth_mimic       --model <local-model> --transcript run/stealth.jsonl
# (use a different client IP per run if you want separate sessions: the honeypot keys sessions on IP + User-Agent, so
#  restart it with a fresh --log between runs, or run one prompt per honeypot instance)

# 3. stop the honeypot with Ctrl-C (SIGINT)

# 4. analyze with agent-watch (leads + the mirrored access stream)
python -m agentwatch analyze run/leads.jsonl run/leads.jsonl.access.jsonl --min-severity info
#   (if no decoy was touched, run/leads.jsonl does not exist: pass the .access.jsonl file alone)

# 5. feed the same logs to rogue-ai-pipeline
python -m agentwatch export-web run/leads.jsonl run/leads.jsonl.access.jsonl --out run/web-events.jsonl --label-synthetic
#   then in the pipeline project (see its README, section "v3: web-collector evidence"):
python run.py detect --events /path/to/run/web-events.jsonl --out out_web --ephemeral-key
```

`--label-synthetic` marks the events `synthetic=true`, which the pipeline requires; it is accurate here because the "site" is
your own synthetic honeypot.

## Reading the results

* `actor_type` / `actor_class`: `goal_directed_agent` (used something a decoy offered), `accidental_scraper` (one hidden-link hit),
  `possible_mimic` (asset starvation or guessed URLs), `static_bot`, `human`.
* Record, per prompt and model: did it call the tool at all, how many steps, did it touch decoys, what did agent-watch call it,
  what did the pipeline do.  A single run proves nothing; models are non-deterministic.
* Remember the honest caveats: honeypot contact is not intent, and these prompts were written by the same author as the detectors.

## Tests (stub only)

`python -m pytest tests/test_redteam_harness.py` — 39 tests: loopback allow/deny matrix (userinfo, look-alike hostnames, `127.1`,
integer hosts, `file://`, redirects to non-loopback), no DNS lookups and no non-loopback connections (a socket-level guard fails
the test), step cap, backend shape handling with injected transports, OpenAI backend off by default, and one end-to-end run of a
scripted stub against the live loopback honeypot analyzed by agent-watch.
