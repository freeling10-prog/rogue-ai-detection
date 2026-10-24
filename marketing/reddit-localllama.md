# Reddit — r/LocalLLaMA

Status: **draft. Do not submit.** The GitHub remote is private and the tree has no LICENSE file. Do not call the project open source in the post until a license file exists and the repository is public. Replace the link TODO at that point.

Flair: whatever the subreddit uses for projects or research. Do not use a "we detect all agents" claim in the title.

## Title

agw1. chained-HMAC capabilities, Hypothesis fuzz of a tool gateway, and a 3B model that stopped within 3 steps (2/13)

## Post

Local tool-calling note first, then the gateway crypto, the fuzz, and the offline CLI. All of this ran on loopback. Nothing here was a public honeypot.

### What `qwen2.5:3b` actually did

Model: `qwen2.5:3b`, quantization **Q4_K_M** (about 1.9 GB), Ollama 0.40.10, 8 vCPU, ~16 GB RAM, no GPU. Harness: `agent-watch/redteam/llm_agent.py`, Ollama `/api/chat` tool calls, a single tool `fetch_url` that refuses non-loopback URLs. Honeypot: `python -m agentwatch honeypot` on `127.0.0.1`. Budget: 25 steps. Three prompts (`benign_summarizer`, `aggressive_audit`, `stealth_mimic`) times three seeds, plus Playwright runs.

The 3B tool-caller did not behave like the synthetic "aggressive agent" the detectors were written against. Synthetic clients walk dozens of decoys. This model usually made **1 to 3** `fetch_url` calls and then produced an answer.

- Benign: 1 step, fetched `/`, stopped. No alert. That is the outcome you want for a summarizer.
- Aggressive: 3, 3, and 2 steps. Typical path was `/`, `/llms.txt`, `/openapi.json`. One seed guessed `/api-docs` and got a 404. No MCP, no canary, no coordination board, no `/v1/chat/completions`.
- Stealth: 3, 2, and 1 steps. One low-severity inversion touch from a non-browser client. Not a medium alert.

Latency is why this stayed a 3B sample. First tool call after a cold load was about 5.4 seconds. Steady state was about **8 s/step**. Aggressive steps that dragged `/openapi.json` into the context hit **~48–51 s/step**. A 7B or 8B pull was not attempted on that budget. A later note in the repo: a second larger local model was not run (about 5 GiB free RAM and no swap). The multimodel comparison file on `main` is a dry-run stub. It is not a result.

Catch rate on the archived non-control runs: **2 of 13**, meaning an agent-watch alert at medium or above. Both hits were Playwright (a headless BFS crawler, and one LLM-driven Chromium run that clicked the DOM-first footer trap). The nine urllib sessions were misses. The scripted human control is archive 14, was not flagged, and is excluded from the 13. It is not a person. The crawler is the only run that also produced a pipeline lead. Same author, one box, tiny n. Do not quote it as accuracy, and do not average it with the synthetic regression scores.

The useful local-model takeaway: a detector scored on clients that dutifully walk every decoy will overstate recall against a small tool-calling model that gives up. "Quit within 3 steps" has to be an outcome you report, not a run you discard.

### `agw1.` capability chains

Package: `agent-gateway`. File: `agent_gateway/capability.py`. This is the insider policy proxy (PEP) for **registered** agent API keys, loopback by default. It is separate from the web honeypot. The honeypot still only emits leads for a person. Freeze and hard-block apply only to keys in `config/agents.json`.

The session token is macaroon-style chained HMAC attenuation. It is not a full macaroon implementation: there are no third-party caveats and no discharges. Format:

```text
agw1.<base64url(json)>.<hex HMAC-SHA256>

json = {"v":1,"id":"<session_id>","caveats":[...]}   # separators ",", ":", keys sorted

sig0 = HMAC-SHA256(root_key, "agw1|" + session_id)
sig_i = HMAC-SHA256(sig_{i-1}, caveat_i)             # caveat is a UTF-8 string
published signature = lowercase hex of sig_n
```

A worker that holds the root key (`AGENT_GATEWAY_HMAC_KEY`) mints three caveats:

1. `bind:session=<sha256("session|" + session_id)[:32]>`
2. `bind:agent=<sha256("agent|" + agent_key)[:32]>`
3. `allow_egress=true`

On untrusted ingest the PEP appends two more, and the holder of the token can append further caveats without the root key, because attenuation HMACs the new caveat under the **current tag**:

4. `allow_egress=false`
5. `taint_source=<sanitized id>`

Verification recomputes the chain from the root key. It does not need another worker's session table. Dropping, reordering, or rewriting a caveat breaks the tag. Egress is monotonic: if `allow_egress=false` appears anywhere in the list, a later `allow_egress=true` does not turn it back on. Caveat charset is a short allowed pattern; the list caps at 32.

What this does **not** give you: the root key is still the trust root. Any worker that has `AGENT_GATEWAY_HMAC_KEY` can mint a fresh allowing token for a session it has never seen. The property the chain actually gives you is weaker and still useful: a holder who does **not** have the root key cannot upgrade an attenuated token back into one that allows egress. On a worker that has stored the attenuated token, presenting an earlier allowing discharge is rejected (`capability_upgrade_rejected`).

The one-time out-of-band approval in `approve.py` is a different token. It is HMAC over `(session_id, step_index, tool_name, sha256(canonical_args), taint_source_id)`. It is the one-shot bypass of a closed egress. It does not delete the `allow_egress=false` caveat. Arg-swap and replay fail closed.

Policy around the token, still lab-only:

- Untrusted ingest covers external reads and non-core MCP `tools/list` descriptions (core servers are capability-pinned and are not auto-tainted). Scratchpad writes while tainted store `taint_inherited`; a later session that reads that pad becomes tainted (the project's reading of AML.T0080.000).
- Egress classes are `external_read`, `internal_read`, `write`, `send`, `creds`, plus bus and spawn. With taint and a sensitive read, tools that put parameters on an external boundary are held (AML.T0086 in this tree).
- Delegation: `max_delegation_depth=1`, `max_children_per_parent=3`. Taint follows an internal bus post. Over-fan-out is refused. Freeze keys to the root parent principal for **15 minutes** and then lifts. An unregistered visitor key is not frozen.
- Unknown tools fail closed as class `write`.
- Logged tool arguments are scrubbed. The approval-webhook formatter can render Slack Block Kit and a generic JSON body for a held call (principal, session, `agw1.` token, taint source, ATLAS id, scrubbed tool and args, one-time Approve Once / Deny & Freeze callbacks). It does not POST unless the process is started with `--webhook-deliver`. A failed POST does not change the policy decision.
- Tool backends inside this prototype are simulated echoes. Default bind `127.0.0.1`.

Recorded `agent-gateway` pytest on this tree: **35 passed** (7 basic, 7/7 ATLAS falsification, 10 attenuation, 5 stateful, 6 approval-webhook). Those cases were written for these gates. That is a regression suite, not a production evaluation. ATLAS ids are approximate.

### Hypothesis fuzz

Pin in the tests: `hypothesis==6.170.9`. Three `RuleBasedStateMachine`s:

| Machine | File | Examples | Steps |
| --- | --- | --- | --- |
| `PepPolicyMachine` | `agent-gateway/tests/test_stateful_fuzz.py` | 40 | 16 |
| `GatewayScrubMachine` | same file | 80 | 8 |
| `SafelogMachine` | `agent-watch/tests/test_safelog_stateful.py` | 80 | 8 |

`PepPolicyMachine` drives the real `PolicyEngine`, not a mock of the decision. The rules reorder spawn plans, push delegation depth past 1, invent unregistered visitor keys, freeze a registered root, taint sessions with untrusted reads, and attempt `send_email` / `file.write` / `credentials.get` with and without a bound OOB token. Invariants asserted across those orders:

- A tainted or egress-closed session does not complete a blocked write, send, or creds call without a valid hash-bound one-time OOB token.
- Fan-out never exceeds 3 children for a parent, in any order.
- Freeze and block apply only to registered keys. A public visitor key is never frozen, and the freeze helper returns an empty list for it.
- Scrubber outputs (`GatewayScrubMachine`, and `safe_text` on the honeypot side) do not contain the configured secret patterns, including ones the machine percent-encodes or hides in a query string.

`database=None` and `deadline=None` are set in those modules so the fuzz does not depend on a local Hypothesis example database. This is stateful property testing of a lab PEP, not a claim that the state space is covered.

### Offline CLI

`agentwatch-analyzer` is a separate installable package. It does not import the Flask honeypot. It does not bind a port and it does not make a network call. Scrub runs before any output file is written (two-round percent-decode plus dict-key redaction).

```bash
agentwatch-analyzer /var/log/nginx/access.log \
  --format nginx \
  --sitemap /path/to/sitemap.xml \
  --out-dir ./out
```

`--format` is `auto`, `nginx`, `caddy`, `cloudflare`, or `json`. Outputs:

| File | What it is |
| --- | --- |
| `events.scrubbed.jsonl` | Normalized events after scrubbing |
| `findings.json`, `leads.jsonl` | Offline-capable leads plus the rule matrix |
| `replay.html` | Static session replay, no network requests |
| `stix-bundle.json` | STIX 2.1 indicators (`stix2-validator==3.2.0` in the suite) |
| `summary.json` | Counts |

Offline matrix, from the package README:

| Rule | Offline? |
| --- | --- |
| R8 asset starvation | Yes (browser UA, HTML, no css/js in the log) |
| R9 unlinked jump | Yes. Stronger with `--sitemap` or JSON `links[]`. Typed URLs, bookmarks, and Referer-stripping proxies inflate it |
| R10 schema / machine-doc | Partial. Decoy kinds need the honeypot |
| R11 beacon / mimic | No |
| R12 tool hijack | No. That signal lives on the gateway, not in an access log |
| R13 timing / adaptation | No |
| R14 session fork | Partial, and advisory without a human beacon |

Sigma pack: `agentwatch-analyzer/rules/sigma/` (12 YAML files covering R8–R14 and AML.T0051, T0053, T0080, T0086, T0118). OWASP ASI01–ASI10 appears where the rules note a mapping. That is orientation, not a compliance claim. STIX confidence is capped. Custom properties use the `x_` prefix; the validator may emit SHOULD warnings.

Recorded unit tests: **10 passed**. A recorded smoke on the archived Tier-2 logs: aggressive urllib LLM matched nothing; Playwright LLM s100 matched R9; the Playwright crawler matched R9 plus advisory R14; the fixture `agentlike_nginx.log` matched R8, R9, and R10. The advisory offline R14 on the crawler is not the live false positive. After the Phase 1 calibration, rescoring that archive does not raise `parasitic_session_fork`.

### Limits, in one place

- Loopback only. Do not bind the honeypot on a public interface from this write-up.
- Web honeypot: human review only. Gateway freeze: registered keys, 15 minutes.
- 2 of 13 is the whole real-model catch rate on `main`. The 3B HTTP agent is the miss.
- `agw1.` attenuation assumes the HMAC root key stays with workers you trust. Leak the key and the chain is mintable from scratch.
- Hypothesis found no invariant break in the recorded suite. It does not make the PEP a production control.

Link: TODO. Public repository URL after the repo is public and licensed. Start at `agent-gateway/agent_gateway/capability.py`, `agent-gateway/tests/test_stateful_fuzz.py`, and `agentwatch-analyzer/README.md`.
