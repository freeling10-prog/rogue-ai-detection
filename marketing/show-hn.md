# Show HN

Status: **ready to post after the repository is public.** [LICENSE](../LICENSE) is Apache 2.0 and [NOTICE](../NOTICE) is in the tree. Do not submit this post while the GitHub repository is still private. This file has not been posted. Visibility is changed outside this repository.

## Title

Show HN: ATLAS agent guard — a 3B model quit within 3 steps (2/13)

(66 characters. Hacker News titles cap at 80.)

## Post

We built a MITRE ATLAS guard for AI agents, pointed a real local model at the honeypot, and the result worth leading with is a miss.

`qwen2.5:3b` (Q4_K_M, about 1.9 GB, Ollama 0.40.10, 8 vCPU, no GPU) had an aggressive tool-calling prompt and a 25-step budget. The honeypot was bound to `127.0.0.1` and made no outbound request. The model usually issued 1 to 3 `fetch_url` calls and then answered. Aggressive runs often stopped on `/`, `/llms.txt`, or `/openapi.json`. They did not open MCP, the canary pages, the coordination board, or `/v1/chat/completions`. Steady-state latency was about 8 seconds a step; a fat `/openapi.json` context reached about 48–51 seconds a step, which is also why a 7B or 8B model was not pulled for this sample. A later note in the repo: a second, larger local model was not run (about 5 GiB free RAM and no swap). There is no mid-size multimodel table to cite.

The synthetic clients walk dozens of decoys. This 3B harness quit before those decoys mattered. That is why Tier-1 recall on mimics does not transfer to this setup, and why quoting the synthetic scores as a detection rate would be false.

Archived catch rate: **2 of 13** non-control runs, where "caught" means an agent-watch alert at medium or above.

- Both catches were Playwright. One was a headless BFS crawler (critical alert, and the only run that also produced a pipeline lead: R10 and R11 after the R14 calibration). The other was one LLM-driven Chromium run that clicked a footer link placed first in the DOM (`order:99` paints it last). That run was critical in agent-watch and produced **no** pipeline lead.
- Nine of nine HTTP tool-calling sessions were not caught.
- The scripted human control is the fourteenth archive. It was not flagged, and it is not in the 13. It is a scripted proxy, not a real person.
- Same author wrote the prompts, the decoys, and the detectors. One machine. Tiny n. Descriptive only. Not a benchmark.

Three pieces are in the tree. All of them are lab or offline.

**Localhost honeypot** (`agent-watch`). Hidden links, decoy admin and export endpoints, fake credentials, and canary pages that ask an assistant to fetch a URL. Scores come with plain-language reasons. Every web score is a lead for a person. The honeypot does not auto-block a public visitor. Default bind is `127.0.0.1`. Contact with a canary is not intent. The repository records no public deployment.

**Taint-and-freeze gateway** (`agent-gateway`, `pep.py`), for keys registered in `config/agents.json`. It sits between an internal harness and HTTP / JSON-RPC / MCP-style `tools/call`, on `127.0.0.1` unless someone passes `--allow-nonlocal`. Untrusted ingest (a fetched page, ticket text, or a non-core `tools/list` description) sets a taint bit and appends `allow_egress=false` on a chained HMAC capability, prefix `agw1.`. Write, send, and credential tools then wait for a person. The bypass is a one-time HMAC over the session, the step, the tool name, and the hash of the canonical arguments. Swapping the arguments or replaying the token fails. A registered key can be frozen for 15 minutes, including across a delegation cap (depth 1, at most 3 children). An unregistered key is refused and is not frozen. This is the project's reading of ATLAS mitigation AML.M0030. Tool backends in the prototype are simulated echoes. It is a lab policy proxy, not a production WAF, and it does not implement Web Bot Auth. Building the Slack / webhook approval payload does not open a socket; HTTP delivery stays off unless `--webhook-deliver` is set.

**Offline log analyzer** (`agentwatch-analyzer`). One command, no honeypot, no bind, no outbound call. It scrubs secrets before it writes `findings.json`, a CSP-safe `replay.html`, and a STIX 2.1 bundle. From a normal access log: asset starvation (R8) and unlinked jumps (R9) are in scope; schema and machine-doc paths (R10) are partial; beacon, insider tool-hijack, and timing (R11–R13) are not available offline; session-fork (R14) is partial and advisory without a human beacon. A recorded smoke matched the live story: the aggressive urllib archive produced no finding; the Playwright crawler archive matched R9 plus advisory R14.

ATLAS technique ids used in the repo (T0051, T0053, T0080, T0086, T0118, mitigation M0030) were checked against the ATLAS data file for those ids. The mapping from a rule to an id is still approximate. It is not a certification.

I want criticism on two design choices: keeping the public honeypot review-only while the insider gateway is allowed to freeze a registered key, and treating "the model quit" as a first-class evaluation outcome instead of only scoring clients that finish the decoy walk.

The tree includes a free GitHub Action (`.github/workflows/atlas-agent-audit.yml`) that runs the offline audit on pull requests; an optional paid 48-hour tool-boundary note for a security reviewer is in `marketing/audit-offer.md` (not a pen-test, and not a certification).

Link: https://github.com/freeling10-prog/rogue-ai-detection

Further reading in the tree: `docs/phase1-tier2-report.md`, `docs/phase2-gateway.md`, `docs/phase3-analyzer.md`, `agent-gateway/agent_gateway/capability.py`.
