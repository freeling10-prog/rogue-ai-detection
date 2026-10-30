# Mobile quick copy

Copy-paste blocks for sending from a phone. Each block is complete on its own: select from the first line to the last line of the block and paste. Fill `{{first_name}}` and `{{company}}` from a page you actually opened, or use "there" and drop the company line. Send from `alecagentboundary@gmail.com` and sign as Alec.

Links used below:

- Trace inspector (8 recorded scenarios, no login): <https://freeling10-prog.github.io/rogue-ai-detection/#traces>
- Sample sprint report PDF: <https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf>
- Source (Apache 2.0): <https://github.com/freeling10-prog/rogue-ai-detection>

Standing rules (same as [outreach-sequence.md](outreach-sequence.md)): figures are same-author lab checks, not a benchmark or a detection rate for the recipient. Never pool them with the separate **2 of 13** loopback archive figure. Not a penetration test and not a certification; ATLAS ids are approximate. No scare copy and no deadline copy. We do not deploy on their hosts and never take production credentials.

Figures you may quote: **874** gateway tests passing on `main` across **41** modules behind `pep.py`; **57/57** collusion defence checks and **0** denials in **750** benign decisions at the sprint snapshot; CPU **p50 0.126 ms** per decision (slowest **3.84 ms**).

---

## Pitch 1 — SaaS founder: Claude + Postgres + Stripe

```text
Subject: 48-hour MCP server for Postgres + Stripe, $750 flat

Hi {{first_name}},

If you want Claude to answer questions from your Postgres data and Stripe account without giving it a write path, I build that as a fixed-scope job: one MCP server, 48 hours, $750 flat ($350 kickoff, $400 when the acceptance tests pass on your side).

- Read-only, parameterized queries only: each tool is a SELECT template fixed in code, capped at 100 rows per call.
- Stripe lookups for customers, subscriptions, and invoices; refund, cancel, and delete tools stay denied unless you approve them in writing.
- Sensitive fields (api_key, secret, token, password, ssn, plus any you name) are redacted before results reach the model.
- Every call, allowed or denied, goes into a SHA-256 hash-chained audit log you can verify.
- Delivered as a mergeable PR with a pytest acceptance suite. Nothing is deployed on your hosts by me, and I only need staging access.

It runs on the open-source gateway behind this trace inspector: https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample report: https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

If useful, reply with the tables and Stripe objects you want exposed (names only, no data).

Alec
```

## Pitch 2 — Agency: Slack + HubSpot operations agent

```text
Subject: Slack + HubSpot MCP server for your ops agent, 48 hours, $750

Hi {{first_name}},

For agencies running an AI ops agent across client Slack and HubSpot, I build one hardened MCP server per system in 48 hours for $750 flat ($350 kickoff, $400 on passing acceptance tests).

- Scoped HubSpot lookups (contacts, deals, tickets) for the properties you list, with tokens and private fields redacted.
- Creating a task, note, or Slack message needs a one-time confirmation token bound to the exact arguments, so a prompt in a client email cannot post on its own.
- bulk_export, delete, and other mutation verbs are denied unless you approve them.
- Tool calls pass through a policy engine that holds outbound writes once a session has read untrusted content.
- Hash-chained audit log per call and a pytest acceptance suite, delivered as a mergeable PR. Nothing is deployed on your hosts by me.

Recorded traces of the policy engine (no login): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample report: https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

Reply with the Slack channels and HubSpot objects in scope and I will confirm the tool list.

Alec
```

## Pitch 3 — Internal REST / GraphQL API MCP wrapper

```text
Subject: MCP wrapper for your internal API, 48 hours, $750 flat

Hi {{first_name}},

If your team wants Claude or another agent to use an internal REST or GraphQL API, I can wrap it as an MCP server with explicit allow and deny rules in 48 hours, $750 flat ($350 kickoff, $400 on passing acceptance tests).

- Only the endpoints or GraphQL operations you list become tools; everything else is denied.
- Read operations return capped, redacted results; write operations need a per-call confirmation token.
- Mutation verbs (delete, refund, cancel, drop, truncate, bulk_export) are denied by default.
- URLs pointing at cloud metadata or internal-only hosts are refused before any request is made.
- SHA-256 hash-chained audit log and a pytest acceptance suite, delivered as a mergeable PR against staging. Nothing is deployed on your hosts by me.

The policy engine and its recorded traces: https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample report: https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

Send an OpenAPI file or the operation names you want exposed and I will reply with a fixed tool list.

Alec
```

---

## Community post 1 — r/forhire

Title:

```text
[For Hire] Hardened MCP server for Claude / AI agents (Postgres, Stripe, HubSpot, Slack, internal API) — $750 flat, 48 hours
```

Body:

```text
I build one MCP server for one system, fixed scope, delivered as a PR in 48 hours.

Rate: $750 flat. $350 to start, $400 when the acceptance tests pass on your side.

What you get:
- Read-only parameterized queries or scoped API lookups, capped at 100 rows per call
- Sensitive-field redaction (keys, tokens, passwords, SSNs, plus fields you name)
- Write or task-creation tools gated by a one-time confirmation token; delete / refund / cancel / bulk export denied unless you approve them
- Every call checked by an open-source policy engine and logged in a SHA-256 hash-chained audit log
- A pytest acceptance suite; nothing deployed on your hosts by me, staging access only

Open-source engine (Apache 2.0), 874 tests passing: https://github.com/freeling10-prog/rogue-ai-detection
Recorded policy traces: https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample report: https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

Not a penetration test or a certification. DM or email alecagentboundary@gmail.com with the system and the tools you want.
```

## Community post 2 — r/ClaudeAI and r/LocalLLaMA

Title:

```text
Open-source PreToolUse hook for Claude Code: blocks .env / ~/.ssh reads, rm -rf ~, force-push to main, and metadata URLs, with a hash-chained audit log
```

Body:

```text
I released a small Claude Code PreToolUse hook as part of an Apache 2.0 agent gateway. One command:

    python -m agent_gateway.claude_code_hook --install

It adds a single PreToolUse command hook to ~/.claude/settings.json (running it twice adds nothing). Before each tool call it checks:

- CREDENTIAL_PATH_DENIED: Read / Write / Edit / Bash touching .env files (.env.example, .env.sample, .env.template stay allowed), ~/.ssh, ~/.aws, .npmrc, .pypirc
- SHELL_POLICY_DENIED: recursive rm of / or ~, force push to main/master, curl | sh style pipes
- METADATA_URI_DENIED: 169.254.169.254 (also hex / decimal / IPv6-mapped), metadata.google.internal, file:// URIs

Each decision, allowed or denied, is appended to a SHA-256 hash-chained ~/.claude/agentgate_audit.jsonl, and the chain can be re-verified. `--self-test` runs four checks and prints CPU time per decision; on my machine each decision takes well under 1 ms. Standard library only.

These are lexical configuration checks, not a sandbox: anything run outside Claude Code is out of scope, and a determined user can get around them.

The same repo has the gateway itself: a loopback policy engine with taint tracking, capability attenuation, and split-exfiltration checks. 874 gateway tests pass on main. You can step through 8 recorded scenarios in the browser (rug-pull, split-chunk exfil, confused deputy, schema drift, memory lineage, and more): https://freeling10-prog.github.io/rogue-ai-detection/#traces

Sample lab report (same-author scripted checks, not a benchmark): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf
Source: https://github.com/freeling10-prog/rogue-ai-detection

Bypasses and false positives welcome as issues.
```
