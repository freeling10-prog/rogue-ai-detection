# Launch copy

Customer-facing and community copy for the lab stack on current `main`: `agent-watch` (localhost honeypot), `agent-gateway` (taint-and-freeze policy proxy), and `agentwatch-analyzer` (offline CLI). The name used for that stack, matching the root README and [NOTICE](../NOTICE), is AgentGate.

Nothing in this folder has been posted or emailed by adding it to the tree. Show HN and the Reddit draft are ready to post only after the GitHub repository is public. Visibility is changed outside this repository.

| Piece | Audience | File |
| --- | --- | --- |
| Paid offer | Security reviewer at a B2B agent or MCP team | [audit-offer.md](audit-offer.md) |
| Email and LinkedIn sequence | LA companies in [la-targets.md](la-targets.md) | [outreach-sequence.md](outreach-sequence.md) |
| First 10 LA targets | Alec, before anyone is emailed | [la-targets.md](la-targets.md) |
| Day 0–7 checklist | Zero-budget week | [7-day-execution-checklist.md](7-day-execution-checklist.md) |
| Show HN title and post | Hacker News, optional, after the repo is public | [show-hn.md](show-hn.md) |
| Technical write-up | Reddit, r/LocalLLaMA, optional, after the repo is public | [reddit-localllama.md](reddit-localllama.md) |
| Phone copy-paste blocks | Three $750 build pitches, r/forhire, r/ClaudeAI and r/LocalLLaMA | [mobile-quick-copy.md](mobile-quick-copy.md) |
| Scope source for the audit | Do not send this body | [ciso-outreach.md](ciso-outreach.md) |

## Live call to action

**[Book a 48-hour Agentic Tool-Boundary Audit](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)**

Offer page: [audit-offer.md](audit-offer.md). **$1,800** Tool Inventory Review (one page: egress classification, top 3 taint paths, short remediation list), **$4,500** Fixed Tool-Boundary Note, or **$6,500** with instrumentation (a lab gateway pass on `127.0.0.1`, plus an offline analyzer pass on an authorized log they supply). Optional add-ons (Integration Blueprint +$2,500, Reviewer Briefing Call +$750, Quarterly Refresh Retainer $2,500 per quarter) are on the offer page. They can reply to that email with a tool inventory. There is no scheduling link and no company domain.

The open core is Apache 2.0 ([LICENSE](../LICENSE), [NOTICE](../NOTICE)). The paid audit is a commercial service. It is not a second license to the code, and it is not in the Apache grant. The free GitHub Action stays free.

Public repository, once visibility has been changed: https://github.com/freeling10-prog/rogue-ai-detection

## Honesty rules

These are the limits already recorded in the root README, [docs/phase1-tier2-report.md](../docs/phase1-tier2-report.md), [docs/phase2-gateway.md](../docs/phase2-gateway.md), and [docs/phase3-analyzer.md](../docs/phase3-analyzer.md). If a sentence in a draft disagrees with those files, the docs win. Edit the draft.

- **Tier-2 catch rate is 2 of 13.** That is agent-watch medium-or-higher on the archived non-control runs: the headless Playwright crawler, and one LLM-driven Playwright run. The nine `qwen2.5:3b` urllib sessions were not caught. The scripted human control is the fourteenth archive, was not flagged, and is not in the 13. It is not a real person. Only the crawler also produced a pipeline lead. Same author, one machine, one 3B model. Not a benchmark. Do not pool it with synthetic recall.
- **The 3B model usually stopped after 1 to 3 tool calls.** "Quit within 3 steps" is that observation. It is not a claim about frontier computer-use agents.
- **Lab bind.** The honeypot and the gateway default to `127.0.0.1`. Non-loopback gateway bind requires `--allow-nonlocal`.
- **Honeypot output is a lead for a person.** The web honeypot does not auto-block a public visitor. Honeypot contact is not intent.
- **Freeze is for registered internal keys**, listed in `agent-gateway/config/agents.json`, for 15 minutes (900 seconds). An unregistered key is not frozen.
- **No wild-deployment result** is recorded. Do not add one.
- **ATLAS mappings are approximate** (AML.M0030, T0051, T0053, T0080, T0086, T0118). They are not a certification. OWASP ASI notes on the Sigma rules are orientation, not a compliance claim.
- **`agw1.` is macaroon-style chained HMAC attenuation**, not a full macaroon library (no third-party caveats, no discharges). A worker that holds `AGENT_GATEWAY_HMAC_KEY` can mint a fresh allowing token. A holder who does not have that key cannot strip `allow_egress=false`.
- **Post-sprint `main` (28 October 2026).** `agent-gateway` **796 passed** with **9** stateful Hypothesis machines (389 at v11, plus 48 Claude Code hook and 20 MCP blueprint tests in v11.1, plus 49 PHP Defense Guard tests, plus 146 v12 evasion-guard tests, plus 144 v12.1 tests); `agent-watch` **512 passed, 2 skipped**; `agentwatch-analyzer` **10 passed**: **1318** passing across the workspace. The 127 new gateway tests cover the four v11 guards and their wiring and are reported as a separate Group D, never added to 57/57. Quote 796 for `main` and 262 for the sprint snapshot.
- **Recorded tests (re-run 25 October 2026 at commit `cefec0d`).** `agent-gateway` **262 passed** (7/7 ATLAS falsification and 5 stateful Hypothesis machines inside), `agent-watch` **512 passed, 2 skipped** (514 collected), `agentwatch-analyzer` **10 passed**: **784** passing across the workspace. Breakdown by file: [docs/phase2-gateway.md](../docs/phase2-gateway.md) and the root README. Earlier floors (35, then 40, then 240 on the v10 tree) are history; quote 262 for this tree. Hypothesis pin in those tests is `hypothesis==6.170.9`.

## Before anyone posts or sends

- Show HN and the Reddit draft are **ready to post after the repository is public**. They have not been posted. If the remote is still private when you sit down to post, do not submit them. The link line is already https://github.com/freeling10-prog/rogue-ai-detection. Apache 2.0 describes the code. It does not by itself change repository visibility.
- Send [outreach-sequence.md](outreach-sequence.md), not the body of [ciso-outreach.md](ciso-outreach.md). The sequence uses the mailto above. Do not invent a domain to fill a gap.
- [la-targets.md](la-targets.md) is the first ten companies. Re-open the cited URL the day you send. Drop a row when the page no longer says what the row says.
- Leave the numbers as fractions (`2 of 13`, `1 to 3` calls). Do not round them into a percentage in a title.
