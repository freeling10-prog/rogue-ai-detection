# Launch copy (drafts)

Drafts for a technical launch of the lab stack on current `main`: `agent-watch` (localhost honeypot), `agent-gateway` (taint-and-freeze policy proxy), and `agentwatch-analyzer` (offline CLI). They are written to be posted or sent later. They are not posted by adding them to the tree.

| Draft | Audience | File |
| --- | --- | --- |
| Show HN title and post | Hacker News | [show-hn.md](show-hn.md) |
| Technical write-up | Reddit, r/LocalLLaMA | [reddit-localllama.md](reddit-localllama.md) |
| Cold email | Security lead at a B2B AI startup in an enterprise procurement review | [ciso-outreach.md](ciso-outreach.md) |

Names match the packages on `main`. This folder does not introduce a product brand.

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
- **Recorded tests, not re-run for these drafts.** [docs/phase2-gateway.md](../docs/phase2-gateway.md) records `agent-gateway` **35 passed** (7 basic, 7/7 ATLAS falsification, 10 attenuation, 5 stateful Hypothesis, 6 approval-webhook) and `agent-watch` **512 passed, 2 skipped**. [docs/phase3-analyzer.md](../docs/phase3-analyzer.md) records `agentwatch-analyzer` **10 passed**. Hypothesis pin in those tests is `hypothesis==6.170.9`.

## Before anyone posts or sends

- The GitHub remote is still **private**. A root [LICENSE](../LICENSE) (Apache 2.0) and [NOTICE](../NOTICE) are in the tree. That does not make the repository public, and these drafts are not a public open-source announcement. Until the repository visibility is public, do not submit the Show HN post or the Reddit post, and do not describe the project as a public open-source release. Replace the link `TODO` only after the repository is public.
- The CISO template has no company domain, no booking URL, and no mailto. Replace every `TODO` before sending. Do not invent a domain to fill the gap.
- Leave the numbers as fractions (`2 of 13`, `1 to 3` calls). Do not round them into a percentage in a title.
