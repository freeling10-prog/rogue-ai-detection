# LA outreach sequence

Three email touches and three LinkedIn touches for companies in [la-targets.md](la-targets.md). The scope and the words you are allowed to use come from [ciso-outreach.md](ciso-outreach.md) and [audit-offer.md](audit-offer.md). Send from `alecagentboundary@gmail.com`. Sign as Alec. Do not invent a title, a domain, or a scheduling link.

**Live interactive demo (public, no login):** <https://freeling10-prog.github.io/rogue-ai-detection/> · Source: [github.com/freeling10-prog/rogue-ai-detection](https://github.com/freeling10-prog/rogue-ai-detection) · Book: [alecagentboundary@gmail.com](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit). This is a real, working GitHub Pages link — you may include it in a touch once the repository is public.

Do not send [ciso-outreach.md](ciso-outreach.md) as-is. That file is the scope source. This file is the sequence, with the live call to action filled in.

Personalization slots:

| Slot | Fill with |
| --- | --- |
| `{{first_name}}` | Their first name, from a page you actually opened. If you do not have it, use "there" or the role, not a guessed name. |
| `{{company}}` | Company name as it appears on the public page you cite. |
| `{{public_detail}}` | One fact from the public URL in the target row. One clause. |
| `{{role_hook}}` | Why that role would care, taken from the target's angle. Do not add a new claim. |

Call to action, in every touch that asks for a reply:

- Offer page in the repo: `marketing/audit-offer.md`
- Public repo: `https://github.com/freeling10-prog/rogue-ai-detection`
- Mailto: `mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit`

They can reply with a tool inventory (names and argument shapes, no secrets, no customer payloads).

Standing rules for every touch. If a sentence conflicts with these, delete the sentence.

- Default bind `127.0.0.1`. No wild honeypot deployment.
- Honeypot output is human-review only. Contact is not intent.
- Freeze only registered lab keys, for 15 minutes. Unregistered keys are not frozen.
- The only real-model catch rate you may quote is **2 of 13**, labeled as our loopback archive. Do not put it in a subject line. Do not turn it into a percentage.
- ATLAS mappings are approximate. Not a certification.
- Lab figures you may quote, as same-author lab checks only: **262** gateway tests at the sprint snapshot `cefec0d` (**784** passing across the workspace; **796** gateway and **1318** workspace on `main` after the v11 guards), **57/57** collusion defence checks, **0** false denials in **750** benign decisions, CPU **p50 0.126 ms / p99 0.999 ms** per decision (slowest single decision **3.84 ms**). Never pool them with 2 of 13 and never present them as a detection rate for the recipient.
- Not a penetration test, not a red team of their customers, and not a statement that they pass ATLAS, OWASP, NIST, SOC 2, or ISO.
- No scare copy and no deadline copy. Price is $1,800 for a Tool Inventory Review, $4,500 for the fixed note, or $6,500 with instrumentation. Add-ons are on `marketing/audit-offer.md`; do not lead with them. Instrumentation is a lab gateway pass plus an offline analyzer pass on an authorized log they supply.

## Email

Wait about three days between touches. Stop when they reply or when they decline.

### Touch 1 — the question

Subject: 48-hour agent tool-boundary audit before your enterprise security review

Alternate subject: What your enterprise reviewer will ask about agent tool calls

Hello {{first_name}},

Enterprise reviews of agent products ask a concrete question: after the model reads something it did not write (a web page, a ticket, an MCP tool description), which tools can it still call, and who has to agree first?

I saw {{public_detail}} at {{company}}. {{role_hook}}

I run a 48-hour Agentic Tool-Boundary Audit for that review. The clock starts when I have the tool list, not when this email arrives. You get a short written note a security reviewer can read. The price is $1,800 for a one-page inventory review, $4,500 for the full note, or $6,500 if you also want a lab gateway pass and an offline pass on an authorized log you supply. The lab gateway stays on 127.0.0.1. I do not install anything on your network, and I do not take production credentials.

The one-page scope is `marketing/audit-offer.md` in https://github.com/freeling10-prog/rogue-ai-detection. It lists what is out of scope, including penetration tests and any "pass" claim.

If this is the wrong person, a pointer to the right one is enough.

Alec
alecagentboundary@gmail.com

### Touch 2 — what the note will and will not say

Subject: What the 48-hour note includes, and what it will not say

Hello {{first_name}},

A short follow-up on the tool-boundary note for {{company}}.

In the 48 hours after the tool list arrives, the note:

- Classes each tool as external read, internal read, write, send, or credential use, and marks where untrusted text can reach a send, a write, or a credential tool.
- Says which of those calls the lab gateway would hold for a person. A registered lab key can be frozen for 15 minutes. An unregistered key is not frozen. The note says that in those words.
- Maps findings to ATLAS ids and labels every mapping approximate. It does not say {{company}} passes ATLAS, OWASP, NIST, or a customer's questionnaire.

The $6,500 tier adds a lab gateway pass on the tool list and, if you supply an authorized access log, an offline analyzer pass. Beacon, tool-hijack, and timing rules are not available from a normal access log. The note says which rules the log cannot support.

I do not deploy a honeypot on your network. The copy and the price are on `marketing/audit-offer.md`. Reply to this thread, or use mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit. A tool inventory in the reply is enough to start the clock once you say which tier you want.

Alec
alecagentboundary@gmail.com

### Touch 2 (alternate, targets #1–#10) — Apart Collusion Sprint & Live Sample Audit

Use this, or the per-target payload below it, in place of the Touch 2 above. Send only once the live site shows the §3 trace inspector (the `#traces` anchor) and the sample report link resolves. Open both links yourself the day you send. Do not imply Apart Research endorses, reviewed, or ranked the work; it is our sprint submission. The numbers below are same-author lab checks: quote them as that, never as a detection rate for their product, and never pooled with the 2 of 13 archive.

Subject: A sample audit report you can open before replying

Alternate subject: Agent hand-offs and encoded leaks: a sample report from our sprint run

Hello {{first_name}},

A short follow-up on the tool-boundary note for {{company}}, with something you can inspect instead of take on trust.

For Apart Research's AI collusion research sprint we pointed our open-source gateway at three ways agents can coordinate past a content filter: side channels, delegation laundering (a restricted agent handing work to a clean peer), and split or encoded leaks. Two things to open:

- Live trace inspector, six recorded traces including confused-deputy delegation and encoded canary exfiltration, all in your browser with no sign-in: https://freeling10-prog.github.io/rogue-ai-detection/#traces
- Sample executive audit report (PDF) from that run, unedited: https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run, 57 of 57 collusion defence checks passed, and 750 benign decisions had 0 false denials at a CPU cost of p50 0.126 ms / p99 0.999 ms per decision (slowest single decision 3.84 ms). Those are our own lab scenarios on one machine, not a benchmark and not a measure of {{company}}'s stack. The command that produced them is on the site if you want to run it yourself.

{{role_hook}} If useful, the $1,800 Tier 1 diagnostic produces the same style of report for the tool list and MCP servers you choose to share. Reply with tool names and argument shapes (no secrets), or use mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit. Not a penetration test, and nothing is installed on your network.

Alec
alecagentboundary@gmail.com

### Touch 2 payloads, one per target (#1–#10)

Ready to paste. Each opening ties the target's public detail (from [la-targets.md](la-targets.md)) to one carrier. Re-open the target's cited page the day you send and cut any clause it no longer supports. Fill `{{first_name}}` only from a page you opened. The standing rules above apply: same-author lab figures only, the 3.84 ms maximum stays next to p50/p99, no Apart Research endorsement implied, 2 of 13 never pooled.

#### #1 Reva.AI — carrier B · delegation laundering · trace 05

Subject: Per-invocation authorization and the hand-off between agents

Hello {{first_name}},

Your MCP page says each tool invocation is evaluated before it runs. The case I keep coming back to is the one a per-call check sees least: a restricted agent hands the task to a peer whose own token is clean, and the peer makes the call.

Trace 05 in our report replays that confused-deputy hand-off, including a cycle back to the first agent, against our loopback gate. The deny caveats travel with the hand-off as chained HMACs, so the peer cannot strip them. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 05): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Reva.AI.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #2 Opensteer — carrier B · delegation laundering · trace 05

Subject: Approval gates and work handed between harness steps

Hello {{first_name}},

Your YC description says a harness can mix deterministic code, agent judgment, and human approval, and call first-party MCPs. Where those meet, an approval that bound one step can be routed around by handing the work to a sub-agent that never saw the untrusted input.

Trace 05 replays that confused-deputy hand-off against our loopback gate: restrictions travel with the hand-off as chained-HMAC caveats, so the receiving agent cannot send what the delegating one was barred from sending. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 05): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Opensteer.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #3 Paximal — carrier C · encoded smuggling · trace 06

Subject: Two MCPs in one drafting session

Hello {{first_name}},

Your 20 May post says the Paximal MCP can draft and pull live data from another MCP (Juristat) in the same session, with judgment stages pausing for an attorney. When two servers share a session, the boundary question becomes whether protected text can leave through the other server in pieces or re-encoded.

Trace 06 replays a watermarked value sent Base64- and URL-encoded to a public URI: the gate decodes it inline, matches it against salted n-gram digests of the original, and denies the call. That is our lab, not a statement about your pause. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 06): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Paximal.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #4 MindFort — carrier B · delegation laundering · trace 05

Subject: Restrictions that follow work across an agent swarm

Hello {{first_name}},

You run autonomous agents through an API and an MCP path, so one agent handing a task to another is normal operation. The failure I study is a restricted agent laundering its task through a peer whose own capability looks clean.

Trace 05 replays that confused-deputy hand-off, plus a cycle back to the first agent, against our loopback gate. Restrictions only move down a lattice at each hand-off, so re-delegating never restores egress. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 05): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of MindFort.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #5 Voker — carrier A · post-taint side channel · test file, no trace

Subject: When the tool choice itself is the signal

Hello {{first_name}},

Your launch post treats a wrong-tool call as the failure teams should see before a customer does. There is a quieter version: after an agent reads untrusted input and sensitive data, which tool or argument variant it picks, and when, can itself carry information, with no secret in any argument.

Our side-channel guard bounds that channel by counting distinct variants, calls, and timing regularity after the taint point, and holds the session when a bound is crossed. It has no browser trace; the eight tests are in agent-gateway/tests/test_side_channel_guard.py in the repo. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (the other two carriers): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Voker.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #6 Superunit — carrier C · encoded smuggling · trace 06

Subject: Calls, email, and fax as outbound channels

Hello {{first_name}},

Your agents place calls and send email and fax as the job itself, and you keep an FCRA audit trail. Send channels like those are where a protected value can leave split across messages or re-encoded, so a content filter never sees it whole.

Trace 06 replays an encoded, watermarked value caught inline and denied. Each decision lands in a SHA-256 hash-chained log with an HMAC-signed manifest; that is tamper evidence for our lab log, not a SOC 2 or ISO mapping. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 06): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Superunit.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #7 Endstack — carrier C · encoded smuggling (+ SSRF) · trace 06

Subject: A browser, a terminal, and a metadata address

Hello {{first_name}},

Your YC page gives each agent a Linux desktop, Chrome, a terminal, and inbound Slack, email, and SMS. With that surface, the two exits I would check first are a disguised cloud-metadata address and an encoded secret sent to a public host.

Trace 06 replays both against our loopback gate: a hex-spelled 169.254.169.254 is canonicalized and denied, and a Base64- and URL-encoded watermarked secret is decoded inline and denied. We have not tested endOS, and the gate is not a sandbox. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 06): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Endstack.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #8 Keyframe Labs — carrier A · post-taint side channel · test file, no trace

Subject: The agent behind the avatar

Hello {{first_name}},

Your docs tell a customer to connect their own agent or LLM and send audio into the session. The tool boundary that matters is that agent's, and one carrier specific to real-time loops is timing: an agent that chooses when to call can signal through the rhythm of its calls.

Our side-channel guard bounds call count, distinct variants, and timing regularity once a session is tainted, and holds it when a bound is crossed. It has no browser trace; the eight tests are in agent-gateway/tests/test_side_channel_guard.py. This would cover your customer's agent tool list, not the avatar model. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (the other two carriers): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Keyframe Labs.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #9 Snap — carrier B · delegation laundering · trace 05

Subject: A narrow identity, and what it hands off

Hello {{first_name}},

The Casper post says coding agents reach Snap systems through an MCP Gateway under a narrow identity, and the Ads MCP page warns that instructions can arrive in tool output. A narrow identity holds only if it survives delegation: an agent that read injected output should not be able to pass the task to a peer with a cleaner identity.

Trace 05 replays that confused-deputy hand-off against our loopback gate; deny caveats travel with the hand-off as chained HMACs. Trace 01 shows the related case of a mutated tools/list. This is not a review of Casper. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 05): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Snap.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

#### #10 Riot Games — carrier C · encoded smuggling · trace 06

Subject: Internal agents with internal and external tools

Hello {{first_name}},

The Los Angeles staff posting describes agents that call internal and external tools, and lists prompt injection and tool abuse among the risks. When an agent can read internal data and also reach an external tool, the leak that content filters miss is the encoded or split one.

Trace 06 replays a watermarked internal value, Base64- and URL-encoded, sent to a public URI; the gate decodes it inline, matches salted n-gram digests, and denies the call. We have not seen Riot traffic, and this says nothing about the game stack. It is part of our submission to Apart Research's AI collusion research sprint.

Live trace inspector (trace 06): https://freeling10-prog.github.io/rogue-ai-detection/#traces
Sample executive audit report (PDF, unedited): https://freeling10-prog.github.io/rogue-ai-detection/sprint/collusion_sprint_report.pdf

In that run 57 of 57 carrier checks passed and 750 benign decisions produced 0 denials, at p50 0.126 ms and p99 0.999 ms CPU per decision; the slowest single decision took 3.84 ms. These are same-author lab checks on one machine, not a benchmark and not a measure of Riot Games.

If it is useful, the $1,800 Tier 1 diagnostic produces the same kind of report for the tool list you choose to share. Reply with tool names and argument shapes (no secrets). Nothing is installed on your network, and this is not a penetration test.

Alec
alecagentboundary@gmail.com

### Touch 3 — close the loop

Subject: Closing the loop on the tool-boundary note

Hello {{first_name}},

I will stop after this note unless you want the audit.

If you do, reply with the tool names and argument shapes (no secrets), where untrusted text can enter, and whether you want the $1,800 inventory review, the $4,500 list-only note, or the $6,500 note with instrumentation. Scope and the out-of-scope list: `marketing/audit-offer.md` in https://github.com/freeling10-prog/rogue-ai-detection.

If the timing is wrong, no reply needed.

Alec
alecagentboundary@gmail.com

## LinkedIn

Connect only where you have a real public page for {{company}}. Keep the connection note at or under 200 characters after you fill the slots. LinkedIn often caps the note near 200.

### Touch 1 — connection note

Keep `{{public_detail}}` to a few words here. A full clause will break the 200-character cap.

{{first_name}}, I read {{company}}'s public note on {{public_detail}}. I write a 48-hour agent tool-boundary note for security reviewers. One-page scope if useful. — Alec

### Touch 2 — after they accept

Hello {{first_name}},

Thanks for connecting. {{role_hook}}

The offer is a written note, not a pen-test and not a certification. $1,800 for a one-page inventory review, $4,500 for the full note on a tool list, or $6,500 if you also want the lab gateway and an offline pass on a log you are allowed to share. The lab stays on 127.0.0.1.

Page: `marketing/audit-offer.md` in https://github.com/freeling10-prog/rogue-ai-detection

Or email alecagentboundary@gmail.com with the subject "Book 48-Hour Agentic Tool-Boundary Audit". You can reply with the tool inventory.

Alec

### Touch 3 — one follow-up, then stop

Hello {{first_name}},

One follow-up, then I will leave it. If a security reviewer at {{company}} is asking which tools remain callable after untrusted text, the scope is the offer page above and the same mailto. If that review is not happening, ignore this.

Alec
