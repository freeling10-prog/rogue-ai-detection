# CISO / security-lead outreach

Cold email for a **B2B AI startup** that is in an enterprise procurement security review and has been asked how its agents are allowed to call tools. The offer is a **48-hour Agentic Tool-Boundary Audit** using the lab stack on `main`.

Status: **scope source. Do not send this body.** The sequence to send is [outreach-sequence.md](outreach-sequence.md). The one-page offer and the live mailto are in [audit-offer.md](audit-offer.md). The greeting below still says `[TODO: first name]` on purpose. This file invents no company domain and no scheduling link.

This is not a pen-test order form, not a certification, and not legal advice. The lab evidence you are allowed to describe is the evidence in [README.md](README.md) of this folder.

## Subject

48-hour agent tool-boundary audit before your enterprise security review

Alternate subject, if the first feels broad:

What your enterprise reviewer will ask about agent tool calls — 48-hour lab audit

## Body

Hello [TODO: first name],

Enterprise reviews of agent products now ask a concrete question: after the model reads something it did not write (a web page, a ticket, an MCP tool description), which tools can it still call, and who has to agree first?

We run a 48-hour Agentic Tool-Boundary Audit for startups in that review. The clock starts when we have your tool list. You get a short written note your security reviewer can read, not a logo and not a detection-rate claim.

In those 48 hours we:

- Class each tool you list as external read, internal read, write, send, or credential use, and mark where untrusted text can reach a send, a write, or a credential tool.
- Say which of those calls our lab gateway would hold for a person, and which registered internal key it would freeze for 15 minutes. Unregistered keys are not frozen. The note says that in those words.
- If you already have an access log you are allowed to share (nginx, Caddy, Cloudflare, or JSON), we run it through an offline analyzer that does not connect to your network. We will say which rules that log cannot support. Beacon, tool-hijack, and timing rules are not available from a normal access log.
- Map the findings to MITRE ATLAS ids we use in the lab (mitigation M0030, and techniques T0051, T0053, T0080, T0086, T0118) and label every mapping approximate.

We do not install anything in your production environment, we do not bind a honeypot on your network, and we do not take production credentials. A loopback demo is available if you want to reproduce a held `send` after a tainted read. The only real-model number in the note is the one in our own archive: a local `qwen2.5:3b` against our honeypot on 127.0.0.1, catch rate 2 of 13 non-control runs, both of them browser harnesses, none of them the HTTP tool-caller. That figure is not a measure of your product.

What we need from you, by reply:

- Tool names and argument shapes (no secrets, no customer payloads).
- Where each tool's input can come from untrusted content.
- Optional: an authorized access log, already stripped if you prefer. Our scrubber is a backstop, not a reason to send live tokens.

Reply to this message. You can also use the mailto below. There is no separate booking site. A tool inventory in the reply is enough to talk about starting the clock.

Alec
alecagentboundary@gmail.com
Offer: [audit-offer.md](audit-offer.md)
Mailto: [alecagentboundary@gmail.com](mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)

## Scope card (keep next to the sent mail, do not paste the whole card unless they ask)

**In scope**

- A tool inventory they send, classified by egress.
- The taint path: untrusted ingest, then a held write / send / creds call unless a person approves that exact call (session, step, tool, canonical args).
- Delegation limits we will describe as lab policy, not as their current production settings: depth 1, at most 3 child agents, taint following an internal handoff.
- An offline log pass when they supply a log the CLI accepts.
- A written note with approximate ATLAS ids and an explicit list of rules the log could not support (R11, R12, R13 offline).

**Out of scope**

- Deploying `agent-watch` or `agent-gateway` on their hosts or on a public address.
- Blocking their users, freezing a key outside the lab registry, or turning on `--webhook-deliver` toward their Slack.
- A penetration test, a red-team of their customers, or a jailbreak campaign against a third-party model.
- Any statement that they "pass" ATLAS, OWASP, NIST, or a customer's questionnaire. Sigma notes that mention OWASP ASI are orientation in the rule pack, not a finding that their product complies.
- A detection-rate, false-positive rate, or benchmark. Synthetic scores in the repository stay out of the customer note. The 2 of 13 figure stays labeled as our loopback archive.
- Legal advice, insurance language, or a SOC 2 / ISO control mapping.

**If they ask "what did you catch in the wild?"**

Say that the repository has no wild deployment. The honeypot default is `127.0.0.1`. Web findings are leads for a person. Then stop. Do not fill the silence with the synthetic precision and recall tables.
