# AgentGate — 48-Hour Agentic Tool-Boundary Audit

A written note for a security reviewer, produced from a tool list you send. For B2B teams that ship AI agents, MCP tools, or an agent product and are in an enterprise security review that asks which tools the model can still call after it reads something it did not write.

The open-source lab in this repository stays Apache 2.0. This page is a paid service: a person's time and the note. Paying does not buy a different license to the code, and there is no proprietary module in the tree. The free GitHub Action remains free.

This is not a penetration test, not a red team, and not a certification. It is not legal advice.

## Price

| | Fixed | With instrumentation |
| --- | --- | --- |
| Price | **$4,500** | **$6,500** |
| Tool list classified by egress | Yes | Yes |
| Taint-path map | Yes | Yes |
| Which calls the lab gateway would hold | Yes | Yes |
| Approximate ATLAS ids on the note | Yes | Yes |
| Written note for the security reviewer | Yes | Yes |
| Instrumentation | No | Yes |

**Instrumentation** means an optional pass in our lab, on material you are allowed to share. It is two things, and only those two:

1. A **lab gateway pass**: we run your tool list through the lab policy proxy on `127.0.0.1`. Tool backends in that proxy are simulated echoes. We do not install the gateway on your hosts.
2. An **analyzer pass**: if you supply an authorized access log (nginx, Caddy, Cloudflare, or JSON), we run it through the offline analyzer. The analyzer does not connect to your network. We will say which rules that log cannot support. Beacon, tool-hijack, and timing rules are not available from a normal access log.

A log is not required for the $4,500 tier, and we do not run the log or the lab gateway pass unless you take the $6,500 tier. The scrubber is a backstop. Strip live tokens before you send a log.

## Clock

The **48-hour clock starts when we have the tool list**: tool names, argument shapes, and where untrusted text can enter. It does not start at the first email. If the list is incomplete, we say so and the clock starts when a usable list arrives.

## What you receive

- Each listed tool classed as external read, internal read, write, send, or credential use, and where untrusted text can reach a send, a write, or a credential tool.
- A taint-path map: untrusted ingest, then a held write, send, or credential call unless a person approves that exact call (session, step, tool, canonical args).
- Which of those calls the lab gateway would hold for a person, and which registered internal key it would freeze for 15 minutes. Unregistered keys are not frozen. The note says that in those words.
- On the instrumentation tier, the offline log pass when you supply a log the CLI accepts, including the rules that log cannot support (R11, R12, R13 offline).
- Approximate MITRE ATLAS ids used in the lab (mitigation AML.M0030, techniques T0051, T0053, T0080, T0086, T0118). Every mapping is labeled approximate.
- A short written note a security reviewer can read. No logo. No detection-rate claim about your product.

Delegation limits in the note are lab policy, not your current production settings: depth 1, at most 3 child agents, taint following an internal handoff.

A loopback demo is available if you want to reproduce a held `send` after a tainted read. The only real-model number in the note is from our own archive: a local `qwen2.5:3b` against the honeypot on `127.0.0.1`, catch rate **2 of 13** non-control runs, both of them browser harnesses, none of them the HTTP tool-caller. That figure is not a measure of your product. Same author, one machine, small n. Not a benchmark.

## In scope

- A tool inventory you send, classified by egress.
- The taint path described above, as lab policy.
- The delegation limits above, described as lab policy.
- An offline log pass on the instrumentation tier, when you supply a log the CLI accepts.
- A written note with approximate ATLAS ids and, when a log was run, an explicit list of rules the log could not support.

## Out of scope

- Deploying `agent-watch` or `agent-gateway` on your hosts or on a public address.
- Blocking your users, freezing a key outside the lab registry, or turning on `--webhook-deliver` toward your Slack.
- A penetration test, a red team of your customers, or a jailbreak campaign against a third-party model.
- Any statement that you "pass" ATLAS, OWASP, NIST, or a customer's questionnaire. Sigma notes that mention OWASP ASI are orientation in the rule pack, not a finding that your product complies.
- A detection-rate, false-positive rate, or benchmark. Synthetic scores in the repository stay out of the customer note. The 2 of 13 figure stays labeled as our loopback archive.
- Legal advice, insurance language, or a SOC 2 / ISO control mapping.

If you ask what was caught in the wild: this repository has no wild deployment. The honeypot default is `127.0.0.1`. Web findings are leads for a person. Contact with a honeypot is not intent.

## Lab limits that stay in the note

- Default bind is `127.0.0.1`. This engagement does not ship a public honeypot.
- The web honeypot is human-review only. It does not auto-block a visitor.
- Freeze applies only to keys registered in the lab registry, for 15 minutes. An unregistered key is not frozen.
- ATLAS mappings are approximate. They are not a certification.

## How to book

Email [fleckalec@gmail.com](mailto:fleckalec@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit) with the subject **Book 48-Hour Agentic Tool-Boundary Audit**. You can book in that message, and you can reply in the same thread with the tool inventory. There is no separate scheduling site.

Attach or paste:

- Tool names and argument shapes. No secrets and no customer payloads.
- Where each tool's input can come from untrusted content (a web page, a ticket, an MCP tool description, or something else you name).
- Which tier you want: $4,500 fixed, or $6,500 with instrumentation.
- For the $6,500 tier, an authorized access log if you have one you are allowed to share. Already stripped is better.
- The reviewer's role, if you want the note addressed to a function. A name is optional.

We do not take production credentials. We do not install anything in your production environment. Reply first. The clock starts when the tool list arrives, not when the email does.

Free alternative, if you only want the lab to run on logs you already have: the Apache 2.0 GitHub Action [`.github/workflows/atlas-agent-audit.yml`](../.github/workflows/atlas-agent-audit.yml) in [this repository](https://github.com/freeling10-prog/rogue-ai-detection). That action does not bind a port and does not write the reviewer note described above.
