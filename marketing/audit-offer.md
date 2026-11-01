# AgentGate — 48-Hour Agentic Tool-Boundary Audit

A written note for a security reviewer, produced from a tool list you send. For B2B teams that ship AI agents, MCP tools, or an agent product and are in an enterprise security review that asks which tools the model can still call after it reads something it did not write.

**Live interactive demo (public, no login):** <https://freeling10-prog.github.io/rogue-ai-detection/> · Source: [github.com/freeling10-prog/rogue-ai-detection](https://github.com/freeling10-prog/rogue-ai-detection) · Book: [alec@room23.net](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit)

The open-source lab in this repository stays Apache 2.0. This page is a paid service: a person's time and the note. Paying does not buy a different license to the code, and there is no proprietary module in the tree. The free GitHub Action remains free.

This is not a penetration test, not a red team, and not a certification. It is not legal advice.

## Offer ladder

Fixed-price services below and around the flagship audit. Prices already stated in [Price](#price) are unchanged: the **$750** Hardened MCP Server Build ($350 at kickoff, $400 when acceptance tests pass), Tier 1 at **$1,800**, Tier 2 at **$4,500**, Tier 3 at **$6,500**, Integration Blueprint **+$2,500**, Reviewer Briefing Call **+$750**, and Quarterly Refresh **$2,500 per quarter**.

The public cards are on the [marketing page](https://freeling10-prog.github.io/rogue-ai-detection/#services). Sample sprint artifacts stay on the [live demo](https://freeling10-prog.github.io/rogue-ai-detection/demo/#engagements).

| Offer | Fee | Clock | Scope |
| --- | --- | --- | --- |
| **MCP Permission Quick Check** | **$149** | 24 hours from a usable config | Up to 5 MCP server configs you send (`mcp.json` or `claude_desktop_config.json`, secrets removed) and 60 tools. Each tool classed as read, write, send, or credential use. Flags for plaintext tokens, over-broad scopes, and tools that read untrusted content and can also write or send. One-page PDF, top 5 fixes ranked. Config and tool-manifest review only: no code review, no runtime testing, no access to your systems, no fixes applied. Add-ons: +$49 per extra 5 servers; +$99 for a 20-minute call. Mailto subject: `Book MCP Permission Quick Check`. |
| **Starter MCP Server Build** | **$450** | 4 business days from kickoff | One system. An MCP server in Python or TypeScript, stdio, plus Streamable HTTP if requested. Up to 4 tools, read-only by default, at most 1 write tool behind an explicit confirmation argument. API key or bearer token via environment variables. Input schema validation, allow-listed endpoints or tables, output caps, secret redaction in logs. Tests for each tool and the deny paths. README for Claude Desktop, Cursor, and Claude Code. 1 revision within 7 days of delivery. Kickoff is API docs or a schema, a test or staging credential, and the agreed tool list. Out of scope: OAuth (add-on), multi-tenant auth, hosting, more than 4 tools, more than 1 write tool, delete / refund / bulk-export tools, building the underlying API, production credentials. Add-ons: extra read tool +$60 (up to 8 tools); extra confirmation-gated write +$100; OAuth 2.1 for one provider +$300; Dockerfile and a remote deploy guide (the client deploys) +$150; 48-hour rush +$150; extra revision +$75. A policy wrap and hash-chained audit log is the $750 Hardened Build. Mailto subject: `Book Starter MCP Server Build`. |
| **48-Hour Hardened MCP Server Build** | **$750** | 48 hours | Unchanged. See the package table under [Price](#price): one system, `pep.py` allow / deny rules, sensitive-field redaction, SHA-256 hash-chained audit log, pytest acceptance suite, delivered as a pull request. $350 at kickoff and $400 when acceptance tests pass. Mailto subject: `Book 48-Hour Hardened MCP Server Build`. |
| **MCP Server Security Review** | **$950** one server · **$1,500** two servers | 3 business days from repo access (or a source zip) and a test configuration | Code and tool-definition review, with descriptions read the way the model reads them: injection surfaces, over-broad tools, missing input validation, path / URL / SQL argument risks, secrets handling, auth, and scoping. Local lab run through `agent-gateway` validators on loopback with test data, never production. Findings ranked by severity, each with a concrete fix; SARIF 2.1.0; a 30-minute walkthrough; one re-test of fixed high or critical findings within 30 days. Up to 15 tools per server. No live production testing, no pentest of surrounding infrastructure, no social engineering, no compliance attestation. Fixes are recommendations. Add-ons: implement up to 5 findings as a pull request +$400; extra server +$550; 48-hour rush +$250. Mailto subject: `Book MCP Server Security Review`. |
| **Agent-Gateway Guardrail Drop-In** | **$1,500** | 5 business days from the tool list and repo access | `agent-gateway` MCP proxy for up to 3 servers / 30 tools and one agent harness: allow / deny lists, argument validators (path, URI egress, SQL / AST), toxic-combination rules for an untrusted read that can reach a write or a send. **Log-only by default**: decisions are logged, not enforced. It enforces only deterministic rules the client approves in writing, and only the client switches those rules on. SHA-256 hash-chained decision log with `verify`. A CI job that exports SARIF and fails on policy regressions. Pull request plus a runbook; the client's team reviews, merges, and deploys. Nothing is deployed on their hosts by AgentGate. 30-minute handover and 14 days of fixes for config issues. No custom validator development beyond configuration, no production on-call, no SIEM integration. Add-ons: extra server +$300; custom validator +$400; SIEM / log-shipping guide +$250; Integration Blueprint remains +$2,500. Mailto subject: `Book Agent-Gateway Guardrail Drop-In`. |
| **Boundary Watch** | **$395 / month** | Monthly re-run, delivered within 3 business days of the updated list | For a team that has bought a build, review, drop-in, or audit and keeps adding tools. Re-run of the `agent-gateway` audit and SARIF export; review of up to 5 new or changed tools (no rollover); one small policy or code change (at most 2 hours); a one-page change summary; email support with a reply within 2 business days. No on-call. Month to month, cancel anytime; 2 months recommended. Add-on: extra 5 tools +$150. A quarterly written-note refresh remains $2,500 per quarter. Mailto subject: `Book Boundary Watch`. |
| **48-Hour Agentic Tool-Boundary Audit** (flagship) | **$4,500** / **$6,500** with lab instrumentation | 48 hours from a usable tool list | Unchanged. Tier 2 is the fixed note at $4,500. Tier 3 adds instrumentation at $6,500, then $2,500 per quarter. Tier 1 Exposure Diagnostic stays **$1,800**. See the tier table under [Price](#price). Mailto subject: `Book 48-Hour Agentic Tool-Boundary Audit`. The instrumentation booking on the site uses `Book 48-Hour Agentic Tool-Boundary Audit with Instrumentation`. |

**Credit toward the audit.** 100% of a Quick Check fee and 50% of a Security Review or Drop-In fee credits toward the flagship audit ($4,500, or $6,500 with instrumentation) if that audit is booked within 30 days. The earlier deliverable is reused in the audit.

The usual path is the $149 check, then a $450 build or a $950 review, then the $1,500 drop-in, then the $4,500 audit, then Boundary Watch at $395 a month or the $2,500 quarterly refresh. Each lower deliverable ends with a short note on what it did not cover.

No client list, testimonial, or certification is claimed. The proof offered is the public repository and the live demo. Every deliverable says it is not a penetration test, a certification, or legal advice.

## Price

**Fast-turnaround implementation package.** The build sits above Tier 1 and can be booked on its own.

| Package | Fee | Deliverables |
| --- | --- | --- |
| **48-Hour Hardened MCP Server Build** (Fixed-Scope Implementation) | **$750 flat** ($350 kickoff / $400 on passing acceptance tests) | Custom MCP server (Postgres, Stripe, HubSpot, Slack, or internal REST API) built on `mcp_blueprint.py` and wrapped in `pep.py` allow / deny rules, sensitive-field redaction, SHA-256 hash-chained audit logging, and a `pytest` acceptance suite, delivered as a mergeable PR in 48 hours. Nothing is deployed on your hosts by us. |

The build covers one system and its read-only queries (parameterized, at most 100 rows per call), scoped lookups, and up to a few confirmed write or task-creation tools. Mutation verbs such as `delete`, `refund`, `cancel`, `drop`, `truncate`, and `bulk_export` stay denied unless you approve them in writing, and an approved one still needs a per-call confirmation token. The $400 balance is due when the acceptance suite passes on your side. The 48-hour clock starts when access to a test or staging instance (never production credentials) and the list of tools you want are in hand.

| | Tier 1: MCP & Multi-Agent Exposure Diagnostic (Tool Inventory Review) | Tier 2: Inline PEP Hardening & CI Gate Sprint (Fixed Tool-Boundary Note) | Tier 3: Continuous Red-Team, Canary & Deception Retainer (Note + Lab Instrumentation) |
| --- | --- | --- | --- |
| Price | **$1,800** | **$4,500** | **$6,500** |
| Tool list classified by egress | Yes | Yes | Yes |
| Top 3 taint paths | Yes | Full taint-path map | Full taint-path map |
| Short remediation list | Yes (one page) | Remediation sketch (first three controls) | Remediation sketch (first three controls) |
| Which calls the lab gateway would hold | No | Yes | Yes |
| Approximate ATLAS ids on the note | No | Yes | Yes |
| Written note for the security reviewer | One-page boundary map | Full note | Full note |
| Instrumentation | No | No | Yes |
| Named artifacts | Posture report PDF, SARIF bundle, Sigma + STIX 2.1 | Tier 1 plus policy set, CI regression machines, hash-chained logging | Tier 2 plus tripwire, canary, and guard configuration and quarterly re-verification |

**Optional add-ons**, attached to any tier. All prices are fixed; there is no hourly billing.

| Add-on | Price | What it is |
| --- | --- | --- |
| Integration Blueprint | +$2,500 | Code or config sketches for the top held calls: how to route them through the gateway or an equivalent check in your harness. Sketches only. Nothing is deployed on your hosts. |
| Reviewer Briefing Call | +$750 | A 30-minute walkthrough of the note with your security reviewer. |
| Quarterly Refresh Retainer | $2,500 per quarter | The note re-run against an updated tool list, for teams that add tools often. |

The **Tool Inventory Review** is the lowest-friction entry. It is a one-page egress classification, the top three taint paths, and a short remediation list. It is not the full note and it has no lab pass. It is a fair start if you only need the classification step or want to see how the work reads before you commit to a full note.

**Instrumentation** means an optional pass in our lab, on material you are allowed to share. It is two things, and only those two:

1. A **lab gateway pass**: we run your tool list through the lab policy proxy on `127.0.0.1`. Tool backends in that proxy are simulated echoes. We do not install the gateway on your hosts.
2. An **analyzer pass**: if you supply an authorized access log (nginx, Caddy, Cloudflare, or JSON), we run it through the offline analyzer. The analyzer does not connect to your network. We will say which rules that log cannot support. Beacon, tool-hijack, and timing rules are not available from a normal access log.

A log is not required for the $4,500 tier, and we do not run the log or the lab gateway pass unless you take the $6,500 tier. The Inventory Review includes neither. The scrubber is a backstop. Strip live tokens before you send a log.

## Artifacts by tier

Each artifact is produced by a module in this repository, so you can read the code that makes it before you book. Sample output from our own collusion-sprint run (commit `cefec0d`, unedited): [report PDF](../sprint_submission/collusion_sprint_report.pdf), [briefing deck PDF](../sprint_submission/collusion_sprint_slides.pdf), [JSON benchmark artifact](../sprint_submission/collusion_benchmark_results.json). The same files are linked from the [live demo](https://freeling10-prog.github.io/rogue-ai-detection/demo/#engagements).

- **Tier 1, MCP & Multi-Agent Exposure Diagnostic ($1,800).** An executive collusion and posture report (PDF) from `python -m agent_gateway audit`; a SARIF 2.1.0 bundle for GitHub code scanning (`sarif_export.py`) with approximate MITRE ATLAS ids; Sigma rules and a STIX 2.1 bundle from `agentwatch-analyzer`, chosen for the log format you name.
- **Tier 2, Inline PEP Hardening & CI Gate Sprint ($4,500).** Tier 1 and the full written note, plus a loopback `pep.py` and `mcp_proxy.py` policy set configured for your tool list (`delegation_guard.py`, `toxic_combinations.py`, `arg_ast_guard.py`, `egress_uri_guard.py`); the 13 stateful Hypothesis regression machines wired into a CI workflow; and per-run tamper-evident logging (`audit_chain.py`: SHA-256 hash-chained decision log, HMAC-signed manifest, `verify`). Delivered as files and a pull request your team reviews and merges. We do not deploy on your hosts. Wiring the gateway into your own agent harness remains the Integration Blueprint add-on.
- **Tier 3, Continuous Red-Team, Canary & Deception Retainer ($6,500, then the $2,500 quarterly refresh).** Tier 2 and the lab instrumentation pass, plus configuration for localhost honeypot tripwires (`agent-watch`, `127.0.0.1`, human-review leads only), canary watermark tracking (`canary_watermark.py`), de-obfuscation and side-channel guards (`deobfuscate.py`, `side_channel_guard.py`), and a quarterly `evaluate-collusion` latency and posture re-run. "Red-team" here means scripted adversarial regression scenarios run in our lab against your tool list. It is not a red team of your users or customers.

`evaluate-collusion` figures are same-author lab checks. They show the guards behave as their tests specify; they are not a detection rate for your product and are never pooled with the 2 of 13 archive figure.

## Clock

The clock starts when we have a usable tool list: tool names, argument shapes, and where untrusted text can enter. It does not start at the first email. If the list is incomplete, we say so and the clock starts when a usable list arrives.

- Tool Inventory Review: 24 hours from a usable list.
- Fixed Tool-Boundary Note: 48 hours from a usable list.
- Note + Lab Instrumentation: 48 hours from a usable list. The log is optional.

Add-ons are scheduled with you after the note is delivered.

## What you receive

One sentence version: you receive a written tool-boundary note that lists every untrusted-ingest to held-call path, the approximate ATLAS techniques involved, and the exact places a reviewer should ask for controls. The Inventory Review is the one-page version of that: classification, the top three taint paths, and a short remediation list.

- Each listed tool classed as external read, internal read, write, send, or credential use, and where untrusted text can reach a send, a write, or a credential tool.
- A taint-path map: untrusted ingest, then a held write, send, or credential call unless a person approves that exact call (session, step, tool, canonical args).
- Which of those calls the lab gateway would hold for a person, and which registered internal key it would freeze for 15 minutes. Unregistered keys are not frozen. The note says that in those words.
- On the instrumentation tier, the offline log pass when you supply a log the CLI accepts, including the rules that log cannot support (R11, R12, R13 offline).
- Approximate MITRE ATLAS ids used in the lab (mitigation AML.M0030, techniques T0051, T0053, T0080, T0086, T0118). Every mapping is labeled approximate.
- A remediation sketch: the first three controls worth asking for (for example, which calls to gate or attenuate first, and the pattern of change). On the Inventory Review this is a short list. Code or config sketches for the held calls are the Integration Blueprint add-on. Nothing is deployed on your hosts.
- A short written note a security reviewer can read. No logo. No detection-rate claim about your product.

Delegation limits in the note are lab policy, not your current production settings: depth 1, at most 3 child agents, taint following an internal handoff.

A loopback demo is available if you want to reproduce a held `send` after a tainted read. The only real-model number in the note is from our own archive: a local `qwen2.5:3b` against the honeypot on `127.0.0.1`, catch rate **2 of 13** non-control runs, both of them browser harnesses, none of them the HTTP tool-caller. That figure is not a measure of your product. Same author, one machine, small n. Not a benchmark.

## In scope

- A tool inventory you send, classified by egress.
- The taint path described above, as lab policy.
- The delegation limits above, described as lab policy.
- An offline log pass on the instrumentation tier, when you supply a log the CLI accepts.
- A short remediation list or sketch, and, if you buy the Integration Blueprint, configuration sketches for the top held calls.
- A written note with approximate ATLAS ids and, when a log was run, an explicit list of rules the log could not support.

## Out of scope

- Deploying `agent-watch` or `agent-gateway` on your hosts or on a public address. The Integration Blueprint is sketches, not a deployment.
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

Email [alec@room23.net](mailto:alec@room23.net?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit) with the subject **Book 48-Hour Agentic Tool-Boundary Audit**. You can book in that message, and you can reply in the same thread with the tool inventory. There is no separate scheduling site.

Attach or paste:

- Tool names and argument shapes. No secrets and no customer payloads.
- Where each tool's input can come from untrusted content (a web page, a ticket, an MCP tool description, or something else you name).
- Which offer you want: MCP Permission Quick Check ($149), Starter MCP Server Build ($450), the $750 48-Hour Hardened MCP Server Build (name the system), MCP Server Security Review ($950 for one server or $1,500 for two), Agent-Gateway Guardrail Drop-In ($1,500), Boundary Watch ($395/month), $1,800 Tier 1 (Exposure Diagnostic / Tool Inventory Review), $4,500 Tier 2 (PEP Hardening & CI Gate Sprint / Fixed Note), or $6,500 Tier 3 (Retainer / Note + Lab Instrumentation). Name any add-ons. Use a subject that names the offer; the flagship subject above still covers Tier 1, Tier 2, and Tier 3.
- For the $6,500 tier, an authorized access log if you have one you are allowed to share. Already stripped is better.
- The reviewer's role, if you want the note addressed to a function. A name is optional.

We do not take production credentials. We do not install anything in your production environment. Reply first. The clock starts when the tool list arrives, not when the email does.

**Free alternative**, if you only want the lab to run on logs you already have: the Apache 2.0 GitHub Action [`.github/workflows/atlas-agent-audit.yml`](../.github/workflows/atlas-agent-audit.yml) in [this repository](https://github.com/freeling10-prog/rogue-ai-detection). That action does not bind a port and does not write the reviewer note or the one-page inventory described above. The paid work is the written document and a person's time; the code stays free either way.
