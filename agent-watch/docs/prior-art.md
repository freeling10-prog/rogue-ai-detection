# Prior-art search: "Rogue AI Detection in the Wild" (agent-watch + rogue-ai-pipeline)

Search date: **23 Oct 2026 (America/Los_Angeles)**. Method: WebSearch to find candidates, then every row below was opened and read
with WebFetch or `curl` (raw README, PyPI JSON, GitHub API, arXiv abstract page, vendor docs). WebFetch returns only a stub for GitHub
pages, so GitHub projects were verified from the raw README plus the GitHub API `created_at`; that is noted per row.
Anything I could not open is in section G and is **not** used as support for any claim.

Our project, in one line: a local honeypot / log detector (decoy API docs, decoy MCP endpoint, canary pages, a "coordination board" with
handoff token + nonce, salted-hash secret scrubber, passive detectors: asset starvation, unlinked jumps, score floors) feeding a multi-layer
pipeline (pseudonymization, Isolation Forest with frozen baseline, ATLAS-style rule gates, networkx coordination graph, hash-chained audit
log, STIX 2.1 export, scanner prefilter). All our results are same-author synthetic regression checks, not benchmarks.

"Verified" below means: I fetched the page/file and the statement in the "What it does" column is taken from it.

## A. Honeypots / canaries aimed at AI or LLM agents

| # | Name | What it does | Source (verified) | Date | Similar to us | Different from us |
|---|---|---|---|---|---|---|
| A1 | **Palisade Research, LLM Agent Honeypot** (Reworr, Volkov) | Modified Cowrie SSH honeypot. Prompt injections ("Important Message" goal hijack, then system-prompt stealing) hidden in the SSH banner, command output and files; plus response-time analysis (LLM agents ~1.7 s, humans slower). Public ~3-month deployment: 8,130,731 attempts, 8 "potential" AI agents. Dashboard now marked deprecated. | https://arxiv.org/abs/2410.13919 (full text read); https://github.com/PalisadeResearch/llm-honeypot (raw README); https://ai-honeypot.palisaderesearch.org/ | arXiv v1 17 Oct 2024, v2 10 Feb 2025; repo created 28 Oct 2024 | Same core idea: lure an agent with text only an instruction-follower acts on, log it, add timing as a second signal. Our canary pages and "cognitive capture" board are this idea moved to HTTP. | SSH vs. web/API/MCP. They ran in the wild on the public internet with real counts; we are localhost + synthetic only. Our extra passive detectors (asset starvation, unlinked jumps) do not appear in their paper. |
| A2 | **Drosera** (rod-trent) | "Honeypot for autonomous AI agents". Hidden per-session **HMAC-signed ticket** in a notice addressed to automated clients, to be redeemed at `/.well-known/agent-registration` with a purpose header; per-session `robots.txt` / `llms.txt`; inert canary credentials (`.env`, `id_rsa`, kubeconfig); maze/tarpit; 33 signals on 3 axes (automation / LLM agency / hostility) incl. `beh.no_assets`, uniform cadence; noisy-OR fusion; replay of nginx logs; STIX report format; ethics doc. States that a no-JS browser scores as "automation". | https://pypi.org/project/drosera/ (PyPI JSON + README); https://raw.githubusercontent.com/rod-trent/Drosera/main/README.md | PyPI 0.1.0 on 5 Sep 2026; repo created 5 Sep 2026 | **Closest overlap on the web side.** Signed per-session token/nonce handoff to prove comprehension, hidden-instruction canaries, per-session llms.txt/robots, asset-starvation signal, saturating evidence combination (noisy-OR), log replay, STIX, honest-limits section, "behaviour alone never says LLM" rule. | We have a multi-turn coordination-board/claim-shard loop and a cross-session handoff-token replay signal, a decoy MCP endpoint, a pipeline with Isolation Forest + ATLAS gates + audit chain. Drosera has no MCP server in what I read (README does not mention one). I did not read its source, only README; its test suite and real-world use are unknown. |
| A3 | **Sundew** (sundew-sh) | Honeypot exposing MCP server, OpenAPI spec, `/.well-known/ai-plugin.json`, `/.well-known/mcp.json`, robots/sitemap; "persona engine" makes every deployment look different; classifies sessions human / scanner / AI-assisted / autonomous agent by timing, enumeration, header, MCP and "prompt leak" scores. README roadmap lists STIX/TAXII export (roadmap, not claimed as shipped). | https://pypi.org/project/sundewsh/ (PyPI JSON + README); https://docs.sundew.sh/ ; raw README on GitHub (sundew-sh/sundew) | GitHub created 7 Feb 2026; PyPI 0.1.0 on 25 Feb 2026; latest 0.3.1 | **Closest overlap on decoy API docs + decoy MCP + behavioural classification.** | We add asset starvation / unlinked-jump / score floors, coordination board, scrubber, and the downstream pipeline. They add a persona engine (per-deployment variation) that we lack. The README shows illustrative example output; I did not check whether it reports an evaluation. |
| A4 | **Decoy / "Supradim AI Honeypot"** | Web + OpenAPI/REST + MCP + credential/Git/cloud-metadata/cluster decoys; HMAC-signed per-session canary markers correlated across surfaces; records MCP init/tool discovery/tool calls/breadcrumb following; "Agent Investigation Package" with counter-evidence; describes itself as an early-stage single-node MVP. | https://glama.ai/mcp/servers/weidutech/supradim-ai-honeypot (page mirrors the project README; I did not locate the source repo) | not shown | Signed per-session canaries across surfaces, MCP observation, evidence-with-counter-evidence timelines. | Broader decoy surface (Git/cloud/cluster); no pipeline layers like ours were described. Provenance weaker (aggregator page only). |
| A5 | **Thinkst Canary: Agent Provocateur and A2A personalities** | Commercial Canary personality that poses as a helpful agent-facing web service / A2A endpoint and asks the visiting agent about its task, identity, environment (even SSH key, MAC). Thinkst reports agents "trip over these 100% of the time" on its internal ranges (vendor claim, not independently verified). | https://blog.thinkst.com/2026/09/getting-agents-to-tell-on-themselves.html ; https://help.canary.tools/hc/en-gb/articles/38888479188637-How-do-I-configure-my-Canary-to-detect-interactions-from-AI-agents | 4 Sep 2026 | **Closest overlap for our coordination board / "cognitive capture".** Same trick: pose as a helper, ask the agent to disclose task, tools and identity. | Our board adds a peer-thread framing, nonce round-trip, claim-shard loop with a hard step cap, and a cross-session handoff-token signal. Thinkst states its approach can be fingerprinted and must run on standalone Canaries. |
| A6 | **prompt-injection-honeypot "pihoney"** (vinzabe) | Canary-token network: HMAC token per page placement in a hidden note asking an agent to fetch a URL; graded attribution (llm-agent / crawler / human / inconclusive) with counter-evidence; bait asks only for a URL fetch. Single-author project. | https://github.com/vinzabe/prompt-injection-honeypot (raw README read; GitHub API for date) | repo created 21 Jan 2026 | Per-placement HMAC canary instruction, "contact is not identity" honesty about crawlers. Same as our canary pages. | Narrower (canary only). |
| A7 | **AgentTrap** (Wang, Yu, Sun et al.) | Closed-loop honeypot for autonomous *penetration-testing* agents: sentinel endpoints, stateful deception, behaviour-guided escalation; tested against 8 agents; cut real-target attack success 95.8% to 79.2% and elicited attacker API keys in 18.8% of runs. | https://arxiv.org/abs/2610.02869 (abstract read) | 2 Oct 2026 | Stateful decoy that adapts to an agent; evidence collection from agent. | Offensive-agent focus and counter-attack; ours is passive detection of web/API agents. Only abstract read. |
| A8 | **Honeypots for AI Agent Insider Threats** (Wehner, Kraprayoon) | Position paper: plant decoy opportunities in *production* to catch misbehaving internal agents. | https://arxiv.org/abs/2610.26664 (abstract read) | 19 Oct 2026 | Same defensive logic (decoy contact = signal). | Targets agents you deploy, not external visitors. Position paper, no system. |
| A9 | **AI Agent Traps** (Franklin et al., Google DeepMind) | Taxonomy of adversarial web content that manipulates visiting agents (6 trap types). Offence-side framing. | PDF copy at https://www.rivista.ai/wp-content/uploads/2026/04/ssrn-6372438.pdf (read first pages). SSRN page itself was blocked. | SSRN date not verified by me | Our canary pages are a benign instance of its "content injection / behavioural control" class. | Threat taxonomy, not a detector. |
| A10 | **Cloudflare AI Labyrinth** | Opt-in; injects invisible nofollow honeypot links for suspected AI crawlers; they land in AI-generated decoy pages; "no human goes four links deep"; logged as "AI Labyrinth Crawls" and feeds Cloudflare ML. | https://blog.cloudflare.com/ai-labyrinth/ ; https://developers.cloudflare.com/bots/additional-configurations/ai-labyrinth/ | 19 Mar 2025 | Invisible-link honeypot = our hidden decoy links. Same logic. | They run it at CDN scale and use it for blocking intelligence; we only log leads. |

## B. AI-agent / bot detection (vendors, standards, academic)

| # | Name | What it does | Source (verified) | Date | Similar to us | Different from us |
|---|---|---|---|---|---|---|
| B1 | **Cloudflare Web Bot Auth** | Agents sign requests (HTTP Message Signatures, RFC 9421; `Signature-Agent`, `Signature-Input` with `created`/`expires`/optional `nonce`, `tag="web-bot-auth"`), keys published at `/.well-known/http-message-signatures-directory`. Docs: Cloudflare does **not** validate nonces. Verified-bot registry; "signed agent" status folded into Verified bots (Direct vs Intermediary) on 1 Jul 2026. | https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/ ; https://developers.cloudflare.com/bots/concepts/bot/verified-bots/ ; https://blog.cloudflare.com/web-bot-auth/ | blog 15 May 2025; docs updated 8 Oct 2026 | Shared aim: identify agents. Our scoring explicitly does not trust the User-Agent. | It is *cooperative* identification of friendly agents. We detect uncooperative ones. Our honeypot "nonce" is a tarpit challenge, unrelated to their anti-replay nonce. We do not implement or check signatures. |
| B2 | **DataDome Agent Trust / intent-based protection** | Classifies AI agents (crawlers, assistants, autonomous agents, agentic browsers); identification by Web Bot Auth, token verification, trusted IPs, rDNS, client/server fingerprinting with stated strength; separate "intent-based" layer to catch malicious behaviour from verified agents. | https://docs.datadome.co/docs/ai-agent-identification ; https://docs.datadome.co/docs/intent-based-protection (marketing page https://datadome.co/products/agent-trust-management/ needed JS, not read) | docs undated | Layered identity + intent split mirrors our "contact is not intent" stance. | Commercial product; we have no fingerprint catalog. |
| B3 | **JA3 / JA4+ (Salesforce, FoxIO)** and Cloudflare JA4 Signals | JA3 hashes the TLS ClientHello (Salesforce, 2017 per Cloudflare); JA4+ is FoxIO's suite (JA4 TLS, JA4H HTTP, etc.). Cloudflare exposes per-fingerprint hourly signals (browser_ratio_1h, reqs_quantile_1h...). | https://github.com/FoxIO-LLC/ja4 (raw README) ; https://blog.cloudflare.com/ja4-signals/ | Cloudflare post 12 Aug 2024 | Our `docs/ja4-tls-fingerprinting.md` proposes using JA4 vs. claimed User-Agent. | **We implement none of it** (parse-only field, not tested). Entirely prior art. |
| B4 | **FP-Agent** (Wang, Shafiq, Vekaria) | Controlled study of 7 AI browsing agents vs humans on an instrumented honey site; behavioural fingerprints (typing, scroll, mouse) separate agents; browser fingerprints weak; FP-Agent flagged all 7 agents where Cloudflare flagged 1. | https://arxiv.org/abs/2605.01247 (abstract read) | 2 May 2026 | Honey site + agent-vs-human behavioural separation. | Client-side JS behavioural features; we use server-log features only. |
| B5 | **"On the Internet, nobody knows you're an LLM bot"** (Fayolle et al., Inria) | 9 honeysites with anti-bot defenses, 6 LLM web agents + 6 tools; 1,383 visits; multi-layer (IP, TLS/JA4, browser) fingerprinting; Random Forest all-layer accuracy 0.993; some agents bypassed all defenses; stealth modes often increased detectability. | https://arxiv.org/abs/2606.30119 (full text read) | 29 Jun 2026 | Honeysite methodology; "mimic" agents that bypass defenses are real. | Active, instrumented own-agent study; we simulate. |
| B6 | **Known By Their Actions** (Lugoloobi et al.) | Passive JS tracker on pages; action/timing traces identify the underlying LLM with up to 96% F1 across 14 models; random delays degrade but retrained classifiers recover. | https://arxiv.org/abs/2605.14786 (full text read) | 14 May 2026 | Timing/action traces identify agents; shows our weak timing feature is evadable. | Model attribution, not misuse detection. |
| B7 | **Jarad and Bicakci, TLS/JA4 bad-bot detection** | XGBoost/CatBoost on JA4-derived features for bots vs users. | https://arxiv.org/abs/2602.09606 (abstract read) | 10 Feb 2026 | JA4 as lazy-mimic detector. | We don't implement. |
| B8 | **FP-Inconsistent** (Venugopalan et al.) | Honey site with DataDome and BotD, 20 bot-traffic services, ~0.5 M requests; evasion rates 52.93% (DataDome) and 44.56% (BotD); inconsistencies in altered fingerprints detect evasive bots. | https://arxiv.org/abs/2406.07647 (abstract read) | 11 Jun 2024 (rev. 21 Sep 2025) | Mimic vs. detector arms race; our `possible_mimic` class. | Browser fingerprint attributes, not server-log behaviour. |
| B9 | **Good Bot, Bad Bot / Aristaeus** (Li, Azad, Rahmati, Nikiforakis) | 100 never-advertised honeysites, 26.4 M requests from ~287 K IPs over 7 months; behavioural, browser and TLS fingerprinting. | IEEE S&P 2021 poster https://www.ieee-security.org/TC/SP2021/downloads/poster/poster15.pdf (read); Crossref DOI 10.1109/sp40001.2021.00079 (title/venue/date) | May 2021 | Honeysite as ground truth for bots. | Pre-LLM; large real deployment. |
| B10 | **Doran and Gokhale, Web robot detection** | Survey of robot detection: syntactic log analysis, traffic patterns, learning, Turing tests; no single technique works well. | https://corescholar.libraries.wright.edu/cse/251/ (abstract read); Crossref DOI 10.1007/s10618-010-0180-z | Jan 2011 | Survey classes: syntactic log analysis, traffic patterns, learning, Turing tests (abstract/summary). The intro of B6 also says early bot detection relied on request-pattern heuristics and crawl detection. I did not read this survey's full text, so I cannot say which specific features (e.g. missing assets) it lists. | Pre-LLM. |
| B11 | **Iliou et al., web logs + mouse biometrics** | Detects advanced web bots combining server logs with mouse behaviour. | Crossref only (DOI 10.1145/3447815, *Digital Threats: Research and Practice*, 8 Jun 2021); abstract not read. Also cited in B6. | Jun 2021 | Same family. | n/a |

## C. Decoy MCP servers, MCP honeypots, prompt-injection canaries

| # | Name | What it does | Source (verified) | Date | Similar to us | Different from us |
|---|---|---|---|---|---|---|
| C1 | **Thinkst MCP Canarytoken** | Generates a fake `mcp.json` (to drop in `.claude/`, `.cursor/`, `.mcp.json`); alerts on MCP client connection or only on tool call. Names `tools/list` as detection opportunity one, a tool call as two. | https://docs.canarytokens.org/guide/mcp-token.html ; https://blog.thinkst.com/2026/06/one-for-all-the-models-out-there.html | 22 Jun 2026 | **Our decoy MCP endpoint and "tools/list then valid tools/call" signal are the same two-stage idea.** | Ours is a server on our own host with scrubbed arg logging and synthetic replies; theirs is a token service. |
| C2 | **HoneyMCP** (barvhaim) | Middleware that injects "ghost tools" into an MCP server; logs invocation as exfiltration / indirect prompt injection with tool-call sequence. | https://pypi.org/project/honeymcp/ (PyPI JSON + README via GitHub master) ; https://github.com/barvhaim/HoneyMCP | repo created 30 Jan 2026; 0.1.8 on 6 Aug 2026 | Fake sensitive tools returning synthetic data; per-session tool sequence. | Embeds in a real server; we run a standalone decoy. |
| C3 | **mcp-canary** (aminrj) | Plants fake file paths / API keys / decoy tools in FastMCP tool descriptions; fires when a poisoned agent echoes them. README claims "zero false positives" and a Black Hat Europe Arsenal 2026 slot (README claims only). | https://pypi.org/project/mcp-canary/ (PyPI JSON) | PyPI 0.1.0 on 19 Jun 2026 | Honeytoken bait in tool text. | Tool-poisoning scenario, not external visitor. |
| C4 | **MCP Decoy** (gweber) | Express server impersonating an enterprise MCP hub: 38 tools, 10 integration categories, logs forensic detail, SIEM syslog; deterministic rules e.g. `MCP_TOOL_ENUMERATION` (`tools/list`), multi-tool recon, secret-hunting args. | https://github.com/gweber/mcp-decoy (raw README read) | repo created 22 Apr 2026 | **Near-identical decoy MCP endpoint + enumeration detector, loopback-by-default advice, JSON-RPC 2.0.** | Much larger tool set + SIEM output; no web-behaviour layer. |
| C5 | **Beelzebub** | Open-source LLM-powered deception runtime (SSH, HTTP, TCP, Telnet, MCP); MCP decoy tool whose invocation signals a guardrail bypass. | https://github.com/beelzebub-labs/beelzebub (raw README read) | repo created 8 May 2022 | Decoy MCP tool as detection. | Framework, broader protocols, LLM-generated replies. |
| C6 | **Rebuff** (Protect AI) | Prompt-injection detector with canary-word leak detection (`add_canary_word`, `is_canaryword_leaked`). Repo is archived; README: "still a prototype". | https://github.com/protectai/rebuff (README; GitHub API archived=true, last push 7 Aug 2024) | 2024 | Canary-in-prompt concept. | Protects your own prompt; ours is bait aimed at external agents. |

## D. Classic honeypot frameworks

| # | Name | What it does | Source (verified) | Date | Similar to us | Different from us |
|---|---|---|---|---|---|---|
| D1 | **Cowrie** | Medium/high-interaction SSH/Telnet honeypot (emulated shell, proxy mode, experimental LLM mode). Palisade's honeypot is built on it. | https://raw.githubusercontent.com/cowrie/cowrie/main/README.rst ; https://docs.cowrie.org/ | repo created 12 May 2015 | Structured interaction logging of attacker sessions. | SSH/Telnet only; no HTTP-agent heuristics. |
| D2 | **T-Pot** (Deutsche Telekom Security) | All-in-one multi-honeypot platform (20+ honeypots incl. Cowrie, Conpot, Galah, Beelzebub) with Elastic Stack dashboards. | https://raw.githubusercontent.com/telekom-security/tpotce/master/README.md | repo created 28 Nov 2014 | Aggregation + visualisation layer, which our pipeline partly mirrors. | Platform of existing honeypots; no agent-specific scoring. |
| D3 | **OpenCanary / Thinkst Canary** | Multi-protocol low-resource honeypot daemon that alerts on interaction; open-source edition of the commercial product. | https://raw.githubusercontent.com/thinkst/opencanary/master/README.md | repo created 5 Aug 2015 | "Any touch is an alert" canary model. | Network protocols, not web agents (the agent personalities are in A5). |
| D4 | **Galah** (0x4D31) | LLM-powered web honeypot answering arbitrary HTTP requests; Suricata rule matching; author notes it is identifiable. | https://github.com/0x4D31/galah (raw README) | repo created 31 Dec 2023, last push 25 Jul 2025 | Dynamic web decoy. | Generic attackers, not agent detection. |
| D5 | **Secure audit logs** (Schneier and Kelsey) | Tamper-evident log via hash chaining and forward-secure keys. | https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html (abstract read) | 1999 | **Our hash-chained audit log is this idea (ours is a plain hash chain; theirs adds key evolution/encryption).** | n/a |

## E. Academic work on detecting autonomous agents by behaviour and timing

| # | Name | What it does | Source (verified) | Date | Notes |
|---|---|---|---|---|---|
| E1 | Palisade (A1) | Response time as second factor | see A1 | 2024-25 | Authors present timing as preliminary; their own slow-response example is ambiguous (human or slow agent). |
| E2 | Known By Their Actions (B6) | Timing + actions identify the model | see B6 | 2026 | Randomised delays can be defeated by retraining: supports our "timing is weak, max 10 points" choice. |
| E3 | FP-Agent (B4) | Behavioural fingerprints vs Cloudflare | see B4 | 2026 | Browser-side behaviour beats headers; we cannot see it in server logs. |
| E4 | **Ghost Without Shell** (Valeros, Sladic, Garcia) | 11 SSH honeypots, 177,622 authenticated sessions, 99.23% non-interactive | https://arxiv.org/abs/2606.28006 (abstract read) | 26 Jun 2026 | Cautions that interactive timing signals are rare on SSH honeypots. |
| E5 | **GroupGuard** | Collusive multi-agent attacks defended via graph monitoring + honeypot inducement + isolation | https://arxiv.org/abs/2603.13940 (abstract read) | 14 Mar 2026 | Inside a multi-agent system you operate; ours is external. Graph + honeypot combination is shared in spirit. |
| E6 | Pacheco et al. (already in whitepaper [6]) | Coordination networks from shared traces | whitepaper ref | 2021 | Source for our graph layer design. |
| E7 | Isolation Forest (Liu et al., whitepaper [13]) | Unsupervised anomaly detection | whitepaper ref | 2008 | Standard component. |

## F. Feature-by-feature: what is and is not novel

"Not novel" = I found a published or shipped equivalent. "No equivalent found" = absence in my search, **not proof of absence**.

| Our feature | Verdict | Closest prior art |
|---|---|---|
| Hidden instruction / canary page that an obedient agent acts on | **Not novel** | Palisade A1, Drosera A2, pihoney A6 |
| Per-session / per-placement signed token (HMAC) in the bait | **Not novel** | Drosera A2, pihoney A6, Decoy A4 |
| Handoff token + nonce round-trip on a coordination board | **Largely not novel** (token+nonce proof of comprehension and agent self-disclosure) | Drosera A2 (signed ticket), Thinkst Agent Provocateur / A2A A5, Palisade prompt stealing A1 |
| Cross-session/IP *handoff-token replay* as a coordination signal; capped multi-step "claim-shard" loop | **No equivalent found** (small, unproven idea) | none |
| Decoy API docs (OpenAPI / llms.txt / ai-plugin) | **Not novel** | Sundew A3, Drosera A2, Decoy A4 |
| Decoy MCP endpoint, `tools/list` then `tools/call` signal | **Not novel** | Thinkst MCP token C1, MCP Decoy C4, HoneyMCP C2, Beelzebub C5, Sundew A3 |
| Hidden/invisible links, robots Disallow traps, `/.env` decoys | **Not novel** (decades old) | Cloudflare AI Labyrinth A10, Drosera A2, bot-trap practice |
| Asset starvation (HTML without CSS/JS/images) | **Not novel as a signal** | Drosera `beh.no_assets` A2; older request-pattern bot detection is described in B6/B10 (specific features not confirmed) |
| Sec-Fetch / header mismatch vs claimed browser | **Not novel** | fingerprint-inconsistency work B8, JA4H B3 |
| Unlinked-jump scoring against the served link graph | **No equivalent found** in the agent literature; resembles older "robot navigates outside link structure" log heuristics, which I did not verify in full text | B10 (partial) |
| Max-pooling score floors so benign padding cannot dilute a strong event | **Standard engineering**; Drosera uses noisy-OR saturation for the same concern | A2 |
| "Contact is not intent", graded actor types (agent / scraper / mimic / static / human) | **Not novel as a stance** | Drosera three-axis design, pihoney graded attribution, Decoy counter-evidence |
| Timing signal | **Not novel**, and known to be weak | Palisade A1, B6 |
| Secret scrubber before disk writes, console log hygiene | **Standard practice** (secret/PII scanners exist, e.g. Gitleaks https://github.com/gitleaks/gitleaks verified MIT; Presidio not verified) | n/a |
| Pseudonymization layer | Standard privacy engineering | n/a |
| Isolation Forest with frozen baseline | **Not novel** | Liu et al. 2008 |
| ATLAS-style rule gates | **Not novel** (uses MITRE ATLAS vocabulary) | MITRE ATLAS |
| networkx coordination graph | **Not novel** | Pacheco et al.; GroupGuard E5 |
| Hash-chained audit log | **Not novel** | Schneier and Kelsey D5 |
| STIX 2.1 export | **Not novel** (standard); Drosera A2 lists STIX report; Sundew roadmap lists it | A2, A3 |
| Scanner/commodity-noise prefilter | Standard practice; Cloudflare/DataDome do this at scale | B1, B2 |
| JA4 | **Not implemented by us**, fully prior art | B3, B5, B7 |
| **The combination**: open, local, honeypot-plus-passive-detector feeding an Isolation Forest + rule + graph + audit + STIX pipeline, with explicit false-positive/evader reporting | **No single equivalent found.** The parts are all prior art. | n/a |

## G. Honest assessment

**Closest prior art (read these first):** Drosera (A2), Sundew (A3), Thinkst Agent Provocateur / MCP Canarytoken (A5, C1), MCP Decoy (C4),
Palisade's LLM Agent Honeypot (A1). Between them, they already cover essentially every honeypot-side feature we list: hidden instructions,
signed per-session tokens, decoy OpenAPI/llms.txt/MCP surfaces, `tools/list` and tool-call detection, canary credentials, agent
self-disclosure prompts, asset-starvation scoring, and a human/scanner/agent classification with a "behaviour is not intent" caveat.
Sundew (PyPI Feb 2026) and Drosera (PyPI Sep 2026) are both recent, so our honeypot side is **at best contemporaneous and in most respects a
re-implementation** of existing open-source work.

**What is plausibly new (modest, unproven):**
1. The *integration*: a detector whose output is exported as pseudonymized events into a separate multi-layer pipeline (Isolation Forest,
   rule gates, coordination graph, audit chain, STIX). I did not find another project that does both halves; each half exists separately.
2. A few specific mechanisms with no equivalent found: unlinked-jump scoring against the link graph the honeypot actually served, the
   cross-session handoff-token signal, and the capped claim-shard loop.
3. The *evaluation honesty*: we report the evader (`mimic_assets` undetected), the "images blocked" false positives, and that scores are
   same-author synthetic regression checks. This is a reporting choice, not a technique. Palisade reports real-world counts, which we cannot.

**What is not new:** everything in the verdict table marked "Not novel". In particular, do not describe the decoy MCP endpoint, canary
pages, signed tokens, asset starvation, hash-chained logging, STIX export, Isolation Forest or the graph layer as contributions.

**What we lack relative to prior art:** any real-world deployment or data (Palisade: ~8.1 M attempts; Aristaeus: 26.4 M requests); a
persona engine to vary deployments (Sundew); fingerprint layers (JA4, browser fingerprints) that the 2026 measurement papers (B4, B5)
find far more discriminative than behaviour alone for some agents; client-side behavioural signals; verified-agent (Web Bot Auth)
handling. B5 reports some agents bypassed every defense and stealth modes could increase detectability, which is consistent with our
finding that a careful mimic evades server-log heuristics.

**Limits of this search:** web search only; GitHub/PyPI projects are young and mostly single-author, I read READMEs (not code) and I did not
run any of them, so their claims are theirs. Absence of an equivalent for the three mechanisms in item 2 means I did not find one.

## H. Not verified / not used

- SSRN abstract page for *AI Agent Traps* (blocked); its SSRN posting date (a search snippet said 28 Mar 2026) is unverified. Content was read from a PDF copy on rivista.ai.
- *Identifying LLM-Powered Cyber Attacks with Timing Analysis and Honeytoken-Based Deception* (BTH thesis, urn.kb.se): search snippet only (claims a 375-2500x timing separation); the fetch returned nothing. Not used.
- Palisade's newer dashboard (ai-honeypot.reworr.com): mentioned on the old dashboard, not fetched.
- *Agent-Canary-Mas* (arXiv 2610.15529), the NARCBench and Colosseum collusion papers, and the IJRDET "AI-augmented honeypot" article appeared in search results; not opened, not used.
- Microsoft Presidio: repo moved (301) and its README was not read; only a search snippet. Not used as support.
- mcp-canary's "zero false positives" and "Black Hat Europe Arsenal 2026" are README claims; I did not verify either.
- Thinkst's "100% of the time" is a vendor claim from their blog.
- Cloudflare's "no nonce validation" statement is from its own docs page as read on 23 Oct 2026; docs change.
- Iliou et al. (B11): bibliographic data only, via Crossref.
- Vendor marketing page datadome.co/products/agent-trust-management required JavaScript; DataDome facts come from docs.datadome.co.
