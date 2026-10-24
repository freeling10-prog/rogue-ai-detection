# First 10 LA outreach targets

Checked 24 October 2026. No earlier target list was in this repository. This list is new. A row is here only when a public page supports both the Los Angeles tie and the reason to write. Suggested contacts are roles, not named people. Do not invent a person's name to fill `{{first_name}}`.

**Confidence** is about the public evidence, not about whether they will buy.

- **High** — a primary page (the company, Y Combinator, or an SEC filing) states the LA location, and a primary page states the agent, MCP, or security-review fact used in the angle.
- **Medium** — the product fact is primary, and the LA fact is one step removed (a job located in Los Angeles, or a directory line).

Send order for the first five emails is the first five rows. Snap and Riot are real and public. They are last because a $4,500 cold note is a weak fit for a large company. Use them when you have a warmer path.

Prices and limits you may repeat are only those in [audit-offer.md](audit-offer.md). Angles below are the `{{role_hook}}` source. `{{public_detail}}` must stay inside the cited page.

## 1. Reva.AI

- **Why relevant:** Sells runtime authorization for MCP tool calls. Buyers in a security review will ask which tool invocations stay held after untrusted input. A second written note, from a tool list they choose, is a concrete artifact. This is a peer conversation, not a claim that their product has a hole.
- **Suggested role:** Head of Security, or a founding engineer on the MCP authorization path.
- **Angle:** KuppingerCole's vendor page calls Reva headquartered in Los Angeles, and your MCP page says each tool invocation is evaluated before it runs. The 48-hour note classifies a tool list you send and says which calls the lab gateway would hold. It will not say Reva passes ATLAS or anyone's questionnaire.
- **Public URL:** https://www.reva.ai/solutions/mcp-server-security and https://www.kuppingercole.com/vendors/reva
- **Confidence:** High. KuppingerCole states headquarters in Los Angeles. The contact page also shows Los Angeles under "Where the magic happens," next to Bengaluru (https://www.reva.ai/contact-us). That widget is a location display, not a street address. The MCP solution page describes per-invocation authorization. Their drift-detection percentages are theirs. Do not repeat those figures as ours.

## 2. Opensteer

- **Why relevant:** Y Combinator lists the company in Los Angeles. The product is specialized agents with tools, browser access, first-party MCPs, and approval gates. That is the tool-boundary question in product form.
- **Suggested role:** Founder (the YC page names Tim Jang as the active founder; confirm the name on that page before you use it).
- **Angle:** Your YC description says each harness can mix deterministic code, agent judgment, and human approval, and that harnesses can call first-party MCPs. The note maps a tool list you send onto egress classes and states which calls the lab gateway would hold for a person. It does not certify the cloud workspace.
- **Public URL:** https://www.ycombinator.com/companies/opensteer
- **Confidence:** High. YC company page, location Los Angeles, CA, and the harness / MCP / approval text are on that page. Product site: https://opensteer.com

## 3. Paximal

- **Why relevant:** Their own news post is datelined Los Angeles and announces an MCP server that runs patent-drafting stages from Claude and other assistants. Stages that need judgment pause for an attorney. Enterprise and law-firm buyers will ask what the assistant can still call.
- **Suggested role:** Founding engineer, or the person who owns the MCP server. A CISO is unlikely at this size. Do not guess a name.
- **Angle:** The 20 May 2026 post says the MCP can draft, label figures, and pull live data from another MCP (Juristat) in the same session, and that judgment stages pause. The audit classifies those tool calls from a list you send. It is not a SOC 2 opinion and not a statement that the pause is equivalent to our lab gateway.
- **Public URL:** https://www.paximal.com/news/announcing-the-paximal-mcp-your-patent-stack-now-native-in-claude
- **Confidence:** High for the LA dateline and the MCP fact, both on that post. Tool list for the product is also at https://www.paximal.com/mcp

## 4. MindFort

- **Why relevant:** Y Combinator lists MindFort in Los Angeles. They build autonomous agents that find, exploit, and patch vulnerabilities, and their site says agents can be driven through an API and MCP. Their customers' reviewers will ask what those agents are allowed to call.
- **Suggested role:** Founding engineer. Brandon Veiseh and Akul Gupta are named on the YC page. Use a name only after you re-read that page.
- **Angle:** You already run offensive agents and you publish an MCP path. The offer is a written classification of MindFort's own tool list for a reviewer. We do not pentest your customers, we do not jailbreak a model, and we do not certify the swarm.
- **Public URL:** https://www.ycombinator.com/companies/mindfort and https://www.mindfort.ai/
- **Confidence:** High. YC page location is Los Angeles, CA. The product page states live-application testing and "Full MCP & integrations."

## 5. Voker

- **Why relevant:** Y Combinator lists Voker in Los Angeles (a job post on YC also says Woodland Hills). They sell analytics for agent products. Their own launch copy uses a wrong-tool call (a finance agent calling the wrong lookup) as the failure they want teams to see.
- **Suggested role:** Founding engineer, or head of engineering. Tyler Postle and Alex Rudolph are named on the YC page. Confirm there before using a first name.
- **Angle:** Your launch post says teams should not learn from a complaint that an agent called the wrong tool. The 48-hour note is the egress map for a tool list you send: which calls are send, write, or credential use, and which the lab gateway would hold after untrusted text. It is not an accuracy claim about the analytics SDK.
- **Public URL:** https://www.ycombinator.com/companies/voker
- **Confidence:** High for location and product. The wrong-tool example is on https://www.ycombinator.com/launches/LjV-voker-the-agent-analytics-platform

## 6. Superunit

- **Why relevant:** Y Combinator lists Superunit in Los Angeles. The product is AI agents that call, email, and fax employers and return an audit trail. Send and credential-adjacent tools are the core of the fixed-tier classification.
- **Suggested role:** Founding engineer. Peter is the name on the YC contact line. Confirm on that page before using it.
- **Angle:** Your agents place calls and send email and fax as the job, and you publish an FCRA audit trail. The note says which of those calls the lab gateway would hold after untrusted content, and it will not rewrite that trail into a SOC 2 or ISO mapping.
- **Public URL:** https://www.ycombinator.com/companies/superunit
- **Confidence:** High. Location Los Angeles, CA, on the YC page. Phone, email, and fax agents are described there and on https://www.superunit.com/

## 7. Endstack

- **Why relevant:** Y Combinator lists Endstack in Los Angeles. The product is a cloud desktop where agents have a browser, a terminal, files, and a path in from Slack, email, or SMS. That is a wide tool surface for a reviewer.
- **Suggested role:** Founding engineer. Sam Park and Josh Park are named on the YC page. Confirm before using a first name.
- **Angle:** The YC description gives the agent a Linux desktop, Chrome, a terminal, and inbound Slack, email, and SMS. The audit classifies the tool list you choose to share and says what the lab gateway would hold. We do not deploy into endOS, and we do not claim the desktop is a sandbox we tested.
- **Public URL:** https://www.ycombinator.com/companies/endstack
- **Confidence:** High for the LA location and the agent-desktop description on that YC page. The same page also carries an older Lune AI launch. Use the Endstack paragraphs, not the Lune copy, as `{{public_detail}}`.

## 8. Keyframe Labs

- **Why relevant:** The Y Combinator Los Angeles AI directory lists Keyframe Labs in Los Angeles. They sell real-time avatars that customers connect to their own agent or LLM. The tool boundary that matters is the customer's agent behind the avatar, which a buyer's reviewer can ask about.
- **Suggested role:** Founding engineer. The YC company page names Parth Radia and Kaahan Radia. Confirm there before using a first name.
- **Angle:** Your docs tell a customer to connect their agent or LLM, then send audio into the session. The note classifies that agent's tool list, not the avatar model. It will not say a video session passed a security review.
- **Public URL:** https://www.ycombinator.com/companies/industry/ai/los-angeles and https://keyframelabs.com/
- **Confidence:** Medium. The LA line is the YC industry directory ("Los Angeles" on the Keyframe Labs entry), not a sentence I could quote from keyframelabs.com itself. The "connect your agent or LLM" step is on the YC company page: https://www.ycombinator.com/companies/keyframe-labs

## 9. Snap Inc.

- **Why relevant:** Headquarters are in Santa Monica. Snap's engineering blog describes Casper, remote coding agents wired through an internal MCP Gateway, and the public Ads MCP docs tell developers that an agent may follow instructions hidden in tool output.
- **Suggested role:** A staff or platform engineer on the agent platform, or that group's security partner. A cold note to the company CISO is unlikely to land at this price. Prefer a warm introduction.
- **Angle:** The Casper post says agents reach Snap systems through an MCP Gateway under a narrow identity, and the Ads MCP page warns that prompt injection can ride in with tool output. The offer is a written classification of a tool list Snap chooses to share. It is not a review of Casper, and it is not a pen-test.
- **Public URL:** https://eng.snap.com/casper and https://developers.snap.com/marketing-api/Ads-MCP/Introduction
- **Confidence:** High for HQ and for the agent work. Santa Monica headquarters: Snap careers calls Santa Monica the headquarters (https://careers.snap.com/santa-monica) and the 31 March 2026 Form 10-Q lists 3000 31st Street, Santa Monica. Medium for a cold $4,500 email. Do not cite unreleased internal tools beyond what those two pages say.

## 10. Riot Games

- **Why relevant:** A public Enterprise Technology job in Los Angeles asks for an engineer to build internal AI agents, tool integrations, and search, chat, and workflow experiences on top of enterprise data. That is an internal agent program a security partner will eventually have to describe.
- **Suggested role:** The hiring manager's enterprise security partner, or Head of Security for internal AI. Do not write the CISO until you know the program has an owner. The job is evidence they are staffing the work, not evidence of a published incident.
- **Public URL:** https://www.riotgames.com/en/work-with-us/job/8174908
- **Angle:** The Los Angeles staff posting says the engineer will build agents that call internal and external tools, and it lists prompt injection and tool abuse among the risks the role is expected to understand. The note classifies a tool list Riot is willing to share. It does not claim we saw production traffic, and it does not describe the game stack.
- **Confidence:** Medium. The Riot job page states Los Angeles, USA, tool-calling agents, and those risks. The salary line is marked Los Angeles only. I did not use a separate headquarters filing. A second posting, principal enterprise AI, describes agents and copilots with InfoSec as a partner, but the copy I found is on a third-party board (https://gamejobs.co/Principal-Enterprise-AI-Engineer-at-Riot-Games). Prefer the Riot URL as the source.

## Checked and not counted

**Runlayer.** Real MCP security product. TechCrunch covered the November 2025 launch (https://techcrunch.com/2025/11/17/mcp-ai-agent-security-startup-runlayer-launches-with-8-unicorns-11m-from-khoslas-keith-rabois-and-felicis/). The organization address published on https://www.runlayer.com/about is 31 Bond St, Floor 5, New York, NY. Co-founder Tal Peretz's public LinkedIn profile lists Los Angeles. That is a person in LA, not a company headquarters in LA, so Runlayer is not one of the ten.

**Crawlbase.** They ship a Web MCP server (https://crawlbase.com/mcp). Their about page says the team has no single office (https://crawlbase.com/about-us). A June 2025 GlobeNewswire contact block uses a Compton, Los Angeles County address. Headquarters is not clear, so they are not one of the ten.

**Verdun.** The same YC Los Angeles AI directory lists them in Los Angeles and describes AI agents that triage security-camera alarms. The public text is video monitoring, not a tool or MCP boundary. Left off until there is a public tool-use page.
