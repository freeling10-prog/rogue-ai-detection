# Leads for human review

> Lead for human review only. High score means 'worth a person looking', not 'confirmed misuse'. No automatic action is taken or recommended. ATLAS mapping is approximate. Synthetic-data prototype.

Events accepted: 52028; quarantined: 13. Leads: 54.

- NOTE: 14 agent(s)/session(s) had too few events to score against the frozen baseline

## lead-d78a978a89b7  agent `ag_98da521dfc4fdf61`  (score 0.9715, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.8608, rules 1.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Denied-to-allowed request ratio: 0.49 versus a population median of 0.02 (about 20.3x the typical value) - many more refused requests than peers (robust z=+27.6).
- Requests touching sensitive resources: 150 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+15.3).
- Spread of activity across the 24 hours of the day: 0.63 versus a population median of 0.70 - activity concentrated in a few hours (robust z=-4.7).

**R5: Access probing: many denied requests on sensitive resources** - ATLAS AML.T0075 Enterprise Resource Discovery
107 of 324 requests were denied (103 on sensitive resources, 98 distinct). Consistent with an agent enumerating resources it is not authorised to use.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040116` t=1772476393: access status=denied dest=api.corp.example sensitive-resource
- `e0040117` t=1772476396: access status=denied dest=api.corp.example sensitive-resource
- `e0040119` t=1772476399: access status=denied dest=api.corp.example sensitive-resource
- `e0040118` t=1772476399: access status=denied dest=api.corp.example sensitive-resource
- `e0040121` t=1772476404: access status=denied dest=api.corp.example sensitive-resource
- `e0040124` t=1772476414: access status=denied dest=api.corp.example sensitive-resource
- `e0040125` t=1772476416: access status=denied dest=api.corp.example sensitive-resource
- `e0040122` t=1772476418: access status=denied dest=api.corp.example sensitive-resource

## lead-7c7744507215  agent `ag_e942d6dcdca8dd5c`  (score 0.9709, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.8371, rules 1.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Denied-to-allowed request ratio: 0.52 versus a population median of 0.02 (about 21.5x the typical value) - many more refused requests than peers (robust z=+29.2).
- Requests touching sensitive resources: 150 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+15.3).
- Spread of activity across the 24 hours of the day: 0.65 versus a population median of 0.70 - activity concentrated in a few hours (robust z=-3.8).

**R5: Access probing: many denied requests on sensitive resources** - ATLAS AML.T0075 Enterprise Resource Discovery
112 of 327 requests were denied (111 on sensitive resources, 109 distinct). Consistent with an agent enumerating resources it is not authorised to use.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0039882` t=1772422136: access status=denied dest=api.corp.example sensitive-resource
- `e0039884` t=1772422142: access status=denied dest=api.corp.example sensitive-resource
- `e0039886` t=1772422156: access status=denied dest=api.corp.example sensitive-resource
- `e0039887` t=1772422157: access status=denied dest=api.corp.example sensitive-resource
- `e0039888` t=1772422163: access status=denied dest=api.corp.example sensitive-resource
- `e0039889` t=1772422169: access status=denied dest=api.corp.example sensitive-resource
- `e0039898` t=1772422177: access status=denied dest=api.corp.example sensitive-resource
- `e0039893` t=1772422191: access status=denied dest=api.corp.example sensitive-resource

## lead-47bf64cf965c  agent `ag_98a31ed7ceb00f9b`  (score 0.9674, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.6975, rules 1.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Denied-to-allowed request ratio: 0.40 versus a population median of 0.02 (about 16.4x the typical value) - many more refused requests than peers (robust z=+22.1).
- Requests touching sensitive resources: 150 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+15.3).
- Spread of activity across the 24 hours of the day: 0.66 versus a population median of 0.70 - activity concentrated in a few hours (robust z=-2.9).

**R5: Access probing: many denied requests on sensitive resources** - ATLAS AML.T0075 Enterprise Resource Discovery
106 of 372 requests were denied (104 on sensitive resources, 104 distinct). Consistent with an agent enumerating resources it is not authorised to use.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0039126` t=1772472666: access status=denied dest=api.corp.example sensitive-resource
- `e0039128` t=1772472672: access status=denied dest=api.corp.example sensitive-resource
- `e0039129` t=1772472672: access status=denied dest=api.corp.example sensitive-resource
- `e0039131` t=1772472674: access status=denied dest=api.corp.example sensitive-resource
- `e0039130` t=1772472682: access status=denied dest=api.corp.example sensitive-resource
- `e0039132` t=1772472683: access status=denied dest=api.corp.example sensitive-resource
- `e0039134` t=1772472689: access status=denied dest=api.corp.example sensitive-resource
- `e0039133` t=1772472700: access status=denied dest=api.corp.example sensitive-resource

## lead-427fd57f7234  agent `ag_ada95f9578ae974b`  (score 0.9633, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.6025, rules 1.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Denied-to-allowed request ratio: 0.35 versus a population median of 0.02 (about 14.5x the typical value) - many more refused requests than peers (robust z=+19.3).
- Requests touching sensitive resources: 150 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+15.3).
- Event rate: 0.80 events/min versus a population median of 0.46 events/min (about 1.7x the typical value) - far busier than peers (robust z=+1.7).

**R5: Access probing: many denied requests on sensitive resources** - ATLAS AML.T0075 Enterprise Resource Discovery
112 of 430 requests were denied (101 on sensitive resources, 97 distinct). Consistent with an agent enumerating resources it is not authorised to use.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0039555` t=1772449141: access status=denied dest=api.corp.example sensitive-resource
- `e0039557` t=1772449148: access status=denied dest=api.corp.example sensitive-resource
- `e0039559` t=1772449151: access status=denied dest=api.corp.example sensitive-resource
- `e0039562` t=1772449159: access status=denied dest=api.corp.example sensitive-resource
- `e0039561` t=1772449162: access status=denied dest=api.corp.example sensitive-resource
- `e0039560` t=1772449163: access status=denied dest=api.corp.example sensitive-resource
- `e0039568` t=1772449167: access status=denied dest=api.corp.example sensitive-resource
- `e0039565` t=1772449171: access status=denied dest=api.corp.example sensitive-resource

## lead-80f8518990db  agent `ag_260da60b2382dc80`  (score 0.9527, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 1.0, rules 0.95, graph density 0.0

Why this agent looks unusual compared with its peers:
- Share of late tool calls using tools not used earlier: 0.07 versus a population median of 0.00 - recently started using new tools (robust z=+81.7).
- Share of late external calls to hosts not contacted earlier: 1.00 versus a population median of 0.00 - recently started contacting new external hosts (robust z=+21.8).
- Share of events sent to or fetched from external hosts: 0.06 versus a population median of 0.00 - much more external traffic than peers (robust z=+1.1).

**R1: Untrusted content followed by a sudden shift in tool usage** - ATLAS AML.T0051 LLM Prompt Injection
After reading untrusted content, the agent invoked tool(s) ['send_email'] that it neither used in its baseline period nor declared, within 300s. Consistent with injected instructions steering the agent.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050572` t=1772461048: read status=allowed dest=api.corp.example untrusted-content
- `e0050698` t=1772461073: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=41444

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 28806 bytes to 1 external host(s) never contacted before (['drop-sp3.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050699` t=1772459785: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=28806

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
6 call(s) to tool(s) ['send_email'] that are not in the agent's declared tool list (['calendar', 'http_post', 'search_docs', 'summarize']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050699` t=1772459785: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=28806
- `e0050701` t=1772459813: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=7510
- `e0050703` t=1772459917: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=20817
- `e0050694` t=1772460926: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=37617
- `e0050696` t=1772460963: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=23220
- `e0050698` t=1772461073: tool_call status=allowed tool=send_email dest=drop-sp3.example.org (external) bytes=41444

## lead-f91f5a8b0aef  agent `ag_9beb0855d8d8159b`  (score 0.951, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.165, rules 1.0, graph density 0.0

**R1: Untrusted content followed by a sudden shift in tool usage** - ATLAS AML.T0051 LLM Prompt Injection
After reading untrusted content, the agent invoked tool(s) ['send_email', 'upload_file'] that it neither used in its baseline period nor declared, within 300s. Consistent with injected instructions steering the agent.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040723` t=1772472241: read status=allowed dest=blog-29.example.net (external) untrusted-content
- `e0040724` t=1772472250: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040725` t=1772472272: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=18125
- `e0040727` t=1772472310: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=16562
- `e0040728` t=1772473259: read status=allowed dest=blog-46.example.net (external) untrusted-content
- `e0040729` t=1772473274: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040730` t=1772473298: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=19091
- `e0040732` t=1772473332: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=28816

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 18125 bytes to 1 external host(s) never contacted before (['drop-2.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040725` t=1772472272: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=18125

**R4: Immediate call to a new external destination after reading untrusted text** - ATLAS AML.T0051 LLM Prompt Injection
1 outbound call(s) to previously unseen external hosts within 60s of reading untrusted content. Consistent with injected instructions.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040723` t=1772472241: read status=allowed dest=blog-29.example.net (external) untrusted-content
- `e0040725` t=1772472272: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=18125

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
7 call(s) to tool(s) ['send_email', 'upload_file'] that are not in the agent's declared tool list (['calendar', 'http_post', 'search_docs', 'summarize']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040724` t=1772472250: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040725` t=1772472272: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=18125
- `e0040727` t=1772472310: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=16562
- `e0040729` t=1772473274: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040730` t=1772473298: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=19091
- `e0040732` t=1772473332: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=28816
- `e0040734` t=1772473339: tool_call status=allowed tool=send_email dest=drop-2.example.org (external) bytes=16648

## lead-f781be72d546  agent `ag_19d28ab3efe1e425`  (score 0.947, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.4648, rules 1.0, graph density 0.0

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
7 call(s) to tool(s) ['send_email', 'upload_file'] that are not in the agent's declared tool list (['calendar', 'http_post', 'summarize', 'translate']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040415` t=1772435975: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040416` t=1772435989: tool_call status=allowed tool=send_email dest=drop-1.example.org (external) bytes=23627
- `e0040418` t=1772436026: tool_call status=allowed tool=send_email dest=drop-1.example.org (external) bytes=40172
- `e0040420` t=1772436119: tool_call status=allowed tool=send_email dest=drop-1.example.org (external) bytes=19551
- `e0040410` t=1772444052: tool_call status=allowed tool=upload_file dest=api.corp.example
- `e0040411` t=1772444076: tool_call status=allowed tool=send_email dest=drop-1.example.org (external) bytes=46239
- `e0040413` t=1772444132: tool_call status=allowed tool=send_email dest=drop-1.example.org (external) bytes=27954

## lead-e64dc0588203  agent `ag_2cb286b00d9dd231`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 1 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (0 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052015` t=1772442275: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=90

**Coordination cluster** of 2 agents (density 1.0): `ag_2cb286b00d9dd231`, `ag_82353550766da16c`
Evidence events: `e0052013`, `e0052015`

## lead-13e78a2dfd3d  agent `ag_7b8aa47f36080f3b`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052007` t=1772446420: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052008` t=1772446425: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

**Coordination cluster** of 2 agents (density 1.0): `ag_7b8aa47f36080f3b`, `ag_b2976d0d337d9fe5`
Evidence events: `e0052007`, `e0052009`

## lead-0cc2191f6c30  agent `ag_82353550766da16c`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052013` t=1772441741: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052014` t=1772441746: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

**Coordination cluster** of 2 agents (density 1.0): `ag_2cb286b00d9dd231`, `ag_82353550766da16c`
Evidence events: `e0052013`, `e0052015`

## lead-b43c6f67eb38  agent `ag_b2976d0d337d9fe5`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 1 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (0 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052009` t=1772446872: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=90

**Coordination cluster** of 2 agents (density 1.0): `ag_7b8aa47f36080f3b`, `ag_b2976d0d337d9fe5`
Evidence events: `e0052007`, `e0052009`

## lead-c851f5b1c77b  agent `ag_f4bce80589a23c8e`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 1 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (0 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052012` t=1772423450: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=90

**Coordination cluster** of 2 agents (density 1.0): `ag_f4bce80589a23c8e`, `ag_fcf1679fd57a69a8`
Evidence events: `e0052010`, `e0052012`

## lead-0e62c123dae9  agent `ag_fcf1679fd57a69a8`  (score 0.944, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 1.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052010` t=1772422856: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052011` t=1772422861: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

**Coordination cluster** of 2 agents (density 1.0): `ag_f4bce80589a23c8e`, `ag_fcf1679fd57a69a8`
Evidence events: `e0052010`, `e0052012`

## lead-dc7f4d4cd083  agent `ag_2559a16cfe9efa27`  (score 0.905, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 1.0, rules 0.9, graph density 0.0

Why this agent looks unusual compared with its peers:
- Share of late tool calls using tools not used earlier: 0.06 versus a population median of 0.00 - recently started using new tools (robust z=+70.5).
- Share of late external calls to hosts not contacted earlier: 0.69 versus a population median of 0.00 - recently started contacting new external hosts (robust z=+15.1).
- Share of events sent to or fetched from external hosts: 0.06 versus a population median of 0.00 - much more external traffic than peers (robust z=+1.1).

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 53029 bytes to 1 external host(s) never contacted before (['drop-sp1.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050247` t=1772451533: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=53029

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
5 call(s) to tool(s) ['send_email'] that are not in the agent's declared tool list (['calendar', 'http_post', 'search_docs', 'summarize']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050247` t=1772451533: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=53029
- `e0050249` t=1772451599: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=14405
- `e0050250` t=1772459235: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=22300
- `e0050252` t=1772459280: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=25587
- `e0050254` t=1772459347: tool_call status=allowed tool=send_email dest=drop-sp1.example.org (external) bytes=53015

## lead-e8cb77a2bace  agent `ag_1e9c13cce7a5b679`  (score 0.9, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 1.0, graph density 0.0

**R1: Untrusted content followed by a sudden shift in tool usage** - ATLAS AML.T0051 LLM Prompt Injection
After reading untrusted content, the agent invoked tool(s) ['create_ticket'] that it neither used in its baseline period nor declared, within 300s. Consistent with injected instructions steering the agent.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0038328` t=1772450013: read status=allowed dest=api.corp.example untrusted-content
- `e0038329` t=1772450050: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038330` t=1772450577: read status=allowed dest=api.corp.example untrusted-content
- `e0038331` t=1772450609: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038336` t=1772453581: read status=allowed dest=api.corp.example untrusted-content
- `e0038337` t=1772453608: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038334` t=1772456118: read status=allowed dest=api.corp.example untrusted-content
- `e0038335` t=1772456172: tool_call status=allowed tool=create_ticket dest=api.corp.example

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
6 call(s) to tool(s) ['create_ticket'] that are not in the agent's declared tool list (['calendar', 'http_post', 'read_file', 'translate']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0038329` t=1772450050: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038331` t=1772450609: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038337` t=1772453608: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038335` t=1772456172: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038327` t=1772457750: tool_call status=allowed tool=create_ticket dest=api.corp.example
- `e0038333` t=1772464172: tool_call status=allowed tool=create_ticket dest=api.corp.example

## lead-040139c1c829  agent `ag_b06db4687e769deb`  (score 0.8251, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.1592, rules 0.9, graph density 0.0

**R1: Untrusted content followed by a sudden shift in tool usage** - ATLAS AML.T0051 LLM Prompt Injection
After reading untrusted content, the agent invoked tool(s) ['send_email'] that it neither used in its baseline period nor declared, within 300s. Consistent with injected instructions steering the agent.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0041084` t=1772468599: read status=allowed dest=api.corp.example untrusted-content
- `e0041264` t=1772468898: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=24854

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 24854 bytes to 1 external host(s) never contacted before (['drop-4.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0041264` t=1772468898: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=24854

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
5 call(s) to tool(s) ['send_email'] that are not in the agent's declared tool list (['calendar', 'http_post', 'read_file', 'translate']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0041264` t=1772468898: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=24854
- `e0041266` t=1772468963: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=5743
- `e0041267` t=1772480315: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=44642
- `e0041269` t=1772480375: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=23751
- `e0041271` t=1772480467: tool_call status=allowed tool=send_email dest=drop-4.example.org (external) bytes=47968

## lead-e0d70afb80a8  agent `ag_e01f075e0c4b97a0`  (score 0.8164, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.1636, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_7e6335c846530c43`, `ag_978247692c41a02d`, `ag_dc37e6a87ae6d6a5`, `ag_e01f075e0c4b97a0`
Evidence events: `e0043561`, `e0043580`, `e0043619`, `e0043911`, `e0043910`, `e0043919`, `e0043918`, `e0043649`

## lead-b6fc43eee0f2  agent `ag_30d918accd0d4d0a`  (score 0.8161, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.1613, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_1696b03d154ff42f`, `ag_30d918accd0d4d0a`, `ag_3b916b272fa8fcd6`, `ag_8ba7953bc320a30e`
Evidence events: `e0041837`, `e0041871`, `e0041873`, `e0042345`, `e0042344`, `e0042353`, `e0042352`, `e0042360`

## lead-76574ec1d79a  agent `ag_978247692c41a02d`  (score 0.8106, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.1058, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_7e6335c846530c43`, `ag_978247692c41a02d`, `ag_dc37e6a87ae6d6a5`, `ag_e01f075e0c4b97a0`
Evidence events: `e0043561`, `e0043580`, `e0043619`, `e0043911`, `e0043910`, `e0043919`, `e0043918`, `e0043649`

## lead-9a4002d2a863  agent `ag_7e6335c846530c43`  (score 0.8097, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0972, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_7e6335c846530c43`, `ag_978247692c41a02d`, `ag_dc37e6a87ae6d6a5`, `ag_e01f075e0c4b97a0`
Evidence events: `e0043561`, `e0043580`, `e0043619`, `e0043911`, `e0043910`, `e0043919`, `e0043918`, `e0043649`

## lead-ba3acc1ee673  agent `ag_3b916b272fa8fcd6`  (score 0.8052, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0517, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_1696b03d154ff42f`, `ag_30d918accd0d4d0a`, `ag_3b916b272fa8fcd6`, `ag_8ba7953bc320a30e`
Evidence events: `e0041837`, `e0041871`, `e0041873`, `e0042345`, `e0042344`, `e0042353`, `e0042352`, `e0042360`

## lead-a89abbfd8e9a  agent `ag_1696b03d154ff42f`  (score 0.8051, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0508, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_1696b03d154ff42f`, `ag_30d918accd0d4d0a`, `ag_3b916b272fa8fcd6`, `ag_8ba7953bc320a30e`
Evidence events: `e0041837`, `e0041871`, `e0041873`, `e0042345`, `e0042344`, `e0042353`, `e0042352`, `e0042360`

## lead-eef55b8f917a  agent `ag_8ba7953bc320a30e`  (score 0.8032, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0323, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_1696b03d154ff42f`, `ag_30d918accd0d4d0a`, `ag_3b916b272fa8fcd6`, `ag_8ba7953bc320a30e`
Evidence events: `e0041837`, `e0041871`, `e0041873`, `e0042345`, `e0042344`, `e0042353`, `e0042352`, `e0042360`

## lead-9296c7d3cbd2  agent `ag_dc37e6a87ae6d6a5`  (score 0.8032, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0315, rules 0.0, graph density 1.0

**Coordination cluster** of 4 agents (density 1.0): `ag_7e6335c846530c43`, `ag_978247692c41a02d`, `ag_dc37e6a87ae6d6a5`, `ag_e01f075e0c4b97a0`
Evidence events: `e0043561`, `e0043580`, `e0043619`, `e0043911`, `e0043910`, `e0043919`, `e0043918`, `e0043649`

## lead-0bdebf92fbac  agent `ag_25c32e1769576bdd`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_25c32e1769576bdd`, `ag_5dfc223b989f30e0`
Evidence events: `e0051431`, `e0051117`, `e0051122`, `e0051132`, `e0051133`, `e0051134`, `e0051137`, `e0051138`

## lead-1a61f1937c92  agent `ag_4477e17834d798cb`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_4477e17834d798cb`, `ag_71db2367df80d602`
Evidence events: `e0051723`, `e0051435`, `e0051718`, `e0051441`, `e0051448`, `e0051450`, `e0051452`, `e0051471`

## lead-d750b270f451  agent `ag_56e909fb956fcaed`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_56e909fb956fcaed`, `ag_74b36ac982e520ff`
Evidence events: `e0047471`, `e0047485`, `e0047487`, `e0047501`, `e0047502`, `e0047520`, `e0047532`, `e0047534`

## lead-660a91fa902e  agent `ag_5dfc223b989f30e0`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_25c32e1769576bdd`, `ag_5dfc223b989f30e0`
Evidence events: `e0051431`, `e0051117`, `e0051122`, `e0051132`, `e0051133`, `e0051134`, `e0051137`, `e0051138`

## lead-8c9fffa79182  agent `ag_71db2367df80d602`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_4477e17834d798cb`, `ag_71db2367df80d602`
Evidence events: `e0051723`, `e0051435`, `e0051718`, `e0051441`, `e0051448`, `e0051450`, `e0051452`, `e0051471`

## lead-13a52060f07b  agent `ag_74b36ac982e520ff`  (score 0.8, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.0, graph density 1.0

**Coordination cluster** of 2 agents (density 1.0): `ag_56e909fb956fcaed`, `ag_74b36ac982e520ff`
Evidence events: `e0047471`, `e0047485`, `e0047487`, `e0047501`, `e0047502`, `e0047520`, `e0047532`, `e0047534`

## lead-3cc92e120f99  agent `ag_2057b867b2b2883a`  (score 0.7932, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.2401, rules 0.85, graph density 0.0

**R1: Untrusted content followed by a sudden shift in tool usage** - ATLAS AML.T0051 LLM Prompt Injection
After reading untrusted content, the agent invoked tool(s) ['send_email'] that it neither used in its baseline period nor declared, within 300s. Consistent with injected instructions steering the agent.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050344` t=1772457367: read status=allowed dest=api.corp.example untrusted-content
- `e0050445` t=1772457537: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=53014
- `e0050447` t=1772457561: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=40561

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 53014 bytes to 1 external host(s) never contacted before (['drop-sp2.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050445` t=1772457537: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=53014

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
4 call(s) to tool(s) ['send_email'] that are not in the agent's declared tool list (['calendar', 'http_post', 'search_docs', 'summarize']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0050445` t=1772457537: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=53014
- `e0050447` t=1772457561: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=40561
- `e0050441` t=1772471056: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=32434
- `e0050443` t=1772471132: tool_call status=allowed tool=send_email dest=drop-sp2.example.org (external) bytes=37881

## lead-e5c12ae791d3  agent `ag_bc33c55bd7564dbe`  (score 0.7854, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.4672, rules 0.8, graph density 0.0

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 16433 bytes to 1 external host(s) never contacted before (['hooks.newpartner-2.example.net']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0038782` t=1772440492: tool_call status=allowed tool=http_post dest=hooks.newpartner-2.example.net (external) bytes=16433

## lead-7c93012e4c19  agent `ag_2028b68e9e900e9f`  (score 0.7834, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.4528, rules 0.8, graph density 0.0

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 10380 bytes to 1 external host(s) never contacted before (['hooks.newpartner-1.example.net']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0038607` t=1772444600: tool_call status=allowed tool=http_post dest=hooks.newpartner-1.example.net (external) bytes=10380

## lead-59ed7c7c2f69  agent `ag_23b69c53f2c6fd5c`  (score 0.7724, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0632, rules 0.85, graph density 0.0

**R3: Write-capable tool sending data to a new external destination** - ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation
1 write/send call(s) moved 22054 bytes to 1 external host(s) never contacted before (['drop-3.example.org']). Consistent with data leaving via an agent tool.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040975` t=1772464770: tool_call status=allowed tool=send_email dest=drop-3.example.org (external) bytes=22054

**R2: Tool calls outside the agent's declared purpose** - ATLAS AML.T0053 AI Agent Tool Invocation
4 call(s) to tool(s) ['send_email'] that are not in the agent's declared tool list (['http_post', 'read_file', 'summarize', 'translate']).
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0040975` t=1772464770: tool_call status=allowed tool=send_email dest=drop-3.example.org (external) bytes=22054
- `e0040977` t=1772464823: tool_call status=allowed tool=send_email dest=drop-3.example.org (external) bytes=8397
- `e0040979` t=1772478212: tool_call status=allowed tool=send_email dest=drop-3.example.org (external) bytes=25686
- `e0040981` t=1772478286: tool_call status=allowed tool=send_email dest=drop-3.example.org (external) bytes=6025

## lead-c0f8639d610e  agent `ag_03b7c637ea8e7271`  (score 0.765, queue priority: review_first)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.85, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 4 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 3 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052002` t=1772424309: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052003` t=1772424314: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120
- `e0052004` t=1772424317: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120
- `e0052005` t=1772424320: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

**R7: Disclosed its own context to a decoy (cognitive capture)** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0053 AI Agent Tool Invocation, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent sent its own configuration (system-prompt summary / tools / objective / message) to a decoy in 1 request(s). The captured text is attacker-controlled and shown only as sanitized, truncated data.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052006` t=1772424409: message status=allowed dest=api.corp.example honeypot=cognitive_capture

## lead-13115e7f1124  agent `ag_32074d8389a6c512`  (score 0.7275, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.9101, rules 0.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Requests touching sensitive resources: 419 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+42.9).
- Event rate: 1.26 events/min versus a population median of 0.46 events/min (about 2.7x the typical value) - far busier than peers (robust z=+4.1).
- Spread of activity across the 24 hours of the day: 0.61 versus a population median of 0.70 - activity concentrated in a few hours (robust z=-6.1).

## lead-a765dcdc003f  agent `ag_efbf2a6ad54c12f9`  (score 0.7214, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.8857, rules 0.0, graph density 0.0

Why this agent looks unusual compared with its peers:
- Requests touching sensitive resources: 414 versus a population median of 0 - touching sensitive resources far more than peers (robust z=+42.4).
- Event rate: 1.84 events/min versus a population median of 0.46 events/min (about 4.0x the typical value) - far busier than peers (robust z=+7.1).
- Spread of activity across the 24 hours of the day: 0.67 versus a population median of 0.70 - activity concentrated in a few hours (robust z=-2.4).

## lead-cc861511dbe2  agent `ag_1ccf0a38bc2d0001`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052020` t=1772432917: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052021` t=1772432922: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-31857121f460  agent `ag_3f8d14710f967599`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 4 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 3 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0051998` t=1772456911: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0051999` t=1772456916: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120
- `e0052000` t=1772456919: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120
- `e0052001` t=1772456922: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-3594bd5113bb  agent `ag_49b7c79b275c3662`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052022` t=1772433466: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052023` t=1772433471: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-ff585a21d10b  agent `ag_6b6f1076d4ccb907`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052018` t=1772439758: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052019` t=1772439763: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-ea571abb01be  agent `ag_b3796f8b69f4088e`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052026` t=1772437348: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052027` t=1772437353: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-09df5e391c75  agent `ag_eba5ef92f18fc18e`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052016` t=1772439588: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052017` t=1772439593: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-03cda951355c  agent `ag_f8db84c95dc22c43`  (score 0.72, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.0, rules 0.8, graph density 0.0

**R6: Engaged the decoy coordination-board protocol** - ATLAS AML.T0051 LLM Prompt Injection, AML.T0086 Exfiltration via AI Agent Tool Invocation
The agent made 2 request(s) to honeypot coordination-board endpoints that no legitimate workflow points to (1 token(s) issued to it, 1 token presentation(s)). Consistent with an agent acting on instructions it found in untrusted content.
_The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, not proof of it. Verify against the evidence events before relying on the tag._
Evidence events:
- `e0052024` t=1772436992: read status=allowed dest=api.corp.example honeypot=coordination_board
- `e0052025` t=1772436998: write status=allowed dest=api.corp.example honeypot=coordination_board bytes=120

## lead-9865c95b3e18  agent `ag_9f63fe232924f3f0`  (score 0.5872, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.4123, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_36e044b789791178`, `ag_44601abe5ce7b5ef`, `ag_5251462ecf89c432`, `ag_9f63fe232924f3f0`, `ag_a1497de2a20fdea1`
Evidence events: `e0049910`, `e0049911`, `e0049912`, `e0049913`, `e0049916`, `e0049917`, `e0049918`, `e0049919`

## lead-0a855d63b95d  agent `ag_5251462ecf89c432`  (score 0.5844, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.4015, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_36e044b789791178`, `ag_44601abe5ce7b5ef`, `ag_5251462ecf89c432`, `ag_9f63fe232924f3f0`, `ag_a1497de2a20fdea1`
Evidence events: `e0049910`, `e0049911`, `e0049912`, `e0049913`, `e0049916`, `e0049917`, `e0049918`, `e0049919`

## lead-5f8a6bffcb51  agent `ag_d9cced2c3572df79`  (score 0.5839, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3996, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_9af0b0f29bb39a65`, `ag_9b067b9135c2f0c3`, `ag_b32cfbe93f1cfa07`, `ag_b6b5d983674b0fa9`, `ag_d9cced2c3572df79`
Evidence events: `e0049966`, `e0049967`, `e0049968`, `e0049969`, `e0049972`, `e0049973`, `e0049974`, `e0049975`

## lead-9807f089649e  agent `ag_9af0b0f29bb39a65`  (score 0.5814, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3901, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_9af0b0f29bb39a65`, `ag_9b067b9135c2f0c3`, `ag_b32cfbe93f1cfa07`, `ag_b6b5d983674b0fa9`, `ag_d9cced2c3572df79`
Evidence events: `e0049966`, `e0049967`, `e0049968`, `e0049969`, `e0049972`, `e0049973`, `e0049974`, `e0049975`

## lead-248c35348683  agent `ag_b6b5d983674b0fa9`  (score 0.5814, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3901, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_9af0b0f29bb39a65`, `ag_9b067b9135c2f0c3`, `ag_b32cfbe93f1cfa07`, `ag_b6b5d983674b0fa9`, `ag_d9cced2c3572df79`
Evidence events: `e0049966`, `e0049967`, `e0049968`, `e0049969`, `e0049972`, `e0049973`, `e0049974`, `e0049975`

## lead-a9b764f39c1a  agent `ag_36e044b789791178`  (score 0.5797, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3833, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_36e044b789791178`, `ag_44601abe5ce7b5ef`, `ag_5251462ecf89c432`, `ag_9f63fe232924f3f0`, `ag_a1497de2a20fdea1`
Evidence events: `e0049910`, `e0049911`, `e0049912`, `e0049913`, `e0049916`, `e0049917`, `e0049918`, `e0049919`

## lead-7c77116da6d1  agent `ag_a1497de2a20fdea1`  (score 0.5766, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3715, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_36e044b789791178`, `ag_44601abe5ce7b5ef`, `ag_5251462ecf89c432`, `ag_9f63fe232924f3f0`, `ag_a1497de2a20fdea1`
Evidence events: `e0049910`, `e0049911`, `e0049912`, `e0049913`, `e0049916`, `e0049917`, `e0049918`, `e0049919`

## lead-6d5637ec6f3e  agent `ag_b32cfbe93f1cfa07`  (score 0.5759, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3688, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_9af0b0f29bb39a65`, `ag_9b067b9135c2f0c3`, `ag_b32cfbe93f1cfa07`, `ag_b6b5d983674b0fa9`, `ag_d9cced2c3572df79`
Evidence events: `e0049966`, `e0049967`, `e0049968`, `e0049969`, `e0049972`, `e0049973`, `e0049974`, `e0049975`

## lead-a0ce200da32b  agent `ag_44601abe5ce7b5ef`  (score 0.5742, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3622, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_36e044b789791178`, `ag_44601abe5ce7b5ef`, `ag_5251462ecf89c432`, `ag_9f63fe232924f3f0`, `ag_a1497de2a20fdea1`
Evidence events: `e0049910`, `e0049911`, `e0049912`, `e0049913`, `e0049916`, `e0049917`, `e0049918`, `e0049919`

## lead-8549be3c045f  agent `ag_9b067b9135c2f0c3`  (score 0.5652, queue priority: review)
Severity: **low** | Recommended: **human_review** | Automatic action: **none**

Components (0-1): isolation forest 0.3277, rules 0.0, graph density 0.6

**Coordination cluster** of 5 agents (density 0.6): `ag_9af0b0f29bb39a65`, `ag_9b067b9135c2f0c3`, `ag_b32cfbe93f1cfa07`, `ag_b6b5d983674b0fa9`, `ag_d9cced2c3572df79`
Evidence events: `e0049966`, `e0049967`, `e0049968`, `e0049969`, `e0049972`, `e0049973`, `e0049974`, `e0049975`
