# Sample Boundary Note (Anonymized Example)

## AgentGate Tool-Boundary Note — Example: Order-Support Agent

**Prepared for:** Security Reviewer  
**Date:** [redacted]  
**Tier:** Fixed note (no instrumentation)  
**Clock:** Started on receipt of tool list

### Tool inventory (as supplied)

| Tool | Arguments | Untrusted text enters via | Egress class |
|------|-----------|---------------------------|--------------|
| fetch_order | {order_id: string} | ticket body, customer email | internal read |
| web.fetch | {url: string} | page body returned | external read |
| update_ticket_status | {ticket_id, status} | — | write (constrained enum) |
| send_email | {to, body, subject} | body can contain prior tool output | send |
| lookup_customer | {email} | — | internal read |

### Taint paths

1. `web.fetch` → untrusted page body → session tainted + `agw1.` attenuated (`allow_egress=false`)  
   → any subsequent `send_email` or unconstrained write is held for one-time human approval.
2. Ticket body ingested via `fetch_order` (if the ticket contains customer-supplied text) → same taint path.
3. Constrained `update_ticket_status` (enum status only, no free-text) may be allowed under lab policy even while tainted; free-text fields are not.

### What the lab gateway would hold

- `send_email` after any untrusted ingest: held, formatted as a Slack/webhook approval payload.  
  Approve Once authorizes that exact call only. Deny & Freeze freezes the registered lab key for 15 minutes.
- Unregistered keys are refused and never frozen.

### Approximate ATLAS

- AML.M0030 (restrict tool invocation on untrusted data) — mitigation reading used in the lab
- AML.T0051 / T0086 — approximate technique tags on the note

### Lab limits (always included)

- Default bind 127.0.0.1. No public honeypot shipped.
- Freeze only for keys already in the lab registry, 15 minutes.
- ATLAS ids are approximate. This is not a certification.
- Tool backends in the lab pass are simulated echoes.

### Recommended first controls (remediation sketch)

1. Gate `send_email` behind the same capability attenuation + human approval used in the lab.
2. Treat any tool that returns external content as a taint source.
3. Keep free-text sinks (email body, ticket notes) behind an explicit approval or a hard allow-list of recipients.

This note is an example produced from a synthetic tool list. It is not a finding against any real product.
