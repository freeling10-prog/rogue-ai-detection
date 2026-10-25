# Sample Boundary Note 2 (Synthetic): Repository-Maintenance Agent

Synthetic tool list. Not a finding against any real product. Classification below follows `TOOL_EGRESS` as of this tree; ATLAS ids are approximate.

**Prepared for:** Security Reviewer · **Tier:** Fixed note · **Clock:** started on receipt of a usable tool list

## Tool inventory (as supplied)

| Tool | Untrusted text enters via | Class in this tree | Note |
| --- | --- | --- | --- |
| `web.fetch` | page body (docs, issue links) | external read | taint source |
| `file.read` | repo files, including contributor-supplied files | internal read, also a taint source | repo content is not trusted |
| `git.diff` | diff text | **unclassified → write** | read-only in reality; over-held |
| `file.write` | — | write | |
| `shell.exec` | command output | **unclassified → write** | highest-risk tool; see below |
| `git.push` | — | **unclassified → write** | |
| `webhook.send` | body may carry prior tool output | send | |
| `read_internal_secrets` | — | credentials | sensitive read |

## Taint paths

1. `web.fetch` or `file.read` → session tainted, `agw1.` attenuated (`allow_egress=false`) → `shell.exec`, `git.push`, `file.write`, `webhook.send` held for one-time approval.
2. `read_internal_secrets` after a tainted ingest → held. Before any ingest it is allowed and marks the session as having made a sensitive read, so a later `webhook.send` is gated by that too (approximate AML.T0086).
3. `shell.exec` is the weak point. Its own arguments are checked lexically (shell chaining, path traversal), but a held-and-approved shell call can do anything the host allows. The gateway is not a sandbox.

## What the lab gateway would hold

- Everything in paths 1 and 2 except `git.diff` and `file.read` style reads, which should be allowed. `git.diff` is held today only because it is unclassified.
- Free-text sinks (`webhook.send` body) are never covered by the constrained-status exception.

## Approximate ATLAS

AML.M0030 (mitigation reading used in the lab). AML.T0051 and AML.T0086 as approximate technique tags.

## First three controls

1. Add `git.diff` (and other read-only git tools) to `TOOL_EGRESS` as internal reads so they are not over-held. Add `git.push` and `shell.exec` explicitly as writes so the classification is deliberate rather than a default.
2. Route `shell.exec` through approval always, not only after taint, and run it in a sandbox the gateway does not provide.
3. Allow-list `webhook.send` destinations and require approval for any body derived from tool output.

## Lab limits

Default bind `127.0.0.1`. Freeze applies only to registered lab keys for 15 minutes. Tool backends in the lab pass are simulated echoes. Not a certification, not a penetration test.
