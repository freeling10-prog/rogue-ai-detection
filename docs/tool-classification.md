# Tool classification

Lab policy note. The gateway decides what to hold from a tool's egress class, not from what the tool claims to do. The table is `TOOL_EGRESS` in [`agent-gateway/agent_gateway/taint.py`](../agent-gateway/agent_gateway/taint.py). Read the source for the current list; the names below are examples.

| Class | Meaning | Examples in the table | After untrusted ingest |
| --- | --- | --- | --- |
| `internal_read` | Reads inside the trust boundary | `lookup_order_status`, `read_session_note`, `poll_internal_bus` | Allowed |
| `external_read` | Reads content the agent does not control | `web.fetch`, `read_external_url`, `read_customer_ticket` | Allowed. Taints the session and appends `allow_egress=false`. Parameters that carry a query are gated separately |
| `write` | Changes state | `file.write`, `save_session_note`, `update_ticket_status` | Held for one-time approval. Exception: `update_ticket_status` with an enum `status`, an ID, and no free-text field |
| `send` | Leaves the boundary to a person or service | `send_email`, `webhook.send`, `send_webhook` | Held for one-time approval |
| `creds` | Reads or moves credentials | `secrets.get`, `vault.read`, `credentials.pass_through` | Held for one-time approval |
| `bus`, `spawn`, `meta` | Agent bus post, sub-agent spawn, `tools.list` | `post_internal_bus`, `spawn_subagent`, `tools.list` | `bus` is held. `spawn` and `meta` have their own checks (delegation guard, tool-list pinning) |

A few tools sit in two lists. `file.read` is an `internal_read` that is also a taint source, and `read_customer_ticket` is treated as untrusted ingest because customer text is untrusted.

## Unknown tools fail closed

A tool that is not in `TOOL_EGRESS` is classified as `write`. Before any untrusted ingest it is not held for taint. Once the session is tainted it is held like any other write.

Two consequences:

- A read-only tool you forgot to classify is held after taint. In the [boundary replay](../examples/replay_attenuation.py), `lookup_order_status` stays allowed after ingest, while an unclassified `lookup_customer` would be held.
- An untrusted source whose tool is not in the ingest list does not taint the session at all, unless the host marks it itself (`PolicyEngine.mark_untrusted_ingest`). Classification fails closed for the egress side only. See [Known non-goals](../README.md#known-non-goals-and-bypasses-wanted).

To use your own tools, add each one to `TOOL_EGRESS`, and to `UNTRUSTED_INGEST_TOOLS` if its output is untrusted. This is a lab classification, not a certification of any tool.
