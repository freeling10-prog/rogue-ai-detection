# Sample Boundary Note 3 (Synthetic): Research Assistant with a Third-Party MCP Server

Synthetic tool list. Not a finding against any real product. ATLAS ids are approximate.

**Prepared for:** Security Reviewer · **Tier:** Fixed note · **Clock:** started on receipt of a usable tool list

## Tool inventory (as supplied)

| Tool | Source | Untrusted text enters via | Class in this tree |
| --- | --- | --- | --- |
| `web.search` | built-in | result snippets | external read (query parameters are also gated) |
| `search_docs` | built-in | doc snippets | external read |
| `read_session_note` | built-in | earlier notes | internal read |
| `save_session_note` | built-in | note body | write (free-text sink) |
| `send_webhook` | built-in | body | send |
| `notes-plus/*` | third-party MCP server | **tool descriptions** and results | depends on pinning |

## Taint paths

1. `web.search` / `search_docs` → session tainted → `save_session_note` and `send_webhook` held. Reads such as `read_session_note` stay allowed.
2. `tools/list` from the third-party server is not a core server, so its descriptions are treated as untrusted and taint the session. A later change to those descriptions is reported as a rug-pull and holds every later call until a person approves.
3. Scratchpad notes saved while tainted carry the taint into later sessions that read them (`taint_inherited`).

## What the lab gateway would hold

- `send_webhook` and `save_session_note` after any search or non-core `tools/list`.
- Search calls whose parameters carry a query to an external destination after a sensitive read.

## Known limits specific to this setup

- Pinning detects change after the first pin. A hostile first listing is pinned as-is.
- An answer that only repeats injected text, with no tool call, is not held.
- A third-party server that the harness calls directly, without routing through the gateway, is not seen.

## First three controls

1. Pin the third-party server's schema at review time, from a copy a person has read.
2. Require approval for `send_webhook` always, and allow-list destinations.
3. Keep `save_session_note` behind approval after taint so poisoned notes do not persist into later sessions.

## Lab limits

Default bind `127.0.0.1`. Freeze applies only to registered lab keys for 15 minutes. Backends in the lab pass are simulated. Not a certification, not a penetration test.
