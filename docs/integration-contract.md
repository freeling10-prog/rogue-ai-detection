# Integration contract

Lab note. The gateway is a policy check on calls that are routed to it. This page states what it assumes and what the caller must enforce.

## What the gateway assumes

- Every tool call, `tools/list`, and tool result for the session is sent to it, in order, under one stable `session_id` and the agent's registered key.
- The caller carries `capability_token` from each response into the next request. The gateway also keeps session state in process memory, so the token is a second check, not the only one.
- `AGENT_GATEWAY_HMAC_KEY` (at least 32 random bytes) is set and kept secret. It is the trust root; the process refuses to start without it.
- It runs on the same host or a trusted loopback path. A non-loopback bind needs `--allow-nonlocal` and an isolated lab network.
- Tools are classified in `TOOL_EGRESS` ([tool classification](tool-classification.md)). Unknown tools are treated as writes.

## What the caller must enforce

- **No second path.** The dispatch loop must not call a backend unless the gateway returned `ok`. Anything the harness can reach directly is outside the boundary, and nothing in the gateway can detect it.
- **Do not run held calls.** A held or denied response means do not execute. A person issues the one-time approval token for that exact call; pass it back unchanged.
- **Send tool results back.** Results from untrusted sources must reach the gateway (`ingest_tool_result` in process) or the tool must be in the ingest list, otherwise the session is never tainted.
- **Isolation is yours.** The gateway is not an OS sandbox or network isolation. Confine tool processes, files, and sockets separately.
- **Rotation is not supported.** See [Known non-goals](../README.md#known-non-goals-and-bypasses-wanted).

## Resource limits (HTTP path)

Set in `PepConfig`. In-process callers of `PolicyEngine` are not limited.

| Field | Default | Effect |
| --- | --- | --- |
| `max_body_bytes` | 262144 | Larger request body → HTTP 413 |
| `max_arg_bytes` | 65536 | Larger serialized `arguments` → HTTP 413 |
| `max_sessions` | 1000 | New session past the cap → HTTP 429. Existing sessions keep working |
| `max_id_len` | 128 | Longer `session_id` → HTTP 400 |

Sessions are held in memory and are not expired. There is no per-key rate limit and no authentication beyond the registered agent key. These limits reduce accidental and trivial abuse. They are not DoS protection.

## Reference wrapper

[`examples/gated_dispatch.py`](../examples/gated_dispatch.py) is a minimal dispatcher that posts each call to `/v1/call`, carries the capability token forward, and runs the backend only on `ok`. Its self-test shows an ingest executing and a later `send_email` not executing. Adapt `post` to your HTTP client and register your own backends. Backends in the example are simulated.
