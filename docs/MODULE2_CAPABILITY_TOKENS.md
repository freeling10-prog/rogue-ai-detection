# Module 2: `agw2` capability tokens

Status: scaffold. The core module, the engine hook and their tests are in the tree. The steps under "Not built yet" are not.

## Why

`agw1` (`capability.py`) carries two deny bits, egress and sampling. Two things follow from that, both found in the 12 November audit and reproduced against the code:

- A token says what a session may no longer do. It cannot say that a worker may call `send_email` to one address twice and nothing else.
- A caveat `agw1` does not recognise still verifies and is ignored. A holder can append `tool=read_file` and nothing enforces it.

`agw2` is a second token type next to `agw1`. It does not replace it yet.

## What is built

| Piece | Where |
|---|---|
| Token format, caveat vocabulary, mint / attenuate / verify, counters, revocation | `agent-gateway/agent_gateway/capability_token.py` |
| Engine hook, `attach_capability_token`, rule code `CAPABILITY_TOKEN_DENIED` (JSON-RPC -32083) | `agent-gateway/agent_gateway/pep.py` |
| SARIF rule | `agent-gateway/agent_gateway/sarif_export.py` |
| Unit, bounded-enumeration and gateway wiring tests (41) | `agent-gateway/tests/test_capability_token.py` |

Standard library only: `hmac`, `hashlib`, `json`, `base64`, `secrets`.

### Token

```
agw2.<base64url(body)>.<hex>

body  = canonical JSON {"v": 2, "tid": <32 hex>, "scope": {...}, "caveats": [...]}
sig0  = HMAC-SHA256(root_key, "agw2|" + canonical({"v", "tid", "scope"}))
sig_i = HMAC-SHA256(sig_{i-1}, canonical(caveat_i))
```

The root key is `AGENT_GATEWAY_HMAC_KEY`, the same key `agw1` uses, with a different domain prefix. A body that is not byte-for-byte canonical, has a duplicate key, or carries a float does not parse.

Scope is fixed at mint. `session` binds one session. `coalition` names an anchor session and admits any session that is in the anchor's P3 coalition when the call is made. Coalitions only merge, so the anchor stays a member. Session ids are hashed in the token.

### Caveats

| Caveat | Admits a request when |
|---|---|
| `tools` | the tool is in the allow list |
| `dest` | the destination is in the allow list |
| `arg` | one predicate on one argument path holds: `eq`, `in`, `prefix`, `max_len`, `range`, `absent` |
| `session` | the caller is this one session (narrows a coalition token) |
| `exp` | the engine clock is not after `not_after_ms` |
| `calls` | fewer than `max` events were admitted under this caveat |
| `budget_qb` | P3 charge admitted under this caveat stays within `max` quarter bits |
| `once` | nothing was admitted under this caveat before (single use, named by a nonce) |

The vocabulary is closed. A caveat outside it, or a malformed one, makes the whole token fail. No caveat grants anything.

### Attenuation

A request is admitted only when every caveat on the chain admits it, so an appended caveat can only remove requests. Appending needs the current tag and not the root key. Dropping, reordering or editing a caveat breaks the chain.

The counter behind `calls`, `budget_qb` and `once` is keyed by the chain tag at that caveat's position. Every token derived from that prefix shares the counter. A sub-token that adds `calls<=1000` under a parent's `calls<=2` still stops at 2, and siblings draw on the same 2.

Counters use reserve, then commit or abort, the same shape as the P3 ledger. A reservation counts against its limits until it settles.

### Engine hook

`PolicyEngine.attach_capability_token(session_id, token)` binds a token to a session. Nothing changes for a session with no token.

The check runs at the end of `_release`, directly after the P3 reservation, and only for calls that `is_outbound_event` classifies as outbound. That is the one outbound test `_release`, Predicate E and P3 already share; it is now a module-level function so the calibration replay uses it too. The order matters: the `budget_qb` caveat is charged what P3 reserved for the same event.

The reservation is staged with the P3 one. It commits when the call is forwarded and aborts when a later gate denies the call. A token refusal aborts the P3 reservation, so a refused event costs no leakage budget.

A session that already has a token can only be given an extension of it. A person's approval of one call does not override a token. A refusal is a deny, not a hold, and it does not freeze a key.

## What is checked, and how

These are checked by bounded enumeration within the bounds written in the test file. Nothing outside those bounds is claimed.

| Property | Bounds |
|---|---|
| An extension admits a subset of what its prefix admits, and a chain admits exactly the intersection of its caveats in any order | every chain of 0 to 3 caveats over a 9-caveat alphabet (820), every one-caveat extension (7,380), 96 requests |
| A holder can only append | 31 chains, 156 candidate caveat lists, 6 tags the holder can compute (29,016 forgeries, 186 accepted, all of them appends) |
| Committed use under a tag never passes its limit, and every decision equals plain integer counters | parent, child and sibling tokens; 27 step kinds; every schedule of 1 to 3 steps for two limit pairs and 1 to 2 steps for three more (43,146 schedules) |

There are no mutation checks for the token ledger yet. Until there are, "the enumeration would notice a per-token counter" is untested.

## Not built yet

In the order I would build them:

1. **Wire presentation.** The MCP proxy reads `_meta["agentgate/capability_token"]` for `agw1` only. Accept an `agw2` token there per call, checked as an extension of the attached one.
2. **Holder binding.** A token is a bearer token today. That is acceptable while the control plane attaches it server-side; it is not once tokens travel in `_meta`, because a token copied into a prompt works for whoever replays it. Add `pop = HMAC(holder_key, tag || H(canonical request) || counter)` with `holder_key = HMAC(root, "holder|" + agent_id)`.
3. **Delegation.** `PolicyEngine.delegate` and `spawn_subagent` still hand off `agw1` deny bits. Mint the child's sub-token there, and raise the parent's restrictions when a child's result returns upward (audit finding 4).
4. **The passthrough path.** `account_passthrough` (list and cursor params to a non-core server) charges P3 without going through `_release`, so the token does not see it.
5. **Counters across processes.** One process, like the P3 ledger. `sqlite3` in WAL mode is the stdlib option.
6. **Operations.** A revocation command, chain-logged revocations, and token ids in the audit report.
7. **Mutation checks** for the ledger, in the style of the P3 M-table.

## Decisions for the owner

- **Should a token gate calls that are not outbound events?** Today a restricted worker can still make local internal reads. That follows the instruction to hook the shared outbound check. For the confused-deputy case a `tools` caveat that also covers local reads is stronger; it means a second hook earlier in `_evaluate_call`.
- **Should attaching a session token to a different session fail at attach?** It fails at the first call today (`CAP_SCOPE`). Coalition tokens cannot be checked at attach because membership changes.
- **Which charge does `budget_qb` count?** It uses the charge at reservation. P3 recomputes the slot gap at commit, so the two can differ by a few quarter bits when another event lands in between.
