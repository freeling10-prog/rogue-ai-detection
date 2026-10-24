# ATLAS technique ↔ policy gate map

See `/workspace/phase2-gateway.md` for the full design and test matrix.

- AML.M0030 — Restrict Tool Invocation on Untrusted Data (core mitigation this PEP implements; chained HMAC capability attenuation denies egress after untrusted ingest)
- AML.T0051 / T0051.001 / T0053 — prompt injection & tool invocation (bound OOB, tools/list taint)
- AML.T0080.000 — memory/context poisoning (scratchpad `taint_inherited`)
- AML.T0086 — exfiltration via tool invocation (egress classes + lethal-trifecta gate)
- AML.T0118 — autonomous agent communication (bus taint, fan-out quota, root-parent freeze)

v8, v9, and v10 additions. These mappings are approximate, like the ones above:

- AML.T0051 (approximate) — MCP rug pull: a pinned `tools/list` definition (`sha256(name, description, inputSchema)`) changes mid-session. `mcp_proxy.py` records `mcp_rug_pull_detected`, the PEP appends `allow_egress=false`, and every later `tools/call` waits for a bound one-time OOB approval. Server-initiated `sampling/createMessage` is rejected while tainted or without a root-keyed `grant:sampling=` caveat.
- AML.T0086 (approximate) — cross-step and encoded exfiltration: `deobfuscate.py` matches salted n-gram digests of sensitive reads and canaries (raw, Base64, hex, URL-encoded, whitespace-stripped) against a sliding window of released outbound arguments. A match denies the call and freezes the registered root key for 15 minutes.
- AML.T0051 (approximate) — tool-output injection: `tool_output_scanner.py` flags Unicode tag smuggling (U+E0000–U+E007F, decoded for review), zero-width and BiDi override characters, chat-template / tool-result delimiter spoofing, fake JSON-RPC envelopes, and cross-tool name shadowing of registered write / send / credential tools. A finding taints the session and appends `allow_egress=false`.
- AML.T0053 (approximate) — SSRF / cloud metadata in tool arguments: `egress_uri_guard.py` canonicalizes dword, hex, octal, short, IPv4-mapped / NAT64 IPv6, percent-encoded, userinfo, backslash, and wildcard-DNS spellings. Metadata and obfuscated internal targets are denied; plain RFC 1918 / link-local targets are held for a bound OOB approval. No DNS lookup is made.
- AML.T0086 (approximate) — post-trifecta side channels: `side_channel_guard.py` holds a tainted + sensitive session that releases more than 4 distinct argument variants (boolean oracle), more than 16 outbound calls, or 5 equal intervals in a row (timing beacon), and freezes the registered root key for 15 minutes.
- AML.T0086 (approximate) — static toxic combinations: `toxic_combinations.py` enumerates 2-hop and 3-hop `external_read → read → sink` paths in a tool inventory that have no hard `agw1.` boundary at the sink.
- AML.T0051 / AML.T0086 (approximate) — confused-deputy delegation: `delegation_guard.py` carries one agent's `agw1.` restrictions (deny-egress, deny-sampling, taint sources) into a peer or subagent by the meet of their capabilities, and blocks a delegated agent from an egress its delegating chain was barred from (`confused_deputy_delegation_blocked`).
- AML.T0051 / AML.T0053 (approximate) — argument firewall: `arg_ast_guard.py` blocks path traversal (including encoded and backslash forms and sensitive system paths), shell-metacharacter chaining, CRLF header splitting, and mutating / file-exfil SQL in read-classified tools (`arg_firewall_violation`).
- AML.T0086 (approximate) — canary watermarking: `canary_watermark.py` weaves a step-bound zero-width HMAC watermark into sensitive reads and tracks standard credential formats; a watermark or credential surfacing in an outbound call is denied and the registered key is frozen, with `origin_step_index` / `origin_tool_name` in the hash-chained log (`canary_watermark_exfil`).
- The gateway findings, toxic paths, and analyzer matches export to OASIS SARIF 2.1.0 via `sarif_export.py` (`audit --sarif`) for GitHub code scanning.
