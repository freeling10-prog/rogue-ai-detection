# ATLAS technique ↔ policy gate map

See `/workspace/phase2-gateway.md` for the full design and test matrix.

- AML.M0030 — Restrict Tool Invocation on Untrusted Data (core mitigation this PEP implements; chained HMAC capability attenuation denies egress after untrusted ingest)
- AML.T0051 / T0051.001 / T0053 — prompt injection & tool invocation (bound OOB, tools/list taint)
- AML.T0080.000 — memory/context poisoning (scratchpad `taint_inherited`)
- AML.T0086 — exfiltration via tool invocation (egress classes + lethal-trifecta gate)
- AML.T0118 — autonomous agent communication (bus taint, fan-out quota, root-parent freeze)

v8 additions. These mappings are approximate, like the ones above:

- AML.T0051 (approximate) — MCP rug pull: a pinned `tools/list` definition (`sha256(name, description, inputSchema)`) changes mid-session. `mcp_proxy.py` records `mcp_rug_pull_detected`, the PEP appends `allow_egress=false`, and every later `tools/call` waits for a bound one-time OOB approval. Server-initiated `sampling/createMessage` is rejected while tainted or without a root-keyed `grant:sampling=` caveat.
- AML.T0086 (approximate) — cross-step and encoded exfiltration: `deobfuscate.py` matches salted n-gram digests of sensitive reads and canaries (raw, Base64, hex, URL-encoded, whitespace-stripped) against a sliding window of released outbound arguments. A match denies the call and freezes the registered root key for 15 minutes.
