# ATLAS technique ↔ policy gate map

See `/workspace/phase2-gateway.md` for the full design and test matrix.

- AML.M0030 — Restrict Tool Invocation on Untrusted Data (core mitigation this PEP implements; chained HMAC capability attenuation denies egress after untrusted ingest)
- AML.T0051 / T0051.001 / T0053 — prompt injection & tool invocation (bound OOB, tools/list taint)
- AML.T0080.000 — memory/context poisoning (scratchpad `taint_inherited`)
- AML.T0086 — exfiltration via tool invocation (egress classes + lethal-trifecta gate)
- AML.T0118 — autonomous agent communication (bus taint, fan-out quota, root-parent freeze)
