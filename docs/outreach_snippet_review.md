# Outreach snippet review: round 1 leads

Status: **draft for manual review. Not for sending as written.**
Date: 2026-11-02. Branch: `feat/pr42-shell-collusion-and-scorer`.

These are internal notes on five approved leads. None of them is a customer.
Nothing here is a finding about a deployment, a confirmed vulnerability, or a
certification. Every note is a static reading of public material (a README or
a release manifest), and the scorer is the repo's own heuristic
(`benchmarks/wild_mcp_corpus/score.py`, including the opt-in own-data rule
`own_data_lookup/1` added in this branch). No server was contacted and no
tool was called.

## What was checked

| Lead | Where we looked | Public MCP tool schemas found? |
|---|---|---|
| Onplana | [`Onplana/onplana-mcp-server`](https://github.com/Onplana/onplana-mcp-server) at `2d4a25b` (2026-10-17); Smithery frame row `hello-l2w0/onplana` | **Names only.** The README lists 33 of the 285 hosted tools with a one-line description and a read / write section. No `inputSchema` is published: the dispatcher and the tool catalog are closed-source. The Smithery frame row (use_count 0) has no tool list, and the row is not in either scored corpus snapshot. |
| MCPBundles | [`thinkchainai/mcpbundles`](https://github.com/thinkchainai/mcpbundles) at `80c985c` (README only); `hub.mcpb` release asset `hub-v1.0.0+build.8da55d55` | **No.** The `.mcpb` `manifest.json` has no `tools` array. The Hub is a proxy to an authenticated remote endpoint, so its tools depend on the account. Not in the Smithery frame. |
| NitroStack | [`nitrocloudofficial/nitrostack`](https://github.com/nitrocloudofficial/nitrostack) at `10859be` | **No product schema.** NitroStack is a framework for building MCP servers, not one server. `sample-apps/` holds 202 sample and hackathon projects. Those are not NitroStack's own tool surface, so none was scored. Not in the Smithery frame. |
| Rindler | GitHub repository search for "rindler mcp" | **None found.** The only hits are a third-party API profile (`api-evangelist/rindler`) and a "Rindler inspired" bridge from another org. Neither is Rindler's own code. Not in the Smithery frame. Needs the lead's own repo or endpoint URL. |
| Netica | GitHub repository search for "netica mcp" | **None found.** No repositories. Not in the Smithery frame. Needs a URL from the lead. |

Smithery check: case-insensitive search of `smithery_frame.jsonl` (20,758
eligible rows), `servers.jsonl` and `random_servers.jsonl` for each name.
Only Onplana matched, and only in the frame, which stores no tools.

## Scorer run (Onplana README listing only)

The listing is in `benchmarks/wild_mcp_corpus/outreach_round1_listings.jsonl`
with `schema_policy: not_published_as_json`. Without schemas the
schema-dependent predicates (`toxic_2hop`, `toxic_3hop`, `R_cold_path`,
`MCP_FIRST_SEEN_OVERPRIVILEGED`, `MCP_SCHEMA_PURPOSE_MISMATCH`) are `na` by
design and were not run.

| Check | Result | Reading |
|---|---|---|
| `tool_class` counts | 20 write, 10 internal_read, 3 external_read | 12 of the 20 "write" labels come from the fail-closed default branch. That includes `summarize_project`, `analyze_project_risks` and `generate_status_report`, which the README marks `readOnlyHint: true`. `readOnlyHint` is not an input to `tool_class`. |
| `own_data_lookup/1` | 0 tools relabelled | `search_org_knowledge` stays `external_read` because its description says it indexes comments and wiki pages (user-authored text). `search` and `fetch` are App Directory adapters whose one-liners name no scope. |
| `MCP_TOOL_NAMESPACE_FLOOD` | hit | Only because the README lists 33 names and the threshold is more than 32. The hosted catalog is larger and is filtered by role and plan, so this says nothing about what one client sees. |
| `MCP_DESCRIPTION_POISONING` | miss | Lexical scan of 33 one-liners only. |
| `MCP_TOOL_SHADOWING` | miss | Single-server, core built-in names only. |

## One-line notes for manual review

Each line carries its caveat. Do not lift a line without it.

- **Onplana:** The README's 33-of-285 tool list scores names-only, and nothing schema-dependent can be judged without published input schemas. Three `readOnlyHint` AI-summary tools fall to our fail-closed "write" default. *Caveat: README one-liners, not the live catalog; static heuristic, not a vulnerability.*
- **Onplana (possible angle):** The README already wraps tool output for prompt injection and keys task leases to the run. An offer to run our static listing check on their full `tools/list` output, with their consent, is the only scoped next step. *Caveat: we have not seen their dispatcher or the full catalog.*
- **MCPBundles:** The Hub `.mcpb` publishes no tool list (it proxies to an authenticated endpoint), so there is nothing to score publicly. *Caveat: per-bundle `.mcpb` releases were not inspected; any check would need their consent and a sample `tools/list`.*
- **NitroStack:** This is a framework, not one server, so there is no product tool surface to score. The 202 sample apps belong to their authors. *Caveat: any note should be about framework defaults, which we have not reviewed.*
- **Rindler:** No public MCP repo or schema found under that name. *Caveat: GitHub repository search only; we need the lead's own URL before saying anything.*
- **Netica:** No public MCP repo or schema found. *Caveat: GitHub repository search only; we need the lead's own URL before saying anything.*

## Limits

- One reviewer, one pass, on 2026-11-02. Repositories change; commits are pinned above.
- The own-data rule was written after reading the 28 PR #40 cases. Its result on those cases is in-sample (see `own_data_rule_check.json`).
- No outreach claim should cite a prevalence figure from the wild corpus for these leads. None of them is in the scored snapshots.
