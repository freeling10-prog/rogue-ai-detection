# Wild MCP corpus: static predicate prevalence

Retrieval date: **2026-11-01**. This is a convenience sample of public MCP listings and source text. It is not a random sample, not a penetration test, and not a confirmation that any server is vulnerable. No tool was called. No server was started. No secret was used.

The numbers below are from the committed snapshot `benchmarks/wild_mcp_corpus/servers.jsonl` (SHA-256 `379d0776e934a1e107974c66b1cfabfb87334ef7dab033cfca3fe0d7f4b920a0`), scored by `benchmarks/wild_mcp_corpus/score.py` into `results.json`. Re-running the collector hits live registries and will not reproduce these rows.

## What was counted

| Stratum | Rows | Role in the headline |
| --- | ---: | --- |
| Smithery list order, with a published tool list | 150 | Headline denominator |
| `modelcontextprotocol/servers` at `194cc86e3ae6400958555bd4116849d822d69263` | 7 | Separate. Input schemas were not inlined in source, so schema predicates are not applicable |
| One public `mcp.json` that named tools and gave no input schemas | 1 | Separate. Same limitation |
| Official registry, latest version of each server | 40,100 counted, not stored as a tool corpus | None contained a `tools` array |
| Registry-linked `mcp.json` / `.mcp.json` launch configs | 24 | Launch commands only. No tool schemas. Not scored |

The headline is **150 servers, 6,856 tools, every tool carrying a JSON `inputSchema`**. Smithery's list endpoint reported 20,753 to 20,756 servers while this slice was taken (the total moved between calls). These 150 are the first detail documents in that API's default order that contained at least one named tool. Collection issued six page requests of 50 and examined 272 list rows, then stopped. One detail had no tools. No detail request failed. `useCount` on the kept rows runs from 2,410 to 419,019, median 6,606. The order is not monotonic in `useCount`, and it is not a draw from the registry. It over-represents servers the index has already recorded as heavily used.

## Sampling rules

1. **Reference repository.** Every directory under `src/` in [github.com/modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) at commit `194cc86e3ae6400958555bd4116849d822d69263` (2026-10-28). Tool names and description literals were read from `registerTool` calls and `@server.tool` decorators, including `name=Enum.MEMBER.value` when the member is a string in the same file. Zod objects and Python annotations were not executed and were not translated into JSON Schema. Those seven servers are in the file with `schema_policy: not_published_as_json`.

2. **Smithery.** `GET https://registry.smithery.ai/servers?pageSize=50`, pages 1 upward, then `GET /servers/{qualifiedName}` for each row that was not marked unlisted or inactive. Kept when `tools` contained at least one object with a name. Stopped at 150. Deduplicated on case-folded `qualifiedName`. This study did not send `tools/list` or `tools/call`. The schemas are the ones Smithery had published on the retrieval date.

3. **Official registry.** `GET https://registry.modelcontextprotocol.io/v0.1/servers?version=latest&limit=100`, followed to the end of `nextCursor`. **40,100** latest-version documents. **0** had a `tools` field. **25,889** had a repository URL. The compact listing was hashed (`cca727086f402f5f6cfca322c8eca210109f7b233511115f1db2dbd305755206`) and is not committed: it is not a tool corpus. `benchmarks/wild_mcp_corpus/official_registry_census.json` records the count. `collect.py` can regenerate the listing.

4. **Registry-linked configs.** The first 120 distinct `github.com` repository URLs in that registry order. For each, `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, and `.cursor/mcp.json` were fetched from branch `main` (480 requests). JSON objects with `mcpServers` or `servers` were kept (24 files). One file that listed 11 tool names and descriptions and no input schemas was moved into `servers.jsonl` as its own stratum. One JSON file that was neither a launch config nor a tool list was not retained. GitHub code search was not used; the search API was rate-limiting this environment, and a search-ranked slice would have been a different sample.

Dedup is within each stratum (Smithery qualified name, reference directory name, config path). The strata are not pooled in the headline, because the reference and manifest rows do not have published JSON schemas. Treating a missing schema as an open channel, which `toxic_combinations` does when a real `tools/list` omits one, would have scored an extraction gap as if it were the server's listing.

## The fourteen predicates

The gateway's predicate set is the fourteen validators in `docs/AgentGate_Validator_Specification.md`. The dispatch formula is R, W, F, I, P, T, S, V, D, Z, and v14 adds C, E, B, A. Count: **14**.

| Id | Module | Applied to a static listing? |
| --- | --- | --- |
| R | `registry_pin_validator.py` | Cold path only: `make_pin` on one descriptor (lint, local JSON Schema profile, method-name rule, canonical digest). Hot path skipped: pin equality, sticky revocation, and cross-provider alias ambiguity need a prior pin or a second provider |
| W | `workspace_path_validator.py` | No. Needs a command or path and a filesystem snapshot |
| F | `lattice_flow_validator.py` | No. Needs a workflow manifest and a call |
| I | `shingle_similarity_validator.py` | No. Needs protected strings and an outbound argument |
| P | `linear_obligation_validator.py` | No. Needs a Petri-net transition |
| T | `symbolic_fs_transducer.py` | No. Needs file operations and labels |
| S | `canonical_argument_confinement.py` | No. Needs a concrete argument object |
| V | `fork_join_vector_validator.py` | No. Needs a live session |
| D | `dynamic_ingression_validator.py` | No. Needs a tool result and a later outbound string |
| Z | `transform_invariant_validator.py` | No. Needs protected values and an outbound string |
| C | `causality_laundering_validator.py` | No. Needs observed filesystem effects |
| E | `event_channel_capacity_validator.py` | No. Needs an event stream |
| B | `blindfold_opaque_fault_validator.py` | No. Needs a request and remembered refusals |
| A | `reachability_confinement_validator.py` | No. Needs an authored workflow DAG |

Thirteen of the fourteen cannot be evaluated from a name, description, and input schema. They were not approximated.

These static checks already exist and were applied, by calling the gateway functions rather than reimplementing them:

- `toxic_combinations.analyze` (2-hop and 3-hop). This is the coded form of "untrusted read can reach a sink". It is not mere co-occurrence of an untrusted-read tool and a write or send tool. A path is `external_read → internal_read|sensitive_read → sink`, and the 3-hop form inserts a second read. The sink must have a free-text channel, and it must not carry `agw1_boundary`. No listing in this corpus set that flag, so a path the enumerator builds is counted toxic.
- `mcp_capability_manifest_guard.register_listing` with no server profile (the guard's default for an unverified server): `MCP_FIRST_SEEN_OVERPRIVILEGED`, `MCP_SCHEMA_PURPOSE_MISMATCH`, `MCP_TOOL_NAMESPACE_FLOOD`.
- `mcp_rugpull_guard.register_listing` on one server at a time: `MCP_DESCRIPTION_POISONING`, then `MCP_TOOL_SHADOWING` against core built-in names. Poison is checked first, so a poisoned core name counts as poison only. Drift cannot fire on one listing.

Not applied, because the code does not define them or they need a second observation:

- **Over-broad scopes.** Nothing in the gateway decides that a declared OAuth scope is too wide. Smithery detail documents in this slice did not expose a scopes list in the fields walked (`scopes`, `scope`, `oauthScopes`, `permissions`). Twenty-four of the 150 had config-schema field names; those names were stored and not scored.
- **Untrusted-read plus write/send as co-occurrence.** No such function. The Quick Check wording is operationalized here only by `toxic_combinations`.
- `MCP_DEFINITION_DRIFT`, `SCHEMA_DRIFT_DENIED`, and cross-server distance-1 shadowing in `schema_integrity_guard`. One listing has no prior pin. Distance-1 was not run across unrelated rows: the guard itself notes that `get_user` / `get_users` collide, and these servers are not co-installed.

`tool_class` is the classifier behind Quick Check's labels. The product copy says four words (read, write, send, credential use). The code returns six: `external_read`, `internal_read`, `sensitive_read`, `write`, `send`, `credential_use`. There is no separate four-way classifier, so the six were scored and the four were not invented. Published listings do not carry `class`. The label is the egress table, else a token match on the name, else **write** (or `credential_use` if the name looks sensitive). MCP `readOnlyHint` is not an input. None of the 6,856 published tools in this slice included `readOnlyHint: true`.

## Headline prevalence (Smithery slice)

Server-level: a server hits if at least one of its tools trips the check. n = 150 for every row. The interval is the **95% Wilson score interval** for that observed count, with z = 1.959963984540054, bounds quantized to 6 decimal places, half-even. It is the interval a binomial proportion would have under an iid model. **This sample is not iid and not random, so the interval is not a confidence interval for all public MCP servers.** It is reported because it describes the uncertainty of a proportion of this size, and it must not be cited without that limit.

| Predicate | Servers | Prevalence | 95% Wilson |
| --- | ---: | ---: | --- |
| R cold path (`make_pin` denies) | 10/150 | 0.066667 | 0.036612–0.118362 |
| Toxic 2-hop | 79/150 | 0.526667 | 0.447101–0.604901 |
| Toxic 3-hop | 74/150 | 0.493333 | 0.414497–0.572503 |
| `MCP_FIRST_SEEN_OVERPRIVILEGED` | 17/150 | 0.113333 | 0.071974–0.174003 |
| `MCP_SCHEMA_PURPOSE_MISMATCH` | 3/150 | 0.020000 | 0.006825–0.057147 |
| `MCP_TOOL_NAMESPACE_FLOOD` (>32 tools) | 35/150 | 0.233333 | 0.172826–0.307158 |
| `MCP_DESCRIPTION_POISONING` | 1/150 | 0.006667 | 0.001178–0.036793 |
| `MCP_TOOL_SHADOWING` (core built-in name) | 4/150 | 0.026667 | 0.010418–0.066554 |

A 3-hop path in `analyze` implies a 2-hop path on the same nodes, so the union is the 2-hop row: **79/150**.

`analyze` keeps the first 400 named tools. Two servers in the slice list more than 400. They were scored on that prefix, which is what the function does.

### How to read the rows

**R is a contract check, not a vulnerability count.** `make_pin` returns the first denial. Across tools, the first reasons were `UNRESOLVED_REF` 11, `METADATA_LINT` 6, `METHOD_NAME` 5, `TEXT_LIMIT` 1. Those 23 tool denials sit in 10 servers. A local JSON pointer that does not resolve, a method name outside the validator's token rule, a description over the 4 KiB lint cap, or a lint hit on a description is a failure to meet predicate R's enrollment profile. It does not mean the server was exploited or that its schema is hostile. Many ordinary schemas are outside that profile.

**Toxic paths are name heuristics plus schema shape.** Of 6,856 tools, 3,455 were classed by a name rule, 5 by the fixed egress table, and **3,396 (the default branch)** because the name matched neither. Of 3,609 tools classed `write`, 3,346 are that default. Of the 114 servers with any write-classed tool, 75 had every such tool on the default branch. Dropping default-branch tools and applying the same node and path rules leaves **75/150** servers with a 2-hop path and **70/150** with a 3-hop path. The fail-closed default accounts for 4 of the 79 two-hop servers. It does not account for most of them. The remaining paths are still "these names matched the heuristic and the schemas have a free-text channel", not observed exfiltration.

**Overprivileged is the unverified-server default.** With no profile assigned, the guard grants neither credential parameters nor exec parameters. A parameter named like `api_key` or `command` is a hit. That is the policy, applied to a corpus the gateway has not profiled. It is not a finding that a credential was stolen. Purpose mismatch is the guard's second check and only fires when the tool was not already overprivileged, so 3/150 is a lower bound on name/parameter disagreement.

**Flood is a listing length.** More than 32 named tools. Several indexed servers publish large catalogs. Length is not malice.

**Poison and shadowing are lexical.** One Smithery server and one reference-repo server tripped `scan_definition` (hidden-instruction markers: tags, invisible characters, a credential-path phrase, an "ignore previous instructions" phrase, or a smuggling parameter name). The guard's own comment is that quoted documentation can trip this. Shadowing here is only a normalized name equal to a core built-in (`bash`, `read`, `write`, and the rest of that frozenset), on a single server. Neither result was confirmed at runtime.

## Class prevalence (same 150 servers)

A server is counted if at least one tool received that class from `tool_class`. These are labels, not denials.

| Class | Servers | Prevalence | 95% Wilson |
| --- | ---: | ---: | --- |
| `external_read` | 99/150 | 0.660000 | 0.581043–0.730967 |
| `internal_read` | 129/150 | 0.860000 | 0.795448–0.906574 |
| `sensitive_read` | 6/150 | 0.040000 | 0.018459–0.084513 |
| `write` | 114/150 | 0.760000 | 0.685709–0.821307 |
| `send` | 27/150 | 0.180000 | 0.126758–0.249223 |
| `credential_use` | 15/150 | 0.100000 | 0.061541–0.158435 |

Tool-level counts, same slice: external_read 796, internal_read 2,236, sensitive_read 38, write 3,609, send 124, credential_use 53.

The reference repository (n = 7, schemas not scored) tripped namespace flood on 0/7, description poisoning on 1/7, and core-name shadowing on 0/7. Class labels there are also name heuristics. n = 7 is the whole `src/` tree under the extractor, not a sample, and it is too small to mix into the table above. The one-file manifest (11 tools, no schemas) is likewise not in the table.

## Secrets

Strings were compared with `canary_watermark.CREDENTIAL_PATTERNS`, plus URL query credentials and `KEY=` / `TOKEN=` / `SECRET=` / `PASSWORD=` assignments. **Zero** committed strings matched. Eight string values sitting under secret-like keys (header values, env-like fields, OAuth client ids) were replaced with `[REDACTED:precautionary]` without being tested or used. They are not counted as credential findings.

## Limitations

- Static analysis of published names, descriptions, and schemas. Behavior can disagree with the description. Smithery's copy can disagree with the server a person would reach today.
- No runtime exercise, no exploitation, no confirmation of a vulnerability. A predicate hit is the gateway function returning a denial or a positive path count on the declared listing.
- The classifier was written by the same authors as the rest of the gateway, and it was not fitted to this corpus. The corpus was not written by those authors. Class labels are still the authors' name rules. High write prevalence is partly the fail-closed default, as counted above.
- Convenience sample, popularity-skewed, one index's default order, one day. Wilson intervals do not fix that.
- The official registry, which is the protocol's own index, does not publish tool schemas (0 of 40,100 latest documents). Generalizing from an indexer that does publish them to "public MCP servers" would overclaim.
- Reference-repo schemas were left unset on purpose. A partial Zod-to-JSON translation would have been a new parser and could have moved the predicate results.
- Two listings over 400 tools are scored on `analyze`'s prefix.
- Purpose mismatch is conditional on not already being overprivileged.
- Description poisoning and R's metadata lint are syntactic. They fire on phrases a document may quote on purpose.
- Declared scopes were absent in this slice, and no over-breadth rule exists, so scope hygiene was not measured.

## Reproduction

From the repository root, Python 3.12, standard library plus the gateway tree (no extra packages for the scorer; pytest is only for the tests):

```bash
# Rescore the committed snapshot. Writes benchmarks/wild_mcp_corpus/results.json
PYTHONPATH=. python3 benchmarks/wild_mcp_corpus/score.py \
  benchmarks/wild_mcp_corpus/servers.jsonl \
  --out benchmarks/wild_mcp_corpus/results.json

PYTHONPATH=. python3 -m pytest benchmarks/wild_mcp_corpus/test_score.py -q
```

`collect.py` rebuilds a new convenience sample from the live registry, Smithery, the pinned reference commit, and registry-linked config files. It does not call tools. Expect different Smithery rows after 2026-11-01. The official-registry compact JSONL is produced and then omitted from this commit; the census file explains that.

Gateway and agent-watch suites were run on this tree after the corpus landed (Python 3.12.3, no PHP, so the six PHP parity tests skip):

- `agent-gateway`: **1172 passed, 6 skipped**
- `agent-watch`: **512 passed, 2 skipped**
