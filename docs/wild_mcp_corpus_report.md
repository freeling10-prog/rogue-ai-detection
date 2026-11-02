# Wild MCP corpus: static predicate prevalence

Retrieval date: **2026-11-01**. The sections through Reproduction below are a convenience sample of public MCP listings and source text. That slice is not a random sample, not a penetration test, and not a confirmation that any server is vulnerable. No tool was called. No server was started. No secret was used.

**v2, same day.** A simple random sample of Smithery listings that publish a tool schema, scored with the same functions, is in [Random sample and precision check](#v2-random-sample-and-precision-check). The tables above it are the original list-order slice and are unchanged.

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

## v2. Random sample and precision check

Retrieval for the uniform snapshot: **2026-11-01T04:37:21Z** through **2026-11-01T04:38:43Z**. The frozen rows are `benchmarks/wild_mcp_corpus/random_servers.jsonl` (SHA-256 `e027c0fcd2fd913f8bbb7c2ecd465036727b34101d74b3e4a5faff513fa3b5a3`), scored by the same `score.py` into `random_results.json`. The contrast is `comparison.json`. Re-running `sample_random.py` hits the live index and will not reproduce these rows. The committed frame file is what the shuffle permuted.

This is still static analysis of published names, descriptions, and schemas. It is not a penetration test and not a confirmation that any server is vulnerable. No deployment URL was requested or stored. No tool was invoked.

### What the sample can and cannot support

The sample can support a statement about **Smithery listings, on this date, that publish at least one named tool whose `inputSchema` is a JSON object**, with each such listing weighted equally.

It cannot support a statement about all public MCP servers. The protocol's own registry, counted in the v1 census, had a `tools` array on 0 of 40,100 latest documents; that census was not repeated. It cannot support a statement about Smithery listings that publish no tool schema. It cannot support a use-weighted statement about what a typical installation calls. The list-order slice is closer to that second question and is still not a probability sample of installations.

### How the frame was built

`GET https://registry.smithery.ai/servers` reports `totalCount` 20,758 and, without a `seed` parameter, stops at 500 rows (`totalPages` 10 at `pageSize` 50, and 5 at `pageSize` 100). The documented `seed` parameter unlocks the rest of the pages. On this date, seeds 1, 7, and 20261101 returned the same page-2 prefix, so the parameter was not used as a randomizer. Enumeration used `seed=20261101`, `pageSize=100`, pages 1 through 208. Rows retrieved: **20,758**, equal to `totalCount`. The last page had 58 rows.

In that order, every adjacent pair of `useCount` values is nonincreasing (20,757 of 20,757). The unlocked order is a popularity ranking of the whole index, which is why the first 150 rows are a heavily used slice.

Eligibility, applied in retrieval order, drops a missing qualified name, a case-folded duplicate, `unlisted: true`, or `inactive: true`. Those four counts were **0, 0, 0, 0**. The public list on this date did not contain unlisted or inactive rows. The eligible frame has **N = 20,758**. The SHA-256 of the ordered qualified names is `0ed267dd8592944ad82883fc4cf70c35ddacac2913bbfc7677ed0e4142e85c5c`, and the names are in `smithery_frame.jsonl`.

Of those 20,758, **18,493 (0.891)** have `useCount` 0. The median is 0, the 99th percentile is 3,148, and the maximum is 419,019. Thirty-nine listings have `useCount` above 10,000.

### How the 250 were drawn

`random.Random(20261101).shuffle` in CPython 3.12 permutes the frame. Details were read in that order. A server is in the study population when at least one named tool has an `inputSchema` that is a JSON object. Tools without an object schema would have been dropped rather than scored as an open channel; none of the kept servers had such a tool. The draw stops at the 250th success. In a uniform permutation, the relative order of the schema-publishing subset is itself uniform, so those 250 are a simple random sample of that subset. A fetch batch can run past the stopping index; those extra responses are discarded and are not in the file.

**321** details were examined. **250** were kept. **71** had no named tool. **0** detail errors. **0** credential-shaped strings and **0** precautionary redactions in the frame homepages or the sample. The hit rate 250/321 is the rate in this stopping prefix, not a census of the other 20,437 listings. The schema-publishing population size was not enumerated.

The kept listings have median `useCount` 0 (225 of 250 are zero; maximum 4,759). The list-order slice has minimum 2,410, median 6,606, maximum 419,019, and no zeros. One qualified name is in both snapshots. The Newcombe intervals below treat the two samples as independent; that one shared listing is a small dependence and is not removed.

No server in the uniform snapshot lists more than 400 tools (maximum 177), so the analyzer's 400-tool prefix does not bind here. It still binds for the two list-order servers noted above.

### Side-by-side prevalence

Server-level. A hit is at least one tool on that server. Uniform n = 250. List order n = 150. Wilson intervals use `score.wilson` (z = 1.959963984540054, 6 decimal places, half-even). For the uniform column, that interval is a 95% confidence interval for the schema-publishing Smithery frame under the simple random sample above, without a finite-population correction. The correction would be small and was not applied. The list-order interval is still only a description of a proportion of this size: that slice is not a random sample.

The difference is **uniform minus list order**. The interval is Newcombe's 1998 hybrid score interval, quantized the same way. Because the list-order slice is not a random sample, a Newcombe interval that excludes 0 is not a confidence interval for a difference of two population parameters. It is the interval the procedure yields for these two observed proportions.

| Predicate | Uniform | 95% Wilson | List order | 95% Wilson | Difference | 95% Newcombe |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| R cold path | 8/250 (0.032000) | 0.016302–0.061862 | 10/150 (0.066667) | 0.036612–0.118362 | −0.034667 | −0.088693–0.007701 |
| Toxic 2-hop | 121/250 (0.484000) | 0.422764–0.545720 | 79/150 (0.526667) | 0.447101–0.604901 | −0.042667 | −0.142017–0.058031 |
| Toxic 3-hop | 46/250 (0.184000) | 0.140876–0.236689 | 74/150 (0.493333) | 0.414497–0.572503 | −0.309333 | −0.399486–−0.214511 |
| `MCP_FIRST_SEEN_OVERPRIVILEGED` | 31/250 (0.124000) | 0.088748–0.170632 | 17/150 (0.113333) | 0.071974–0.174003 | 0.010667 | −0.059501–0.072998 |
| `MCP_SCHEMA_PURPOSE_MISMATCH` | 0/250 (0.000000) | 0.000000–0.015133 | 3/150 (0.020000) | 0.006825–0.057147 | −0.020000 | −0.057147–0.000065 |
| `MCP_TOOL_NAMESPACE_FLOOD` | 11/250 (0.044000) | 0.024744–0.077058 | 35/150 (0.233333) | 0.172826–0.307158 | −0.189333 | −0.265628–−0.120384 |
| `MCP_DESCRIPTION_POISONING` | 1/250 (0.004000) | 0.000706–0.022306 | 1/150 (0.006667) | 0.001178–0.036793 | −0.002667 | −0.032973–0.016444 |
| `MCP_TOOL_SHADOWING` | 67/250 (0.268000) | 0.216911–0.326111 | 4/150 (0.026667) | 0.010418–0.066554 | 0.241333 | 0.176518–0.301673 |

**Toxic 2-hop does not show the popularity effect the v1 write-up was worried about.** The point estimate is 4.3 percentage points lower in the uniform sample, and the Newcombe interval includes 0 (about −14 to +6 percentage points). Equal-weighted Smithery listings that publish a schema are not, on this evidence, a milder population for the 2-hop flag than the heavily used prefix.

**Toxic 3-hop does.** 0.184 versus 0.493, difference −0.309, Newcombe interval about −0.40 to −0.21, excluding 0. A 3-hop path needs two distinct reads. Mean tools classed internal or sensitive read: **15.16** in the list-order slice and **3.40** in the uniform sample. Servers with at least two such reads: **118/150** versus **98/250**. Medians of the tool counts are similar (11 and 10). The list-order mean is 45.71 because a few catalogs are very large (one listing has 2,530 tools, scored on the first 400). The uniform mean is 17.15 and the maximum is 177. The 3-hop gap tracks that right tail, not a different predicate.

Dropping tools on the default branch of `tool_class` and applying `toxic_path_exists` leaves **112/250** and **40/250** in the uniform sample, against **75/150** and **70/150** in the list-order slice. The 2-hop difference is then −0.052 (Newcombe −0.151 to 0.048, includes 0). The 3-hop difference is −0.307 (Newcombe −0.396 to −0.214, excludes 0). The fail-closed default accounts for 9 of the 121 uniform 2-hop listings and, as in v1, 4 of the 79 list-order listings. It does not account for most of either rate.

Other contrasts whose Newcombe interval excludes 0: namespace flood is lower in the uniform sample (shorter catalogs); core-name shadowing is higher; a listing is more often classed as having a `write` tool and less often as having an `external_read` or a `send` tool. Overprivileged, purpose mismatch, description poisoning, and the R cold path have intervals that include 0. Poison markers, one listing each, were an exfil-directive pattern in the list-order slice and an HTML comment in the uniform sample. Both are the guard's syntactic hits. Neither was confirmed at runtime.

Class labels, same denominators:

| Class | Uniform | 95% Wilson | List order | 95% Wilson | Difference | 95% Newcombe |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `external_read` | 137/250 (0.548000) | 0.486045–0.608503 | 99/150 (0.660000) | 0.581043–0.730967 | −0.112000 | −0.206206–−0.012527 |
| `internal_read` | 203/250 (0.812000) | 0.758983–0.855574 | 129/150 (0.860000) | 0.795448–0.906574 | −0.048000 | −0.118569–0.029882 |
| `sensitive_read` | 4/250 (0.016000) | 0.006239–0.040410 | 6/150 (0.040000) | 0.018459–0.084513 | −0.024000 | −0.069571–0.008556 |
| `write` | 228/250 (0.912000) | 0.870362–0.941169 | 114/150 (0.760000) | 0.685709–0.821307 | 0.152000 | 0.077890–0.231812 |
| `send` | 21/250 (0.084000) | 0.055596–0.124995 | 27/150 (0.180000) | 0.126758–0.249223 | −0.096000 | −0.170824–−0.028804 |
| `credential_use` | 7/250 (0.028000) | 0.013628–0.056658 | 15/150 (0.100000) | 0.061541–0.158435 | −0.072000 | −0.132176–−0.024038 |

The higher uniform `write` rate is the fail-closed default on short, opaque catalogs: 2,445 of 4,287 uniform tools (0.570) took that branch, against 3,396 of 6,856 (0.495) in the list-order slice. A short listing with one unrecognized name is classed as having a write. That moves the server-level rate more than it moves the 2-hop rate.

### One copied catalog, and one copied tool name

**66 of the 250** uniform listings contain the same trio of tool names (`web-fetch`, `status-catalog`, `utc-time`) plus a shared surrounding catalog, with one or two names differing across listings. Exact tool-name sets are mostly unique (242 distinct sets; the largest exact duplicate has 4 listings). The near-copies are still 66 listings. All 66 are among the 121 toxic 2-hop listings. They are 66 rows in the index, so they belong in the equal-weighted estimate. They are not 66 independent products. Collapsing those 66 rows to a single row, as a sensitivity and not as the estimate, leaves **56/185** (0.303, Wilson 0.241067–0.372365). The published estimate remains **121/250**.

**Shadowing is that same catalog plus five `websearch` names.** Of the 67 uniform shadowing hits, 66 are a tool whose raw name is `web-fetch` and whose description is the same sentence on every one of them ("HTTP status and content type for a public URL. Body discarded."). `normalize_name` strips the hyphen, and the result equals the core built-in `webfetch`. The 67th uniform hit, and all 4 list-order hits, are the normalized name `websearch`. This is not evidence that 26.8% of schema-publishing listings impersonate a shell or a filesystem tool. It is one repeated name colliding with one built-in, plus five listings that use the built-in search name.

### Precision of the toxic 2-hop flag

The unit is the server, because the headline is a server-level flag. Path-level precision is not reported. One mislabeled tool multiplies across the Cartesian product of sources, reads, and sinks, so a path count would mostly measure that product.

Draw, fixed before the labels: among servers with `toxic_2hop == hit`, sort by `server_id`, then `random.Random(20261102).sample` takes 14 from each snapshot, with no backfill. Both snapshots had more than 14 hits (79 and 121). **28** servers were read. Case ids and the judgments are in `precision_labels.json`, keyed by SHA-256 of the qualified name and of each tool name. The file has no server name, homepage, or source URL. `precision_summary.json` is the aggregate.

The reviewer is the project author. One rater. There is no second rater and no inter-rater agreement. The reading was the tool name, description, and schema. A public source page was not required for these 28; the listings were specific enough to assign a class, or the tool was marked uncertain. No deployment was contacted.

The judgment is whether `tool_class` matches the capability the listing describes. The free-text channel rule and the rule that an `external_read` with a query or URL parameter is a sink were not relitigated. Those are the predicate. A server is **plausible** when a 2-hop still exists after every tool the reviewer is sure was mislabeled is corrected, and after every tool the reviewer cannot classify is removed. It is a **false positive** when the flag is gone even if uncertain tools keep the scorer's class. It is **can't tell** when the flag remains only while an uncertain tool is kept. "Plausible" means the three kinds of capability are present in the listing. It does not mean an exfiltration was observed.

| | Plausible | False positive | Can't tell |
| --- | ---: | ---: | ---: |
| List order | 7 | 7 | 0 |
| Uniform | 11 | 3 | 0 |
| Both | 18 | 10 | 0 |

Precision among decided labels is **18/28 (0.642857)**, Wilson **0.458303–0.792942**. Can't tell is 0, so counting can't tell as not plausible is the same fraction. The interval is wide. Seven of fourteen list-order servers and eleven of fourteen uniform servers were labeled plausible. **Eight of those eleven** are the copied catalog above, so the uniform precision is not eleven independent products. Counting that catalog once, which is a sensitivity and not the draw, would leave a much smaller uniform set (four plausible and three false positives). The precommitted estimate is the 28-server draw.

False positives, grouped by the misclassification that removes the last hop of its kind:

- **8/10.** The only external-read tool was a search or docs lookup over the server's own index (its catalog, CRM, transit stops, filings database, or API docs). The name rule, or in one case the egress table (`search_docs`), classed that as `external_read`. Relabeling it as an internal read left no untrusted source. One of the eight is the egress-table case; the primary-cause field records it as `table_mismatch`.
- **2/10.** The only internal-read tools were lookups of public external APIs, or a spell-check call. The name rule classed them `internal_read` because `lookup`, `query`, or `read` is a prefix of a token (`readable` matches `read`). Relabeling them as external reads left no internal read.

The reproducible primary-cause field is the modal disagreement, ties broken by a fixed cause order. It counts `name_rule_not_a_source` 5, `default_branch_sink` 2, `name_rule_not_a_read` 2, `table_mismatch` 1. On two of the eight source errors, a pure function classed as `write` was also disagreed, and the mode or the tie-break attributes the server to `default_branch_sink` even though clearing the search label is what removes the source. The grouping above is the reviewer's account of which hop failed. The primary-cause field is the mechanical summary. Both are in the summary file's inputs; the grouping is not a second hidden code path.

Tool-level disagreement counts are dominated by one list-order aggregator: **230** of **240** `name_rule_not_a_read` disagreements are `get_*` tools on that one server that call public APIs. The server stays plausible because other tools read and write the caller's spreadsheet and CRM. A tool-level rate would describe that one catalog.

Two name-rule behaviors showed up often enough to name. The matcher treats a keyword as present when it is a prefix of a token, so `catalog` matches `cat`, `settings` matches `set`, and `readable` matches `read`. Separately, `search` is an external-read word even when the search never leaves the server's own records. Neither behavior was changed. The precision check is a reading of the flags the current functions emit.

### v2 caveats

- Static listings. A description can be wrong, and Smithery's copy can differ from the server a client would reach.
- The uniform Wilson interval refers to schema-publishing Smithery listings on this date, equal-weighted, under the seeded shuffle. It does not refer to all MCP servers, to listings without a schema, or to a use-weighted population.
- The list-order slice is not a random sample. Newcombe intervals are a description of the contrast, not a test that the popularity ranking caused the gap.
- 66 near-copy listings move the uniform 2-hop rate. The estimate keeps them, because they are listed. The collapsed figure is a sensitivity.
- Shadowing at 67/250 is one repeated `web-fetch` name plus five `websearch` names.
- Precision is one rater, the author of the predicate, on 28 servers, with a wide Wilson interval and a copied catalog inside the uniform half. No inter-rater agreement.
- A plausible label is a class assignment the reviewer accepted. It is not a confirmed vulnerability.
- The 400-tool prefix still applies to the list-order server that exceeds it. The reviewer judged that prefix, not tools past it.
- Purpose mismatch remains conditional on not already being overprivileged. Declared scopes were not scored. Thirteen of the fourteen validators still need a call, a session, or a filesystem.

## v3. Opt-in own-data lookup rule (PR #42)

The v2 precision check found that **8 of the 10** false positives had, as their only untrusted source, a search over the server's own index. `score.own_data_lookup` is a deterministic rule that reclassifies such a tool from `external_read` to `internal_read`. It reads only the published listing, and it fires only when all of these hold:

1. `tool_class` reached `external_read` through the name rule or the egress table, not a declared label.
2. `search` is the only external-read token in the name.
3. No input property is URL- or host-shaped.
4. The description names no open or third-party content (web, URLs, links, posts, news, reviews, comments, articles, papers, feeds, media).
5. Either the description names a bounded own record set (catalog, database, documentation, directory, CRM, accounts, contacts, members, inventory, index, stations, stops, "our", internal), or the tool is an ID resolver: it mentions IDs, identifiers, slugs or keys and names a sibling tool in the same listing.

`score_server` does not apply the rule, so every v1 and v2 figure above is unchanged. The refined flag is `toxic_2hop_own_data_refined`, measured by `own_data_check.py` into `own_data_rule_check.json` (case ids only, no server names).

| On the 28 hand-checked servers | Result |
|---|---|
| False positives eliminated | **5 / 10** (p02, p08, p09, p10, p12) |
| Plausible hits preserved | **18 / 18** |
| Precision among servers still flagged | 18/23 (0.782609), Wilson 0.580965–0.903360 |
| Relabelled tools vs the PR #40 reviewer | 11 the reviewer had corrected to `internal_read`; 3 the reviewer had agreed were `external_read` (on two servers that stay flagged) |

Not fixed: the 2 false positives on the internal-read side (`readable` matching `read`, public-API lookups), which this rule does not touch by design. Also not fixed: 3 own-data searches whose one-liners name no scope marker, or that mention a feed or URL. An earlier draft that also accepted the word "records" cleared two plausible hits, so "records" was removed.

Corpus-wide `toxic_2hop`, before and after the rule: list-order **79 → 65** of 150, uniform **121 → 118** of 250.

**Caveats.** This check is in-sample: the rule was written after reading these same 28 cases, so 5/10 and 18/18 are not out-of-sample estimates. The labels come from one rater (the project author). A remaining flag is still a static reading of a published listing, not a confirmed vulnerability.

## Reproduction

From the repository root, Python 3.12, standard library plus the gateway tree (no extra packages for the scorer; pytest is only for the tests):

```bash
# Rescore the committed snapshots.
PYTHONPATH=. python3 benchmarks/wild_mcp_corpus/score.py \
  benchmarks/wild_mcp_corpus/servers.jsonl \
  --out benchmarks/wild_mcp_corpus/results.json

PYTHONPATH=. python3 benchmarks/wild_mcp_corpus/score.py \
  benchmarks/wild_mcp_corpus/random_servers.jsonl \
  --out benchmarks/wild_mcp_corpus/random_results.json

PYTHONPATH=. python3 benchmarks/wild_mcp_corpus/compare.py
PYTHONPATH=. python3 benchmarks/wild_mcp_corpus/precision.py

PYTHONPATH=. python3 -m pytest benchmarks/wild_mcp_corpus/test_score.py \
  benchmarks/wild_mcp_corpus/test_sample.py \
  benchmarks/wild_mcp_corpus/test_own_data_rule.py -q
python3 benchmarks/wild_mcp_corpus/own_data_check.py   # rewrites own_data_rule_check.json
```

`collect.py` rebuilds a new convenience sample from the live registry, Smithery, the pinned reference commit, and registry-linked config files. It does not call tools. `sample_random.py` rebuilds the uniform frame and the size-250 draw from the live index. Neither script connects to a deployment. Expect different Smithery rows after 2026-11-01. The shuffle is CPython 3.12 `random.Random.shuffle`. The official-registry compact JSONL is produced by `collect.py` and then omitted from this commit; the census file explains that.

Gateway and agent-watch suites were run again on this tree after the uniform sample landed (Python 3.12, no PHP, so the six PHP parity tests skip):

- `agent-gateway`: **1172 passed, 6 skipped**
- `agent-watch`: **513 passed, 1 skipped**. The skip is the contract file that lives outside the repo. No agent-watch test failed. The archived phase-1 crawler trace is in this tree, so that test ran rather than skipping.
- Corpus: **28 passed** (`test_score.py` and `test_sample.py`), including the rescore of both snapshots and the recomputation of the precision labels.
