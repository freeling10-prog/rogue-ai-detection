# Changelog

Release notes for the AgentGate lab stack in this repository. This file
describes the v1.0.0 snapshot. It is not a git tag and it is not a GitHub
Release.

## [Unreleased] - v12.6 fork/join conservation ledger (31 October 2026)

- `fork_join_vector_validator.py`: Predicate V. A root and at most 8
  lifetime branches share one immutable ledger of wallets (denial units,
  outbound bytes, 16 token places in 1/256 units) with vector clocks. Forks
  move a grant, joins return it and merge clocks and taint, firings conserve
  the weighted token count, sends are capped at 512 bytes and need cleanup
  state settled across the whole ledger, and every operation is fenced on
  the branch's own clock component. `Owner` applies fenced batches all or
  nothing under one lock; `Root.conserved()` checks the ledger laws.
- `pep.py`: `PolicyEngine.attach_fork_join()`, `fork_branch()` and
  `join_branch()`; spawning from a ledger session auto-forks an empty
  branch. The call's ledger operations are planned after the label
  transducer check and committed, fenced on the clock, before the Petri-net
  fire. Every gateway denial on a ledger session spends a shared denial
  unit, and branch taint is mirrored into sessions. Rule code
  `FORK_JOIN_LEDGER_DENIED` (-32074, approximate AML.T0086) in SARIF
  (CWE-770, CWE-362, ASI07, LLM10:2025) and in the audit-report counts.
- Tests: 10 new cases in `tests/test_validators.py` (including
  `LedgerMachine`) and `tests/test_v12_6_fork_join_wiring.py` (9).
  Gateway tests 1008 -> **1027**; Hypothesis state machines 16 -> **17**.
- `benchmarks/benchmark.py`: full-width ledger batch and an eight-check
  combined case; `benchmark_results.json` regenerated.

## [Unreleased] - v12.5 argument canonicalization and command confinement (31 October 2026)

- `canonical_argument_confinement.py`: Predicate S. `Policy.canonicalize`
  maps a flat argument object onto one byte string under a pinned field
  policy (up to 16 number, set, text and bool fields). Keys are sorted, numbers
  quantized with ROUND_HALF_EVEN at a fixed scale (-0 -> 0), sets sorted by
  encoded bytes, and defaults omitted. C_P(C_P(x)) == C_P(x). Wire bytes
  (2048), raw-byte nesting depth (2), duplicate keys, unknown fields,
  non-finite and oversized numbers, and duplicate set elements are checked
  before or during parsing. `confine(Command)` compiles cp, mv, tee, ln,
  chmod and sed to a fixed argv with `--` before every positional and denies
  operands that start with `-`.
- `pep.py`: `PolicyEngine.pin_argument_policy()` and `pin_command_tool()`.
  S runs first in the reference middleware. The allow result carries the
  canonical bytes or the compiled argv, and a typed command's effects go
  through the workspace model and the label transducer. Rule code
  `ARGUMENT_CONFINEMENT_DENIED` (-32073, approximate AML.T0053) in SARIF
  (CWE-88, CWE-514, ASI02, LLM05:2025) and in the audit-report counts.
- Tests: 82 new cases in `tests/test_validators.py` (including
  `CanonicalArgumentMachine`) and `tests/test_v12_5_argument_confinement_wiring.py`
  (14). Gateway tests 912 -> **1008**; Hypothesis state machines 15 -> **16**.
- `benchmarks/benchmark.py`: full-budget canonicalization, 16-operand
  confinement, and a seven-check combined case; `benchmark_results.json`
  regenerated.
- README: the reference validator intro now says eight rule codes,
  -32066 through -32073.

## [Unreleased] - v12.4 file label transducer (31 October 2026)

- `symbolic_fs_transducer.py`: Predicate T. A (confidentiality, integrity)
  product lattice (PUBLIC < SENSITIVE < PROTECTED, TRUSTED < UNTRUSTED) per
  file object, in an immutable copy-on-write overlay over the workspace
  `Snapshot`. Protected paths and inodes (including symlink and hard-link
  aliases) start PROTECTED. The workspace check runs first. Labels flow from
  read sources to write targets joined with the session integrity, only ever
  rise, and are fenced on an overlay generation. Outbound calls cannot read
  non-PUBLIC files; execution sinks and chmod cannot use UNTRUSTED ones.
  `FsTransducer.rebase()` adopts a newer broker snapshot and keeps labels.
- `pep.py`: `PolicyEngine.attach_fs_transducer()`. Checked right after the
  shell-effect check and committed after every other reference validator,
  before the Petri-net fire. Rule code `FS_LABEL_FLOW_DENIED` (-32072,
  approximate AML.T0086) in SARIF (CWE-201, CWE-829, ASI02, LLM02:2025) and
  in the audit-report counts.
- Tests: 11 new cases in `tests/test_validators.py` (including
  `TransducerMachine`) and `tests/test_v12_4_fs_label_wiring.py` (7).
  Gateway tests 894 -> **912**; Hypothesis state machines 14 -> **15**.
- `benchmarks/benchmark.py`: transducer case (1 read joined into 63 writes)
  and a six-check combined case; `benchmark_results.json` regenerated.

## [Unreleased] - v12.3 Petri-net transition gate (31 October 2026)

- `linear_obligation_validator.py`: a bounded 16-place Petri net with 4-bit
  places packed into one 64-bit marking. The manifest must pass a weighted
  non-minting conservation check when it is compiled (bootstrap transitions
  are one-shot). The per-call check is constant time and covers sufficient
  tokens, place capacity and resource cleanup state settled before outbound
  steps. Bare names owned by two providers never resolve.
- `common.py`: frozen `DispatchEnvelope` with defaulted fields (including
  `petri_marking_hex`) and a domain-separated `commitment()`. Existing
  exports unchanged.
- `pep.py`: `PolicyEngine.attach_obligation_net()`. The transition is checked
  before the outbound-identifier matcher and fired, fenced on the marking
  sequence, only after every other reference validator passes. Rule code
  `OBLIGATION_PROTOCOL_DENIED` (-32071) in SARIF (CWE-691, CWE-772) and in
  the audit-report counts.
- Tests: 14 new cases in `tests/test_validators.py` (including
  `PetriObligationMachine`) and `tests/test_v12_3_obligation_wiring.py` (6).
  Gateway tests 874 -> **894**; Hypothesis state machines 13 -> **14**.
- `benchmarks/benchmark.py`: obligation transition case and a five-check
  combined case. The 31 October run is from a slower container than the
  29 October one; both tables are in `docs/DESIGN.md`.

## [Unreleased] - v12.2 reference middleware validators (29 October 2026)

- Four deterministic, standard-library validators land in `agent_gateway` as
  supplied (byte-identical to the reference package apart from relative
  imports): `common.py` (CJSON-DECIMAL-v1 canonicalizer, deliberately not
  RFC 8785), `registry_pin_validator.py`, `workspace_path_validator.py`,
  `lattice_flow_validator.py`, `shingle_similarity_validator.py`.
- `registry_pin_validator.py`: per-provider descriptor pins over
  inputSchema / outputSchema / description / title / annotations, one
  `Registry` per server sealed after its first listing. Sticky revocation
  (a changed, invalid or removed descriptor stays `REVOKED` for the session),
  local-Pointer-only schema closure, a display-metadata linter, and abnormal
  alias tracking that never resolves by arrival order. Rule codes
  `REGISTRY_PIN_DRIFT` (-32066), `REGISTRY_ALIAS_AMBIGUOUS` (-32067).
  These are the next free JSON-RPC codes: v12.1 already uses -32055 through
  -32059 and -32062 through -32065, and -32060 / -32061 stay the sampling errors.
- `workspace_path_validator.py`: bounded literal-shell analyzer and an
  immutable filesystem model (symlink splicing before `..`, protected-name
  and inode checks, work credits, `move`/`symlink` batches refused).
  `PolicyEngine.attach_workspace_snapshot()` turns it on per session; an
  unmodeled command, a protected path, a shared inode or a stale generation
  is `WORKSPACE_EFFECT_DENIED` (-32068). Both Claude Code hooks run the
  lexical half of the same analyzer, which covers reserved names the v12
  workspace guard does not model (`.clinerules`, `.idea/`, `.windsurf/`).
- `lattice_flow_validator.py`: two-level contamination lattice with
  dispatch-time taint, a precommitted manifest of single-use steps, DAG
  admission, path patterns and an idempotent request ledger.
  `PolicyEngine.pin_workflow_manifest()` makes every call match an unused
  step, else `FLOW_MANIFEST_DENIED` (-32069).
- `shingle_similarity_validator.py`: rolling shingles plus bounded
  bit-parallel LCS over two pinned normalization views, keyed audit
  identifiers only. `PolicyEngine.configure_similarity_matcher()` scans
  outbound string arguments, else `SIMILARITY_LEAK_DENIED` (-32070).
- `sarif_export.py` / `audit_report.py`: the five codes as error-level
  rules with ATLAS, CWE, OWASP Agentic and OWASP LLM tags, counted in the
  decision-log summary, beside the nine v12.1 rules.
- `tests/test_validators.py` (64, including four Hypothesis state machines)
  imported with package-qualified imports and unchanged oracles;
  `tests/test_v12_2_validator_wiring.py` (14, including the JSON-RPC code
  assignment that follows v12.1) covers the decision path, both hooks, the
  SARIF rule set and the inert-until-configured property.
  Gateway tests 796 -> **874** (33 files); modules behind `pep.py`
  36 -> **41**; Hypothesis state machines 9 -> **13**; workspace **1396**;
  CI floor 780 -> **860**. Every validator is inert until a trusted adapter
  attaches its state, so a session without pins, a snapshot, a manifest, or
  a matcher keeps the v12.1 decision path.
- `benchmarks/benchmark.py` and `benchmarks/artifacts/`: the reference
  microbenchmark and its measured output (5000 samples per case, combined
  p99 **4.833856 ms** on Python 3.12.14, retained matcher allocations
  1,426,200 bytes), plus the reference `validation_results.json` and the
  package manifest under `docs/reference-package/`.

## [Unreleased] - v12.1 interpreter, first-listing, and collusion guards (29 October 2026)

- `interpreter_exec_guard.py`: inline payloads of `python -c` (parsed with
  `ast`; `os.path.join`, `Path(...) / ...`, f-strings, concatenation, and
  simple assignments are constant-folded), `node -e`, `ruby -e`,
  `perl -e`, `php -r`, `bash -c` / `sh -c`, heredocs (`python3 - <<EOF`,
  `cat <<EOF | node`), and decode pipelines (`base64 -d`, `xxd -r`,
  `openssl ... -d` into a shell or interpreter, `eval "$(... | base64 -d)"`,
  `bash <(...)`). `INTERPRETER_PROTECTED_WRITE` (paths through
  `workspace_config_guard.classify_path` plus credential and system
  locations), `INTERPRETER_OBFUSCATED_PIPE`,
  `INTERPRETER_DANGEROUS_PRIMITIVE`. Closes the v12 interpreter-write gap.
- `mcp_capability_manifest_guard.py`: zero-trust check of every listing,
  the first included, against a capability profile
  (`PURE_TRANSFORM` ... `PRIVILEGED`). `MCP_FIRST_SEEN_OVERPRIVILEGED`
  (credential parameters below `EXTERNAL_NETWORK`, execution parameters
  below `PRIVILEGED`, neither for unverified servers; pagination tokens
  and token limits are not credentials), `MCP_SCHEMA_PURPOSE_MISMATCH`,
  `MCP_TOOL_NAMESPACE_FLOOD` (more than 32 tools in one listing). Closes
  the v12 first-listing gap.
- `cross_agent_collusion_guard.py`: provenance graph of agents and
  `file:` / `mem:` / `msg:` artifacts with monotone taint origins and
  toxic-chain stages. `COLLUSION_CROSS_AGENT_LAUNDERING`,
  `COLLUSION_SPLIT_TOXIC_CHAIN`, `COLLUSION_CYCLIC_AMPLIFICATION`.
- `pep.py`: interpreter guard before the argument firewall (-32055 /
  -32056 / -32057); capability profiles on every proxied listing (-32058 /
  -32059 / -32062; `PepConfig.mcp_server_profiles`,
  `max_tools_per_server`; core servers are `PRIVILEGED`); collusion graph
  on notes, the internal bus, files, delegation, and spawn, with sinks
  checked after the other gates (-32063 / -32064 / -32065;
  `max_handoff_depth`). -32060 / -32061 stay the sampling errors. A
  secret read by one agent and passed to a peer through an untainted note
  is now denied at the peer's send.
- `claude_code_hook.py`: the interpreter guard on `Bash`, honouring
  `--allow-workspace-writes` for config / hook paths (credential paths
  never).
- `sarif_export.py` / `audit_report.py`: the nine codes as error-level
  rules with CWE, OWASP Agentic, and OWASP LLM tags, counted in the
  decision-log summary.
- `tests/test_v12_1_guards.py` (144, including the ninth Hypothesis state
  machine for cross-agent provenance). Gateway tests 652 -> **796** (31
  files); modules behind `pep.py` 33 -> **36**; Hypothesis state machines
  8 -> **9**; workspace **1318**; CI floor 640 -> 780. 750 benign
  decisions, 0 denials; A / B / C 57/57; Group D 124/124.
  `sprint_submission/` and `site/sprint/` unchanged.

## [Unreleased] - v12 evasion guards (29 October 2026)

- `mcp_rugpull_guard.py`: registry of SHA-256 fingerprints per
  `(server, tool)` over the normalized description and canonical input
  schema. `MCP_DEFINITION_DRIFT` (a pinned definition changed without an
  HMAC re-approval token; the tool stays quarantined), `MCP_TOOL_SHADOWING`
  (name owned by another active server or a core built-in, compared
  case-folded without separators), `MCP_DESCRIPTION_POISONING` (HTML
  comments, `<IMPORTANT>` / `<system>`-style tags, zero-width / bidi / tag
  characters, credential-file and override directives, `sidenote`-style
  parameters, in descriptions and parameter schemas).
- `workspace_config_guard.py`: structured file tools and shell commands
  (`>`, `>>`, `tee`, `cp`, `mv`, `ln -s`, `chmod`, `sed -i`, `rm`, `touch`,
  `dd of=`, `git config`) against normalized, case-insensitive protected
  paths. `WORKSPACE_CONFIG_WRITE`, `WORKSPACE_HOOK_TAMPER`,
  `WORKSPACE_SYMLINK_ESCAPE`; `scan_workspace_instruction_file()` gives
  `WORKSPACE_HIDDEN_DIRECTIVE` for HTML comments and invisible characters
  (a leading BOM and emoji joiners are allowed).
- `control_flow_integrity_guard.py`: per-session `TRUSTED` / `UNTRUSTED`
  label with taint sources; an optionally HMAC-signed
  `UserCapabilityManifest` pinned before any untrusted read grants sink
  classes and target patterns. `CFI_TAINTED_PRIVILEGED_SINK`,
  `CFI_UNENDORSED_TARGET`.
- `stego_exfil_guard.py`: salted k-gram shingles (k=6) of secrets and their
  hex / base32 / URL-safe base64 forms; side-effect identifiers from git,
  package managers, DNS tools, and URLs. `STEGO_SECRET_SHINGLE_LEAK`,
  `STEGO_SUBSEQUENCE_EXFIL` (bit-parallel LCS, coverage and density
  thresholds).
- `pep.py`: workspace guard on every call (-32045 / -32046 / -32047,
  `PepConfig.workspace_allow` to opt in), CFI for sessions with a pinned
  manifest (-32048 / -32049, `pin_capability_manifest()`; the manifest only
  narrows), stego on outbound identifier arguments after a sensitive read
  (-32052 / -32053), poisoned tool definitions dropped from proxied
  listings and calls denied (-32054). MCP drift and shadowing on the proxy
  path stay with `schema_integrity_guard.py`.
- `claude_code_hook.py`: blocks writes and shell redirections to agent
  instruction / config files and execution hooks unless
  `--allow-workspace-writes config,hook` or
  `AGENTGATE_ALLOW_WORKSPACE_WRITES` opts in; blocks a `Read` of an
  instruction file whose content carries hidden directives.
- `sarif_export.py` / `audit_report.py`: the eleven codes as error-level
  rules with CWE, OWASP Agentic Top 10, and OWASP LLM Top 10 (2025) tags,
  counted in the decision-log summary.
- `tests/test_v12_guards.py` (146, including a control-flow-integrity
  Hypothesis state machine and property tests). Gateway tests 506 ->
  **652** (30 files); modules behind `pep.py` 29 -> **33**; Hypothesis
  state machines 7 -> **8**; workspace **1174**; CI floor 500 -> 640.
  750 benign decisions, 0 denials; A / B / C 57/57; Group D 124/124.
  `sprint_submission/` and `site/sprint/` unchanged.

## [Unreleased] - PHP Defense Guard (28 October 2026)

- `php_defense_guard.php`: fixed a parse error (an unescaped quote in the
  tautology pattern) that stopped the file from loading. Patterns now run on
  each decoded key and value of `$_GET` / `$_POST` / `$_COOKIE` (and once
  more after `rawurldecode`) instead of the `json_encode()` output, where
  JSON escaping (`\/`, `\"`) kept the path-traversal and deserialization
  rules from ever matching. Rule codes are `PHP_SQLI_UNION`,
  `PHP_SQLI_TAUTOLOGY`, `PHP_PATH_TRAVERSAL`, `PHP_DESERIALIZE_DENIED`,
  `PHP_RCE_EVAL`; the violation log is now SHA-256 hash-chained in the
  `audit_chain.py` format and stores a hash of the value, not the payload.
- `php_defense_guard.py`: Python mirror of the same rules for request
  dictionaries, with a hash-chained violation log.
- Optional `excludedKeys` / `excluded_keys` (parameters left uninspected,
  for example a search box; a name covers everything nested under it) and
  `logOnly` / `log_only` (record the finding with verdict `LOG_ONLY` and
  return it instead of answering 403). Both default off, and existing
  constructor calls and `inspect()` calls are unchanged;
  `inspectAndEnforce()` now returns the finding in log-only mode.
- `sarif_export.py`: the five `PHP_*` codes are SARIF rules (level
  `error`) with CWE (22, 502, 94/78, 89) and OWASP Top 10 2021 tags;
  `PHP_OBJECT_INJECTION` and `PHP_CODE_EXEC` are accepted as aliases of
  `PHP_DESERIALIZE_DENIED` and `PHP_RCE_EVAL`.
  `php_defense_guard.sarif_report()` turns a PHP- or Python-written log
  into SARIF input.
- `tests/test_php_defense.py` (49): every rule, encoded / nested / key
  variants, benign input, excluded keys and log-only mode, log chain and
  tamper detection, SARIF export, and Python / PHP parity on shared
  fixtures plus a 403 end-to-end run of `inspectAndEnforce()`.
- CI: PHP 8.3 via `shivammathur/setup-php@v2`, `php -l` on the guard, and
  the parity tests fail (rather than skip) when `php` is missing under
  `CI=true` / `GITHUB_ACTIONS=true`. Gateway test floor 450 -> 500.
- Gateway tests 457 -> **506** (29 files); modules behind `pep.py` 28 ->
  **29**; workspace **1028**. `sprint_submission/` and `site/sprint/`
  unchanged.

## [Unreleased] - v11.1 developer and delivery additions (28 October 2026)

- `claude_code_hook.py`: Claude Code `PreToolUse` policy adapter, standard
  library only. `--install` adds one command hook to
  `~/.claude/settings.json` (or `--settings`), idempotently; `--self-test`
  runs four validation checks with CPU time per decision. Rules:
  `CREDENTIAL_PATH_DENIED` (`.env` except `.env.example` / `.sample` /
  `.template`, `.ssh/`, `.aws/`, `.npmrc`, `.pypirc`), `SHELL_POLICY_DENIED`
  (recursive root / home deletion, force push to `main` / `master`, download
  piped to a shell), `METADATA_URI_DENIED` (`169.254.169.254` in several
  spellings, `metadata.google.internal`, `file://`). Malformed input is
  denied (`HOOK_INPUT_INVALID`). Every decision is appended to a SHA-256
  hash-chained `~/.claude/agentgate_audit.jsonl` (`audit_chain.link`,
  `flock`-serialized); a deny writes the Claude Code block response.
- `mcp_blueprint.py`: `HardenedMcpBlueprint`, a reference harness for client
  MCP builds behind `PolicyEngine`: read-only parameterized SQL templates
  validated at registration, a 100-row cap, lookups scanned as untrusted
  output, configurable field redaction, unapproved mutation verbs denied,
  one-time HMAC confirmation tokens bound to session, tool, and arguments
  for writes, a chained audit log of every call, and an MCP
  `tools/list` / `tools/call` surface.
- Tests: `test_claude_code_hook.py` (48, mostly parametrized policy cases)
  and `test_mcp_blueprint.py` (20). Gateway tests 389 -> **457** (28
  files); CI floor 385 -> 450; modules behind `pep.py` 26 -> **28**;
  workspace **979**. Group D (124), Groups A / B / C (57/57), and the 7
  Hypothesis state machines are unchanged.
- Site, README, `marketing/audit-offer.md`: the $750 48-Hour Hardened MCP
  Server Build above Tier 1, and the one-command hook install.
  `marketing/mobile-quick-copy.md`: phone-ready outreach blocks.
  `sprint_submission/` and `site/sprint/` unchanged.

## [Unreleased] - v11 provenance and accumulator wiring (28 October 2026)

- `temporal_accumulator_guard.py`: U+200D (zero-width joiner) removed from
  `ZERO_WIDTH_CHARS`, so compound emoji no longer count as watermarks.
  Protected tokens are held only as per-instance salted SHA-256 digests of
  the token, its Base64 and hex spellings, and its 8-character n-grams (no
  plaintext); an n-gram match needs **2** distinct digests. The window is
  persisted only for `STREAM_CLEAN` calls, so a denied call does not poison
  later benign calls. Tokens can be scoped to one session.
- `pep.py`: `memory_provenance_guard` records scratchpad notes and
  resource-addressed writes in an HMAC-signed lineage ledger (key derived
  from `AGENT_GATEWAY_HMAC_KEY`); reads of a note, a `uri` / `path`
  resource, or an MCP `resources/read` inherit the writer's taint, and a
  record that fails its HMAC is denied (`provenance_tamper_denied`, -32042).
  `export_provenance_ledger()` / `load_provenance_ledger()` persist it.
  `temporal_accumulator_guard` runs on every released outbound call
  (`sharded_exfil_denied`, -32043); sensitive reads and canaries register
  their values with it, scoped like the de-obfuscation fingerprints.
- `mcp_proxy.py`: accumulator windows keyed `mcp:<server>`; resources/read
  goes through the lineage check before it reaches the server.
- `sarif_export.py` / `audit_report.py`: `provenance_tamper_denied`
  (AML.T0080.000, ASI06) and `sharded_exfil_denied` (AML.T0086, ASI02).
- Tests: 3 provenance unit tests (taint inheritance with the origin
  `writer_session_id` kept, `TypeError` on bool inputs, tamper deny and
  `export_ledger` / `load_ledger`), 5 accumulator tests, and
  `test_v11_provenance_accumulator_wiring.py` (12), added to Group D.
- Gateway tests 369 -> **389** (Group D 104 -> **124**, six files); CI floor
  345 -> 385. Hypothesis state machines stay at **7** and modules behind
  `pep.py` at **26**. Workspace **911** (agent-watch 512, analyzer 10).
  Groups A / B / C unchanged (57/57); 750 benign decisions, 0 denials.
- Site: trace 07 (cross-session lineage, a tampered record, sharded
  watermarks) and a re-recorded trace 08, both in-process against
  `PolicyEngine` (`examples/record_site_traces.py 7 8`); traces 01-06 and
  `sprint_submission/` / `site/sprint/` unchanged.

## [Unreleased] - v11 post-sprint guards (28 October 2026)

- `schema_integrity_guard.py`: RFC 8785-style canonical JSON, SHA-256 pin per
  `(server_id, tool_name)` across sessions. `SCHEMA_DRIFT_DENIED` without a
  manifest entry signed with the gateway HMAC key; `TOOL_SHADOWING_DENIED`
  for a normalized name within one edit of a tool pinned on another server.
  Wired into `McpWireProxy` (drifted or colliding tools are not served;
  calls to a drifted tool get `schema_drift_denied`, -32041).
- `gui_action_guard.py`: reserved screen rectangles and viewport bounds
  (`gui_region_denied`, -32038), modifier-normalized shortcut deny-list and
  raw control characters (`gui_keychord_denied`, -32039). Wired into
  `PolicyEngine.evaluate_call` for bare action names, `computer.<action>`,
  and a `computer` tool with `action` / `coordinate` / `text`.
- `memory_provenance_guard.py`: HMAC-signed cross-session resource lineage
  ledger; the taint-origin writer is kept; strict int checks;
  `MAX_TAINT_LEVEL`; `export_ledger` / `load_ledger` verify every record.
- `temporal_accumulator_guard.py`: bounded per-(session, destination) window
  validator for registered tokens and zero-width watermark counts.
- SARIF rules with approximate ATLAS ids and OWASP Agentic ASI tags for the
  four schema / GUI codes; the decision-log summary counts them.
- `collusion_eval.POST_SPRINT_GROUPS["D"]` and `run_post_sprint_suite()`.
  Groups A / B / C (57/57) and `evaluate-collusion` output are unchanged;
  `sprint_submission/` and `site/sprint/` are untouched.
- Gateway tests 262 -> **369** (Group D: 104); Hypothesis state machines
  5 -> **7**; modules behind `pep.py` 22 -> **26**; CI floor 250 -> 345.
  Workspace: **891** passing (agent-watch 512 passed, 2 skipped; analyzer 10).
- Site: trace 08 (schema drift across sessions and a cross-server name
  collision), recorded in-process by `examples/record_site_traces.py 8`;
  post-sprint figures and v11 scope notes added beside the sprint figures.

## [Unreleased] - report-style site and per-target outreach (25 October 2026)

- `site/` rebuilt as a technical report: archival palette, hairline grid,
  self-hosted Newsreader and IBM Plex (SIL OFL 1.1, `site/fonts/`), no
  gradients, shadows, or blur. Sections: empirical summary with a latency
  scale that shows the 3.84 ms maximum, architecture schematic, trace
  inspector, reproduce, scope and non-goals, and a schedule of deliverables
  with hashed sample artifacts.
- `examples/record_site_traces.py` records the six inspector traces against
  the real `PolicyEngine`, `McpWireProxy`, `toxic_combinations.analyze`, and
  `audit_chain` (median CPU of 30 fresh runs per step); `site/app.js` embeds
  its output. The trace-03 graph now counts `web.fetch` as a URL sink, so its
  totals match `analyze()` (12 paths).
- `marketing/outreach-sequence.md`: ten per-target Touch 2 payloads, each tied
  to one carrier and the matching trace.

## [Unreleased] - docs, site, and offer sync (25 October 2026)

- README: sprint-submission callout near the top (report, slides, JSON,
  reproduction command, headline figures with the 3.84 ms max and the scope
  note). Gateway count 240 -> **262** (244 before the sprint: 240 for v10
  plus 4 HTTP resource-limit tests; then 11 `evaluate-collusion` and 7
  sprint-artifact tests). agent-watch: 514 collected, 512 passed, 2 skipped.
- Site (`site/`): metrics bar synced (262 gateway, 784 passing in all,
  57/57, p50 0.126 ms / p99 0.999 ms, 0 of 750 benign denials), a "Verify in
  30 seconds" box, deliverable-backed tier names, sample-deliverable links,
  and two v10 simulator presets (confused-deputy delegation; obfuscated
  canary exfiltration). Copies of the sprint report, slides, and JSON are in
  `site/sprint/` so the Pages links resolve; `sprint_submission/` is
  unchanged.
- Whitepaper dated 25 October 2026 with a new section 6.1 on the v10
  collusion carriers and the `evaluate-collusion` results; PDF regenerated
  from the Word file.

## [Unreleased] - collusion sprint evaluation

- `agent_gateway/collusion_eval.py` and `python -m agent_gateway
  evaluate-collusion [--report OUT_DIR] [--iterations N]`: aggregates the
  existing side-channel (A), delegation (B), and de-obfuscation / canary (C)
  defence tests by group from pytest JUnit XML, times benign `evaluate_call`
  decisions (CPU p50 / p95 / p99 against a 2 ms reference), and verifies a
  hash-chained benign decision log including edit and drop detection. Writes
  `collusion_benchmark_results.json`, `collusion_sprint_report.md`, and
  `collusion_sprint_report.pdf`, a 6-slide `collusion_sprint_slides.pdf`, and
  a 1200x630 `collusion_project_image.png` (`sprint_artifacts.py`, standard
  library only). Generated set in `sprint_submission/`.
  Same-author lab scenarios; not pooled with the 2 of 13 archive figure.

## [Unreleased] - fail-closed HMAC key

- `capability.hmac_key()` now raises if `AGENT_GATEWAY_HMAC_KEY` is unset or
  shorter than 32 bytes. The built-in lab key is used only with an explicit
  `allow_default=True`. The CLI exits with code 2 and a clear message at
  startup. The test suite sets its own key.
- `examples/replay_attenuation.py`: in-process replay against the real
  `PolicyEngine` with simulated backends (one denied call, allowed calls, a
  failed re-enable of egress, and the direct-call limit).
- `docs/tool-classification.md`: egress classes, and that unknown tools fail
  closed as writes once tainted. Quickstart examples now generate a random
  32-byte key. The replay asserts the direct-bypass limit. README notes that
  key rotation is not supported.
- HTTP resource limits (`max_body_bytes`, `max_arg_bytes`, `max_sessions`,
  `max_id_len`) with tests. `docs/integration-contract.md` and
  `examples/gated_dispatch.py` state the caller's side of the boundary. Two
  more synthetic boundary notes under `docs/examples/`.
- Offer page, README, and site pricing now show the Tool Inventory Review
  ($1,800), Fixed Note ($4,500), Note + Lab Instrumentation ($6,500), and
  the add-ons. The marketing drafts (`outreach-sequence.md`, `ciso-outreach.md`,
  `marketing/README.md`, `la-targets.md`) were aligned to the same tiers.
  `show-hn.md`, `reddit-localllama.md`, and the checklist quote no prices
  and are unchanged.
- README: "What this is not" box, boundary replay command, and a "Known
  non-goals and bypasses wanted" section.

## [Unreleased] - v10 delegation guard, argument firewall, canary watermarking, SARIF

All four are zero-compute (standard library; no model calls). ATLAS ids
are approximate.

- `agent_gateway/delegation_guard.py`: monotonic capability attenuation
  across multi-agent hand-offs. The meet of two `agw1.` capabilities
  carries deny-egress, deny-sampling, and taint sources into the
  recipient, cryptographically (appended caveats the recipient cannot
  strip). A delegated agent that was barred upstream is blocked at egress
  with `confused_deputy_delegation_blocked` (approximate AML.T0051 /
  AML.T0086). New `delegate_task` tool; `spawn_subagent` with a child key
  also attenuates.
- `agent_gateway/arg_ast_guard.py`: lexical / canonical argument firewall.
  Path traversal (encoded, backslash, NUL, UNC, sensitive system paths),
  shell-metacharacter chaining, CRLF header splitting, and mutating /
  file-exfil SQL in read-classified tools are denied with
  `arg_firewall_violation` (approximate AML.T0051 / AML.T0053).
- `agent_gateway/canary_watermark.py`: zero-width HMAC watermark bound to
  `(session, step, tool)` woven into sensitive reads, plus a credential
  tracker (AWS / GitHub / OpenAI / Anthropic / Google / Slack / JWT /
  PEM). A watermark or credential in a later outbound call is denied, the
  registered key is frozen for 15 minutes, and provenance is written to
  the hash-chained log (`canary_watermark_exfil`, approximate AML.T0086).
- `agent_gateway/sarif_export.py`: OASIS SARIF 2.1.0 exporter.
  `audit --sarif <path>` emits gateway findings, toxic paths, and analyzer
  matches for GitHub code scanning; a report-dir SARIF is covered by
  `audit_manifest.json`. The workflow uploads `findings.sarif`.
- `agent-gateway` tests: **240 passed** (161 before this change).

## v9 - toxic-flow graph, ingress scanner, SSRF and side-channel guards (PR #17)

All four are zero-compute (standard library; no model calls, no DNS).
ATLAS ids are approximate.

- `agent_gateway/toxic_combinations.py`: static reachability over a tool
  inventory. Lists every 2-hop and 3-hop `external_read -> read -> sink`
  path whose sink has a free-text channel and no hard `agw1.` boundary
  (approximate AML.T0086). `audit --tool-inventory` adds it to
  `findings.json`, the HTML (table plus inline SVG), and the PDF, under
  `audit_manifest.json`. An inventory alone is enough for a
  tool-list-only audit.
- `agent_gateway/tool_output_scanner.py`: Unicode tag smuggling,
  zero-width and BiDi override characters, delimiter / role spoofing,
  fake JSON-RPC envelopes, and cross-tool name shadowing in untrusted tool
  output. Findings taint the session and attenuate the `agw1.` token
  (approximate AML.T0051); the proxy forwards the result with invisible
  characters removed.
- `agent_gateway/egress_uri_guard.py`: canonical SSRF / cloud-metadata
  guard over URI and host arguments; `ssrf_boundary_violation`
  (approximate AML.T0053). Metadata and obfuscated internal spellings are
  denied, plain private targets are held for a bound OOB approval, and
  the literal lab loopback hosts stay allowed.
- `agent_gateway/side_channel_guard.py`: post-trifecta boolean-oracle,
  cardinality, and timing-beacon detection;
  `covert_side_channel_suspected` (approximate AML.T0086) holds the
  session and freezes the registered root key for 15 minutes.
- `agent-gateway` tests: **161 passed** (89 before this change).

## v8 - MCP wire proxy, de-obfuscation, audit chain (PR #16)

All three are zero-compute (standard library plus the existing Flask
dependency; no model calls). ATLAS ids are approximate.

- `agent_gateway/mcp_proxy.py`: MCP JSON-RPC 2.0 wire interceptor around the
  PEP. Tool-schema pinning (`sha256(name, description, inputSchema)`) on the
  first complete `tools/list`. A mid-session mutation or addition records
  `mcp_rug_pull_detected` (approximate AML.T0051), appends
  `allow_egress=false` to the `agw1.` token, and holds later `tools/call`
  requests for a bound one-time OOB approval. Server-initiated
  `sampling/createMessage` is rejected while tainted or without a root-keyed
  `grant:sampling=` caveat.
- `agent_gateway/deobfuscate.py`: salted n-gram digests of sensitive reads
  and canaries (raw, Base64, hex, URL-encoded, whitespace-stripped) matched
  against a per-session window of released outbound arguments. Split-chunk
  and encoded exfiltration is denied and the registered root key is frozen
  for 15 minutes (approximate AML.T0086). New Hypothesis `SmugglingMachine`.
- `agent_gateway/audit_chain.py`: SHA-256 hash chain (`seq`, `prev_hash`,
  `entry_hash`) on every PEP decision-log line; `audit` writes
  `audit_manifest.json`; new `python -m agent_gateway verify <audit_dir>`.
  Not a certification and not a penetration test.
- `agent-gateway` tests: **89 passed** (40 before this change).

## [1.0.0] - 2026-10-24

Prepared as release-prep on the private tree. The installable packages
`agent-gateway` and `agentwatch-analyzer` are versioned 1.0.0. No tag is
created by this change.

### AgentGate Runtime Behavioral Gateway

- Policy enforcement point in `agent-gateway/agent_gateway/pep.py` for
  registered internal agent keys. The project's reading of MITRE ATLAS
  mitigation AML.M0030: taint on untrusted ingest, then restrict the tool
  call. Default bind is `127.0.0.1`.
- `agw1.` capability attenuation is macaroon-style chained HMAC. Untrusted
  ingest appends `allow_egress=false`. A holder who does not have
  `AGENT_GATEWAY_HMAC_KEY` cannot strip that caveat. This is not a full
  macaroon library: there are no third-party caveats and no discharges.
- Stateful Hypothesis checks in `agent-gateway/tests/test_stateful_fuzz.py`
  (`hypothesis==6.170.9`).
- A held call is formatted in-process as Slack Block Kit and as a generic
  webhook document. Nothing is POSTed unless `serve` is started with
  `--webhook-deliver`.
- Freeze is a temporary 15-minute (900-second) freeze of internal keys
  listed in `agent-gateway/config/agents.json`. An unregistered key is
  refused and is not frozen.

### Standalone Offline Log Analyzer

- `agentwatch-analyzer` reads static access logs offline. It does not start
  a honeypot, bind a port, or make an outbound call. Secrets are scrubbed
  before outputs are written.
- **12** Sigma rules in `agentwatch-analyzer/rules/sigma/`: R8 through R14
  (`01_R8.yml`–`07_R14.yml`) and ATLAS AML.T0051, AML.T0053, AML.T0080,
  AML.T0086, AML.T0118 (`08`–`12`). From a normal access log, R8 and R9 are
  in scope, R10 is partial, R11–R13 are not available, and R14 is partial
  and advisory without a human beacon.
- STIX 2.1 bundles. A recorded smoke on the archived Tier-2 Playwright
  crawler log reported `validator_ok=true`. Known warnings on `x_`
  properties can still appear.

### Executive Audit CLI

- `python -m agent_gateway audit` (console script: `agent-gateway audit`)
  reads an analyzer output directory and writes an HTML risk matrix and a
  text PDF (`audit-report.html`, `audit-report.pdf`).
- The PDF writer is pure Python. WeasyPrint and wkhtmltopdf are not
  dependencies and are not required. `--no-pdf` skips the text PDF. HTML
  is always written.
- The command does not start the PEP server, does not start the honeypot,
  and does not open a socket.

### Turnkey CI/CD GitHub Action

- `.github/workflows/atlas-agent-audit.yml` runs `agent-gateway`,
  `agent-watch`, and `rogue-ai-pipeline`, then an offline
  `agentwatch-analyzer` smoke. The smoke checks the STIX bundle, runs
  `python -m agent_gateway audit`, and uploads `findings.json`,
  `replay.html`, the STIX 2.1 bundle, and the executive HTML and PDF.
- The workflow does not bind a port and does not start the honeypot.

### Packaging

- Multi-package tree. From the repository root:
  `pip install -e ./agentwatch-analyzer` and
  `pip install -e ./agent-gateway` (or the same paths without `-e`).
- `agentwatch-analyzer` is the console script for the analyzer.
  `agent-gateway` is the console script for the gateway.
  `python -m agent_gateway audit` works after the gateway package is
  installed, without `PYTHONPATH`.

### Caveats

- Default bind is `127.0.0.1`. A non-loopback gateway bind needs
  `--allow-nonlocal` and an isolated lab network. This repository does not
  ship a public honeypot deploy.
- The web honeypot is human-review only. It does not automatically block
  from unverified heuristics. Honeypot contact is a lead, not intent.
- Freeze applies only to registered lab keys, for 15 minutes.
- Tier-2 catch rate is **2 of 13** non-control archived runs: one machine,
  `qwen2.5:3b`, same author. Both catches were Playwright. Nine urllib
  sessions were not caught. The scripted human control is the fourteenth
  archive and is not in the 13. Not a benchmark. Do not pool it with the
  same-author synthetic regression tables.
- ATLAS mappings are approximate. They are not a certification.
- No outbound webhook delivery by default. A failed POST does not change
  the policy decision.
- Tool backends inside the gateway are simulated echoes. There is no Web
  Bot Auth in this tree.
- The repository is public under Apache 2.0. The paid audit is a separate
  written service and does not change the license.
