# v13 invariants (design note, not implemented)

Status: design note only. Nothing in this file is implemented, wired, or tested. It records the three invariants proposed for v13 so the work can be reviewed before any code lands. Written 15 November 2026 against the v14 tree (`agent-gateway/agent_gateway/`), after the E2 transcript enumerator in `agent-gateway/tests/test_p3_e2.py` moved onto one observation clock ([DESIGN.md](DESIGN.md), section 15).

Constraints that hold for all three:

- `dependencies = []` stays. Everything below is `hashlib`, `hmac`, `ast`, `json`, `zlib`, and integer arithmetic.
- Deterministic and fail-closed, as [DESIGN.md](DESIGN.md) defines them: a decision is reproducible from the policy, the canonical inputs, the trusted state, and the keys; a missing adapter, an unsupported construct, or an exceeded budget contributes false.
- The lab limits in the README are unchanged: default bind `127.0.0.1`, freeze only for registered keys, honeypot output is leads for a person, no OS sandbox, one ledger per gateway process.

## 1. Multi-session causal provenance and composition bounds

**Invariant.** For any set of sessions that could have coordinated (a causal coalition), the sum of charges is at most the root budget B, and the number of distinct externally observable transcripts is at most 2^(B+1), however many forks, spawns, or asynchronous hand-offs occurred. No carrier the gateway mediates may create a fresh budget or a fresh slot clock.

**Why now.** Mutant M5 (one budget per session) is caught by tests, not by structure: a link that is recorded but not merged leaves two budgets and two clocks, and `test_p3_e2.py` shows the unmerged pair emits 1,401 distinct observable transcripts at B=8 against a bound of 512. v13 makes that state unreachable.

**Mechanism.**

1. *Budget shares as caveats.* A fork mints child `agw1.` / `agw2` tokens carrying `qb<=s_i` and `cid=<root>` with the sum of the `s_i` at most the root's remaining budget. Derivation only narrows, as today. Spend counters are keyed by the chain tag, as `capability_token.py` already keys them, so every token derived from one share draws down one counter. A join returns the unspent share to the parent.
2. *Causal edges force merges.* Every cross-session carrier the engine already sees (scratchpad notes, files, the internal bus, spawn, delegation, and the provenance edges of `cross_agent_collusion_guard.py`) registers an edge in the ledger. An outbound event by a session with an unmerged inbound edge is refused with a new reason, `P3_UNLINKED_EDGE`, instead of being charged to a private budget. That closes the M5 adopt path structurally rather than by test.
3. *Asynchronous hand-offs.* An edge whose recipient has not attached yet is a pending adoption. The recipient's `attach` must consume it, and an `attach` that would create a second coalition for a session with a pending adoption fails closed.
4. *One observation clock in production.* A forked child inherits the parent's `last_slot`, so two workers cannot release in the same slot without paying member choice. The clock the enumerator uses in the tests becomes the ledger's clock.

**Checked by.** The observable-transcript enumerator in `test_p3_e2.py` is the oracle. New bounded enumerations over fork trees of depth at most 2 with at most 3 workers, adoption interleaved with emission, assert that a share sum at most B implies at most 2^(B+1) distinct observables. New mutants M12 (a fork mints budget), M13 (an edge without a merge), and M14 (a dropped adoption) must each fail the assertion the real ledger passes.

**Out of scope, stated.** Channels the gateway does not mediate. Several gateway processes: one ledger per process remains the limit until a fencing-token store exists.

## 2. Sound literal-shell and AST abstract interpretation

**Invariant.** For a program in the declared subset, the abstract effect set the guard computes is a superset of every (path, effect) pair the program can perform under any input. Outside the subset the guard fails closed. The claim is soundness relative to a declared subset, not soundness for all programs.

**Why now.** `arg_ast_guard.py` is lexical, `interpreter_exec_guard.py` folds constants over `ast`, and `workspace_path_validator.py` runs a literal-shell effect analyzer that fails closed on unmodelled syntax. Each is correct on what it models; none states what it over-approximates. v13 gives them one abstract domain and one soundness statement.

**Mechanism.**

- *Python payloads.* Abstract interpretation over `ast` with a finite-height string domain (known literal set, prefix, suffix, top), widening to top after k joins, loops run to a fixpoint. Paths resolve against the immutable `Snapshot` with symlink splicing before `..`, as `workspace_path_validator.py` does. Sinks are `open`, `os.*`, `pathlib`, `shutil`, `subprocess`, and sockets. Any `eval`, `exec`, dynamic attribute, or dynamic import with a non-literal operand is top and denies.
- *Shell payloads.* A small-step interpreter over a declared grammar: words, quotes, redirections, pipes, `;`, `&&`, `||`, subshells, heredocs. Word expansion is abstracted; an unset or unknown variable is top and denies. A command table gives effect signatures for `cp`, `mv`, `rm`, `ln`, `chmod`, `sed -i`, `tee`, `git config`, and the interpreters, which recurse into the Python analysis. An unlisted command denies unless it is on a read-only allowlist.
- *Budgets.* Work is precharged as `transform_invariant_validator.py` does: AST node, loop iteration, and expansion budgets; exceeding any one denies the whole query.

**Checked by.** Differential tests against the existing literal-shell transducer on its subset: they must agree. A Hypothesis state machine that generates programs from the grammar and executes them against the in-memory filesystem model, never the real filesystem, as the oracle; the soundness assertion on every generated program is that the concrete effect set is a subset of the abstract one. Mutants that drop a widening or a sink must fail it.

**Out of scope, stated.** Code fetched or decrypted at run time. A script run by name whose content is not in the snapshot. Shell semantics beyond the declared subset.

## 3. Offline deterministic replay commitment

**Invariant.** An auditor holding the audit directory and the policy digest, and no payloads, can verify that every recorded verdict is the deterministic output of the policy on the recorded facts, that the SARIF derives from the log, and that nothing was added, dropped, or reordered.

**Why now.** `audit_chain.py` already hash-chains every record and HMAC-signs the manifest, `sarif_export.py` fingerprints results, and `vendor_risk_proof.py` seals an attestation with SHA-256 digests and an HMAC. What is missing is the link from a verdict back to the facts it depended on, in a form that can be recomputed without the payload.

**Mechanism.**

- *Decision trace.* Each record gains the derived facts the verdict depended on: `rule_code`, the pin digests compared, `content_qb`, `gap`, `spent_qb`, match booleans, manifest hit. Never the values.
- *Commitment.* `c = SHA-256(policy_digest || state_before || input_commitment || trace || verdict || state_after)`, with `input_commitment = HMAC-SHA256(k_session, canonical_args)`. Hiding by the key, binding by the hash: the operator can later prove consistency with the real inputs, and the auditor never sees them.
- *Chain and tree.* Records stay on `ChainWriter`'s chain. The manifest adds a binary SHA-256 Merkle root over the run's commitments and the `policy_digest`, the SHA-256 of the canonical policy configuration and the guard sources. Each SARIF result's `partialFingerprints` becomes its decision commitment, so one finding anchors to one chain entry with an O(log n) inclusion proof.
- *Replay.* `python -m agent_gateway verify --replay` recomputes `verdict(policy, trace)` for every record with the pure verdict function split out of `pep.py`, compares it with the recorded verdict, re-derives the Merkle root, and re-validates the SARIF. Offline, standard library only.

**Checked by.** Replay of the 750-decision benign log and of the E2 enumerations. Mutants that alter one trace field, one verdict, or one SARIF fingerprint must each fail replay.

**Out of scope, stated.** Replay proves the verdict function is deterministic on the recorded trace. It does not prove the trace was honestly recorded by a compromised gateway host, which stays the host- and key-compromise non-goal in the README. There is no external time-stamping of the root.

## Order of work

1 before 3, because the replay trace needs the coalition identity that 1 fixes. 2 is independent of both. None of the three changes a lab limit, a price, or a recorded count.
