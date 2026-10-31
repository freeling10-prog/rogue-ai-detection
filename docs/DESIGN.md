# Four bounded deterministic middleware validators

Prepared for Jordan-Taylor, 29 October 2026. Python 3.12 reference architecture.

## Contract and enforcement boundary

These are proposed engineering specifications, informed by the primary sources below. The included runtime modules use only the Python standard library. Hypothesis and pytest are development dependencies.

Three distinctions are essential:

1. A deterministic decision is reproducible given identical policy, canonical inputs, trusted state, normalization version, and keys. Determinism does not make Python scheduling, garbage collection, storage, or network latency bounded.
2. A static shell analysis cannot establish all effects of arbitrary programs. The reference accepts a literal subset and fails closed outside it. Its filesystem model is not an operating-system sandbox.
3. Rolling shingles are linear to scan for fixed parameters. General exact LCS is not a linear-time operation; the reference bounds its input and uses bit parallelism.

The common safety specification is:

$$\operatorname{Dispatch}(s,c,t)\Rightarrow
 R(s,c,t)\land W(s,c,t)\land F(s,c,t)\land I(s,c,t)\land P(s,c,t)\land T(s,c,t)\land S(s,c,t)\land V(s,c,t).$$

R is registry pin validity, W workspace mutation safety, F manifest/flow validity, I outbound identifier admissibility, P bounded workflow-net transition enablement with resource cleanup state settled before outbound steps (section 5), T file label flow: no non-PUBLIC file into an outbound call and no UNTRUSTED file into an execution sink (section 6), S canonical arguments for pinned tools and no operand in an option position for typed commands (section 7), and V one conservation ledger for a root session and its forked branches, fenced on vector clocks (section 8). A component that is inapplicable to a typed call contributes true; a missing adapter, unsupported construct, exceeded budget, or unavailable trusted state contributes false. Check every item of JSON-RPC batches, including notifications. JSON-RPC itself is stateless and does not impose batch ordering [1].

Treat the specification as a prefix-closed execution safety policy [8]. This does not prove semantic noninterference, correctness of provider implementations, or absence of every possible data leak.

Use one authoritative session owner and one serialized event log. Its linearization point commits the decision, state revision, consumed capability, and exact dispatch envelope together [9]. A Python RLock protects only one process. Distributed ownership needs leases plus fencing tokens or a linearizable store. Partitioned, stale, or missing state must not create a clean new session.

A dispatch envelope binds session/job ID, fencing epoch, event sequence, request key, qualified method, provider route, schema pin, canonical argument digest, typed resources, manifest commitment, filesystem generation, and matcher/policy versions. Never return an unbound allow boolean and later reparse or reroute the request.

Cold operations: registry parsing/hashing/linting, schema compilation, manifest DAG compilation, trusted filesystem snapshot construction, and shingle index construction. Hot operations: immutable lookups, bounded parsing/resolution, capability admission, identifier matching, and a bounded state commit.

## 1. registry_pin_validator.py

### Invariant and representation

Use authenticated provider identity p and exact local method name m as the key (p,m). Provider identity is assigned by a trusted connector/transport configuration, not accepted from advertisement JSON. JSON-RPC method matching is case-sensitive, and its rpc. prefix is reserved [1].

For session s, pin the canonical descriptor digest D_s(p,m). At dispatch:

$$R(s,c,t)\equiv
 \operatorname{state}_s(p,m)=\mathrm{PINNED}
 \land c.\operatorname{pin}=D_s(p,m)
 \land \operatorname{route}(c)=p.$$

The final dispatcher must bind the approved pin to the exact execution route/version. A provider that changes behavior without advertising a change cannot be detected by metadata hashing. If an upstream cannot honor a pinned contract/version, the guarantee is refusal after observed drift, not detection of every hidden change.

Pin inputSchema, outputSchema, description/title, and all accepted annotations. Even annotation-only drift is drift under this policy. Locally assigned impact classification and connector trust are separate policy, never granted by read-only hints. MCP explicitly treats tool annotations as untrusted unless they originate from trusted servers [15]. For MCP, the logical method identity is (authenticated provider, params.name) on tools/call, not the transport method tools/call alone; normalize the advertised tool record into this module's descriptor profile before enrollment.

### Canonical hashing

RFC 8785 JCS has precise numeric serialization and UTF-16 key-order requirements. Python json.dumps(sort_keys=True) is not a substitute [2]. The included implementation deliberately uses a different, versioned profile: CJSON-DECIMAL-v1.

Define C recursively:

- Decode strict UTF-8; reject duplicate object keys before constructing a dict, lone surrogates, NaN, and infinities.
- Preserve decoded string code points. Do not normalize schema strings or property names with NFKC/casefold.
- Encode strings with ordinary JSON escaping, no optional whitespace, and UTF-8 output.
- Sort object keys by their raw UTF-8 byte sequences. Preserve array order.
- Parse numbers directly as Decimal. For nonzero x, derive a unique sign, nonzero integer coefficient a with no trailing zeros, and exponent e such that x = sign × a × 10^e. Emit sign + decimal(a) + "e" + decimal(e). Emit every signed zero as 0. Native binary floats are rejected.
- Bound wire size to 64 KiB, nesting to 32, canonical nodes to 4,096, coefficient digits to 256, exponent magnitude to 4,096, and output to 128 KiB.

Then:

$$D=\operatorname{SHA256}(
 \text{domain}\parallel 0x00\parallel
 C(\{p,m,\text{dialect},\text{descriptor},\text{lintVersion},\text{unicodeVersion}\})).$$

The domain includes canonicalizer and schema-resolution profile versions. All digest equality claims assume collision resistance. The digest identifies a canonical representation, not semantic equivalence of arbitrary schemas. Reordering required or allOf arrays may therefore conservatively trigger drift.

For full JSON Schema 2020-12, pin a closed graph of referenced resources: root retrieval URI, dialect, vocabulary support, resolver policy, and every canonical absolute resource URI with its content digest. Preserve $id/base-URI meaning; reject duplicate resource IDs; allow recursion through visited resource IDs instead of recursively expanding references. Resolve $dynamicRef using the compiled pinned evaluation context. Never fetch a remote reference on the hot path. JSON Schema bundling is defined in terms of preserving resource identity and reference semantics [3].

The runnable reference deliberately supports only local JSON Pointer references. It rejects external references, $id, anchors, dynamic references, and percent-encoded reference fragments. It traverses referenced targets with a visited set, including references into nonstandard containers. Full schema validation and supported-vocabulary enforcement remain with the existing schema validator. A broader deployment must implement the closed graph above instead of silently weakening this restriction.

### State transitions

| Entity | Event | Next state |
|---|---|---|
| Qualified method | Authorized initial enrollment | PINNED |
| PINNED method | Identical valid advertisement | PINNED, unchanged digest |
| PINNED method | Changed/invalid descriptor or removal | REVOKED |
| REVOKED method | Original descriptor reappears | REVOKED |
| Sealed session | Previously unpinned method appears | Refuse; new session required |
| Bare alias | First provider p | UNIQUE(p) |
| UNIQUE(p) alias | Different provider advertises same name | AMBIGUOUS |
| AMBIGUOUS alias | Any removal or later advertisement | AMBIGUOUS |

Ambiguous bare aliases never resolve by arrival order, priority, or last-writer wins. Qualified calls remain distinguishable. New snapshots and migrations are explicit control-plane operations. Keep tombstones until session termination.

### Metadata linting

Inspect only a separate display-analysis view: NFKC, casefold, then whitespace folding. Bound each description to 4 KiB. Flag controls and formatting characters, bidi controls, configured role delimiters, code fences, role prefixes, and an explicit finite list of directive phrases. The reference scans descriptor descriptions/titles and schema descriptions/titles/$comment.

The linter is a deterministic syntactic policy. It cannot decide whether arbitrary prose is a malicious instruction, and quoted documentation can legitimately trigger it. Raw annotations must not become trusted instructions. Any additional metadata surfaced to a model needs its own typed lint policy. Preserve the original canonical bytes for pinning; do not hash the lint-normalized view.

### Python architecture and tests

State is a dict[(provider, method), frozen Pin], a dict[method, owner set], a revoked-key set, a generation counter, and a short critical section. Hashing/linting runs outside the hot lookup lock.

Properties: object order and numeric spelling do not affect C; canonical roundtrip is idempotent; array order matters; duplicate keys reject. A RegistryMachine generates advertisements, collisions, removals, and restoration attempts. Its invariant is that a pinned digest never changes, revocation never heals in-session, and an alias never silently retargets.

## 2. workspace_path_validator.py

### Invariant

For filesystem state F, let ProtectedNames be reserved namespace entries and ProtectedObjects their inode identities. Let Effects(c,F) include all writes, truncations, replacements, unlink/link/rename operations, permission changes, and destructive changes to ancestors that alter protected path resolution.

$$W(s,c,t)\equiv
 \operatorname{Effects}(c,F_t)\cap\operatorname{Protected}(F_t)=\varnothing
 \land \operatorname{Effects}(c,F_t)\subseteq\operatorname{Workspace}(s).$$

The static analyzer must compute a conservative superset of effects. If it cannot, reject. Ordinary creation of an unrelated child is not considered a destructive mutation of every sibling merely because directory mtime changes.

The reference reserves .mcp.json, AGENTS.md, and CLAUDE.md at any depth; .github/workflows; and explicit IDE/configuration names. It conservatively protects all .git, .claude, .cursor, .vscode, .idea, and .windsurf directories plus .cursorrules, .clinerules and .github/copilot-instructions.md. Protecting all .git also prevents hooks from being redirected through Git configuration. Deployment-specific Git worktrees, alternate gitdirs, hooksPath, IDE rules, and external configuration roots must be registered or disallowed.

### Path resolution

Use the actual operation semantics and a broker-pinned physical cwd:

1. Validate UTF-8/scalar text, NUL, path/component lengths, and workspace root. Reject leading // and unsupported platform semantics.
2. Walk path components without first collapsing '..'.
3. On a symlink, splice its target before the remaining suffix. Relative targets start at the symlink's parent. Absolute targets must remain in the workspace.
4. Process '..' after symlink traversal and reject root escape. Reject a regular file used as a directory.
5. For creation, permit only a missing final component under a resolved existing parent.
6. Check visited protected names and the resolved object's device/inode. Conservatively deny mutations of multiply linked files. Check both source and destination for rename, plus replacement destinations and secondary paths.

When cp or mv expands a destination directory into directory/source_basename, retain the complete visited-name trace from resolving that directory. Otherwise expansion through a protected symlink can erase the evidence needed for the namespace check.

The reference uses a complete immutable Snapshot and returns Resolved records. It limits symlink hops to 40, depth to 64, total component steps to 512, component bytes to 255, and uses 2,048 shared work credits for an effect batch. Protected-name classifications are precomputed per immutable snapshot.

Do not Unicode-normalize or URL-decode real POSIX filenames. On a case-insensitive or normalization-insensitive filesystem, use that filesystem's actual name/identity semantics or reject the platform. A Linux lexical policy is not a portable Windows/APFS policy.

### Shell subset and effect extraction

Python shlex is a lexer, not a complete shell parser [4]. The reference uses an explicit bounded scanner preserving whether operators came from quoted text. Its language accepts literal words, quotes, bounded escapes, pipelines, ;, &&, ||, parenthesized groups, and a small set of redirections.

The accepted grammar is structurally:

```text
sequence := unit ((';' | '&&' | '||' | '|') unit)* [';']
unit     := simple | '(' sequence ')' redirection*
simple   := (literal | redirection)+
```

The implementation rejects unsupported variants even if a more complete POSIX parser could accept them. The scanner distinguishes a quoted '>' argument from a redirection and an adjacent unquoted IO number from an ordinary numeric argument.

| Operation | Reference profile |
|---|---|
| >, >>, >|, <> | Record each file as a possible mutation |
| < | Record a regular-file read |
| (...) > file | Inspect nested commands and the group-level redirection |
| tee [-a] [--] files | Every file is an output |
| cp [--] source destination | Source regular file; expand destination-directory basename |
| mv [--] source destination | Protect both removal and destination replacement |
| ln -s [--] target link | Resolve target relative to link parent; protect both |
| ln without -s | Recognized and denied: hardlink creation disabled |
| chmod octal files | Nonrecursive regular-file targets only |
| sed -i script files | One restricted literal substitution; no backup suffix or secondary I/O |

sed -i is an implementation extension, not a portable POSIX interface; GNU documents both in-place and backup behavior [5]. Pin the actual utility implementation/profile.

Reject command substitution, backticks, variables, globs, tilde expansion, process substitution, fd duplication, heredocs, functions, aliases, eval, interpreters, unmodeled options, and arbitrary executables. There is no sound general way to know a command substitution's resulting filename without evaluating its program.

Inspect every redirection: an earlier '> protected' can truncate before a later redirect changes stdout [14]. Conservatively inspect all branches, even those a particular execution may skip. The effect list is a union, not an execution-order AST.

A flat snapshot does not model 'ln -s ...; write-through-link' or rename-then-use. The reference refuses a multi-effect batch containing namespace-changing move/link operations. A fuller executor must interpret and revalidate each namespace transition against a fresh authoritative state.

### Required actual enforcement

Snapshot.check is not sufficient authorization for subprocess.run(raw, shell=True).

Choose either a trusted executor of typed mutation plans, or an OS-isolated shell whose reserved paths cannot be mutated. For a broker:

- Own all namespace mutations and maintain generation/fencing state.
- Resolve from trusted directory descriptors. Linux openat2 can enforce beneath/no-magic-link/no-symlink constraints; optionally reject mount crossing [6]. A Python stdlib alternative walks components with dir_fd and O_NOFOLLOW, under broker-owned namespace invariants [7].
- For existing targets, open without O_TRUNC, verify fstat identity/type/link count, then truncate/write through that same descriptor.
- For creation, use a verified parent and O_CREAT|O_EXCL where appropriate. Bind rename/link/unlink operations to checked parent descriptors.
- Keep protected ancestors immutable to untrusted actors, reject unknown hardlink aliases, close inherited writable descriptors, and prevent out-of-band mutation.

O_NOFOLLOW on the final component alone does not protect ancestor symlinks. openat2 also does not solve hardlinks or every ancestor-rename race. Pure Python path checking cannot provide a general race-free permission boundary against arbitrary peer writers.

### Tests

Generate '..' prefixes, quoted tokens, multiple redirects, nested groups, alias retargeting, and hardlink identities. WorkspaceMachine changes the filesystem generation and symlink target. Invariants: a fresh protected alias never authorizes mutation, stale-generation tickets reject, and protected inode aliases reject. A private real-filesystem fixture checks the model's symlink/'..' results against POSIX resolution. No shell is executed by the tests.

## 3. lattice_flow_validator.py

### Lattice and propagation

Use contamination order, not an ordering of how much a source is trusted:

$$L=\{\mathrm{VERIFIED}=0,\mathrm{EXTERNAL}=1\},\qquad a\sqcup b=\max(a,b).$$

$$\ell_{t+1}=\ell_t\sqcup\operatorname{origin}(e_t).$$

For DAG node v with predecessors pred(v):

$$\ell(v)=\ell_{\mathrm{session}}\sqcup\ell_{\mathrm{input}}(v)
 \sqcup\ell_{\mathrm{control}}(v)
 \sqcup\bigsqcup_{u\in pred(v)}\ell(u).$$

The lattice construction follows the information-flow tradition [10]; this particular two-level policy is deliberately conservative. VERIFIED means approved provenance, not factual correctness.

The trust boundary assigns labels. Tool responses, errors, redirects, restored state, cached artifacts, and control decisions are inputs. Schema-validating or summarizing EXTERNAL data does not remove its label. Children share the session state or inherit/join it through an authenticated mechanism. There is no automatic EXTERNAL-to-VERIFIED transition.

The reference taints at admission of an unverified connector call, before its response arrives, and uses global session taint. This strengthens an ingestion-only rule and avoids an in-flight exposure window.

### Manifest commitment and gating

Compile the initial authorized job specification into an immutable manifest before connector ingestion. A model may propose it, but trusted code and the authorized job policy determine its authority. A digest without controlled provenance or authentication is not authorization.

Each step binds:

- Unique step ID and exact qualified provider/method.
- Registry/schema pin and locally controlled impact classification.
- Required predecessors.
- All resource roles and canonical path patterns.
- Exact argument digest where non-resource arguments must be fixed.
- Cardinality, plus deployment-specific budgets/expiry/parameter constraints.

The reference has single-use steps; repetitions need explicitly separate manifest steps. Unknown methods and unextracted resource-bearing fields are denied by typed adapters. The adapter must discover every effect-bearing path from the validated parameter structure; never trust a caller-supplied 'resources' list.

Let Match_M(c) mean that one unused eligible step matches the qualified method, pin, complete role set, paths, and required argument digest. The requested rule is:

$$\operatorname{Allow}(c)\Rightarrow
 [\ell_{\mathrm{session}}=\mathrm{EXTERNAL}\land\operatorname{High}(c)
 \Rightarrow \operatorname{Match}_M(c)].$$

The runnable reference enforces the stronger policy Match_M(c) for every admitted step, regardless of label. Existing scope, schema, quota, transition, and workspace checks still apply.

Path patterns are segment-aware: literal equals literal; '*' matches exactly one nonempty segment; terminal '**' matches zero or more segments. No general regex, percent decoding, or fnmatch semantics that let '*' cross '/'. Resources must already be physically canonicalized by the correct adapter. For non-filesystem resources, implement a typed canonical resource grammar instead of pretending every identifier is a filesystem path.

### Runtime transition and concurrency

```text
NEW -> QUEUED -> DISPATCHED -> DONE | FAILED | UNKNOWN
```

Admission validates and consumes a step before appending one immutable dispatch record. An identical request key returns the prior receipt without another outbox entry. The same key with different arguments is denied. Only DONE satisfies a predecessor. FAILED and UNKNOWN do not restore spent authority.

At the final dispatch point, recheck relevant pin/fs/fencing revisions under the common session owner. Persist state and outbox together for crash recovery. Downstream idempotency is required to safely reconcile ambiguous remote outcomes; an in-memory ledger does not give exactly-once remote effects.

The reference uses frozen dataclasses, immutable manifest mappings, a dict for step status, an ordered deque outbox, a request ledger, and RLock. It is a local state-machine model; durable outbox storage and distributed fencing are integration requirements.

### Tests

WorkflowMachine generates ingestion, admission, duplicate requests, dispatch, and completion outcomes. Assert monotone taint, no duplicate dispatch, no capability reuse, and predecessor completion. Additional tests alter provider, pin, argument digest, role sets, and path boundaries. Production tests should additionally model owner failover, stale-epoch dispatch, partial batch processing, and crash points around durable enqueue/network acknowledgement.

## 4. shingle_similarity_validator.py

### Normalization and policy

Pin a finite normalization family. Profile nfkc-casefold-filter-fixedpoint-v2 uses two views:

1. Apply NFKC, casefold, NFKC again, then remove Unicode category Cf. Repeat until the value is unchanged, allowing at most four rounds; reject if it does not stabilize.
2. Starting from the first view, apply the same operation while also removing whitespace and the explicit separators '-_./ '. Again require stability within four rounds.

Filtering may bring a base character and combining mark together. Re-normalization makes both accepted views idempotent; for example, A + zero-width joiner + combining ring and the composed character converge to the same view. Check the 256-code-point bound after every round, and fail closed on any exceeded bound.

Apply the same view to enrollment and queries. Do not claim this handles all Unicode confusables, arbitrary encodings, encryption, or semantic paraphrases. URL/transport decoding, if applicable, belongs in a separately specified bounded adapter. Pin the Unicode version. Reject oversize values rather than truncating them.

Default limits: 16 protected strings, 256 normalized code points per string/query, 1 KiB raw text, two views, k=12, LCS coverage threshold 85%, and minimum matched length min(12, protected length). Reject protected strings shorter than four characters in either view.

For protected p and query q under one normalization, define:

$$G_k(x)=\{x[i:i+k]\mid 0\leq i\leq |x|-k\},\quad k_p=\min(k,|p|).$$

$$\operatorname{Hit}(p,q)\equiv
 [G_{k_p}(p)\cap G_{k_p}(q)\neq\varnothing]\ \lor\
 [LCS(p,q)\geq\min(12,|p|)
 \land 100LCS(p,q)\geq85|p|].$$

$$I(s,c,t)\equiv\neg\exists p,j:\operatorname{Hit}(T_j(p),T_j(q)).$$

This is an exact rule over the declared transformations/thresholds, subject to cryptographic collision assumptions for shingle equality. It is not a claim that every blocked string leaks information or that every possible leak is detected. Common snippets and low-entropy patterns can create false positives.

### Rolling hash and equality

For code points mapped to x_i=ord(c_i)+1, base B and modulus 2^64:

$$h_i=\sum_{j=0}^{k-1}x_{i+j}B^{k-1-j}\bmod2^{64},$$
$$h_{i+1}=((h_i-x_iB^{k-1})B+x_{i+k})\bmod2^{64}.$$

This follows the fingerprinting approach of Karp and Rabin [11]. The reference separates a set of rolling fingerprints from a dict of keyed SHA-256 shingle digests. A rolling hit triggers keyed confirmation; the polynomial fingerprint alone never establishes equality.

For short protected strings, index their full length. Therefore there can be several k values, bounded by the configured k. A single-length rolling scan is O(N); a fixed set of lengths/views remains O(N) with a larger constant. Python hash-set/dict lookup provides expected constant time, not an adversarial worst-case guarantee. Confirmation costs O(k) per candidate; k is a small fixed bound.

### Subsequence algorithm

Precompute a bit mask M_p[c] with bit i set when p_i=c. For every query character c:

```python
x = masks.get(c, 0) | state
state = x & ~(x - ((state << 1) | 1))
# after the final character:
length = state.bit_count()
```

Bit-parallel LCS exploits machine-word parallelism [12]. For P patterns of lengths m_p and query length N, its word-operation cost is O(N × sum_p ceil(m_p/w)). Python big integers are multiword objects; treating each operation as constant time for unbounded strings would be incorrect.

The primary ratio is protected-string coverage LCS(p,q)/|p|, so padding the identifier does not dilute a leak. Symmetric 2L/(|p|+|q|) may be a diagnostic but should not replace coverage for this policy. Use integer comparisons, avoiding float threshold boundaries.

Always run the bounded LCS stage when needed, even if no shingles match. Inserting a character between every protected character can preserve full subsequence coverage while destroying every contiguous k-gram. A safe prefilter is the upper bound LCS <= min(|p|,|q|); a shingle miss is not a safe LCS prefilter.

### Memory and audit

The index stores rolling integers, keyed gram digests, protected-item keyed identifiers, and private LCS masks. The masks encode ordered information and must be treated as sensitive in-memory state. This design promises no plaintext in audit records, not cryptographic secrecy of the matcher process.

Audit content fields use domain-separated HMAC-SHA256 under a private key. Log only identifier_hash, protected_hash, a fixed reason code, and decision; add key/policy versions and numeric metadata in production. Plain SHA-256 of low-entropy configuration values is vulnerable to guessing. Never log raw query/secret strings, matched windows, exception payloads, or debug representations of masks. Keys are not logged.

Memory is O(number of shingles) plus mask storage O(sum_p alphabet_size(p) × ceil(m_p/w)), with Python object overhead. The benchmark records actual retained allocations for the supported maximum-size synthetic set.

### Tests

Compare the rolling recurrence with independently recomputed window hashes. Compare bit-parallel LCS with an independent O(mn) dynamic program. Test symmetry/bounds, no-shingle subsequences, padding, short strings, normalization stability, forced rolling collisions, threshold boundaries, and keyed audit output. SimilarityMachine adds protected patterns and checks that prior blocked queries never become allowed and every registered string remains blocked.

## 5. linear_obligation_validator.py

### Invariant and representation

A session's workflow state is a marking of a bounded Petri net with 16 places P_0..P_15, each holding 0..15 tokens. The marking is packed as 16 unsigned 4-bit nibbles into one integer M with 0 <= M < 2^64. A transition t (keyed by authenticated provider and exact method) carries Pre[t] and Post[t] vectors in the same packed form and an is_external_egress flag set by the trusted manifest compiler. The manifest also fixes the initial marking, a positive weight vector w in (Z+)^16, and obligation_places_mask: whole 0xF nibbles over the places that hold resource cleanup state.

$$P(s,c,t)\equiv
 \forall i:\ M_t[i]\ge \mathrm{Pre}[c][i]
 \ \land\ \forall i:\ M_t[i]-\mathrm{Pre}[c][i]+\mathrm{Post}[c][i]\le 15
 \ \land\ (\mathrm{egress}(c)\Rightarrow M_t\,\&\,\mathrm{mask}_{ob}=0).$$

On admission the successor marking M_t - Pre[c] + Post[c] is committed under the session lock. An unknown method, a bare method name owned by two providers, a stale marking sequence, or a spent bootstrap transition contributes false.

### Cold-path conservation

At manifest compilation every vector must have at most 16 entries in 0..15, every key must be unique, there are 1..64 transitions, and the weights lie in 1..2^16. Every repeatable transition must satisfy the weighted non-minting rule

$$\forall c\in T\setminus T_{boot}:\ \sum_{i=0}^{15} w_i\,(\mathrm{Post}[c][i]-\mathrm{Pre}[c][i])\le 0,$$

so the weighted token count w·M is non-increasing along any firing sequence, apart from the explicitly designated bootstrap transitions T_boot, each of which can fire at most once per session. A manifest that violates the rule is never attached. The manifest commitment is a domain-separated digest over the packed vectors, flags, weights, initial marking, and obligation mask.

### Hot path

Each nibble is spread into an 8-bit lane of a 128-bit integer. With values 0..15, the lane-wise expression (lanes | 0x80…) - Pre has its high bit set in lane i exactly when M[i] >= Pre[i], and no borrow crosses lanes. Given sufficient tokens, lanes - Pre + Post holds values 0..30 per lane, so no carry crosses lanes, and any bit in the upper nibble of a lane means a place above capacity. Each check is a constant number of integer operations over a fixed 16-place width: O(1) in the manifest size. A rejected firing leaves the marking and sequence unchanged.

### Gateway wiring

PolicyEngine.attach_obligation_net(session_id, manifest) attaches a compiled net. The gateway resolves the tool name to a transition and checks it before the outbound-identifier matcher. It fires the transition, fenced on the marking sequence read before the other checks, only after every other reference validator has passed. A denial from a later validator therefore never consumes tokens. Denials use OBLIGATION_PROTOCOL_DENIED (JSON-RPC -32071, approximate ATLAS AML.T0051) and record the reason code, the packed marking in hex, and the sequence. The frozen DispatchEnvelope in common.py has a petri_marking_hex field for binding the marking into the dispatch commitment.

### Tests

Nibble get/set round-trips leave the other 15 places unchanged. The lane-parallel successor is compared with an independent per-place loop over random markings and vectors. Minting, out-of-range, duplicate, malformed-mask, and malformed-weight manifests are rejected. Bootstrap transitions are one-shot, places cannot exceed capacity, and check() is pure. PetriObligationMachine fires random acquire/work/settle/release/egress/probe/grant sequences against a Python model. It asserts nibble bounds, a non-increasing weighted token count outside the one-shot grant, agreement with the model, and that no egress is admitted while a cleanup place is non-zero. tests/test_v12_3_obligation_wiring.py covers the gateway path, the JSON-RPC code, commit-after-all-checks ordering, and the SARIF rule.

## 6. symbolic_fs_transducer.py

### Invariant and representation

W denies mutation of protected paths and inodes but deliberately admits reading them, so a protected or sensitive file can be copied into an ordinary workspace file and the copy attached to an outbound call. Content written while the session is untrusted can likewise be written into a workspace file and later consumed by an execution sink. T closes both flows with a label per file object in the product lattice

$$\mathcal{L}=\{\mathrm{PUBLIC}<\mathrm{SENSITIVE}<\mathrm{PROTECTED}\}\times\{\mathrm{TRUSTED}<\mathrm{UNTRUSTED}\},$$

joined pointwise with max. Labels live in an immutable copy-on-write overlay over W's Snapshot, keyed by inode identity when the model has one and by canonical path otherwise, with a generation counter. A path or inode that W classifies as protected (including a symlink or hard-link alias of one) defaults to (PROTECTED, TRUSTED); every other file defaults to (PUBLIC, TRUSTED).

For a call c with resolved read sources R and write targets E, after W(s,c,t) holds:

$$\ell_{new}=(\mathrm{PUBLIC},\ell_{session})\sqcup\bigsqcup_{r\in R}\ell(r),\qquad \forall w\in E:\ \ell'(w)=\ell(w)\sqcup\ell_{new}$$

$$T(s,c,t)\equiv(\mathrm{egress}(c)\Rightarrow\forall r\in R:\ \ell(r).C=\mathrm{PUBLIC})\ \land\ (\mathrm{exec}(c)\Rightarrow\forall r\in R:\ \ell(r).I=\mathrm{TRUSTED}).$$

The specification text assigns ℓ_new to each target; the implementation joins it into the target's existing label instead, so labels only rise. The model cannot see whether a write completed or replaced the whole file, so lowering a label on overwrite could understate what the file holds, while raising it can only overstate. Append and in-place edit also count the target as a read source. A chmod target is treated as an execution sink because Intent does not carry the mode bits. The whole analyzed command is one unit: W's effect union does not record which pipeline member feeds which, so joining across the command over-approximates the flow and never misses one. ℓ_session is monotone and becomes UNTRUSTED when the gateway marks the session tainted or the broker calls observe_untrusted().

### Hot path

check() runs W's check_all first; a W denial propagates unchanged and nothing changes. It then resolves copy and move sources, looks up at most 64 read labels (one overlay probe per key, O(1) each), applies the sink rules, and builds the successor overlay by copying the mapping, O(|overlay| + |E|). Overlays are capped at 65,536 entries. commit() is fenced on the generation the pending result was computed from. rebase(snapshot) adopts a strictly newer base with the same root, keeps the overlay, and bumps the generation so results computed against the old base cannot commit. Reason codes are fixed strings and carry no paths or content.

### Gateway wiring

PolicyEngine.attach_fs_transducer(session_id, nodes, generation, root) builds a Snapshot from the same trusted broker model as attach_workspace_snapshot. A literal shell command is analyzed into its effect union; its fixed command set never interprets file content and its output returns to the agent, so it is neither an egress nor an execution sink. Any other call is applicable only when a resource argument (uri, resource_uri, resource, path) names a path inside the workspace root: a write tool's paths are write targets, and every other tool's paths are read sources checked against the call's sink stage (outbound for send and credential classes or external parameter boundaries, execution for spawn and shell, exec and script tool names). T is checked right after the shell-effect check. Labels are committed after every other reference validator has passed and before the Petri-net fire, so a later denial never commits labels, and a failed fire after the commit can only overstate a label. Label denials use FS_LABEL_FLOW_DENIED (JSON-RPC -32072, approximate ATLAS AML.T0086) and record the reason code, the axis, the overlay generation, and the session integrity. A denial from the workspace model inside T is reported as WORKSPACE_EFFECT_DENIED with via=fs_transducer.

### Tests

The lattice laws (commutativity, associativity, idempotence, identity, absorption, and order agreeing with join) are checked over all six labels. Further cases cover protected defaults through symlink and hard-link aliases, pipeline joins, session integrity, labels never lowering on overwrite, the egress, execution, and chmod sinks, W and sink denials leaving state unchanged, evaluate() purity and overlay immutability, generation fencing, rebase rules, and reason codes without paths. TransducerMachine runs random copies, pipes, appends, overwrites, taint events, sink reads, chmods, and protected writes against an independent label model and asserts agreement after every step; a deliberately broken join fails it. tests/test_v12_4_fs_label_wiring.py covers the gateway path, the JSON-RPC code, commit-after-all-checks ordering, a broker rebase, and the SARIF rule.

## 7. canonical_argument_confinement.py

### Invariant and representation

Two blind spots are about representation, not meaning. First, an argument object can say the same thing in many byte strings: key order, number spelling (1, 1.0, 10e-1, -0), set element order, duplicate keys, explicit defaults. Each choice can carry bits past checks that look only at meaning. Second, a file name that starts with "-" is read as a flag by cp, tee, sed and the other file utilities. S closes both for the tools a trusted adapter pins.

A pinned Policy P has 1..16 FieldPolicy entries (name, kind in {number, set, text, bool}, scale 0..6 for numbers, an optional canonical default, required). The canonical form C_P sorts keys by their UTF-8 bytes and emits compact UTF-8 JSON. It quantizes numbers to the field's scale with ROUND_HALF_EVEN under a local 40-digit context, writes them in positional notation, and turns -0 into 0. It writes set fields as arrays of distinct strings sorted by their canonical UTF-8 JSON encodings, and omits optional fields whose encoding equals the default. Where Canon_P(x) is "x is accepted by P":

$$S(s,c,t)\equiv \big(\mathrm{pinned}_P(c)\Rightarrow \mathrm{Canon}_P(\mathrm{args}(c))\big)\land\big(\mathrm{typed}(c)\Rightarrow \forall o\in\mathrm{operands}(c):\ o_0\neq\text{-}\big),\qquad C_P(C_P(x))=C_P(x).$$

Input is bounded before parsing: at most 2048 wire bytes, and a quote- and escape-aware scan of the raw bytes allows nesting depth 2 (the object plus one array level). Duplicate keys, unknown fields, missing required fields, non-finite numbers, numbers longer than 48 characters, with more than 24 significant digits or with exponent magnitude above 12, sets above 32 elements or elements above 128 characters, duplicate set elements, invalid UTF-8, and lone surrogates contribute false. A quantized number that would itself fail those limits is refused (NUMBER_RANGE), which keeps C_P idempotent. A default must be its own canonical encoding, or the policy is never built. An optional field with no default keeps one bit: an absent field and, for example, an empty set stay distinct. Pinning a default closes that bit.

confine(Command) accepts cp, mv, tee, ln, chmod and sed with 1..16 operands of 1..256 characters, at most 1024 characters in total, no NUL, and no operand starting with "-" ("./-name" is the explicit spelling). It compiles a fixed argv (utility, *options, "--", *positionals): options come only from typed fields (tee -a, ln -s, sed -i), and chmod's mode and sed's script are positionals placed after "--" ahead of the operands. Each one must match the same literal profile the workspace analyzer accepts. cp, mv and ln take exactly two operands, and ln is symbolic only.

### Hot path

Canonicalization is linear in the wire bytes plus sorting at most 16 keys and at most 32 elements per set. The 40-digit context bounds every quantization. confine is linear in the operand text. Neither keeps state, so there is no commit step.

### Gateway wiring

PolicyEngine.pin_argument_policy(tool_name, policy) and PolicyEngine.pin_command_tool(tool_name) pin a tool one way or the other, never both. S runs first in the reference middleware. A pinned argument object is re-encoded as compact JSON, because the gateway receives arguments already parsed. Duplicate keys and number spelling are therefore collapsed by the HTTP JSON parser before S sees them, and the wire-level checks apply in full to raw bytes a broker passes to Policy.canonicalize. The allow result carries confinement.canonical_arguments and the policy commitment, and those bytes are what a dispatcher forwards. A typed command's arguments must be exactly {utility, operands, mode, script, append}. Its compiled argv goes on the allow result as confinement.argv, and its effects (from the workspace analyzer's command_intents) go through W and T when those are attached. It never falls back to shell-text parsing, because its script field is a sed expression. Denials use ARGUMENT_CONFINEMENT_DENIED (JSON-RPC -32073, approximate ATLAS AML.T0053) and record the reason code, the kind (arguments or command), and the policy commitment.

### Tests

Unit cases cover ROUND_HALF_EVEN boundaries, -0, equivalent spellings sharing one form, set order by encoded bytes, every rejection reason, depth counting that ignores brackets and escaped quotes inside strings, policy validation (including non-canonical defaults), the presence bit, a Hypothesis property for idempotence and order independence, every utility's argv, every confine rejection, the typed-argument adapter, a repr without operands, and a property that operands never reach an option position. Every compiled argv is also accepted by the workspace analyzer. CanonicalArgumentMachine keeps a semantic argument object and re-spells it on every step: key order, number notation including exact halves, set order, explicit defaults, and escaped or raw text. It compares the canonical bytes with an oracle that formats amounts with integer arithmetic, independent of Decimal. Replacing ROUND_HALF_EVEN with ROUND_HALF_UP fails it. tests/test_v12_5_argument_confinement_wiring.py covers the gateway path, the JSON-RPC code, identical bytes for equivalent objects, option injection, typed commands through W and T, results not leaking into later calls, one-way pinning, and the SARIF rule.

## 8. fork_join_vector_validator.py

### Invariant and representation

Per-session budgets and markings assume one session. When a root session forks sub-agent branches and later joins them, a child that gets a fresh, independent quota multiplies the root's budgets, and two branches that dispatch concurrently can both spend one balance. V keeps a root and at most WIDTH = 8 lifetime branches under one immutable ledger. Slot 0 is the root, and slots are never reused. Each branch b has a parent, an active flag, a vector clock c_b in N^8, a taint bit, and a wallet w_b = (denial units, outbound bytes, 16 token places). Token amounts are in units of 1/UNIT of a capability, with UNIT = 256. The root also records the initial wallet I, the consumed denial units and outbound bytes in spent, a positive weight vector, an obligation mask over the 16 places, and an event count. Over the active branches A:

$$\forall k\in\{0,1\}:\ \sum_{b\in A} w_b[k]+\mathrm{spent}[k]=I[k],\qquad \sum_{b\in A}\sum_{i}\omega_i\,w_b[2+i]=\sum_i \omega_i\,I[2+i],\qquad \sum_b c_b[b]=\mathrm{events}+|\mathrm{branches}|-1.$$

An inactive branch holds the zero wallet. Every operation names a slot and the expected value of that branch's own clock component. It needs the branch active, the clock current, and fewer than 65,535 events, and a commit ticks that component.

- fork moves a grant (each entry at most the parent's) into a new child. The child's clock is the parent's after the tick with its own component set to 1, and it inherits the parent's taint.
- join needs the child active, a direct child of the joining slot, and no active children of its own. It adds the child's wallet back, takes the elementwise maximum of clocks and taint, and deactivates the child for good.
- fire needs take ≤ the branch's tokens and the weighted sums of take and put to be equal, so no firing mints. A branch holding a fraction below UNIT cannot take a full-token transition until that fraction is joined back.
- send allows at most 512 bytes per call, needs a remaining denial unit and enough outbound bytes, and needs every active branch in the ledger to hold zero tokens in the obligation places. Cleanup state is settled ledger-wide, not per branch.
- deny spends one denial unit.

$$V(s,c,t)\equiv \mathrm{active}(b_s)\land \mathrm{clock}_c=c_{b_s}[b_s]\land \mathrm{ops}(c)\ \text{admissible on}\ w_{b_s}\ \text{and the ledger}.$$

### Hot path

Each operation is O(WIDTH × PLACES) at worst; that bound comes from the ledger-wide obligation scan on send. Owner holds the current Root under one lock. check() runs a batch against a snapshot and changes nothing. apply() runs the whole batch fenced on the expected clock and commits it all or nothing, so a dispatch computed from a stale view never commits. Owner validates its transition table at construction: every (take, put) entry must conserve the weighted token count.

### Gateway wiring

PolicyEngine.attach_fork_join(session_id, Root.make(...), transitions) puts a session at slot 0. fork_branch(parent, child, grant) and join_branch(parent, child) are the trusted control plane. A ledger session that calls spawn_subagent forks the child session automatically with an empty grant, so a spawned child starts with no budget unless the control plane gives it one. The forked slot is committed when the spawn passes the reference validators; a spawn denied later in the pipeline still uses a lifetime slot.

The reference middleware plans the call's operations once the label transducer has been checked. Those are a taint mark if the session is tainted, the tool's transition if it has one, a send for outbound calls (send and credential classes or external parameter boundaries), measured as the canonical JSON size of the arguments, and the auto-fork. The plan is checked against the current ledger, then applied, fenced on the clock read at planning time, after every other reference validator has passed and before the Petri-net fire.

Every gateway denial on a ledger session, from any gate, spends one of that branch's denial units, and an exhausted branch cannot send. Branch taint is mirrored into the session whenever the session is loaded, so a child of a tainted branch starts tainted and a join that brings taint back taints the parent. A joined child's later calls are denied (BRANCH_INACTIVE). Denials use FORK_JOIN_LEDGER_DENIED (JSON-RPC -32074, approximate ATLAS AML.T0086) and record the reason code, the slot, the event count, and spent.

### Tests

Unit cases cover Root.make validation; fencing on slot, activity, clock and event budget; fork grants and child clocks; lifetime width with no slot reuse; join rules (not a child, has children, inactive) and the merge; send, deny and fire semantics with weighted conservation and ledger-wide cleanup state; a fraction below UNIT; tampered roots rejected by conserved() and by Owner; and atomic, fenced Owner batches. LedgerMachine forks, joins, fires weighted moves, sends, denies, taints and attempts stale writes on random branches against an independent Python model, and asserts the conservation laws after every step. A fork that mints, or a send that checks cleanup state only on its own branch, fails it. tests/test_v12_6_fork_join_wiring.py covers shared budgets, fractional tokens, ledger-wide cleanup state, denial charging, a stale-clock commit, spawn auto-forks, taint along forks and joins, and the SARIF rule.

## Validation and deployment criteria

The original reference suite has 64 passing test cases, including four RuleBasedStateMachine classes. Section 5 adds 14 cases to test_validators.py, including PetriObligationMachine, and 6 gateway wiring cases. Section 6 adds 11 cases, including TransducerMachine, and 7 gateway wiring cases. Section 7 adds 82 cases (most of them parametrized), including CanonicalArgumentMachine, and 14 gateway wiring cases. Section 8 adds 10 cases, including LedgerMachine, and 9 gateway wiring cases. Hypothesis generates/shrinks sequences rather than just isolated messages [13]. These tests are executable evidence, not a formal proof of all schedules or operating-system behavior.

benchmark.py records 5,000 samples per case, nearest-rank p99, wall and process CPU clocks, GC enabled, and warm single-process execution. Cold construction is excluded. Path measurements use a trusted in-memory filesystem model. The 16-by-256 matcher case exercises the maximum configured number and length of protected strings, but is one synthetic miss workload; it does not establish the worst case over all alphabets, shingle-length mixes, hash collisions, normalization work, or workloads. benchmark_results.json is the authoritative measured output.

Do not translate a passing microbenchmark into a deployment SLA. Measure actual parsing, contention, rejection-heavy traffic, input distributions, cache misses, GC, batch sizes, broker syscalls, durable commits, crash recovery, and load. A maximum above 5 ms is compatible with p99 below 5 ms; it is not compatible with a hard 5 ms deadline. Set deterministic admission/work budgets; never let timeout or partial analysis become an allow.

The production acceptance conditions are: adapters enumerate all effects; all dispatch paths are mediated; registry/fs/manifest checks share a final fenced authorization boundary; storage preserves sticky taint/revocation/spent steps; OS enforcement covers real filesystem operations; and the target deployment meets the measured latency budget.

### Measured results — 29 October 2026

| Benchmark case | Wall p99 (ms) | Wall maximum (ms) |
|---|---:|---:|
| registry: qualified lookup, 256 pins | 0.000721 | 0.585095 |
| path: parse + snapshot validation, 64 writes | 2.626140 | 13.533400 |
| flow: fresh EXTERNAL step admission | 0.029465 | 1.267627 |
| similarity: 16 x 256, 256-char miss, both modes | 3.765636 | 37.809231 |
| combined: four bounded checks | 4.833856 | 12.030749 |

Python 3.12.14, Linux x86-64, 5,000 samples per case. Combined p99 was 4.833856 ms; the 12.030749 ms combined maximum demonstrates that this is not a hard deadline guarantee. The measured matcher retained 1,426,200 bytes of traced Python allocations. See the JSON results for the complete methodology.

### Measured results — 31 October 2026 (adds the obligation cases)

| Benchmark case | Wall p99 (ms) | Wall maximum (ms) |
|---|---:|---:|
| registry: qualified lookup, 256 pins | 0.002004 | 0.048793 |
| path: parse + snapshot validation, 64 writes | 2.093854 | 9.089749 |
| flow: fresh EXTERNAL step admission | 0.056480 | 0.122664 |
| similarity: 16 x 256, 256-char miss, both modes | 5.506425 | 14.532536 |
| obligation: outbound transition, 16 places x 64 transitions | 0.056841 | 2.109065 |
| combined: four bounded checks | 8.030680 | 17.220236 |
| combined: five bounded checks (with obligation) | 7.307601 | 18.571365 |

Python 3.12.3, Linux x86-64, 5,000 samples per case, in a different and slower container than the 29 October run. The unchanged similarity case measured 5.506 ms p99 here against 3.766 ms there, so compare the rows within a table, not across tables. The obligation transition itself measured 0.056841 ms p99. On this host both combined cases exceed the 5 ms reference at p99 (8.031 ms for four checks, 7.308 ms for five). Almost all of that cost comes from the path and similarity checks. The five-check case can read lower than the four-check case because run-to-run variance on this host is larger than the obligation check's cost. benchmark_results.json holds this run.

### Measured results — 31 October 2026 (adds the transducer cases)

| Benchmark case | Wall p99 (ms) | Wall maximum (ms) |
|---|---:|---:|
| registry: qualified lookup, 256 pins | 0.001310 | 0.019146 |
| path: parse + snapshot validation, 64 writes | 1.554548 | 6.242128 |
| flow: fresh EXTERNAL step admission | 0.035524 | 0.087832 |
| similarity: 16 x 256, 256-char miss, both modes | 4.112741 | 5.570932 |
| obligation: outbound transition, 16 places x 64 transitions | 0.026391 | 0.092510 |
| transducer: 1 read joined into 63 writes, copy-on-write overlay | 0.860511 | 2.734727 |
| combined: four bounded checks | 5.524086 | 10.616541 |
| combined: five bounded checks (with obligation) | 5.615334 | 8.698577 |
| combined: six bounded checks (with transducer) | 6.486561 | 14.034532 |

Python 3.12.3, Linux x86-64, 5,000 samples per case, in another container than either earlier run, so compare rows within this table only. The transducer case measured 0.860511 ms p99; its shell text is parsed once outside the timed region, so it times W's check plus the label work, not parsing. The six-check combined case measured 6.487 ms p99, above the 5 ms reference, and so did the four- and five-check cases on this host (5.524 ms and 5.615 ms). benchmark_results.json holds this run.

### Measured results — 31 October 2026 (adds the argument confinement cases)

| Benchmark case | Wall p99 (ms) | Wall maximum (ms) |
|---|---:|---:|
| registry: qualified lookup, 256 pins | 0.001789 | 0.028948 |
| path: parse + snapshot validation, 64 writes | 1.494277 | 4.803039 |
| flow: fresh EXTERNAL step admission | 0.029512 | 0.044910 |
| similarity: 16 x 256, 256-char miss, both modes | 4.294520 | 5.909389 |
| obligation: outbound transition, 16 places x 64 transitions | 0.029973 | 1.957910 |
| transducer: 1 read joined into 63 writes, copy-on-write overlay | 0.809063 | 5.509325 |
| arguments: canonicalize 16 fields, 2048-byte wire | 0.473239 | 0.626497 |
| command: confine 16 operands | 0.007191 | 0.155770 |
| combined: four bounded checks | 5.824797 | 23.323409 |
| combined: five bounded checks (with obligation) | 5.619005 | 14.187225 |
| combined: six bounded checks (with transducer) | 6.608683 | 15.088489 |
| combined: seven bounded checks (with canonicalization) | 7.006841 | 28.656578 |

Python 3.12.3, Linux x86-64, 5,000 samples per case, same container as the previous table. The canonicalization case is the full budget: 16 fields, 2048 wire bytes, four 32-element sets in reverse order, and eight numbers quantized at scale 6. It measured 0.473239 ms p99, and confining 16 operands measured 0.007191 ms. Every combined case is above the 5 ms reference at p99 on this host. The maxima include scheduler outliers; the 28.66 ms seven-check maximum is not a deadline. benchmark_results.json holds this run.

### Measured results — 31 October 2026 (adds the fork/join ledger cases)

| Benchmark case | Wall p99 (ms) | Wall maximum (ms) |
|---|---:|---:|
| registry: qualified lookup, 256 pins | 0.001332 | 0.030552 |
| path: parse + snapshot validation, 64 writes | 1.744593 | 5.277180 |
| flow: fresh EXTERNAL step admission | 0.048727 | 0.071643 |
| similarity: 16 x 256, 256-char miss, both modes | 4.017664 | 5.239107 |
| obligation: outbound transition, 16 places x 64 transitions | 0.031539 | 0.588212 |
| transducer: 1 read joined into 63 writes, copy-on-write overlay | 0.909569 | 6.889158 |
| arguments: canonicalize 16 fields, 2048-byte wire | 0.614009 | 6.587237 |
| command: confine 16 operands | 0.016011 | 0.144224 |
| ledger: fire + send batch, 8 branches x 16 places | 0.111582 | 0.224673 |
| combined: four bounded checks | 5.632157 | 13.899377 |
| combined: five bounded checks (with obligation) | 5.770401 | 11.548429 |
| combined: six bounded checks (with transducer) | 6.748795 | 20.982895 |
| combined: seven bounded checks (with canonicalization) | 7.264731 | 19.152971 |
| combined: eight bounded checks (with fork/join ledger) | 7.301175 | 14.358839 |

Python 3.12.3, Linux x86-64, 5,000 samples per case, same container as the previous two tables. The ledger case runs on a full-width ledger, with the root and seven forked branches holding shares of every budget. Each sample applies one fenced batch: a weighted transition and a 512-byte send whose cleanup-state scan covers all 8 branches and 16 places without stopping early. It measured 0.111582 ms p99. Every combined case is above the 5 ms reference at p99 on this host. benchmark_results.json holds this run.

## Primary sources

1. [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification).
2. [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), 2020.
3. [JSON Schema 2020-12 Core, including compound documents](https://json-schema.org/draft/2020-12/json-schema-core).
4. [Python 3.12 shlex documentation](https://docs.python.org/3.12/library/shlex.html).
5. [GNU sed command-line options](https://www.gnu.org/software/sed/manual/html_node/Command_002dLine-Options.html).
6. [Linux openat2(2) manual](https://man7.org/linux/man-pages/man2/openat2.2.html).
7. [Python 3.12 os documentation](https://docs.python.org/3.12/library/os.html).
8. [Schneider, Enforceable Security Policies](https://www.cs.cornell.edu/fbs/publications/EnfSecPols.pdf), ACM TISSEC, 2000.
9. [Herlihy and Wing, Linearizability](https://www.cs.cmu.edu/~wing/publications/HerlihyWing90.pdf), ACM TOPLAS, 1990.
10. [Denning, A Lattice Model of Secure Information Flow](https://doi.org/10.1145/360051.360056), CACM, 1976.
11. [Karp and Rabin, Efficient Randomized Pattern-Matching Algorithms](https://doi.org/10.1147/rd.312.0249), IBM JRD, 1987.
12. [Allison and Dix, A Bit-String Longest-Common-Subsequence Algorithm](https://allisons.org/ll/Publications/1986IPL/), IPL, 1986.
13. [Hypothesis stateful testing documentation](https://hypothesis.readthedocs.io/en/latest/stateful.html).
14. [GNU Bash redirection semantics](https://www.gnu.org/s/bash/manual/html_node/Redirections.html) and [command grouping](https://www.gnu.org/s/bash/manual/html_node/Command-Grouping.html).
15. [Model Context Protocol, Tools, version 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
