# Deterministic middleware reference package

Read DESIGN.md for the formal invariants, sources, supported profiles, and required enforcement boundaries.

- common.py: bounded exact-decimal canonical JSON and stable rejection codes.
- registry_pin_validator.py: session pins, sticky drift revocation, alias collisions, metadata linting.
- workspace_path_validator.py: literal-shell effect analysis and an immutable filesystem model.
- lattice_flow_validator.py: two-level provenance, manifest capabilities, DAG admission, local outbox model.
- shingle_similarity_validator.py: rolling shingles, bounded bit-parallel LCS, keyed audit identifiers.
- test_validators.py: independent oracles, examples, properties and four Hypothesis state machines.
- validation_results.json: test results, tested dependency versions, and runtime source hashes.
- benchmark.py and benchmark_results.json: reproducible bounded microbenchmarks and measured results.

Runtime: Python 3.12; standard library only. Tests use development dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
python3 benchmark.py
```

Run these commands from this directory. The runtime files can be adapted to a package with relative imports when integrated.

The path module does not execute commands or enforce real filesystem permissions. The gate's outbox is in-memory. Neither is a production sandbox or durable distributed transaction manager. Do not call a raw shell based only on a successful model check. Do not claim RFC 8785 compatibility for the custom canonicalizer.
