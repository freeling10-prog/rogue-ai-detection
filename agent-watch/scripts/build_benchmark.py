#!/usr/bin/env python3
"""Build the three-tier benchmark bundle (never opens a network connection; refuses to package raw secrets).

    python scripts/build_benchmark.py --out benchmark_out                      # tier1 from existing eval JSON + fresh 5-seed generation
    python scripts/build_benchmark.py --out out --no-generate                  # existing outputs only (fastest)
    python scripts/build_benchmark.py --out out --tier3-input /path/to/pulled  # wild logs (provenance.json + *.access.jsonl/*.leads.jsonl)
    python scripts/build_benchmark.py --check-jsonl a.jsonl b.jsonl            # only verify inputs are secret-free

Exit codes: 0 ok | 2 validation failed | 3 secrets found (nothing packaged) | 4 usage.
See docs/benchmark-protocol.md.  Tier 1 is SAME-AUTHOR SYNTHETIC; tiers are never merged into one number.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from benchmark.common import BenchmarkError, SecretsFound               # noqa: E402
from benchmark.packer import DEFAULT_PIPE_ROOT, DEFAULT_T2_SLOT, DEFAULT_T3_SLOT, build_bundle, check_jsonl_inputs   # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", help="output directory (tier dirs + manifest.json are replaced; other files untouched)")
    ap.add_argument("--aw-root", default=str(HERE))
    ap.add_argument("--pipeline-root", default=str(DEFAULT_PIPE_ROOT))
    ap.add_argument("--seeds", type=int, nargs="*", default=[0, 1, 2, 3, 4])
    ap.add_argument("--no-generate", action="store_true", help="tier1: only consume existing eval outputs, do not run the generators")
    ap.add_argument("--eval-json", type=Path, action="append", default=[], help="extra eval output JSON to include in tier1 (repeatable)")
    ap.add_argument("--tier2-input", type=Path, default=DEFAULT_T2_SLOT)
    ap.add_argument("--tier3-input", type=Path, default=DEFAULT_T3_SLOT)
    ap.add_argument("--allow-stub", action="store_true", help="accept STUB-* tier2 fixtures (tests only; reported separately, never as real)")
    ap.add_argument("--scrub-inputs", action="store_true", help="tier3/eval inputs: scrub with the project scrubber first, then verify (default: verify and refuse)")
    ap.add_argument("--generated-at", help="fixed timestamp for a byte-reproducible manifest (or BENCH_GENERATED_AT)")
    ap.add_argument("--check-jsonl", nargs="+", type=Path, help="only check these JSONL files for unscrubbed secrets, then exit")
    a = ap.parse_args(argv)
    try:
        if a.check_jsonl:
            check_jsonl_inputs(a.check_jsonl)
            print("clean: no secret patterns found")
            return 0
        if not a.out:
            ap.error("--out is required")
        m = build_bundle(Path(a.out), aw_root=Path(a.aw_root), pipe_root=Path(a.pipeline_root), seeds=tuple(a.seeds), generate=not a.no_generate,
                         eval_jsons=a.eval_json, t2_slot=a.tier2_input, t3_slot=a.tier3_input, allow_stub=a.allow_stub,
                         scrub_inputs=a.scrub_inputs, generated_at=a.generated_at)
    except SecretsFound as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3
    except BenchmarkError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    for tier, blk in m["tiers"].items():
        print(f"{tier}: {blk['status']}")
    print(f"manifest: {Path(a.out) / 'manifest.json'}\n{m['not_comparable']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
