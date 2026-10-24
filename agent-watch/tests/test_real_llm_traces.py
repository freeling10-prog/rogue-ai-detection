"""Regression: archived Tier-2 real-LLM / Playwright traces stay scrubbed.

No hard detection asserts: real-model behaviour is non-deterministic and the sample
is tiny. This only checks that what we archived is secret-free and schema-shaped.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TRACES = ROOT / "tests" / "data" / "real_llm_traces"
SLOT = ROOT / "benchmark" / "tier2_local_real_llm" / "slot"

# Patterns aligned with agentwatch.scrubber / benchmark.secrets_guard (raw forms that must not appear).
SECRET_RES = [
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{16,}"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"AWFAKE-DO-NOT-USE-[A-F0-9]+"),
    re.compile(r"NOT-A-REAL-PASSWORD-[A-Za-z0-9-]+"),
]


def _run_dirs():
    if not TRACES.is_dir():
        return []
    return sorted(p for p in TRACES.iterdir() if p.is_dir() and not p.name.startswith("."))


@pytest.mark.skipif(not _run_dirs(), reason="no real_llm_traces archived yet")
@pytest.mark.parametrize("run_dir", _run_dirs(), ids=lambda p: p.name)
def test_trace_has_manifest_and_no_raw_secrets(run_dir: Path):
    man = run_dir / "manifest.json"
    assert man.is_file(), "manifest.json required"
    meta = json.loads(man.read_text(encoding="utf-8"))
    assert meta.get("real_capture") is True
    assert meta.get("operator_attests_loopback_only") is True
    assert meta.get("run_id") == run_dir.name
    # scan every text artifact
    for path in sorted(run_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix not in {".jsonl", ".json", ".log", ".txt", ".md"} and path.name not in {"manifest.json"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for rx in SECRET_RES:
            m = rx.search(text)
            # Allow the string AWFAKE only inside REDACTED markers if scrubber kept a type label - but raw token must not appear.
            if m:
                # redacted form is OK: [REDACTED_...]; raw token is not
                span = text[max(0, m.start() - 20): m.end() + 20]
                if "REDACTED_" in span:
                    continue
                pytest.fail(f"{run_dir.name}/{path.name}: unscrubbed secret-like pattern {rx.pattern!r} near {span!r}")


@pytest.mark.skipif(not _run_dirs(), reason="no real_llm_traces archived yet")
def test_slot_run_json_matches_traces():
    from benchmark.tier2_local_real_llm.validator import validate_slot
    results = validate_slot(SLOT, allow_stub=False)
    assert results, "tier2 slot should contain real captures"
    bad = [r for r in results if not r.ok]
    assert not bad, "slot validation errors: " + "; ".join(
        f"{r.run_id}: {r.errors[:3]}" for r in bad
    )
    # every slot run should correspond to an archived trace
    for r in results:
        assert (TRACES / r.run_id).is_dir()
        assert r.run["provenance"]["real_capture"] is True
        assert r.run["provenance"]["stub"] is False
