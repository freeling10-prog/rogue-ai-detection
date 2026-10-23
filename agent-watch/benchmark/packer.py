"""Bundle packer used by scripts/build_benchmark.py (kept importable so tests call it directly).  No network access, ever."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import MANIFEST_SCHEMA, NOT_COMPARABLE_NOTE, TIER1, TIER2, TIER3, TIERS, TOOLKIT_VERSION
from .common import BAD_LINE, BenchmarkError, SecretsFound, file_entry, iter_jsonl, write_json
from .secrets_guard import PATTERNS, PROJECT_PATTERNS_USED, BundleScrubber, scan_file, scan_tree
from .tier1_synthetic_regression import export_tier1
from .tier2_local_real_llm import aggregate, score_run, validate_slot
from .tier3_wild_honeypot import build_card, collect_stats, load_slot

ROOT = Path(__file__).resolve().parent
AW_ROOT = ROOT.parent
DEFAULT_PIPE_ROOT = AW_ROOT.parent / "rogue-ai-pipeline"
DEFAULT_T2_SLOT = ROOT / "tier2_local_real_llm" / "slot"
DEFAULT_T3_SLOT = ROOT / "tier3_wild_honeypot" / "slot"

CLAIMS = {
    TIER1: {"can_claim": "A code change did or did not alter behaviour on the fixed same-author synthetic scenarios (regression check).",
            "cannot_claim": "Anything about real-world detection, generalisation to unseen agents, or fairness of the comparison: the data author is the detector author."},
    TIER2: {"can_claim": "How the detectors/honeypot react to the behaviour of specific real local models and headless browsers under named prompts (descriptive, small n).",
            "cannot_claim": "Population-level performance, behaviour of unlisted models, or anything about wild traffic. Operator prompts are intent, not detector ground truth."},
    TIER3: {"can_claim": "What reaches an isolated public honeypot: volumes, scanner noise share, which decoys/rules fire, descriptive archetype mix.",
            "cannot_claim": "Detector accuracy (no ground truth), that any client is an AI agent, or equivalence with tier 1/2 numbers."},
}


def _now(generated_at: Optional[str]) -> str:
    return generated_at or os.environ.get("BENCH_GENERATED_AT") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_jsonl_inputs(paths: list[Path]) -> None:
    """Reject any input JSONL containing an unscrubbed secret pattern (or malformed lines)."""
    findings: list[dict[str, Any]] = []
    for p in paths:
        findings += scan_file(p, p.name)
        for n, rec in iter_jsonl(p):
            if rec is BAD_LINE:
                raise BenchmarkError(f"{p.name}:{n}: not valid JSON")
    if findings:
        raise SecretsFound(findings)


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def pack_tier2(out_root: Path, slot: Path, allow_stub: bool) -> dict[str, Any]:
    d = out_root / TIER2
    d.mkdir(parents=True, exist_ok=True)
    results = validate_slot(slot, allow_stub=allow_stub)
    secrets_found = [f for r in results for f in r.secret_findings]
    if secrets_found:
        raise SecretsFound(secrets_found)
    bad = [r for r in results if not r.ok]
    if bad:
        raise BenchmarkError("tier2 validation failed: " + "; ".join(f"{r.run_dir.name}: {r.errors[0]} (+{len(r.errors) - 1} more)" for r in bad))
    scored = [score_run(r.run_dir) for r in results]
    real, stub = [s for s in scored if not s["stub"]], [s for s in scored if s["stub"]]
    for r in results:
        for p in sorted(r.run_dir.iterdir()):
            if p.is_file():
                _copy(p, d / "runs" / r.run_id / p.name)
    for p in (ROOT / "tier2_local_real_llm" / "schema").glob("*.json"):
        _copy(p, d / "schema" / p.name)
    metrics = aggregate(real) if real else None
    stub_metrics = aggregate(stub) if stub else None
    if real:
        status = "populated_real_traces"
    elif stub:
        status = "stub_fixture_only_NOT_REAL_DATA"
    else:
        status = "empty_slot_no_real_traces"
    write_json(d / "scores.json", {"per_run": scored, "real_metrics": metrics, "stub_selftest_metrics": stub_metrics})
    (d / "README.md").write_text(
        "# Tier 2 - local real-LLM traces\n\n" + (
            "**This slot is EMPTY: no real local red-team trace has been captured yet.** There are no tier-2 metrics.\n" if not real else
            f"{len(real)} real captured run(s). Descriptive statistics only; see `scores.json`.\n") +
        ("\n**Contains STUB fixture runs (run_id STUB-*) that are NOT real data**; their numbers are in `stub_selftest_metrics` and are never real results.\n" if stub else "") +
        "\nSee docs/benchmark-protocol.md for how to capture and add runs.\n", encoding="utf-8")
    return {"status": status, "same_author_synthetic": False, "n_real_runs": len(real), "n_stub_runs": len(stub),
            "metrics": metrics, "stub_selftest_metrics": stub_metrics, "files": [file_entry(out_root, p) for p in sorted(d.rglob("*")) if p.is_file()]}


def pack_tier3(out_root: Path, slot: Path, scrub: bool) -> dict[str, Any]:
    d = out_root / TIER3
    d.mkdir(parents=True, exist_ok=True)
    inp = load_slot(slot)
    if inp.errors:
        raise BenchmarkError("tier3 validation failed: " + "; ".join(inp.errors[:5]) + (f" (+{len(inp.errors) - 5} more)" if len(inp.errors) > 5 else ""))
    gate = "no data (empty slot)"
    if not inp.empty:
        srcs = [*inp.access_files, *inp.lead_files, *inp.report_files, slot / "provenance.json"]
        if scrub:
            scrubber = BundleScrubber()
            staged = Path(tempfile.mkdtemp(prefix="aw-bench-t3-", dir=str(out_root)))
            for p in srcs:
                if p.suffix == ".jsonl":
                    with open(staged / p.name, "w", encoding="utf-8") as fh:
                        for _, rec in iter_jsonl(p):
                            fh.write(json.dumps(scrubber.scrub(rec), sort_keys=True) + "\n")
                else:
                    (staged / p.name).write_text(json.dumps(scrubber.scrub(json.loads(p.read_text(encoding="utf-8"))), indent=2), encoding="utf-8")
            inp = load_slot(staged)
            if inp.errors:
                raise BenchmarkError("tier3 validation failed after scrubbing: " + inp.errors[0])
            gate = "inputs scrubbed with the project scrubber (+decoy-token redaction) by --scrub-inputs, then verified clean"
        else:
            findings = [f for p in srcs for f in scan_file(p, p.name)]
            if findings:
                raise SecretsFound(findings)
            gate = "inputs verified free of secret patterns (not modified)"
        for p in [*inp.access_files, *inp.lead_files, *inp.report_files, inp.root / "provenance.json"]:
            _copy(p, d / "data" / p.name)
    try:
        stats = None if inp.empty else collect_stats(inp)
    finally:
        if scrub and not inp.empty:
            shutil.rmtree(inp.root, ignore_errors=True)         # the scrubbed staging copy lives inside the stage dir
    card = build_card(inp, stats, {"secret_gate": gate})
    (d / "DATASET_CARD.md").write_text(card, encoding="utf-8")
    if stats is not None:
        write_json(d / "stats.json", stats)
    return {"status": "empty_slot_no_wild_data_yet" if stats is None else "populated_wild_data", "same_author_synthetic": False,
            "metrics": stats, "secret_gate": gate, "files": [file_entry(out_root, p) for p in sorted(d.rglob("*")) if p.is_file()]}


def build_bundle(out: Path, *, aw_root: Path = AW_ROOT, pipe_root: Path = DEFAULT_PIPE_ROOT, seeds: tuple[int, ...] = (0, 1, 2, 3, 4),
                 generate: bool = True, eval_jsons: Optional[list[Path]] = None, t2_slot: Path = DEFAULT_T2_SLOT, t3_slot: Path = DEFAULT_T3_SLOT,
                 allow_stub: bool = False, scrub_inputs: bool = False, generated_at: Optional[str] = None,
                 inject: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Build the three tiers + manifest into *out* (staged then moved; on any refusal nothing is left behind).  Returns the manifest."""
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".bench-stage-", dir=str(out.parent)))
    try:
        # inputs that are plain JSONL are rejected up front if they carry a secret pattern
        pre = [p for p in (eval_jsons or [])]
        if pre and not scrub_inputs:
            findings = [f for p in pre for f in scan_file(p, p.name)]
            if findings:
                raise SecretsFound(findings)
        tiers = {
            TIER1: export_tier1(stage, aw_root=aw_root, pipe_root=pipe_root, seeds=seeds, generate=generate, eval_jsons=eval_jsons, inject=inject),
            TIER2: pack_tier2(stage, t2_slot, allow_stub),
            TIER3: pack_tier3(stage, t3_slot, scrub_inputs),
        }
        for t in TIERS:
            tiers[t] = {**tiers[t], **CLAIMS[t]}
        manifest = {
            "schema": MANIFEST_SCHEMA, "toolkit_version": TOOLKIT_VERSION, "generated_at": _now(generated_at),
            "network_access": "none: this toolkit never opens a network connection",
            "tiers": tiers,
            "not_comparable": NOT_COMPARABLE_NOTE,
            "secret_scan": {"patterns": sorted({n for n, _ in PATTERNS}), "project_scrubber_patterns_used": PROJECT_PATTERNS_USED,
                            "views": ["raw", "percent-decoded x2", "\\uXXXX-decoded", "newline/control-split", "project match view"], "result": "clean"},
        }
        write_json(stage / "manifest.json", manifest)
        findings = scan_tree(stage)                          # final gate over EVERYTHING in the bundle, manifest and cards included
        if findings:
            raise SecretsFound(findings)
        for name in (*TIERS, "manifest.json"):
            tgt = out / name
            if tgt.is_dir():
                shutil.rmtree(tgt)
            elif tgt.exists():
                tgt.unlink()
        out.mkdir(parents=True, exist_ok=True)
        for p in stage.iterdir():
            shutil.move(str(p), str(out / p.name))
        return manifest
    finally:
        shutil.rmtree(stage, ignore_errors=True)
