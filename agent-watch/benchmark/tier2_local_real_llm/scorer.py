"""Tier-2 scorer: DESCRIPTIVE per-run / per-group statistics of what a real model did and what the honeypot recorded.

There is deliberately no "accuracy": the operator's prompt names an intent, not a ground-truth label for the detectors.
Groups (per prompt, per model) are two VIEWS of the same runs; nothing is pooled across groups, and stub fixtures are scored
separately from real runs by the caller (``aggregate`` refuses to mix them).
"""
from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..common import BAD_LINE, BenchmarkError, iter_jsonl

SEV_ORDER = ("info", "low", "medium", "high", "critical")


def _read(path: Path) -> list[dict]:
    return [r for _, r in iter_jsonl(path) if r is not BAD_LINE and isinstance(r, dict)]


def score_run(run_dir: Path) -> dict[str, Any]:
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    files = run["files"]
    steps = _read(run_dir / files["transcript"])
    paths = [urlsplit(s["url"]).path or "/" for s in steps]
    out: dict[str, Any] = {
        "run_id": run["run_id"],
        "stub": bool(run["provenance"]["stub"]),
        "prompt": run["capture"].get("prompt", "unspecified"),
        "model": run["capture"].get("model", "unspecified"),
        "tool": run["capture"]["tool"],
        "steps": len(steps),
        "distinct_paths": len(set(paths)),
        "status_counts": dict(sorted(Counter(str(s["status"]) for s in steps).items())),
        "method_counts": dict(sorted(Counter(s["method"] for s in steps).items())),
        "leads": None, "report": None,
    }
    if "leads" in files:
        leads = _read(run_dir / files["leads"])
        real = [r for r in leads if r.get("event_type") == "honeytoken_hit"]
        out["leads"] = {
            "records": len(leads), "honeytoken_hits": len(real),
            "high_priority": sum(1 for r in real if r.get("priority") in ("high", "critical")),
            "decoy_kinds": dict(sorted(Counter(str(r.get("decoy_kind") or (r.get("decoy") or {}).get("kind") or "unknown") for r in real).items())),
            "any_honeytoken_hit": bool(real),
        }
    if "report" in files:
        rep = json.loads((run_dir / files["report"]).read_text(encoding="utf-8"))
        sess = rep.get("sessions", [])
        sev = [s.get("severity") for s in sess if s.get("severity") in SEV_ORDER]
        out["report"] = {
            "sessions": len(sess),
            "max_severity": max(sev, key=SEV_ORDER.index) if sev else None,
            "labels": dict(sorted(Counter(str(s.get("label")) for s in sess).items())),
            "harness_archetypes": dict(sorted(Counter(str(s.get("harness_archetype") or "unlabelled") for s in sess).items())),
        }
    return out


def _group(runs: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in runs:
        groups.setdefault(str(r[key]), []).append(r)
    out = {}
    for g, rs in sorted(groups.items()):
        withleads = [r for r in rs if r["leads"] is not None]
        out[g] = {
            "n_runs": len(rs),
            "median_steps": statistics.median(r["steps"] for r in rs),
            "runs_with_lead_log": len(withleads),
            "runs_with_any_honeytoken_hit": sum(1 for r in withleads if r["leads"]["any_honeytoken_hit"]),
            "runs_with_high_priority_lead": sum(1 for r in withleads if r["leads"]["high_priority"]),
        }
    return out


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-prompt and per-model descriptive stats.  All runs must be the same kind (all real or all stub)."""
    if len({r["stub"] for r in runs}) > 1:
        raise BenchmarkError("refusing to aggregate stub and real runs together")
    return {"kind": "stub_fixture" if runs and runs[0]["stub"] else "real_local", "n_runs": len(runs),
            "by_prompt": _group(runs, "prompt"), "by_model": _group(runs, "model"),
            "note": "descriptive counts only; n is small; 'by_prompt' and 'by_model' are two views of the same runs, not additive."}
