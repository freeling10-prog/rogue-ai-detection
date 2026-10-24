"""Offline-capable R8–R14 signal detectors for static access logs.

Honest limits: beacon booleans, challenge proofs, kinematic dwell, VLM scroll,
and insider R12 tool-chain gates are N/A without the honeypot / agent gateway.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from urllib.parse import parse_qs

from .linkgraph import build_offered_graph, classify_transition
from .parse import Event

BROWSER_UA = re.compile(r"(?i)mozilla/|chrome/|firefox/|safari/|edg/")
ASSET_RE = re.compile(r"(?i)\.(css|js|mjs|png|jpe?g|gif|webp|ico|svg|woff2?|ttf)(?:$|\?)")
SCHEMA_CURSOR = re.compile(r"(?i)cursor=prov\.schema\.|client_schema_rev=|schema_rev=")
MACHINE_PATHS = re.compile(r"(?i)/(openapi\.json|swagger|llms\.txt|robots\.txt|mcp|/api/v\d+/)")


@dataclass
class Finding:
    rule_id: str
    title: str
    session_key: str
    strength: float
    summary: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    offline: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


# Documented matrix (also emitted in report)
OFFLINE_MATRIX = {
    "R8": {"offline": True, "note": "UA claims browser + HTML pages without css/js asset fetches"},
    "R9": {"offline": True, "note": "Referer link-graph; stronger with sitemap or JSON links[]; weak parent-Referer fallback"},
    "R10": {"offline": "partial", "note": "schema cursor / machine-doc path patterns in query/path; decoy kinds need honeypot"},
    "R11": {"offline": False, "note": "beacon forged/missing, kinematic dwell, inversion, VLM — honeypot/beacon only"},
    "R12": {"offline": False, "note": "insider tool-chain hijack — agent-gateway / API telemetry, not web access logs"},
    "R13": {"offline": False, "note": "timing/adaptation signatures that need honeypot think-time instrumentation"},
    "R14": {"offline": "partial", "note": "interleaved disjoint Referer trees possible; human-beacon corroboration N/A offline"},
}


def _is_htmlish(e: Event) -> bool:
    if e.content_type and "html" in e.content_type.lower():
        return True
    if ASSET_RE.search(e.path):
        return False
    if e.method != "GET":
        return False
    if e.path.endswith((".json", ".txt", ".xml", ".js", ".css")):
        return False
    return e.status in (0, 200, 301, 302, 304)


def detect_r8(session_key: str, events: list[Event]) -> list[Finding]:
    pages = [e for e in events if _is_htmlish(e)]
    if len(pages) < 2:
        return []
    if not any(BROWSER_UA.search(e.ua or "") for e in events):
        return []
    assets = [e for e in events if ASSET_RE.search(e.path)]
    kinds = set()
    for e in assets:
        m = ASSET_RE.search(e.path)
        if m:
            ext = m.group(1).lower()
            kinds.add("css" if ext == "css" else "js" if ext in ("js", "mjs") else "image")
    if kinds & {"css", "js"}:
        return []
    return [Finding(
        "R8", "Asset starvation (offline)", session_key, 0.55,
        f"{len(pages)} HTML-like fetches with browser UA but no css/js assets in the log",
        evidence=[{"path": p.path, "ua": (p.ua or "")[:80]} for p in pages[:5]],
        atlas=["AML.T0053"],
        extra={"asset_kinds": sorted(kinds)},
    )]


def detect_r9(session_key: str, events: list[Event], graph: dict[str, set[str]]) -> list[Finding]:
    if not graph:
        # Abstain without link graph (honest offline limit) — unless we can use referer-parent weak mode
        weak_jumps = []
        prev = None
        for e in sorted(events, key=lambda x: x.ts):
            if not _is_htmlish(e) and not MACHINE_PATHS.search(e.path):
                prev = e if _is_htmlish(e) else prev
                continue
            st = classify_transition(e, prev, {})
            if st == "never_offered" and e.path not in ("/", "/index.html"):
                weak_jumps.append(e)
            if _is_htmlish(e):
                prev = e
        if len(weak_jumps) < 3:
            return []
        return [Finding(
            "R9", "Unlinked jump (weak offline — no sitemap/links)", session_key, 0.35,
            f"{len(weak_jumps)} navigations with missing/non-parent Referer and no sitemap link-graph; "
            "false positives likely (typed URLs, bookmarks). Provide --sitemap for a stronger R9.",
            evidence=[{"path": e.path, "referer": e.referer} for e in weak_jumps[:8]],
            atlas=["AML.T0053"],
            extra={"mode": "weak_no_graph"},
        )]
    jumps = []
    prev = None
    for e in sorted(events, key=lambda x: x.ts):
        if ASSET_RE.search(e.path):
            continue
        st = classify_transition(e, prev, graph)
        if st == "never_offered" and e.path not in ("/", "/index.html"):
            jumps.append((e, st))
        if _is_htmlish(e):
            prev = e
    if len(jumps) < 2:
        return []
    return [Finding(
        "R9", "Unlinked jump (Referer link-graph)", session_key, 0.6,
        f"{len(jumps)} path(s) not offered by prior page/sitemap edges",
        evidence=[{"path": e.path, "referer": e.referer, "status": st} for e, st in jumps[:10]],
        atlas=["AML.T0053"],
        extra={"mode": "graph"},
    )]


def detect_r10(session_key: str, events: list[Event]) -> list[Finding]:
    hits = []
    for e in events:
        q = e.query or ""
        if SCHEMA_CURSOR.search(q) or SCHEMA_CURSOR.search(e.path):
            hits.append(e)
        elif MACHINE_PATHS.search(e.path) and "schema" in (e.query or "").lower():
            hits.append(e)
    if not hits:
        return []
    return [Finding(
        "R10", "Schema/machine-doc pattern (partial offline)", session_key, 0.5,
        f"{len(hits)} request(s) with schema-cursor or machine-doc patterns; "
        "honeypot decoy kinds (mcp tool call, canary) are N/A offline",
        evidence=[{"path": e.path, "query": "[query-redacted]"} for e in hits[:8]],
        atlas=["AML.T0051", "AML.T0053"],
        extra={"offline": "partial"},
    )]


def detect_r14(session_key: str, events: list[Event]) -> list[Finding]:
    """Partial offline R14: interleaved depth on disjoint path prefixes within 500ms (no beacon corroboration)."""
    nav = [e for e in sorted(events, key=lambda x: x.ts) if not ASSET_RE.search(e.path)]
    if len(nav) < 6:
        return []

    def seg(p: str) -> str:
        parts = [x for x in p.split("/") if x]
        return parts[0] if parts else ""

    def parse_ts(e: Event) -> float:
        # coarse: rely on lexicographic ISO or count index
        return float(nav.index(e))

    # Use ordering index * 0.05s as pseudo-time if timestamps equal; prefer real if distinct
    from datetime import datetime
    times = []
    for e in nav:
        try:
            times.append(datetime.fromisoformat(e.ts.replace("Z", "+00:00")).timestamp())
        except Exception:
            times.append(float(len(times)))
    forks = []
    for i, e in enumerate(nav):
        ref = e.referer_path()
        if ref == "/" or (ref and e.path.startswith(ref.rstrip("/") + "/")):
            continue  # parent referer / BFS root — not a parasitic fork signal alone
        if ref:
            continue
        # missing referer on non-entry path while another nav with different segment is nearby
        for j, h in enumerate(nav):
            if i == j:
                continue
            if abs(times[i] - times[j]) > 0.5:
                continue
            if seg(e.path) and seg(h.path) and seg(e.path) != seg(h.path) and h.referer_path():
                forks.append(e)
                break
    if len(forks) < 2:
        return []
    return [Finding(
        "R14", "Parasitic-like interleaved disjoint trees (partial offline)", session_key, 0.45,
        f"{len(forks)} missing-Referer navigations interleaved with a different subtree within 500ms; "
        "human-beacon corroboration N/A offline — treat as advisory",
        evidence=[{"path": e.path, "referer": e.referer} for e in forks[:10]],
        atlas=["AML.T0075"],
        extra={"offline": "partial", "beacon_corroboration": False},
    )]


def na_findings() -> list[dict[str, Any]]:
    return [
        {"rule_id": rid, **meta}
        for rid, meta in OFFLINE_MATRIX.items()
        if meta["offline"] is False or meta["offline"] == "partial"
    ]


def analyze_sessions(
    by_key: dict[str, list[Event]],
    sitemap_paths: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    for key, evs in by_key.items():
        graph = build_offered_graph(evs, sitemap_paths)
        out.extend(detect_r8(key, evs))
        out.extend(detect_r9(key, evs, graph))
        out.extend(detect_r10(key, evs))
        out.extend(detect_r14(key, evs))
    return out


def findings_to_json(findings: list[Finding]) -> list[dict[str, Any]]:
    return [asdict(f) for f in findings]
