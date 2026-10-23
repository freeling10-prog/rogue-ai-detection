"""Per-agent feature extraction."""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Tuple

import numpy as np

from .schema import Event

FEATURE_NAMES = [
    "n_events", "rate_per_min", "iet_cv", "burstiness", "activity_entropy",
    "denied_ratio", "out_of_scope_ratio", "distinct_targets", "sensitive_hits",
    "ext_dest_ratio", "novel_tool_ratio", "ingest_then_ext_novel",
    "msg_ratio", "distinct_recipients", "text_entropy", "encoded_ratio", "log_max_payload",
]

SENSITIVE = re.compile(r"/(admin|secrets?|internal|credentials?|config)/|\.env\b|/\.ssh|id_rsa", re.I)
_BLOB = re.compile(r"[A-Za-z0-9+/=]{24,}")
BIN_S = 600.0  # activity-entropy bin width
INGEST_LINK_S = 120.0  # an external ingest "explains" a tool call within this many seconds


def _entropy_chars(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def group_by_agent(events: Sequence[Event]) -> Dict[str, List[Event]]:
    g: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        g[e.agent_id].append(e)
    for v in g.values():
        v.sort(key=lambda e: e.ts)
    return dict(g)


def novel_external_sequences(evs: List[Event], min_baseline_events: int = 20,
                             min_baseline_s: float = 1800.0) -> List[Tuple[Event, Event]]:
    """(ingest, tool_call) pairs where an agent pulled in external content and shortly after used an
    external-destination tool that was NEW to it. Mirrors indirect prompt injection followed by exfiltration
    through a tool (see report, injection section).

    Guards against false positives: "new" only counts once the agent has a baseline (at least
    ``min_baseline_events`` earlier events spanning ``min_baseline_s`` seconds), and agents that routinely use
    the tool are not matched. Once a tool has been introduced through such a sequence, later external uses of
    it that follow an ingest are counted too. Evasion path (documented in README): an agent that already uses
    the tool routinely would not match."""
    out: List[Tuple[Event, Event]] = []
    seen_tools: set = set()
    suspect: set = set()
    last_ingest = None
    first_ts = evs[0].ts if evs else 0.0
    for i, e in enumerate(evs):
        if e.ingest_external:
            last_ingest = e
        if e.kind == "tool_call":
            linked = e.dest_external and last_ingest is not None and e.ts - last_ingest.ts <= INGEST_LINK_S
            has_baseline = i >= min_baseline_events and (e.ts - first_ts) >= min_baseline_s
            if linked and ((e.target not in seen_tools and has_baseline) or e.target in suspect):
                out.append((last_ingest, e))
                suspect.add(e.target)
            seen_tools.add(e.target)
    return out


def agent_features(evs: List[Event], t_min: float, t_max: float) -> Dict[str, float]:
    n = len(evs)
    span_min = max((t_max - t_min) / 60.0, 1e-9)
    ts = np.array([e.ts for e in evs])
    gaps = np.diff(ts) if n > 1 else np.array([])
    if len(gaps) >= 2 and gaps.mean() > 0:
        mu, sd = float(gaps.mean()), float(gaps.std())
        cv = sd / mu
        burst = (sd - mu) / (sd + mu) if (sd + mu) > 0 else 0.0
    else:
        cv, burst = 1.0, 0.0
    nb = max(int(math.ceil((t_max - t_min) / BIN_S)), 1)
    counts = np.zeros(nb)
    for t in ts:
        counts[min(int((t - t_min) // BIN_S), nb - 1)] += 1
    p = counts[counts > 0] / counts.sum() if counts.sum() else np.array([1.0])
    ent = float(-(p * np.log2(p)).sum() / math.log2(nb)) if nb > 1 else 0.0

    denied = sum(e.status == "denied" for e in evs)
    oos = sum(not e.in_scope for e in evs)
    targets = {e.target for e in evs if e.kind in ("access", "read")}
    sens = sum(1 for e in evs if e.kind == "access" and SENSITIVE.search(e.target))
    tools = [e for e in evs if e.kind == "tool_call"]
    ext = sum(e.dest_external for e in evs)
    half = t_min + (t_max - t_min) / 2
    base_tools = {e.target for e in tools if e.ts < half}
    late = [e for e in tools if e.ts >= half]
    novel = sum(e.target not in base_tools for e in late) / len(late) if late and base_tools else 0.0
    msgs = [e for e in evs if e.kind == "message"]
    texts = [e.text for e in evs if e.text]
    enc = sum(bool(_BLOB.search(t)) for t in texts) / len(texts) if texts else 0.0
    return {
        "n_events": float(n),
        "rate_per_min": n / span_min,
        "iet_cv": cv,
        "burstiness": burst,
        "activity_entropy": ent,
        "denied_ratio": denied / n,
        "out_of_scope_ratio": oos / n,
        "distinct_targets": float(len(targets)),
        "sensitive_hits": float(sens),
        "ext_dest_ratio": ext / n,
        "novel_tool_ratio": novel,
        "ingest_then_ext_novel": float(len(novel_external_sequences(evs))),
        "msg_ratio": len(msgs) / n,
        "distinct_recipients": float(len({e.target for e in msgs})),
        "text_entropy": float(np.mean([_entropy_chars(t) for t in texts])) if texts else 0.0,
        "encoded_ratio": enc,
        "log_max_payload": math.log10(1 + max((e.payload_bytes for e in evs), default=0)),
    }


def extract_features(events: Sequence[Event], min_events: int = 5):
    """Return (agent_ids, matrix [n_agents x n_features], by_agent_events, (t_min, t_max)).

    Agents with fewer than ``min_events`` events are skipped (too little evidence to profile)."""
    if not events:
        raise ValueError("no events")
    g = group_by_agent(events)
    t_min = min(e.ts for e in events)
    t_max = max(e.ts for e in events)
    if t_max <= t_min:
        t_max = t_min + 1.0
    ids = sorted(a for a, v in g.items() if len(v) >= min_events)
    X = np.array([[agent_features(g[a], t_min, t_max)[f] for f in FEATURE_NAMES] for a in ids], dtype=float)
    return ids, X, g, (t_min, t_max)
