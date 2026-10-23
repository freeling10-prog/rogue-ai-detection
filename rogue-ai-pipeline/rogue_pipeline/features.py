"""Per-agent feature extraction (input: pseudonymized ``NormalizedEvent`` only).

Feature families
    Timing    event_rate_per_min, iet_cv, hour_entropy
    Access    denied_to_allowed_ratio, sensitive_hits
    Tool use  external_dest_ratio, new_tool_ratio, new_ext_host_ratio

"New" tool / host means: first seen in the second half of the observation window while absent from the first
half. It is a deliberately simple notion of a *pattern shift*; agents with too little first-half history get
0 (no baseline, no claim).
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence, Tuple

import numpy as np

from .schema import NormalizedEvent


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    family: str
    label: str                       # plain-language name used in explanations
    fmt: Callable[[float], str]      # value formatter for explanations
    higher_means: str                # plain-language reading of an unusually HIGH value
    lower_means: str                 # ... of an unusually LOW value


def _f2(v: float) -> str:
    return f"{v:.2f}"


FEATURES: Tuple[FeatureSpec, ...] = (
    FeatureSpec("event_rate_per_min", "timing", "Event rate", lambda v: f"{v:.2f} events/min",
                "far busier than peers", "much quieter than peers"),
    FeatureSpec("iet_cv", "timing", "Irregularity of timing (variation of gaps between events)", _f2,
                "bursty, irregular activity", "unusually regular, machine-like timing"),
    FeatureSpec("hour_entropy", "timing", "Spread of activity across the 24 hours of the day", _f2,
                "active evenly around the clock", "activity concentrated in a few hours"),
    FeatureSpec("denied_to_allowed_ratio", "access", "Denied-to-allowed request ratio", _f2,
                "many more refused requests than peers", "fewer refusals than peers"),
    FeatureSpec("sensitive_hits", "access", "Requests touching sensitive resources", lambda v: f"{v:.0f}",
                "touching sensitive resources far more than peers", "touching fewer sensitive resources"),
    FeatureSpec("external_dest_ratio", "tool_use", "Share of events sent to or fetched from external hosts", _f2,
                "much more external traffic than peers", "less external traffic than peers"),
    FeatureSpec("new_tool_ratio", "tool_use", "Share of late tool calls using tools not used earlier", _f2,
                "recently started using new tools", "no change in tool use"),
    FeatureSpec("new_ext_host_ratio", "tool_use", "Share of late external calls to hosts not contacted earlier", _f2,
                "recently started contacting new external hosts", "no change in external hosts"),
)
FEATURE_NAMES: Tuple[str, ...] = tuple(f.name for f in FEATURES)
_SPEC: Dict[str, FeatureSpec] = {f.name: f for f in FEATURES}


@dataclass
class FeatureTable:
    agents: List[str]
    X: np.ndarray                                   # shape (n_agents, n_features)
    events_by_agent: Dict[str, List[NormalizedEvent]]
    window: Tuple[float, float]

    def row(self, agent: str) -> Dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.X[self.agents.index(agent)]))


def group_events(events: Sequence[NormalizedEvent]) -> Dict[str, List[NormalizedEvent]]:
    g: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if not isinstance(e, NormalizedEvent):  # structural guard: raw / un-pseudonymized events are refused
            raise TypeError("feature extraction accepts NormalizedEvent only (pseudonymize first)")
        g[e.agent].append(e)
    for v in g.values():
        v.sort(key=lambda e: e.ts)
    return dict(g)


def _hour_entropy(ts: np.ndarray) -> float:
    hours = ((ts % 86400) // 3600).astype(int)
    counts = np.bincount(hours, minlength=24).astype(float)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum() / math.log2(24))


def agent_feature_vector(evs: List[NormalizedEvent], t0: float, t1: float, min_baseline: int = 10) -> np.ndarray:
    n = len(evs)
    ts = np.array([e.ts for e in evs])
    span_min = max((t1 - t0) / 60.0, 1e-9)
    gaps = np.diff(ts)
    cv = float(gaps.std() / gaps.mean()) if len(gaps) >= 2 and gaps.mean() > 0 else 1.0
    denied = sum(e.denied for e in evs)
    allowed = n - denied
    half = t0 + (t1 - t0) / 2
    first = [e for e in evs if e.ts < half]
    late = [e for e in evs if e.ts >= half]
    have_base = len(first) >= min_baseline
    tools_first = {e.tool for e in first if e.action == "tool_call"}
    late_tools = [e for e in late if e.action == "tool_call"]
    new_tool = (sum(e.tool not in tools_first for e in late_tools) / len(late_tools)) if (have_base and tools_first and late_tools) else 0.0
    hosts_first = {e.dest_host for e in first if e.dest_external}
    late_ext = [e for e in late if e.dest_external]
    new_host = (sum(e.dest_host not in hosts_first for e in late_ext) / len(late_ext)) if (have_base and late_ext) else 0.0
    return np.array([
        n / span_min,
        cv,
        _hour_entropy(ts),
        denied / (allowed + 1.0),
        float(sum(e.sensitive for e in evs)),
        sum(e.dest_external for e in evs) / n,
        new_tool,
        new_host,
    ], dtype=float)


def build_feature_table(events: Sequence[NormalizedEvent], min_events: int = 8) -> FeatureTable:
    """Group events per pseudonymous agent and compute the feature matrix (agents with < min_events skipped)."""
    if not events:
        raise ValueError("no events to profile")
    g = group_events(events)
    t0 = min(e.ts for e in events)
    t1 = max(e.ts for e in events)
    if t1 <= t0:
        t1 = t0 + 1.0
    agents = sorted(a for a, v in g.items() if len(v) >= min_events)
    X = np.vstack([agent_feature_vector(g[a], t0, t1) for a in agents]) if agents else np.zeros((0, len(FEATURES)))
    return FeatureTable(agents, X, g, (t0, t1))


def spec(name: str) -> FeatureSpec:
    return _SPEC[name]


def session_feature_vector(evs: List[NormalizedEvent], entropy_min_span_s: float = 10800.0) -> np.ndarray:
    """Features for ONE agent/session scored on its own, with no population (online / frozen-baseline mode).

    Differences from batch mode: the observation window is the session's own first-to-last event span (at least
    60 s) instead of the batch span, and hour-of-day entropy is NaN when the session is shorter than
    ``entropy_min_span_s`` (a short session is always 'concentrated in one hour'; that says nothing). NaN is
    imputed with the reference median by the caller. Training and scoring MUST use this same function."""
    evs = sorted(evs, key=lambda e: e.ts)
    t0, t1 = evs[0].ts, max(evs[-1].ts, evs[0].ts + 60.0)
    v = agent_feature_vector(evs, t0, t1)
    if (t1 - t0) < entropy_min_span_s:
        v[FEATURE_NAMES.index("hour_entropy")] = np.nan
    return v
