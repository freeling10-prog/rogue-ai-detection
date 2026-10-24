"""v6 R13 statistics: sequential CUSUM over boundary-probing actions, multi-horizon micro-window densities and the timing
"sub-window variance collapse" check - plus the calibration routine that sets their thresholds from BENIGN data only.

Why: an adversary wrapped in a constrained-MDP controller can pad probes with benign requests so that every SESSION AVERAGE
(denied ratio, sensitive hits ...) stays inside human percentiles.  Averages forget order; a CUSUM log-likelihood ratio does not:
a steady trickle of probes at rate p1 among benign events at rate p0 has positive drift and accumulates, while benign sessions
(rate <= p0) drift down to zero.  Micro-windows (W=3, W=7 consecutive events) catch short bursts that a full-session average
dilutes.  ``subwindow_variance_collapse`` flags timing that is unnaturally regular in EVERY sub-window yet not a clock (a pacing
controller), which benign Poisson-like traffic and bursty humans do not produce; strict crons are excluded explicitly.

All of it is deterministic arithmetic over pseudonymous normalized events.  Nothing here learns from attack data.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

import numpy as np

from .config import ProbingCfg
from .schema import NormalizedEvent


def is_probe(e: NormalizedEvent) -> bool:
    """Boundary-probing action: a REFUSED request that targets a sensitive resource, an explicit access check, or (web) a page/API
    URL that does not exist / is refused AND was not reached by following a link (a guessed URL).  Refused reads of ordinary documents
    (a misconfigured benign agent), dead links a crawler or person followed, and allowed sensitive reads (a compliance scanner doing
    its job) are not probes."""
    if not e.denied:
        return False
    if e.sensitive or e.action == "access" and e.web is None:
        return True
    w = e.web
    return (w is not None and w.content_kind in ("html", "api", "other") and not w.is_entry
            and not (w.linked_from_prev is True or w.referer_valid is True))


def _order(evs: Sequence[NormalizedEvent]) -> List[NormalizedEvent]:
    """Events that count as 'actions' for R13: everything except page sub-resources and beacons (a browser loading 4 assets per
    page would otherwise dilute every window)."""
    return [e for e in sorted(evs, key=lambda x: x.ts)
            if e.web is None or e.web.content_kind not in ("asset", "beacon")]


def _target(e: NormalizedEvent) -> str:
    return e.web.path_key if e.web is not None and e.web.path_key else e.resource_key


def probe_vector(ordered: Sequence[NormalizedEvent]) -> List[int]:
    """1 for the FIRST boundary-probing action on each resource, 0 otherwise.  A client retrying the same refused resource (backoff
    after a permission change) learns nothing new from the retry, and a refusal that the SAME session later gets served (a transient
    5xx / timeout followed by a successful retry) was not a boundary at all; a prober has to touch NEW resources that stay refused."""
    served = {_target(e) for e in ordered if not e.denied}
    seen: set = set()
    out: List[int] = []
    for e in ordered:
        hit = 0
        if is_probe(e):
            key = _target(e)
            if key not in seen and key not in served:
                seen.add(key)
                hit = 1
        out.append(hit)
    return out


@dataclass
class ProbingStats:
    n_events: int
    n_probes: int
    cusum_max: float
    w3_max: int
    w7_max: int
    session_density: float
    collapse: bool
    collapse_detail: Dict[str, float] = field(default_factory=dict)
    cusum_peak_index: int = -1
    cusum_low: float = 0.0
    probe_ids: List[str] = field(default_factory=list)


def cusum(x: Sequence[int], p0: float, p1: float) -> tuple[float, int]:
    """Bernoulli CUSUM: S_t = max(0, S_{t-1} + log-likelihood ratio of event t under p1 vs p0).  Returns (max S, index of the max)."""
    up, down = math.log(p1 / p0), math.log((1 - p1) / (1 - p0))
    s, best, at = 0.0, 0.0, -1
    for i, v in enumerate(x):
        s = max(0.0, s + (up if v else down))
        if s > best:
            best, at = s, i
    return best, at


def _window_max(x: Sequence[int], w: int) -> int:
    if not x:
        return 0
    if len(x) < w:
        return int(sum(x))
    c = np.convolve(np.asarray(x, dtype=int), np.ones(w, dtype=int), mode="valid")
    return int(c.max())


def timing_collapse(ts: Sequence[float], cfg: ProbingCfg) -> tuple[bool, Dict[str, float]]:
    """True when the session has >= ``collapse_min_windows`` sub-windows of ``collapse_window`` inter-request gaps, EVERY sub-window has
    a std of log-gaps below ``collapse_max_logstd``, the sub-window means are within ``collapse_max_mean_spread`` of each other, and the
    session is NOT strictly periodic (CV of gaps >= ``collapse_min_cv``; crons are periodic and are left to graph suppression)."""
    g = np.diff(np.sort(np.asarray(ts, dtype=float)))
    g = g[g > 0.05]                                   # sub-50 ms gaps are page/asset bursts, not decisions
    n_win = len(g) // cfg.collapse_window
    if n_win < cfg.collapse_min_windows:
        return False, {"windows": float(n_win)}
    lg = np.log(g[: n_win * cfg.collapse_window]).reshape(n_win, cfg.collapse_window)
    stds, means = lg.std(axis=1), lg.mean(axis=1)
    cv = float(g.std() / g.mean()) if g.mean() > 0 else 0.0
    detail = {"windows": float(n_win), "max_window_logstd": round(float(stds.max()), 3),
              "mean_spread": round(float(means.max() - means.min()), 3), "gap_cv": round(cv, 3)}
    ok = bool(stds.max() <= cfg.collapse_max_logstd and (means.max() - means.min()) <= cfg.collapse_max_mean_spread
              and cv >= cfg.collapse_min_cv)
    return ok, detail


def stats(evs: Sequence[NormalizedEvent], cfg: ProbingCfg) -> ProbingStats:
    ordered = _order(evs)
    x = probe_vector(ordered)
    cm, at = cusum(x, cfg.p0, cfg.p1)
    lo, _ = cusum(x, cfg.p0, cfg.p1_low)
    col, det = timing_collapse([e.ts for e in ordered], cfg)
    return ProbingStats(len(ordered), sum(x), round(cm, 3), _window_max(x, 3), _window_max(x, 7),
                        round(sum(x) / len(x), 4) if x else 0.0, col, det, cusum_peak_index=at, cusum_low=round(lo, 3),
                        probe_ids=[e.event_id for e, v in zip(ordered, x) if v])


# ----------------------------------------------------------------------------------------------------------------- calibration
@dataclass
class Calibration:
    """Thresholds derived from BENIGN sessions only.  ``source`` names the data so the numbers can be reproduced."""
    n_sessions: int
    p0: float
    cusum_max_benign: float
    cusum_h: float
    cusum_low_max_benign: float
    cusum_h_low: float
    w3_max_benign: int
    w7_max_benign: int
    w3_min: int
    w7_min: int
    logstd_q01: float
    collapse_max_logstd: float
    collapse_hits_benign: int
    source: str = ""

    def as_dict(self) -> Dict[str, object]:
        return dict(self.__dict__)


def calibrate(benign_by_agent: Mapping[str, Sequence[NormalizedEvent]], cfg: Optional[ProbingCfg] = None, *, source: str = "",
              h_margin: float = 1.25, p0_quantile: float = 0.99, logstd_quantile: float = 0.01) -> Calibration:
    """p0 = ``p0_quantile`` of benign per-session probe rates (>= 0.005); h = benign max CUSUM (under that p0) x ``h_margin`` and never
    below 3 net probes' worth of log-likelihood; W3/W7 minimums = benign maxima + 1 (W+1 = that window is DISABLED because some
    benign session already saturates it); the collapse log-std threshold = half
    the ``logstd_quantile`` of benign per-session MAX sub-window log-std (so ordinary Poisson / bursty timing never collapses)."""
    cfg = cfg or ProbingCfg()
    sessions = [_order(v) for v in benign_by_agent.values()]
    sessions = [s for s in sessions if len(s) >= cfg.min_events]
    vecs = [probe_vector(s) for s in sessions]
    rates = [sum(v) / len(v) for v in vecs]
    p0 = max(0.005, float(np.quantile(rates, p0_quantile))) if rates else cfg.p0
    p1 = max(cfg.p1, 3 * p0)
    cm = [cusum(v, p0, p1)[0] for v in vecs]
    floor_h = 3 * math.log(p1 / p0)
    h = max(floor_h, (max(cm) if cm else 0.0) * h_margin)
    p1l = max(cfg.p1_low, 1.5 * p0)
    cml = [cusum(v, p0, p1l)[0] for v in vecs]
    h_low = max(3 * math.log(p1l / p0), (max(cml) if cml else 0.0) * h_margin)
    w3 = max((_window_max(v, 3) for v in vecs), default=0)
    w7 = max((_window_max(v, 7) for v in vecs), default=0)
    stds: List[float] = []
    for s in sessions:
        _, d = timing_collapse([e.ts for e in s], cfg)
        if "max_window_logstd" in d and d["gap_cv"] >= cfg.collapse_min_cv:     # clocks are excluded by the CV test anyway
            stds.append(d["max_window_logstd"])
    q = float(np.quantile(stds, logstd_quantile)) if stds else cfg.collapse_max_logstd * 2
    thr = round(q / 2, 3)
    probe_cfg = cfg.model_copy(update={"collapse_max_logstd": max(thr, 1e-3)})
    hits = sum(timing_collapse([e.ts for e in s], probe_cfg)[0] for s in sessions)
    return Calibration(len(sessions), round(p0, 4), round(max(cm) if cm else 0.0, 3), round(h, 3),
                       round(max(cml) if cml else 0.0, 3), round(h_low, 3), w3, w7, min(4, w3 + 1), min(8, w7 + 1),
                       round(q, 3), thr, hits, source)


def calibrate_many(groups: Iterable[Mapping[str, Sequence[NormalizedEvent]]], cfg: Optional[ProbingCfg] = None, source: str = "") -> Calibration:
    merged: Dict[str, Sequence[NormalizedEvent]] = {}
    for i, g in enumerate(groups):
        for a, v in g.items():
            merged[f"{i}:{a}"] = v
    return calibrate(merged, cfg, source=source)
