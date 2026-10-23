"""Near-real-time monitoring by replaying events through a sliding window.

The replay simulates a live stream using synthetic data. Every ``step_s`` seconds of event-time it re-runs the
full pipeline on the trailing ``window_s`` seconds and appends any NEW alert (deduplicated by kind+subjects)
to the hash-chained alert log. A real deployment would swap the replay for a streaming consumer."""
from __future__ import annotations

from typing import Callable, List, Optional, Sequence

from .alerts import Alert, AlertLog
from .pipeline import analyze
from .schema import Event

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def replay(events: Sequence[Event], log: AlertLog, window_s: float = 3 * 3600, step_s: float = 900,
           min_events: int = 400, min_severity: str = "info",
           on_alert: Optional[Callable[[Alert, float], None]] = None) -> List[Alert]:
    evs = sorted(events, key=lambda e: e.ts)
    if not evs:
        return []
    t_start, t_end = evs[0].ts, evs[-1].ts
    emitted: List[Alert] = []
    clusters: List[tuple] = []  # (member set, max severity emitted) for overlap suppression
    t = t_start + step_s
    while True:
        t_now = min(t, t_end)
        win = [e for e in evs if t_now - window_s <= e.ts <= t_now]
        if len(win) >= min_events:
            try:
                an = analyze(win)
            except ValueError:
                an = None
            if an:
                for al in an.alerts:
                    if SEV_ORDER[al.severity] < SEV_ORDER[min_severity] or log.has(al):
                        continue
                    if al.kind == "collusion_cluster":
                        # a growing window re-discovers the same group with shifting membership: suppress
                        # overlapping clusters unless severity escalates
                        m = set(al.subjects)
                        hit = next((i for i, (ms, sv) in enumerate(clusters)
                                    if len(m & ms) / min(len(m), len(ms)) >= 0.5), None)
                        if hit is not None:
                            ms, sv = clusters[hit]
                            if SEV_ORDER[al.severity] <= sv:
                                clusters[hit] = (ms | m, sv)
                                continue
                            clusters[hit] = (ms | m, SEV_ORDER[al.severity])
                        else:
                            clusters.append((m, SEV_ORDER[al.severity]))
                    al.ts = min(al.ts, t_now)
                    log.append(al)
                    emitted.append(al)
                    if on_alert:
                        on_alert(al, t_now)
        if t_now >= t_end:
            break
        t += step_s
    return emitted
