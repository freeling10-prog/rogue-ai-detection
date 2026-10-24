"""Post-taint boolean-oracle and timing side-channel guard (approximate AML.T0086).

Once a session is both TAINTED and SENSITIVE_READ, the PEP already holds
writes, sends, and query-parameter egress. What still leaves is a bare
external read, or a constrained sink such as ``update_ticket_status``. A
compromised loop can still leak a secret through those, without ever
writing it: one bit per call through *which* URL it fetches or which enum it
picks (a boolean oracle), or through *when* it calls (a timing beacon). No
n-gram of the secret appears, so ``deobfuscate.py`` cannot see it.

This guard watches released outbound calls after the trifecta point and
flags ``covert_side_channel_suspected`` when any of these holds:

- ``branching``: more than ``max_distinct`` distinct argument variants
  (tool + canonical argument hash), the alphabet an oracle encodes into
- ``cardinality``: more than ``max_calls`` outbound calls in total (a
  two-URL oracle leaks at most ``max_calls`` bits before it is held)
- ``timing_beacon``: at least ``beacon_min_intervals`` inter-call intervals
  with a mean of at least ``beacon_min_mean_s`` and a coefficient of
  variation at or below ``beacon_max_cv`` (a regular rhythm, not a burst)

A call a person released with a bound one-time OOB token is not counted.
On a signal the PEP denies the call, holds the session for review, and
freezes the registered root key for 15 minutes.

Pure arithmetic on timestamps and SHA-256 argument hashes. The arguments
themselves are not stored.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

ATLAS_SIDE_CHANNEL = "AML.T0086"


@dataclass(frozen=True)
class SideChannelPolicy:
    max_distinct: int = 4
    max_calls: int = 16
    beacon_min_intervals: int = 5
    beacon_max_cv: float = 0.1
    beacon_min_mean_s: float = 0.5
    window: int = 64


@dataclass
class _SessionTrack:
    times: deque = field(default_factory=lambda: deque(maxlen=64))
    variants: set = field(default_factory=set)
    calls: int = 0


@dataclass
class SideChannelSignal:
    reason: str
    calls: int
    distinct: int
    interval_mean_s: Optional[float] = None
    interval_cv: Optional[float] = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reason": self.reason, "post_taint_calls": self.calls,
                               "distinct_variants": self.distinct,
                               "atlas": ATLAS_SIDE_CHANNEL, "atlas_approximate": True}
        if self.interval_mean_s is not None:
            out["interval_mean_s"] = round(self.interval_mean_s, 4)
            out["interval_cv"] = round(self.interval_cv or 0.0, 4)
        return out


def variant_key(tool_name: str, arguments: Any) -> str:
    raw = json.dumps({"t": tool_name, "a": arguments}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def interval_stats(times: list[float]) -> tuple[Optional[float], Optional[float], int]:
    """(mean, coefficient of variation, n) of the gaps between timestamps."""
    gaps = [b - a for a, b in zip(times, times[1:])]
    if not gaps:
        return None, None, 0
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return mean, None, len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return mean, math.sqrt(var) / mean, len(gaps)


class SideChannelGuard:
    def __init__(self, policy: Optional[SideChannelPolicy] = None):
        self.policy = policy or SideChannelPolicy()
        self._tracks: dict[str, _SessionTrack] = {}

    def _track(self, session_id: str) -> _SessionTrack:
        t = self._tracks.get(session_id)
        if t is None:
            t = self._tracks[session_id] = _SessionTrack(times=deque(maxlen=self.policy.window))
        return t

    def check(self, session_id: str, tool_name: str, arguments: Any, now: float) -> Optional[SideChannelSignal]:
        """Would releasing this post-trifecta call cross a threshold? Read-only."""
        p = self.policy
        t = self._tracks.get(session_id) or _SessionTrack()
        key = variant_key(tool_name, arguments)
        distinct = len(t.variants | {key})
        calls = t.calls + 1
        if distinct > p.max_distinct:
            return SideChannelSignal("branching", calls, distinct)
        if calls > p.max_calls:
            return SideChannelSignal("cardinality", calls, distinct)
        # Only the latest run of intervals counts, so an old rhythm stops flagging once it stops.
        recent = [*t.times, now][-(p.beacon_min_intervals + 1):]
        mean, cv, n = interval_stats(recent)
        if (n >= p.beacon_min_intervals and mean is not None and mean >= p.beacon_min_mean_s
                and cv is not None and cv <= p.beacon_max_cv):
            return SideChannelSignal("timing_beacon", calls, distinct, mean, cv)
        return None

    def commit(self, session_id: str, tool_name: str, arguments: Any, now: float) -> None:
        t = self._track(session_id)
        t.variants.add(variant_key(tool_name, arguments))
        t.calls += 1
        t.times.append(now)

    def stats(self, session_id: str) -> dict[str, Any]:
        t = self._tracks.get(session_id) or _SessionTrack()
        mean, cv, n = interval_stats(list(t.times))
        return {"post_taint_calls": t.calls, "distinct_variants": len(t.variants),
                "intervals": n, "interval_mean_s": mean, "interval_cv": cv}
