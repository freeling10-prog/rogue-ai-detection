"""Session building.

1. Group by (IP, user agent) and split on an idle gap.
2. Optionally re-join same-IP sessions when a client was blocked (403/429) and
   a *different* user agent appears shortly afterwards - that is UA rotation,
   and without this step the evasion would hide inside separate sessions.
"""
from __future__ import annotations

import hashlib
from bisect import bisect_left
from collections import defaultdict
from typing import Any

from .models import Request, Session


def _split_on_gap(reqs: list[Request], idle_gap_s: float) -> list[list[Request]]:
    chunks: list[list[Request]] = []
    cur: list[Request] = []
    for r in reqs:
        if cur and (r.ts - cur[-1].ts).total_seconds() > idle_gap_s:
            chunks.append(cur)
            cur = []
        cur.append(r)
    if cur:
        chunks.append(cur)
    return chunks


def build_sessions(requests: list[Request], cfg: dict[str, Any]) -> list[Session]:
    """Turn a time-sorted request list into sessions (see module docstring)."""
    scfg = cfg["session"]
    blocks = set(scfg["block_statuses"])
    groups: dict[tuple[str, str], list[Request]] = defaultdict(list)
    for r in requests:
        groups[(r.ip, r.ua)].append(r)

    chunks_by_ip: dict[str, list[list[Request]]] = defaultdict(list)
    for (ip, _ua), reqs in groups.items():
        chunks_by_ip[ip].extend(_split_on_gap(reqs, float(scfg["idle_gap_s"])))

    sessions: list[Session] = []
    for ip, chunks in chunks_by_ip.items():
        parent = list(range(len(chunks)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        if scfg["link_ua_rotation"] and len(chunks) > 1:
            gap = float(scfg["rotation_link_gap_s"])
            stamps = [[r.ts for r in c] for c in chunks]
            for a, ca in enumerate(chunks):
                for r in ca:
                    if r.status not in blocks:
                        continue
                    for b, cb in enumerate(chunks):
                        if a == b or find(a) == find(b):
                            continue
                        j = bisect_left(stamps[b], r.ts)
                        if j < len(cb) and cb[j].ua != r.ua and (cb[j].ts - r.ts).total_seconds() <= gap:
                            parent[find(b)] = find(a)

        merged: dict[int, list[Request]] = defaultdict(list)
        for i, c in enumerate(chunks):
            merged[find(i)].extend(c)
        for reqs in merged.values():
            reqs.sort(key=lambda r: r.ts)
            sid = "s-" + hashlib.sha1(f"{ip}|{reqs[0].ts.isoformat()}".encode()).hexdigest()[:8]
            sessions.append(Session(session_id=sid, ip=ip, requests=reqs))

    sessions.sort(key=lambda s: (s.start, s.ip))
    return sessions
