"""Glue: log files -> parsed requests -> sessions -> scored results."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from .models import Request
from .parser import ParseResult, merge_results, parse_file
from .scoring import SessionResult, analyze_sessions
from .sessions import build_sessions


def merge_mirror(requests: list[Request]) -> tuple[list[Request], int]:
    """Collapse mirrored access records that describe the same request as a honeypot lead.

    The honeypot writes every request to the mirrored access stream; requests that were also decoy hits additionally
    produce a lead (same request, richer detail).  Counting both would double the session's request count, so the lead is
    kept (it carries the decoy kind and detail) and takes over the mirror's link graph / content type; the mirror record
    is dropped.  Mirror records whose lead is not in the input (leads withheld) stay as ordinary log requests.
    Returns (requests, number of mirror records merged away)."""
    leads = {r.event_id: r for r in requests if r.event_id and not r.lead_event_id}
    if not leads:
        return requests, 0
    kept: list[Request] = []
    merged = 0
    for r in requests:
        lead = leads.get(r.lead_event_id) if r.lead_event_id else None
        if lead is None:
            kept.append(r)
            continue
        if lead.served_links is None:
            lead.served_links = r.served_links
        lead.content_type = lead.content_type or r.content_type
        lead.beacon_offered = lead.beacon_offered or r.beacon_offered
        lead.ja4, lead.ja4h = lead.ja4 or r.ja4, lead.ja4h or r.ja4h
        lead.beacon = lead.beacon or r.beacon                      # v6: a beacon_forged lead keeps its booleans
        lead.cursor_route = lead.cursor_route or r.cursor_route
        lead.cursor_prov = lead.cursor_prov or r.cursor_prov
        lead.signals = sorted(set(lead.signals) | set(r.signals))
        merged += 1
    return kept, merged


def run_pipeline(paths: Sequence[str | Path], cfg: dict[str, Any]) -> tuple[list[SessionResult], ParseResult]:
    """Parse every file (any supported format), session-ise and score."""
    parsed = merge_results([parse_file(p) for p in paths])
    parsed.requests, parsed.mirror_merged = merge_mirror(parsed.requests)
    sessions = build_sessions(parsed.requests, cfg)
    return analyze_sessions(sessions, cfg), parsed
