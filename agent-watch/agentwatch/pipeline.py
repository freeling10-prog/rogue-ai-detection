"""Glue: log files -> parsed requests -> sessions -> scored results."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from .parser import ParseResult, merge_results, parse_file
from .scoring import SessionResult, analyze_sessions
from .sessions import build_sessions


def run_pipeline(paths: Sequence[str | Path], cfg: dict[str, Any]) -> tuple[list[SessionResult], ParseResult]:
    """Parse every file (any supported format), session-ise and score."""
    parsed = merge_results([parse_file(p) for p in paths])
    sessions = build_sessions(parsed.requests, cfg)
    return analyze_sessions(sessions, cfg), parsed
