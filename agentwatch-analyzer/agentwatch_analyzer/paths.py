"""Locate the Sigma pack in a checkout or in an installed wheel."""
from __future__ import annotations

from pathlib import Path


def sigma_rules_dir() -> Path:
    """Directory of the 12 Sigma rules shipped with the analyzer.

    A source checkout and an editable install keep the pack at
    ``agentwatch-analyzer/rules/sigma``. A wheel copies those files to
    ``agentwatch_analyzer/sigma``.
    """
    pkg = Path(__file__).resolve().parent
    candidates = (
        pkg.parent / "rules" / "sigma",
        pkg / "sigma",
    )
    for path in candidates:
        if path.is_dir() and any(path.glob("*.yml")):
            return path
    return candidates[0]
