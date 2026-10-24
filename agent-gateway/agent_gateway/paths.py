"""Locate the lab agent registry in a checkout or in an installed wheel."""
from __future__ import annotations

from pathlib import Path


def default_registry_path() -> Path:
    """``config/agents.json`` beside the package, or the copy inside a wheel.

    Editable installs and a source checkout use
    ``agent-gateway/config/agents.json``. A non-editable install copies that
    file to ``agent_gateway/data/agents.json`` at build time. Freeze and
    block still apply only to keys listed in that file.
    """
    pkg = Path(__file__).resolve().parent
    candidates = (
        pkg.parent / "config" / "agents.json",
        pkg / "data" / "agents.json",
    )
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]
