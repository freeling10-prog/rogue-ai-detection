"""MITRE ATLAS technique references used by the rule layer.

The IDs and names below were checked against the ATLAS data file ``dist/v6/ATLAS-2026.09.yaml``
(mitre-atlas/atlas-data) on 2026-10-22. The mapping from a *behavioral rule* to an ATLAS technique is
APPROXIMATE: ATLAS describes adversary techniques, while a rule here only observes symptoms that are
consistent with one. Treat tags as triage orientation, not as a finding.

``verify_against_yaml`` re-checks the table against a local copy of the ATLAS YAML (no network access).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

ATLAS_VERSION_CHECKED = "ATLAS-2026.09"

ATLAS_TECHNIQUES: Dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0075": "Enterprise Resource Discovery",
    # v6 additions.  Names copied from the agent-watch replay table (the sibling project); they were NOT re-checked against an ATLAS
    # YAML on this machine (none is present offline).  Run ``run.py check-atlas --yaml <local ATLAS file>`` before relying on them.
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0118": "Autonomous AI Agent Communication",
}
V6_UNVERIFIED = ("AML.T0080", "AML.T0118")      # listed for honesty: added without an offline re-check

ATLAS_MAPPING_NOTE = (
    "The MITRE ATLAS mapping is approximate: the rule observes behavior consistent with the technique, "
    "not proof of it. Verify against the evidence events before relying on the tag."
)


def atlas_ref(technique_id: str) -> Dict[str, str]:
    """Return a serialisable reference (id, name, url) for a technique id."""
    return {
        "id": technique_id,
        "name": ATLAS_TECHNIQUES[technique_id],
        "url": f"https://atlas.mitre.org/techniques/{technique_id}",
    }


def verify_against_yaml(yaml_path: str | Path) -> List[str]:
    """Check ATLAS_TECHNIQUES against a local ATLAS YAML file. Returns a list of problems (empty = OK).

    A tiny regex scan is used instead of a YAML parser to avoid an extra dependency; the ATLAS file layout
    is ``<id>:\\n    name: <name>`` for techniques.
    """
    text = Path(yaml_path).read_text(encoding="utf-8")
    problems: List[str] = []
    for tid, expected in ATLAS_TECHNIQUES.items():
        m = re.search(r"^\s+" + re.escape(tid) + r":\n\s+name: (.*)$", text, re.M)
        if not m:
            problems.append(f"{tid}: not found")
        elif m.group(1).strip().strip("'\"") != expected:
            problems.append(f"{tid}: name is {m.group(1)!r}, expected {expected!r}")
    return problems
