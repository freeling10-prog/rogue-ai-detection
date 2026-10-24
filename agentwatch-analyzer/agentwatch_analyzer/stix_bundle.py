"""STIX 2.1 indicator bundle generator for offline findings (lab/SOC export).

Validates with pinned stix2-validator==3.2.0 when installed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import stix2

from .scrub import scrub_text

ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0118": "Autonomous AI Agent Communication",
    "AML.T0075": "RAG Poisoning",  # approximate orientation for R14-like session fork labels
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_bundle(findings: list[dict[str, Any]], *, producer_name: str = "agentwatch-analyzer") -> tuple[str, dict[str, Any]]:
    """Return (bundle_json, validation_summary)."""
    identity = stix2.Identity(
        name=producer_name,
        identity_class="organization",
        description="Offline static web-log analyzer (lab). Not a honeypot.",
    )
    marking = stix2.MarkingDefinition(
        definition_type="statement",
        definition={"statement": "TLP:CLEAR — synthetic/lab or operator-owned logs; review before sharing."},
    )
    objects: list[Any] = [identity, marking]
    patterns_used = set()

    attack_patterns = {}
    for tech, name in ATLAS.items():
        ap = stix2.AttackPattern(
            name=name,
            description=f"Approximate ATLAS mapping ({tech}) for orientation only.",
            external_references=[{
                "source_name": "mitre-atlas",
                "external_id": tech,
                "url": f"https://atlas.mitre.org/techniques/{tech}",
            }],
        )
        attack_patterns[tech] = ap
        objects.append(ap)

    for f in findings:
        rule = f.get("rule_id") or "Rx"
        # STIX pattern: observe URL path prefix from evidence (scrubbed)
        paths = []
        for ev in (f.get("evidence") or [])[:5]:
            p = scrub_text(str(ev.get("path") or ""), drop_query=True)
            if p and p not in paths:
                paths.append(p)
        if not paths:
            paths = ["/"]
        # Simple observation expression
        clauses = [f"url:value = '{p.replace(chr(39), '')}'" for p in paths[:3]]
        pattern = f"[{' OR '.join(clauses)}]"
        if pattern in patterns_used:
            continue
        patterns_used.add(pattern)
        ind = stix2.Indicator(allow_custom=True, 
            name=f"offline-{rule}-{f.get('session_key', 'sess')[:32]}",
            description=scrub_text(str(f.get("summary") or ""), drop_query=True)[:500],
            pattern=pattern,
            pattern_type="stix",
            valid_from=_now(),
            confidence=40,
            indicator_types=["anomalous-activity"],
            object_marking_refs=[marking.id],
            custom_properties={
                "x_agentwatch_rule": rule,
                "x_offline_analysis": True,
                "x_atlas_approx": list(f.get("atlas") or []),
            },
        )
        objects.append(ind)
        for tech in f.get("atlas") or []:
            ap = attack_patterns.get(tech)
            if ap:
                objects.append(stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=ind.id,
                    target_ref=ap.id,
                ))
        objects.append(stix2.Note(
            content=(
                "Human-review lead from offline log analysis. Beacon/VLM/R11–R13 signals were N/A. "
                "ATLAS mappings are approximate. Do not execute any captured agent text."
            ),
            object_refs=[ind.id],
            abstract="Offline analysis caveat",
        ))

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    bundle_json = bundle.serialize(pretty=False)
    summary = validate_bundle(bundle_json)
    return bundle_json, summary


def validate_bundle(bundle_json: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "parsed_ok": False,
        "validator_available": False,
        "validator_ok": None,
        "messages": [],
        "object_count": 0,
    }
    try:
        parsed = stix2.parse(bundle_json, allow_custom=True)
        out["parsed_ok"] = True
        out["object_count"] = len(getattr(parsed, "objects", []) or [])
    except Exception as e:  # noqa: BLE001
        out["messages"].append(f"parse: {e}")
        return out
    try:
        from stix2validator import validate_string, ValidationOptions
        out["validator_available"] = True
        res = validate_string(bundle_json, ValidationOptions(version="2.1"))
        out["validator_ok"] = bool(getattr(res, "is_valid", False))
        for err in list(getattr(res, "errors", []) or [])[:20]:
            out["messages"].append(str(err))
        for w in list(getattr(res, "warnings", []) or [])[:10]:
            out["messages"].append(f"WARN: {w}")
    except ImportError:
        out["validator_available"] = False
    except Exception as e:  # noqa: BLE001
        out["validator_available"] = True
        out["validator_ok"] = False
        out["messages"].append(str(e))
    return out
