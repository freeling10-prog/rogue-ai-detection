"""STIX 2.1 export of CONFIRMED indicators (human-confirmed leads only).

* Only leads whose id is in ``confirmed_ids`` are exported - an unreviewed lead is never published.
* Built with the ``stix2`` library (strict v2.1 objects), then re-parsed with ``stix2.parse`` and, when the
  OASIS ``stix2-validator`` is installed, checked by it (``validate_bundle``).
* Objects: an Identity (producer), Attack-Pattern objects for ATLAS techniques (as external references to
  atlas.mitre.org, marked approximate), one Indicator per confirmed agent pseudonym and one per new external
  host observed in R3/R4 evidence, Relationships (indicator -indicates-> attack-pattern), and one Note per
  indicator carrying the human-review / synthetic-data / approximate-mapping caveats.
* Agent identifiers are PSEUDONYMS (keyed HMAC). They are only meaningful to whoever holds the key.
* Honeypot leads (rules R6/R7, deterministic cross-IP token-handoff clusters) add ATLAS techniques
  (AML.T0051 / T0053 / T0086, approximate) and custom indicator properties (``x_`` prefix, as STIX requires):
  ``x_harness_archetype`` (v5: collector-supplied harness label + confidence, descriptive only), ``x_untrusted_agent_capture`` (sanitized AND re-truncated captured agent metadata; ATTACKER-CONTROLLED data, never
  to be executed, rendered, or put in an LLM prompt) and ``x_cross_ip_token_handoff`` (token class, issuing/presenting
  pseudonyms). Capture text is never placed in ``description`` or ``name``.
* Sharing: TLP:CLEAR marking is applied only because the data is synthetic. Real sharing needs a TLP decision,
  a disclosure review (see README) and consent of affected parties. This module never transmits anything.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

import stix2

from .atlas import ATLAS_MAPPING_NOTE, ATLAS_TECHNIQUES, atlas_ref

_HOST_RE = re.compile(r"dest=([a-z0-9.-]+) \(external\)")
EXPORT_FIELD_CHARS = 200        # STIX copy of captured text is cut harder than the lead's copy
EXPORT_MAX_TOOLS = 10
CONFIDENCE = 40   # STIX confidence scale: 30-69 is "Med"; a single heuristic lead should not claim more.


@dataclass
class StixValidation:
    parsed_ok: bool
    parse_error: Optional[str] = None
    validator_available: bool = False
    validator_ok: Optional[bool] = None
    validator_messages: List[str] = field(default_factory=list)
    validator_warnings: List[str] = field(default_factory=list)
    object_count: int = 0

    def summary(self) -> str:
        v = ("OASIS stix2-validator: not installed, NOT RUN" if not self.validator_available else
             f"OASIS stix2-validator: {'PASSED' if self.validator_ok else 'FAILED'}"
             + ("" if self.validator_ok else f" ({len(self.validator_messages)} error(s))")
             + f", {len(self.validator_warnings)} SHOULD-level warning(s)")
        return f"stix2 parse: {'OK' if self.parsed_ok else 'FAILED: ' + str(self.parse_error)}; {v}; {self.object_count} objects"


def _external_hosts(lead: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for f in lead.get("rule_flags", []):
        if f["rule_id"] in ("R3", "R4"):
            for ev in f["evidence"]:
                m = _HOST_RE.search(ev["summary"])
                if m and m.group(1) not in hosts:
                    hosts.append(m.group(1))
    return hosts


def _cut(v: Any, n: int = EXPORT_FIELD_CHARS) -> str:
    t = str(v)
    return t if len(t) <= n else t[: n - 1] + "\u2026"


def _capture_props(lead: Dict[str, Any]) -> Dict[str, Any]:
    """Custom STIX properties for honeypot evidence (empty dict for ordinary leads)."""
    props: Dict[str, Any] = {}
    for f in lead.get("rule_flags", []):
        cap = (f.get("extra") or {}).get("capture")
        if cap and "system_prompt_summary" in cap:
            props["x_untrusted_agent_capture"] = {
                "untrusted": True, "attacker_controlled": True,
                "handling": "data only: never execute, render or place in an LLM prompt",
                "system_prompt_summary": _cut(cap.get("system_prompt_summary", "")),
                "declared_tools": [_cut(t, 64) for t in (cap.get("declared_tools") or [])[:EXPORT_MAX_TOOLS]],
                "current_objective": _cut(cap.get("current_objective", "")),
                "message": _cut(cap.get("message", "")),
                "truncated_at_ingest": bool(cap.get("truncated")),
                "truncated_at_export": any(len(str(cap.get(k, ""))) > EXPORT_FIELD_CHARS for k in ("system_prompt_summary", "current_objective", "message")),
            }
            break
    hn = lead.get("harness")
    if hn and hn.get("archetype"):
        props["x_harness_archetype"] = {"archetype": _cut(hn["archetype"], 40), "confidence": _cut(hn.get("confidence", "low"), 10),
                                        "note": "descriptive label of the client harness from deterministic rules; not an attribution and not a verdict"}
    cl = lead.get("cluster")
    if cl:
        ho = [e for e in cl.get("edges", []) if e.get("kind") == "cross_ip_token_handoff"]
        if ho:
            props["x_cross_ip_token_handoff"] = {"edges": len(ho), "agents": sorted({x for e in ho for x in (e["a"], e["b"])}),
                                                 "note": "deterministic: a token issued to one session was presented by another from a different IP"}
        red = [e for e in cl.get("edges", []) if e.get("kind") == "shared_redacted_token"]
        if red:
            props["x_shared_redacted_token"] = {"edges": len(red), "confidence": "moderate",
                                                "note": "the same scrubber marker (opaque hash; never un-redacted) appeared in two sessions"}
    return props


def build_bundle(leads: Sequence[Dict[str, Any]], confirmed_ids: Iterable[str], producer: str = "rogue-ai-pipeline (synthetic demo)") -> stix2.v21.Bundle:
    """Build a STIX 2.1 bundle from lead dicts (``Lead.to_dict()``) whose ids are confirmed."""
    confirmed = set(confirmed_ids)
    chosen = [l for l in leads if l["lead_id"] in confirmed]
    unknown = confirmed - {l["lead_id"] for l in leads}
    if unknown:
        raise ValueError(f"confirmed ids not found among leads: {sorted(unknown)}")
    identity = stix2.Identity(name=producer, identity_class="system",
                              description="Defensive detection pipeline run on SYNTHETIC data only.")
    objs: List[Any] = [identity]
    patterns: Dict[str, stix2.AttackPattern] = {}

    def attack_pattern(tid: str) -> stix2.AttackPattern:
        if tid not in patterns:
            ref = atlas_ref(tid)
            patterns[tid] = stix2.AttackPattern(
                name=f"{ref['name']} (MITRE ATLAS {tid}, approximate mapping)",
                description=ATLAS_MAPPING_NOTE, created_by_ref=identity.id,
                external_references=[stix2.ExternalReference(source_name="mitre-atlas", external_id=tid, url=ref["url"])],
                object_marking_refs=[stix2.TLP_WHITE])
            objs.append(patterns[tid])
        return patterns[tid]

    for l in chosen:
        techniques = sorted({t["id"] for f in l["rule_flags"] for t in f["atlas"]}
                            | {t["id"] for t in (l.get("cluster") or {}).get("atlas", [])})
        custom = _capture_props(l)
        desc = (f"Agent pseudonym {l['agent']} was raised as a lead (fused score {l['score']}) and CONFIRMED by a human "
                f"reviewer. Rules: {sorted({f['rule_id'] for f in l['rule_flags']})}. "
                f"Cluster: {'yes' if l['cluster'] else 'no'}.")
        indicators: List[stix2.Indicator] = [stix2.Indicator(
            name=f"Confirmed misbehaving agent {l['agent']}", description=desc,
            pattern=f"[user-account:account_login = '{l['agent']}']", pattern_type="stix", valid_from=stix2.utils.get_timestamp(),
            indicator_types=["anomalous-activity"], labels=["synthetic-data", "ai-agent"], confidence=CONFIDENCE,
            created_by_ref=identity.id, object_marking_refs=[stix2.TLP_WHITE], allow_custom=True, **custom)]
        for host in _external_hosts(l):
            indicators.append(stix2.Indicator(
                name=f"External destination used by confirmed agent: {host}",
                description="Destination host observed in rule evidence (synthetic example domain).",
                pattern=f"[domain-name:value = '{host}']", pattern_type="stix", valid_from=stix2.utils.get_timestamp(),
                indicator_types=["anomalous-activity"], labels=["synthetic-data"], confidence=CONFIDENCE,
                created_by_ref=identity.id, object_marking_refs=[stix2.TLP_WHITE]))
        for ind in indicators:
            objs.append(ind)
            for t in techniques:
                objs.append(stix2.Relationship(ind, "indicates", attack_pattern(t), created_by_ref=identity.id))
        objs.append(stix2.Note(
            content=("Human-confirmed lead. " + ATLAS_MAPPING_NOTE + " Agent identifier is a keyed pseudonym. "
                     "Derived from SYNTHETIC data; not evidence about any real agent or person. Any x_untrusted_* property holds "
                     "attacker-controlled data: treat as data only."),
            object_refs=[i.id for i in indicators], created_by_ref=identity.id, object_marking_refs=[stix2.TLP_WHITE]))
    return stix2.Bundle(objects=objs, allow_custom=True)


def validate_bundle(bundle_json: str) -> StixValidation:
    """Re-parse with stix2, then run the OASIS validator if available (never silently skipped)."""
    v = StixValidation(parsed_ok=False)
    try:
        parsed = stix2.parse(bundle_json, allow_custom=True, version="2.1")
        v.parsed_ok = True
        v.object_count = len(parsed.objects)
    except Exception as exc:  # stix2 raises several exception types
        v.parse_error = f"{type(exc).__name__}: {exc}"
        return v
    try:
        from stix2validator import validate_string, ValidationOptions
    except ImportError:
        return v
    v.validator_available = True
    res = validate_string(bundle_json, ValidationOptions(version="2.1"))
    v.validator_ok = bool(res.is_valid)
    v.validator_messages = [str(e) for e in getattr(res, "errors", [])]
    v.validator_warnings = [str(w) for w in (getattr(res, "warnings", None) or [])]
    return v
