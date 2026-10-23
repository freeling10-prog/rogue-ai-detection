"""Intel-sharing export (STIX 2.1) and community report intake.

Everything exported from this prototype is labeled synthetic. The STIX bundle is structurally valid for the
object types used (identity, indicator) but has not been run through the OASIS validator in this project."""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from .alerts import Alert

_NS = uuid.UUID("6f1f6a52-0000-4000-8000-00000000a1a1")
_SEV_CONF = {"info": 10, "low": 30, "medium": 55, "high": 75}


def _ts(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_stix_bundle(alerts: List[Alert], min_severity: str = "medium") -> Dict:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    now = _ts(time.time())
    ident_id = "identity--" + str(uuid.uuid5(_NS, "rogue-ai-detection-prototype"))
    objs: List[Dict] = [{
        "type": "identity", "spec_version": "2.1", "id": ident_id, "created": now, "modified": now,
        "name": "Rogue AI Detection prototype (SYNTHETIC DATA)", "identity_class": "system",
        "description": "Demonstration producer. All indicators derive from synthetic data and are not real intelligence.",
    }]
    for al in alerts:
        if order[al.severity] < order[min_severity]:
            continue
        for s in al.subjects:
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": "indicator--" + str(uuid.uuid5(_NS, al.alert_id + "|" + s)),
                "created_by_ref": ident_id, "created": now, "modified": now,
                "name": f"{al.kind} candidate: {s}",
                "description": al.summary,
                "indicator_types": ["anomalous-activity"],
                "pattern": f"[user-account:user_id = '{s}']", "pattern_type": "stix",
                "valid_from": _ts(al.ts), "confidence": _SEV_CONF[al.severity],
                "labels": ["synthetic-example", al.kind],
                "external_references": [{"source_name": "mitre-atlas", "external_id": t["id"], "url": t["url"],
                                         "description": t["name"]} for t in al.atlas],
                "x_synthetic": True,
                "x_review_status": "unreviewed - a behavioral flag, not an attribution",
            })
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}


# ----------------------------------------------------------------------------- community reports

_SECRETISH = re.compile(r"(?i)(api[_-]?key|secret|passw(or)?d|token|bearer)\s*[:=]\s*\S+|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def validate_report(form: Dict[str, str]) -> Dict[str, str]:
    """Validate a community report. Returns cleaned fields or raises ValueError with a user-facing message."""
    ref = (form.get("agent_ref") or "").strip()
    desc = (form.get("description") or "").strip()
    cat = (form.get("category") or "").strip()
    url = (form.get("evidence_url") or "").strip()
    if not (1 <= len(ref) <= 100):
        raise ValueError("Agent reference is required (up to 100 characters).")
    if not (20 <= len(desc) <= 2000):
        raise ValueError("Description must be 20 to 2000 characters.")
    if cat not in ("unauthorized_access", "coordination", "injection_misuse", "other"):
        raise ValueError("Choose a category.")
    if url and not re.match(r"^https?://[^\s]+$", url):
        raise ValueError("Evidence link must be an http(s) URL or left blank.")
    for field_name, val in (("agent reference", ref), ("description", desc)):
        if _SECRETISH.search(val):
            raise ValueError(f"Your {field_name} looks like it contains a credential. Remove it and resubmit.")
        if _EMAIL.search(val):
            raise ValueError(f"Your {field_name} contains an email address. Please remove personal data.")
    return {"agent_ref": ref, "description": desc, "category": cat, "evidence_url": url}


def store_report(clean: Dict[str, str], path: str) -> Dict:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    rec = {"report_id": "CR-" + uuid.uuid4().hex[:8], "received": _ts(time.time()), "status": "unreviewed",
           "note": "Prototype: stored locally only; nothing is sent to anyone.", **clean}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def load_reports(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]
