"""Alerts, MITRE ATLAS tagging, and a tamper-evident (hash-chained) alert log."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# IDs and names checked against the MITRE ATLAS v2026.09 data file (dist/v6/ATLAS-2026.09.yaml).
# The mapping from our detectors to techniques is APPROXIMATE and meant for triage orientation.
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0075": "Enterprise Resource Discovery",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0118": "Autonomous AI Agent Communication",
}

SEVERITIES = ("info", "low", "medium", "high")


def atlas_tags(ids: List[str]) -> List[Dict[str, str]]:
    return [{"id": i, "name": ATLAS[i], "url": f"https://atlas.mitre.org/techniques/{i}"} for i in ids]


@dataclass
class Alert:
    alert_id: str
    ts: float                     # event-time of the last evidence
    kind: str                     # access_probe | injection_exfil | hidden_channel | collusion_cluster |
                                  # scheduled_sync | behavior_anomaly
    severity: str
    subjects: List[str]
    score: float
    summary: str
    evidence: Dict = field(default_factory=dict)
    atlas: List[Dict[str, str]] = field(default_factory=list)
    synthetic: bool = True
    status: str = "open"

    def key(self) -> str:
        return self.kind + "|" + ",".join(sorted(self.subjects))

    def to_dict(self) -> Dict:
        return asdict(self)


def _canon(d: Dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


class AlertLog:
    """Append-only JSONL log. Each record stores ``prev_hash`` and ``hash`` = sha256(prev_hash + record).

    This detects accidental or casual tampering (edit, delete, reorder). It is not a substitute for
    external anchoring or WORM storage in a real deployment."""

    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._last = self.GENESIS
        self._keys = set()
        if os.path.exists(path):
            for rec in self.read():
                self._last = rec["hash"]
                self._keys.add(rec["alert"]["kind"] + "|" + ",".join(sorted(rec["alert"]["subjects"])))

    def has(self, alert: Alert) -> bool:
        return alert.key() in self._keys

    def append(self, alert: Alert) -> Dict:
        body = {"alert": alert.to_dict(), "prev_hash": self._last}
        h = hashlib.sha256((self._last + _canon(body["alert"])).encode()).hexdigest()
        rec = {**body, "hash": h}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self._last = h
        self._keys.add(alert.key())
        return rec

    def read(self) -> List[Dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def verify(self) -> Optional[int]:
        """Return None if the chain is intact, else the 1-based index of the first bad record."""
        prev = self.GENESIS
        for i, rec in enumerate(self.read(), 1):
            h = hashlib.sha256((prev + _canon(rec["alert"])).encode()).hexdigest()
            if rec["prev_hash"] != prev or rec["hash"] != h:
                return i
            prev = rec["hash"]
        return None
