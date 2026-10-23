"""Tier-3 ingestion validator.  A slot directory holds ``provenance.json`` + ``*.access.jsonl`` and/or ``*.leads.jsonl`` (+ optional
``*.report.json``).  Strict about structure, tolerant about field aliases (nginx JSON log formats name fields differently).
Errors never echo record content.  The secret gate lives in build_benchmark / secrets_guard and runs BEFORE anything is packaged."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..common import BAD_LINE, iter_jsonl
from ..minischema import validate

HERE = Path(__file__).resolve().parent
PROV_SCHEMA = json.loads((HERE / "schema" / "provenance.schema.json").read_text(encoding="utf-8"))
ACCESS_ID, LEAD_ID = "agentwatch.access/1", "agentwatch.lead/1"
ALIASES = {
    "ts": ("timestamp", "time_iso8601", "time", "@timestamp"),
    "ip": ("client_ip", "remote_addr", "source_ip", "ip"),
    "method": ("method", "request_method"),
    "path": ("path", "uri", "request_uri"),
    "status": ("status",),
}


def pick(rec: dict[str, Any], what: str) -> Any:
    for k in ALIASES[what]:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


def parse_ts(v: Any) -> Optional[datetime]:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        try:
            return datetime.utcfromtimestamp(float(v))
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


@dataclass
class Tier3Input:
    root: Path
    provenance: dict[str, Any] = field(default_factory=dict)
    access_files: list[Path] = field(default_factory=list)
    lead_files: list[Path] = field(default_factory=list)
    report_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.access_files or self.lead_files or self.report_files) and not self.provenance


def load_slot(root: Path) -> Tier3Input:
    """Validate a slot.  An absent/empty slot (only dot-files) is valid and yields ``empty=True``."""
    inp = Tier3Input(root=root)
    if not root.is_dir():
        return inp
    entries = [p for p in sorted(root.iterdir()) if not p.name.startswith(".")]
    if not entries:
        return inp
    errs = inp.errors
    for p in entries:
        if p.is_dir():
            errs.append(f"{p.name}: subdirectories are not allowed in a tier3 slot")
        elif p.name == "provenance.json":
            continue
        elif p.name.endswith(".access.jsonl"):
            inp.access_files.append(p)
        elif p.name.endswith(".leads.jsonl"):
            inp.lead_files.append(p)
        elif p.name.endswith(".report.json"):
            inp.report_files.append(p)
        else:
            errs.append(f"{p.name}: unrecognised file (expected provenance.json, *.access.jsonl, *.leads.jsonl, *.report.json)")
    prov = root / "provenance.json"
    if not prov.is_file():
        errs.append("provenance.json: missing (required for any wild data)")
    else:
        try:
            inp.provenance = json.loads(prov.read_text(encoding="utf-8"))
            errs += [f"provenance.json {e}" for e in validate(inp.provenance, PROV_SCHEMA)]
        except (ValueError, UnicodeDecodeError):
            errs.append("provenance.json: not valid JSON")
    if not (inp.access_files or inp.lead_files):
        errs.append("no *.access.jsonl or *.leads.jsonl files found")
    for kind, files in (("access", inp.access_files), ("lead", inp.lead_files)):
        for f in files:
            _check_jsonl(f, kind, errs)
    for f in inp.report_files:
        try:
            rep = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(rep, dict) or rep.get("schema") != "agentwatch.report/1":
                errs.append(f"{f.name}: not an agentwatch.report/1 file")
        except ValueError:
            errs.append(f"{f.name}: not valid JSON")
    return inp


def _check_jsonl(path: Path, kind: str, errs: list[str]) -> None:
    want = ACCESS_ID if kind == "access" else LEAD_ID
    n_ok = 0
    for n, rec in iter_jsonl(path):
        if rec is BAD_LINE or not isinstance(rec, dict):
            errs.append(f"{path.name}:{n}: not a JSON object")
            continue
        sch = rec.get("schema")
        if sch is not None and sch != want:
            errs.append(f"{path.name}:{n}: schema is not {want}")
            continue
        if kind == "lead" and sch is None:
            errs.append(f"{path.name}:{n}: lead records must carry schema {want}")
            continue
        miss = [w for w in ("ts", "ip", "method", "path", "status") if pick(rec, w) is None and not (kind == "lead" and w in ("method", "path", "status"))]
        if kind == "lead":
            req = rec.get("request") if isinstance(rec.get("request"), dict) else {}
            miss = [w for w in miss if w not in ("method", "path", "status")]
            if not (rec.get("event_type") and (req.get("path") or rec.get("path"))):
                miss.append("event_type/path")
        if miss:
            errs.append(f"{path.name}:{n}: missing field(s): {', '.join(miss)}")
            continue
        if parse_ts(pick(rec, "ts")) is None:
            errs.append(f"{path.name}:{n}: unparseable timestamp")
            continue
        n_ok += 1
    if n_ok == 0:
        errs.append(f"{path.name}: no valid records")
