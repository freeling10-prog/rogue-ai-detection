"""Tier-2 ingestion validator.  One run == one directory (run.json + transcript.jsonl [+ leads.jsonl, access.jsonl, report.json]).

Hard rules: loopback-only targets / transcript URLs / client IPs; schema-valid files; no secret patterns anywhere in the run;
STUB fixtures are accepted only with ``allow_stub=True`` and can never be mistaken for real captures (real_capture must be false,
run_id must start with STUB-).  Errors never echo record content.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from ..common import BAD_LINE, iter_jsonl
from ..minischema import validate
from ..secrets_guard import scan_file

HERE = Path(__file__).resolve().parent
RUN_SCHEMA = json.loads((HERE / "schema" / "run.schema.json").read_text(encoding="utf-8"))
LINE_SCHEMA = json.loads((HERE / "schema" / "transcript_line.schema.json").read_text(encoding="utf-8"))
LEAD_SCHEMA_ID = "agentwatch.lead/1"
ACCESS_SCHEMA_ID = "agentwatch.access/1"
MAX_TRANSCRIPT_LINES = 10_000


def is_loopback_host(host: Optional[str]) -> bool:
    """Literal check, no DNS: ``localhost`` or an IP literal in 127.0.0.0/8 or ::1."""
    if not host:
        return False
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def url_is_loopback(url: str) -> bool:
    try:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or p.username or p.password:
            return False
        return is_loopback_host(p.hostname)
    except ValueError:
        return False


@dataclass
class RunResult:
    run_dir: Path
    run: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    secret_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and not self.secret_findings

    @property
    def run_id(self) -> str:
        return str(self.run.get("run_id", self.run_dir.name))

    @property
    def stub(self) -> bool:
        return bool(self.run.get("provenance", {}).get("stub"))


def _jsonl(path: Path, errs: list[str], label: str) -> list[tuple[int, dict]]:
    out: list[tuple[int, dict]] = []
    bad = 0
    for n, rec in iter_jsonl(path):
        if rec is BAD_LINE or not isinstance(rec, dict):
            bad += 1
            errs.append(f"{label}:{n}: not a JSON object")
            continue
        out.append((n, rec))
    if len(out) > MAX_TRANSCRIPT_LINES:
        errs.append(f"{label}: more than {MAX_TRANSCRIPT_LINES} records")
    return out


def validate_run_dir(run_dir: Path, allow_stub: bool = False) -> RunResult:
    res = RunResult(run_dir=run_dir)
    errs = res.errors
    run_json = run_dir / "run.json"
    if not run_json.is_file():
        errs.append("run.json: missing")
        return res
    try:
        run = json.loads(run_json.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        errs.append("run.json: not valid JSON")
        return res
    res.run = run if isinstance(run, dict) else {}
    errs += [f"run.json {e}" for e in validate(run, RUN_SCHEMA)]
    if errs:
        return res
    prov, cap = run["provenance"], run["capture"]
    if not url_is_loopback(cap["target"]):
        errs.append("run.json capture.target: not a loopback URL")
    if prov["stub"]:
        if not allow_stub:
            errs.append("run.json: STUB fixture rejected (only the test suite may pass allow_stub)")
        if prov["real_capture"]:
            errs.append("run.json: stub=true is incompatible with real_capture=true")
        if not run["run_id"].startswith("STUB-"):
            errs.append("run.json: stub runs must have a run_id starting with STUB-")
    else:
        if not prov["real_capture"]:
            errs.append("run.json: a non-stub run must declare real_capture=true (what was run, by whom, is in the notes)")
        if run["run_id"].startswith("STUB-"):
            errs.append("run.json: run_id STUB- prefix is reserved for stubs")
        if prov.get("operator_attests_loopback_only") is not True:
            errs.append("run.json provenance.operator_attests_loopback_only must be true for real captures")
    if cap["tool"] == "redteam/llm_agent.py" and not cap.get("model"):
        errs.append("run.json capture.model: required for llm_agent.py runs")
    # files: plain names inside the run dir only
    resolved: dict[str, Path] = {}
    for key, name in run["files"].items():
        if Path(name).name != name or name in ("", ".", ".."):
            errs.append(f"run.json files.{key}: must be a plain file name inside the run directory")
            continue
        p = run_dir / name
        if not p.is_file():
            errs.append(f"files.{key}: {name} missing")
        else:
            resolved[key] = p
    if errs:
        return res
    # transcript
    steps = _jsonl(resolved["transcript"], errs, "transcript")
    if not steps:
        errs.append("transcript: empty")
    last = -1
    for n, rec in steps:
        errs += [f"transcript:{n} {e}" for e in validate(rec, LINE_SCHEMA)]
        if isinstance(rec.get("url"), str) and not url_is_loopback(rec["url"]):
            errs.append(f"transcript:{n}: URL is not loopback")
        if isinstance(rec.get("step"), int):
            if rec["step"] < last:
                errs.append(f"transcript:{n}: step numbers go backwards")
            last = rec["step"]
    for key, sid, ipkey in (("leads", LEAD_SCHEMA_ID, "source_ip"), ("access", ACCESS_SCHEMA_ID, "client_ip")):
        if key in resolved:
            for n, rec in _jsonl(resolved[key], errs, key):
                if rec.get("schema") != sid:
                    errs.append(f"{key}:{n}: schema must be {sid}")
                ip = rec.get(ipkey)
                if not isinstance(ip, str) or not is_loopback_host(ip):
                    errs.append(f"{key}:{n}: {ipkey} is not loopback (non-local traffic mixed into a local capture?)")
                if not isinstance(rec.get("timestamp"), str):
                    errs.append(f"{key}:{n}: missing timestamp")
    if "report" in resolved:
        try:
            rep = json.loads(resolved["report"].read_text(encoding="utf-8"))
            if not isinstance(rep, dict) or rep.get("schema") != "agentwatch.report/1":
                errs.append("report: not an agentwatch.report/1 file")
        except ValueError:
            errs.append("report: not valid JSON")
    for p in [run_json, *resolved.values()]:
        res.secret_findings += scan_file(p, f"{run_dir.name}/{p.name}")
    return res


def validate_slot(slot: Path, allow_stub: bool = False) -> list[RunResult]:
    """Validate every run directory in a slot (directories only; dot-files such as .gitkeep are ignored)."""
    if not slot.is_dir():
        return []
    return [validate_run_dir(d, allow_stub) for d in sorted(slot.iterdir()) if d.is_dir() and not d.name.startswith(".")]
