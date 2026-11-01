"""Offline executive audit report for agentwatch-analyzer output directories.

Reads the files an analyzer smoke writes (``events.scrubbed.jsonl``,
``findings.json``, ``leads.jsonl``, ``replay.html``, ``stix-bundle.json``,
``summary.json``) and writes a self-contained HTML report plus a text PDF.

This module does not bind a port, start a honeypot, or open a socket.
Secrets are scrubbed before they are written. ``agw1.`` capability signatures
are not copied into the report.
"""
from __future__ import annotations

import html
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import toxic_combinations
from . import sarif_export
from .audit_chain import DECISION_LOG_NAME, write_manifest
from .capability import parse, verify
from .scrub import scrub_text

SCHEMA = "agent-gateway.audit-report/1"
EXPECTED_FILES = (
    "events.scrubbed.jsonl",
    "findings.json",
    "leads.jsonl",
    "replay.html",
    "stix-bundle.json",
    "summary.json",
)
TRACKED = (
    ("AML.T0051", "LLM Prompt Injection"),
    ("AML.T0080", "AI Agent Context Poisoning"),
    ("AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
)
ATLAS_NAMES = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0075": "RAG Poisoning",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0118": "Autonomous AI Agent Communication",
}
_EXFIL_TOOLS = frozenset({
    "web.fetch",
    "http.request",
    "http.get",
    "http.post",
    "send_email",
    "browser.fetch",
    "fetch_url",
    "curl",
})
INVENTORY_NAME = "tool-inventory.json"
GATEWAY_FINDING_KINDS = (
    "toxic_combinations",
    "tool_output_injection",
    "ssrf_boundary_violation",
    "covert_side_channel_suspected",
    "deobfuscated_exfil_detected",
    "mcp_rug_pull_detected",
    "confused_deputy_delegation_blocked",
    "arg_firewall_violation",
    "canary_watermark_exfil",
    "schema_drift_denied",
    "tool_shadowing_denied",
    "gui_region_denied",
    "gui_keychord_denied",
    "provenance_tamper_denied",
    "sharded_exfil_denied",
    "MCP_DEFINITION_DRIFT",
    "MCP_TOOL_SHADOWING",
    "MCP_DESCRIPTION_POISONING",
    "WORKSPACE_CONFIG_WRITE",
    "WORKSPACE_HOOK_TAMPER",
    "WORKSPACE_SYMLINK_ESCAPE",
    "WORKSPACE_HIDDEN_DIRECTIVE",
    "CFI_TAINTED_PRIVILEGED_SINK",
    "CFI_UNENDORSED_TARGET",
    "STEGO_SECRET_SHINGLE_LEAK",
    "STEGO_SUBSEQUENCE_EXFIL",
    "INTERPRETER_PROTECTED_WRITE",
    "INTERPRETER_OBFUSCATED_PIPE",
    "INTERPRETER_DANGEROUS_PRIMITIVE",
    "MCP_FIRST_SEEN_OVERPRIVILEGED",
    "MCP_SCHEMA_PURPOSE_MISMATCH",
    "MCP_TOOL_NAMESPACE_FLOOD",
    "COLLUSION_CROSS_AGENT_LAUNDERING",
    "COLLUSION_SPLIT_TOXIC_CHAIN",
    "COLLUSION_CYCLIC_AMPLIFICATION",
    "REGISTRY_PIN_DRIFT",
    "REGISTRY_ALIAS_AMBIGUOUS",
    "WORKSPACE_EFFECT_DENIED",
    "FLOW_MANIFEST_DENIED",
    "SIMILARITY_LEAK_DENIED",
    "OBLIGATION_PROTOCOL_DENIED",
    "FS_LABEL_FLOW_DENIED",
    "ARGUMENT_CONFINEMENT_DENIED",
    "FORK_JOIN_LEDGER_DENIED",
    "DYNAMIC_INGRESSION_DENIED",
    "TRANSFORM_INVARIANT_DENIED",
    "CAUSALITY_LAUNDERING_DENIED",
    "EVENT_CHANNEL_CAPACITY_DENIED",
    "BLINDFOLD_PERTURBATION_DENIED",
    "REACHABILITY_CONFINEMENT_DENIED",
)
_EXFIL_EGRESS = frozenset({"external_read", "send", "write", "creds"})
_ATLAS_RE = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")
_AGW1_RE = re.compile(r"agw1\.[A-Za-z0-9_-]{8,}\.[0-9a-f]{64}")
_MAX_EVENTS = 20000
_MAX_REPLAY_CHARS = 1_500_000
_PDF_NOTE = (
    "audit-report.pdf is a text rendering of these figures, written by a "
    "pure-Python PDF writer. WeasyPrint and wkhtmltopdf are optional and are "
    "not required."
)


class AuditInputError(ValueError):
    """The input directory is missing or has none of the analyzer JSON artifacts."""


@dataclass
class LoadedAudit:
    source_dir: Path
    events: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    summary: dict[str, Any]
    stix_objects: Optional[int]
    replay_text: Optional[str]
    source_log: str
    missing: list[str]
    notes: list[str] = field(default_factory=list)


@dataclass
class PathRow:
    disposition: str
    tool: str
    session: str
    tainted: bool
    capability: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "session": self.session,
            "tainted": self.tainted,
            "capability": self.capability,
            "reason": self.reason,
        }


def _public(text: Any, limit: int = 240) -> str:
    raw = text if isinstance(text, str) else "" if text is None else str(text)
    cleaned = _AGW1_RE.sub("agw1.[redacted]", raw)
    cleaned = scrub_text(cleaned)
    cleaned = _AGW1_RE.sub("agw1.[redacted]", cleaned)
    return cleaned[:limit]


def _parent_id(tech: str) -> str:
    parts = tech.split(".")
    if len(parts) >= 3 and parts[0] == "AML" and parts[1].startswith("T"):
        return f"{parts[0]}.{parts[1]}"
    return tech


def _ids_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return _ATLAS_RE.findall(value)
    if isinstance(value, list):
        found: list[str] = []
        for item in value:
            found.extend(_ids_in(item) if not isinstance(item, str) else _ATLAS_RE.findall(item))
        return found
    return []


def _record_atlas(obj: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for key in ("atlas", "atlas_id", "technique", "techniques"):
        if key in obj:
            found.extend(_ids_in(obj.get(key)))
    extra = obj.get("extra")
    if isinstance(extra, dict):
        for key in ("atlas", "atlas_id", "technique"):
            if key in extra:
                found.extend(_ids_in(extra.get(key)))
    seen: list[str] = []
    for tech in found:
        if tech not in seen:
            seen.append(tech)
    return seen


def _dedup_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(finding.get("rule_id") or ""),
        str(finding.get("session_key") or ""),
        str(finding.get("summary") or ""),
    )


def _load_json(path: Path, notes: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        notes.append(f"{path.name} could not be parsed ({exc.__class__.__name__}).")
        return None


def _finding_rows(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return [row for row in doc if isinstance(row, dict)]
    if isinstance(doc, dict):
        rows = doc.get("findings")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _load_jsonl(path: Path, notes: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    skipped = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        notes.append(f"{path.name} could not be read ({exc.__class__.__name__}).")
        return rows
    for line in lines:
        if not line.strip():
            continue
        if len(rows) >= _MAX_EVENTS:
            notes.append(f"Stopped after {_MAX_EVENTS} events.")
            break
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(obj, dict):
            rows.append(obj)
        else:
            skipped += 1
    if skipped:
        notes.append(f"Skipped {skipped} malformed line(s) in {path.name}.")
    return rows


def load_audit_dir(path: Path, *, allow_empty: bool = False) -> LoadedAudit:
    """Load an analyzer output directory. Raises AuditInputError when it cannot.

    ``allow_empty`` permits a tool-list-only audit (no analyzer outputs).
    """
    if not path.is_dir():
        raise AuditInputError(f"not a directory: {path}")
    missing = [name for name in EXPECTED_FILES if not (path / name).is_file()]
    notes: list[str] = []
    if missing:
        notes.append("Missing input file(s): " + ", ".join(missing) + ".")

    events: list[dict[str, Any]] = []
    if (path / "events.scrubbed.jsonl").is_file():
        events = _load_jsonl(path / "events.scrubbed.jsonl", notes)

    findings: list[dict[str, Any]] = []
    source_log = ""
    findings_doc = None
    if (path / "findings.json").is_file():
        findings_doc = _load_json(path / "findings.json", notes)
        findings = _finding_rows(findings_doc)
        if isinstance(findings_doc, dict) and isinstance(findings_doc.get("source_log"), str):
            source_log = findings_doc["source_log"]
    seen = {_dedup_key(row) for row in findings}
    if (path / "leads.jsonl").is_file():
        for row in _load_jsonl(path / "leads.jsonl", notes):
            key = _dedup_key(row)
            if key in seen:
                continue
            # Leads that are not finding-shaped (no rule id and no atlas) are not matches.
            if not row.get("rule_id") and not _record_atlas(row):
                continue
            findings.append(row)
            seen.add(key)

    summary: dict[str, Any] = {}
    if (path / "summary.json").is_file():
        loaded = _load_json(path / "summary.json", notes)
        if isinstance(loaded, dict):
            summary = loaded
            if not source_log and isinstance(loaded.get("source_log"), str):
                source_log = loaded["source_log"]

    stix_objects: Optional[int] = None
    if (path / "stix-bundle.json").is_file():
        bundle = _load_json(path / "stix-bundle.json", notes)
        if isinstance(bundle, dict) and isinstance(bundle.get("objects"), list):
            stix_objects = len(bundle["objects"])
    if stix_objects is None and isinstance(summary.get("stix"), dict):
        count = summary["stix"].get("object_count")
        if isinstance(count, int):
            stix_objects = count

    replay_text: Optional[str] = None
    replay_path = path / "replay.html"
    if replay_path.is_file():
        text = replay_path.read_text(encoding="utf-8", errors="replace")
        if len(text) > _MAX_REPLAY_CHARS:
            notes.append("replay.html is too large to embed; the report links the filename only.")
        else:
            replay_text = text

    recognized = any((path / name).is_file() for name in EXPECTED_FILES if name != "replay.html")
    if not recognized and not allow_empty:
        raise AuditInputError(
            "no analyzer outputs in "
            f"{path} (expected {', '.join(EXPECTED_FILES)})"
        )
    return LoadedAudit(
        source_dir=path,
        events=events,
        findings=findings,
        summary=summary,
        stix_objects=stix_objects,
        replay_text=replay_text,
        source_log=_public(source_log, limit=400),
        missing=missing,
        notes=notes,
    )


def _method(event: dict[str, Any]) -> str:
    return str(event.get("method") or event.get("jsonrpc_method") or "").strip()


def _tool_name(event: dict[str, Any]) -> str:
    method = _method(event)
    params = event.get("params") if isinstance(event.get("params"), dict) else {}
    for key in ("tool_name", "tool"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:120]
    named = params.get("name") if isinstance(params, dict) else None
    if isinstance(named, str) and named.strip() and method in {"tools/call", "tool_call"}:
        return named.strip()[:120]
    if method in {"tools/call", "tool_call"}:
        return "tools/call"
    path = str(event.get("path") or "")
    if method.upper() == "POST" and path.rstrip("/").endswith("/mcp"):
        return "mcp"
    return ""


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    for key in ("arguments", "args"):
        value = event.get(key)
        if isinstance(value, dict):
            return value
    params = event.get("params") if isinstance(event.get("params"), dict) else {}
    nested = params.get("arguments") if isinstance(params, dict) else None
    if isinstance(nested, dict):
        return nested
    return {}


def _tokens(event: dict[str, Any]) -> list[str]:
    try:
        blob = json.dumps(event, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        blob = str(event)
    return _AGW1_RE.findall(blob)


def _tainted(event: dict[str, Any], cap: Any) -> bool:
    if event.get("tainted") is True or event.get("taint_inherited") is True:
        return True
    if str(event.get("taint") or "").upper() in {"TAINTED", "TRUE", "1"}:
        return True
    for key in ("taint_source", "taint_source_id"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return True
    flags = event.get("flags") if isinstance(event.get("flags"), list) else event.get("taint_flags")
    if isinstance(flags, list) and any("TAINT" in str(item).upper() for item in flags):
        return True
    if cap is not None and getattr(cap, "taint_source", ""):
        return True
    return False


def _is_exfil(event: dict[str, Any], tool: str, atlas_ids: list[str]) -> bool:
    egress = str(event.get("egress_class") or event.get("egress") or "").strip().lower()
    if egress in _EXFIL_EGRESS:
        return True
    if tool.lower() in _EXFIL_TOOLS:
        return True
    if any(_parent_id(tech) == "AML.T0086" for tech in atlas_ids):
        return True
    blob = json.dumps(_arguments(event), default=str).lower()
    if "http://" in blob or "https://" in blob or "query=" in blob:
        return True
    return False


def _capability_view(event: dict[str, Any]) -> dict[str, Any]:
    parsed: list[tuple[Any, bool]] = []
    for token in _tokens(event):
        cap = parse(token)
        if cap is None:
            continue
        parsed.append((cap, verify(token) is not None))
    attenuated = [item for item in parsed if not item[0].allows_egress]
    chosen = attenuated[0] if attenuated else (parsed[0] if parsed else None)
    return {
        "present": bool(_tokens(event)),
        "parsed": chosen[0] if chosen else None,
        "verified": bool(chosen[1]) if chosen else False,
        "attenuated": bool(attenuated),
    }


def _capability_label(view: dict[str, Any]) -> str:
    cap = view["parsed"]
    if cap is None:
        return "agw1. present (unparsed)" if view["present"] else "none"
    egress = "allow_egress=false" if not cap.allows_egress else "allow_egress=true"
    hmac_state = "HMAC verified" if view["verified"] else "HMAC not verified"
    taint = f", taint_source={cap.taint_source}" if cap.taint_source else ""
    return _public(f"agw1. {egress}, {hmac_state}{taint}", limit=300)


def _session_of(event: dict[str, Any], cap: Any) -> str:
    for key in ("session_id", "session", "session_key", "session_hint"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return _public(value.strip(), limit=200)
    if cap is not None and getattr(cap, "session_id", ""):
        return _public(cap.session_id, limit=200)
    return ""


def _classify(event: dict[str, Any]) -> Optional[PathRow]:
    tool = _tool_name(event)
    if not tool:
        return None
    view = _capability_view(event)
    cap = view["parsed"]
    atlas_ids = _record_atlas(event)
    tainted = _tainted(event, cap)
    tool_label = _public(tool, limit=120)
    session = _session_of(event, cap)
    label = _capability_label(view)
    if view["attenuated"]:
        if view["verified"]:
            reason = (
                "agw1. capability is attenuated (allow_egress=false) and the HMAC chain verifies. "
                "Egress stays closed."
            )
        else:
            reason = (
                "agw1. capability includes allow_egress=false. The HMAC signature did not verify "
                "with this worker's key, so this is structural attenuation only."
            )
        return PathRow("protected", tool_label, session, tainted, label, reason)
    exposed = _is_exfil(event, tool, atlas_ids)
    if exposed and view["parsed"] is not None and view["parsed"].allows_egress:
        reason = (
            "Tool call can place data on an external boundary. An agw1. token is present but "
            "still allows egress, so it is not attenuated."
        )
        return PathRow("vulnerable", tool_label, session, tainted, label, reason)
    if exposed:
        reason = (
            "Tool call can place data on an external boundary and no attenuated agw1. "
            "capability is present."
        )
        return PathRow("vulnerable", tool_label, session, tainted, label, reason)
    return PathRow(
        "other",
        tool_label,
        session,
        tainted,
        label,
        "No external-boundary signal and no agw1. attenuation caveat on this tool call.",
    )


def _atlas_counts(findings: list[dict[str, Any]], events: list[dict[str, Any]]) -> tuple[dict[str, int], dict[str, int]]:
    """Return (specific id counts, tracked parent rollup).

    The STIX bundle is not a match source. The analyzer writes an attack-pattern
    catalog for orientation, including techniques that no finding matched.
    """
    specific: Counter[str] = Counter()
    rollup = {tech: 0 for tech, _name in TRACKED}

    def _consume(ids: list[str]) -> None:
        if not ids:
            return
        for tech in ids:
            specific[tech] += 1
        parents = {_parent_id(tech) for tech in ids}
        for tech in parents:
            if tech in rollup:
                rollup[tech] += 1

    for finding in findings:
        _consume(_record_atlas(finding))
    for event in events:
        if not any(key in event for key in ("atlas", "atlas_id", "technique", "techniques")):
            continue
        _consume(_record_atlas(event))
    return dict(specific), rollup


def compile_report(loaded: LoadedAudit) -> dict[str, Any]:
    rows = [row for event in loaded.events if (row := _classify(event)) is not None]
    taint_events = 0
    for event in loaded.events:
        view = _capability_view(event)
        if _tainted(event, view["parsed"]):
            taint_events += 1
    specific, rollup = _atlas_counts(loaded.findings, loaded.events)
    notes = list(loaded.notes)
    if not rows:
        notes.append(
            "No tool-call records in this directory. Scrubbed access-log lines are not counted "
            "as tool calls. The exfiltration matrix stays empty until a record names a tool or uses tools/call."
        )
    detail = [
        {"id": tech, "count": count, "name": ATLAS_NAMES.get(_parent_id(tech), ATLAS_NAMES.get(tech, "ATLAS technique"))}
        for tech, count in sorted(specific.items())
    ]
    findings_preview = []
    for finding in loaded.findings[:40]:
        findings_preview.append({
            "rule_id": _public(finding.get("rule_id"), limit=40),
            "title": _public(finding.get("title"), limit=180),
            "session": _public(finding.get("session_key"), limit=120),
            "atlas": _record_atlas(finding),
            "summary": _public(finding.get("summary"), limit=280),
        })
    grouped = {
        "vulnerable_exfiltration": [row.as_dict() for row in rows if row.disposition == "vulnerable"],
        "protected_agw1": [row.as_dict() for row in rows if row.disposition == "protected"],
        "other_tool_calls": [row.as_dict() for row in rows if row.disposition == "other"],
    }
    return {
        "schema": SCHEMA,
        "lab_only": True,
        "honeypot_started": False,
        "network": False,
        "source_dir": str(loaded.source_dir),
        "source_log": loaded.source_log,
        "missing_inputs": list(loaded.missing),
        "notes": notes,
        "inputs": {
            "events": len(loaded.events),
            "findings": len(loaded.findings),
            "replay": loaded.replay_text is not None,
            "stix_objects": loaded.stix_objects,
            "summary_events": loaded.summary.get("events") if isinstance(loaded.summary.get("events"), int) else None,
            "summary_findings": loaded.summary.get("findings") if isinstance(loaded.summary.get("findings"), int) else None,
        },
        "executive_summary": {
            "tool_calls": len(rows),
            "taint_events": taint_events,
            "atlas_matches": {
                tech: {"count": rollup[tech], "name": name}
                for tech, name in TRACKED
            },
        },
        "atlas_detail": detail,
        "risk_matrix": grouped,
        "findings_preview": findings_preview,
        "pdf_note": _PDF_NOTE,
        "replay_embedded": loaded.replay_text is not None,
    }


def _e(value: Any) -> str:
    return html.escape(_public(value, limit=500), quote=True)


def _render_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p class='empty'>None in this set.</p>"
    body = [
        "<table><thead><tr><th>Tool</th><th>Session</th><th>Taint</th><th>Capability</th><th>Why</th></tr></thead><tbody>"
    ]
    for row in rows:
        body.append(
            "<tr>"
            f"<td>{_e(row['tool'])}</td>"
            f"<td>{_e(row['session'])}</td>"
            f"<td>{'yes' if row['tainted'] else 'no'}</td>"
            f"<td>{_e(row['capability'])}</td>"
            f"<td>{_e(row['reason'])}</td>"
            "</tr>"
        )
    body.append("</tbody></table>")
    return "".join(body)


def render_html(report: dict[str, Any]) -> str:
    summary = report["executive_summary"]
    atlas = summary["atlas_matches"]
    matrix = report["risk_matrix"]
    inputs = report["inputs"]
    cards = [
        ("Tool calls", str(summary["tool_calls"]), "records that name a tool or use tools/call"),
        ("Taint events", str(summary["taint_events"]), "records with a taint flag, source, or taint caveat"),
    ]
    for tech, _name in TRACKED:
        cards.append((tech, str(atlas[tech]["count"]), atlas[tech]["name"]))
    card_html = "".join(
        f"<li><span>{_e(label)}</span><strong>{_e(count)}</strong><small>{_e(blurb)}</small></li>"
        for label, count, blurb in cards
    )
    detail_rows = "".join(
        f"<tr><td>{_e(row['id'])}</td><td>{row['count']}</td><td>{_e(row['name'])}</td></tr>"
        for row in report["atlas_detail"]
    ) or "<tr><td colspan='3'>No technique ids on findings or tool-call records.</td></tr>"
    finding_rows = "".join(
        "<tr>"
        f"<td>{_e(row['rule_id'])}</td>"
        f"<td>{_e(', '.join(row['atlas']) or '—')}</td>"
        f"<td>{_e(row['title'])}</td>"
        f"<td>{_e(row['summary'])}</td>"
        "</tr>"
        for row in report["findings_preview"]
    ) or "<tr><td colspan='4'>No findings.</td></tr>"
    notes = "".join(f"<li>{_e(note)}</li>" for note in report["notes"])
    source = _e(report.get("source_log") or "not recorded")
    stix = inputs["stix_objects"]
    stix_label = str(stix) if isinstance(stix, int) else "not present"
    if report["replay_embedded"]:
        replay_block = (
            "<p><a href='replay.html'>Open the static session replay (replay.html)</a></p>"
            "<iframe title='Static session replay' sandbox='' src='replay.html'></iframe>"
        )
    else:
        replay_block = "<p>replay.html was not in the input directory, so there is nothing to embed.</p>"
    vuln_n = len(matrix["vulnerable_exfiltration"])
    prot_n = len(matrix["protected_agw1"])
    toxic_block = _render_toxic(report.get("toxic_combinations"))
    gateway_block = _render_gateway(report.get("gateway_findings"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src 'self'; base-uri 'none'; form-action 'none'">
<title>Executive audit report</title>
<style>
:root {{ color-scheme: light; }}
body {{ margin: 0; background: #f4f1ea; color: #1c1917; font: 16px/1.5 "Segoe UI", Helvetica, Arial, sans-serif; }}
header, main {{ max-width: 980px; margin: 0 auto; padding: 24px 20px; }}
header {{ padding-bottom: 0; }}
h1 {{ font-size: 1.8rem; line-height: 1.2; margin: 0 0 8px; }}
h2 {{ font-size: 1.15rem; margin: 28px 0 8px; }}
.banner {{ background: #1e3a5f; color: #f8fafc; padding: 10px 20px; font-size: 0.92rem; }}
.kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; list-style: none; padding: 0; margin: 12px 0; }}
.kpis li {{ background: white; border: 1px solid #e7e5e4; border-radius: 8px; padding: 10px 12px; }}
.kpis span {{ display: block; color: #57534e; font-size: 0.78rem; letter-spacing: 0.02em; }}
.kpis strong {{ display: block; font-size: 1.6rem; line-height: 1.1; }}
.kpis small {{ display: block; color: #57534e; }}
.matrix {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
.matrix section {{ background: white; border-radius: 8px; padding: 12px; border: 1px solid #e7e5e4; }}
.vulnerable {{ border-top: 4px solid #9f1239; }}
.protected {{ border-top: 4px solid #166534; }}
table {{ width: 100%; border-collapse: collapse; background: white; font-size: 0.92rem; }}
th, td {{ text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #e7e5e4; }}
th {{ color: #44403c; font-weight: 600; }}
.empty {{ color: #57534e; margin: 4px 0; }}
.graph {{ background: white; border: 1px solid #e7e5e4; border-radius: 8px; padding: 8px; overflow-x: auto; }}
iframe {{ width: 100%; height: 480px; border: 1px solid #d6d3d1; background: white; }}
.note, footer {{ color: #44403c; font-size: 0.92rem; }}
footer {{ max-width: 980px; margin: 0 auto; padding: 0 20px 32px; }}
@media (max-width: 800px) {{ .matrix {{ grid-template-columns: 1fr; }} }}
@media print {{
  body {{ background: white; }}
  .banner {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  iframe {{ height: 320px; }}
  a {{ color: inherit; text-decoration: none; }}
}}
</style>
</head>
<body>
<p class="banner">Lab report for human review. Not a production verdict. No honeypot was started. No outbound requests were made.</p>
<header>
<h1>Executive audit report</h1>
<p>Scrubbed <code>agentwatch-analyzer</code> output. Source log: {source}.</p>
<p class="note">{inputs['events']} scrubbed log events, {inputs['findings']} findings, STIX objects: {_e(stix_label)}.</p>
</header>
<main>
<section id="executive-summary">
<h2>Executive Summary</h2>
<ul class="kpis">{card_html}</ul>
<p class="note">Tool calls are scrubbed records with a tool name or a <code>tools/call</code> method. Access-log fetches are not tool calls. Taint events carry an explicit taint flag, taint source, or <code>taint_source</code> caveat. The three ATLAS figures roll subtechniques up to the parent id (a finding that lists both <code>AML.T0080</code> and <code>AML.T0080.000</code> counts once). Match counts come from findings and from log records that carry an atlas id. The STIX attack-pattern catalog is not counted: the analyzer emits it for orientation even when a technique was not matched.</p>
</section>
<section id="atlas-detail">
<h2>ATLAS ids on findings</h2>
<table><thead><tr><th>Id</th><th>Matches</th><th>Name</th></tr></thead><tbody>{detail_rows}</tbody></table>
</section>
<section id="risk-matrix">
<h2>Risk matrix</h2>
<p class="note">Tool-call paths that can place data on an external boundary, set against paths held closed by an attenuated <code>agw1.</code> capability (<code>allow_egress=false</code>).</p>
<div class="matrix">
<section class="vulnerable"><h3>Vulnerable to exfiltration</h3><p>{vuln_n} tool-call path(s)</p>{_render_rows(matrix['vulnerable_exfiltration'])}</section>
<section class="protected"><h3>Protected by agw1. HMAC attenuation</h3><p>{prot_n} tool-call path(s)</p>{_render_rows(matrix['protected_agw1'])}</section>
</div>
<h3>Other tool calls</h3>
{_render_rows(matrix['other_tool_calls'])}
</section>
{toxic_block}
{gateway_block}
<section id="session-replay">
<h2>Session replay</h2>
<p class="note">Static file produced by the analyzer. It does not call the network. The copy next to this report is scrubbed again before it is embedded.</p>
{replay_block}
</section>
<section id="findings">
<h2>Findings</h2>
<table><thead><tr><th>Rule</th><th>ATLAS</th><th>Title</th><th>Summary</th></tr></thead><tbody>{finding_rows}</tbody></table>
</section>
<section id="notes">
<h2>Notes</h2>
<ul>{notes}</ul>
<p class="note" id="pdf-note">{_e(_PDF_NOTE)}</p>
</section>
</main>
<footer>Generated offline by agent-gateway audit. Secrets scrubbed. Capability signatures omitted. Leave the honeypot undeployed.</footer>
</body>
</html>
"""


def _render_toxic(toxic: Optional[dict]) -> str:
    if not toxic:
        return ("<section id='toxic-combinations'><h2>Toxic combinations</h2>"
                "<p class='empty'>No tool inventory was supplied (tool-inventory.json or --tool-inventory).</p></section>")
    t = toxic["totals"]
    cards = "".join(
        f"<li><span>{_e(label)}</span><strong>{int(value)}</strong><small>{_e(blurb)}</small></li>"
        for label, value, blurb in (
            ("Toxic 2-hop", t["toxic_2hop"], "external_read → read → sink"),
            ("Toxic 3-hop", t["toxic_3hop"], "external_read → read → read → sink"),
            ("Behind agw1.", t["protected"], "sink holds a hard capability boundary"),
            ("Tools", toxic["tools"], f"{t['sources']} sources, {t['reads']} reads, {t['sinks']} sinks"),
        )
    )
    constrained = ", ".join(toxic.get("constrained_sinks") or []) or "none"
    trunc = "<p class='note'>Path list truncated; totals are complete.</p>" if toxic.get("truncated") else ""
    return (
        "<section id='toxic-combinations'><h2>Toxic combinations</h2>"
        "<p class='note'>Static reachability over the declared tool inventory: every path where an untrusted "
        "external read can steer an internal or sensitive read into a sink that carries free text, without a "
        "hard <code>agw1.</code> capability boundary at the sink. Approximate AML.T0086. Not a penetration test.</p>"
        f"<ul class='kpis'>{cards}</ul>"
        f"<div class='graph'>{toxic_combinations.render_svg(toxic)}</div>"
        f"{toxic_combinations.render_table(toxic)}{trunc}"
        f"<p class='note'>Constrained sinks (no free-text channel, not counted): {_e(constrained)}.</p>"
        "</section>"
    )


def _render_gateway(gateway: Optional[dict]) -> str:
    if not gateway:
        return ""
    counts = "".join(
        f"<tr><td>{_e(kind)}</td><td>{int(n)}</td></tr>" for kind, n in gateway["counts"].items()
    )
    rows = "".join(
        "<tr>"
        f"<td>{_e(r['kind'])}</td><td>{_e(r['tool'])}</td><td>{_e(r['session'])}</td>"
        f"<td>{_e(r['atlas'])}</td><td>{_e(r['detail'])}</td>"
        "</tr>"
        for r in gateway["rows"]
    ) or "<tr><td colspan='5'>None.</td></tr>"
    return (
        "<section id='gateway-findings'><h2>Gateway findings (decision log)</h2>"
        "<p class='note'>From the hash-chained PEP decision log. ATLAS ids are approximate.</p>"
        f"<table><thead><tr><th>Kind</th><th>Count</th></tr></thead><tbody>{counts}</tbody></table>"
        "<table><thead><tr><th>Kind</th><th>Tool</th><th>Session</th><th>ATLAS</th><th>Detail</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


def summarize_decision_log(path: Path, limit: int = 40) -> dict[str, Any]:
    """Counts and a preview of v8/v9 gateway findings in a decision log."""
    counts = {kind: 0 for kind in GATEWAY_FINDING_KINDS}
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("kind") not in counts:
            continue
        kind = entry["kind"]
        counts[kind] += 1
        if len(rows) >= limit:
            continue
        if kind == "tool_output_injection":
            detail = ", ".join(sorted({str(s.get("kind")) for s in entry.get("signals") or [] if isinstance(s, dict)}))
        elif kind == "toxic_combinations":
            detail = f"toxic paths: {(entry.get('totals') or {}).get('toxic')}"
        else:
            detail = (entry.get("reason") or ", ".join(map(str, entry.get("reasons") or [])) or entry.get("form")
                      or entry.get("rule") or entry.get("verdict") or "")
        rows.append({"kind": kind, "tool": _public(entry.get("tool"), 80), "session": _public(entry.get("session_id"), 80),
                     "atlas": _public(entry.get("atlas"), 20), "detail": _public(detail, 200)})
    return {"counts": counts, "rows": rows, "atlas_approximate": True}


def _pdf_escape(text: str) -> str:
    encoded = text.encode("latin-1", errors="replace").decode("latin-1")
    return encoded.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_pdf(text: str, width: int = 92) -> list[str]:
    lines: list[str] = []
    for para in text.split("\n"):
        if para == "":
            lines.append("")
            continue
        rest = para
        while len(rest) > width:
            cut = rest.rfind(" ", 0, width)
            if cut < 16:
                for sep in ("/", "-", "_"):
                    alt = rest.rfind(sep, 16, width)
                    if alt > cut:
                        cut = alt + 1
            if cut < 16:
                cut = width
            lines.append(rest[:cut].rstrip())
            rest = rest[cut:].lstrip()
        lines.append(rest)
    return lines


def render_pdf_lines(report: dict[str, Any]) -> list[str]:
    summary = report["executive_summary"]
    atlas = summary["atlas_matches"]
    matrix = report["risk_matrix"]
    lines = [
        "Lab executive audit report",
        "Not a production verdict. No honeypot. No outbound requests.",
        _PDF_NOTE,
        "",
        "Executive Summary",
        f"Tool calls: {summary['tool_calls']}",
        f"Taint events: {summary['taint_events']}",
    ]
    for tech, _name in TRACKED:
        lines.append(f"{tech} {atlas[tech]['name']}: {atlas[tech]['count']}")
    lines.append("")
    lines.append("Risk matrix")
    lines.append(f"Vulnerable to exfiltration: {len(matrix['vulnerable_exfiltration'])}")
    for row in matrix["vulnerable_exfiltration"]:
        lines.append(f"- {row['tool']} session={row['session']} taint={'yes' if row['tainted'] else 'no'} {row['capability']}")
        lines.append(f"  {row['reason']}")
    lines.append(f"Protected by agw1. HMAC attenuation: {len(matrix['protected_agw1'])}")
    for row in matrix["protected_agw1"]:
        lines.append(f"- {row['tool']} session={row['session']} taint={'yes' if row['tainted'] else 'no'} {row['capability']}")
        lines.append(f"  {row['reason']}")
    lines.append(f"Other tool calls: {len(matrix['other_tool_calls'])}")
    for row in matrix["other_tool_calls"]:
        lines.append(f"- {row['tool']} session={row['session']}")
    toxic = report.get("toxic_combinations")
    lines.append("")
    lines.append("Toxic combinations (static reachability, approximate AML.T0086)")
    if toxic:
        t = toxic["totals"]
        lines.append(f"Toxic 2-hop: {t['toxic_2hop']}  Toxic 3-hop: {t['toxic_3hop']}  Behind agw1.: {t['protected']}")
        for p in [p for p in toxic["paths"] if p["toxic"]][:40]:
            lines.append(f"- [{p['severity']}] {' -> '.join(p['path'])} via {', '.join(p['channel']) or '-'}")
    else:
        lines.append("No tool inventory supplied.")
    gateway = report.get("gateway_findings")
    if gateway:
        lines.append("")
        lines.append("Gateway findings (decision log)")
        for kind, n in gateway["counts"].items():
            lines.append(f"{kind}: {n}")
    lines.append("")
    lines.append("Session replay")
    if report["replay_embedded"]:
        lines.append("Static replay embedded in the HTML report as replay.html.")
    else:
        lines.append("replay.html was not in the input directory.")
    if report.get("source_log"):
        lines.append(f"Source log: {report['source_log']}")
    lines.append("")
    lines.append("Notes")
    lines.extend(f"- {note}" for note in report["notes"])
    return [_public(line, limit=500) for line in lines]


def render_pdf(lines: list[str]) -> bytes:
    """PDF 1.4, Helvetica, one text column. No external library."""
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(_wrap_pdf(line))
    per_page = 48
    pages = [wrapped[i:i + per_page] for i in range(0, len(wrapped), per_page)] or [[]]
    objects: dict[int, bytes] = {
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    page_ids: list[int] = []
    next_id = 4
    for page_lines in pages:
        page_id = next_id
        content_id = next_id + 1
        next_id += 2
        page_ids.append(page_id)
        commands = ["BT", "/F1 10 Tf", "13 TL", "54 738 Td"]
        for index, line in enumerate(page_lines):
            if index:
                commands.append("T*")
            commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects[content_id] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_id} 0 R /Resources << /Font << /F1 3 0 R >> >> >>"
        ).encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("ascii")
    max_id = next_id - 1
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0] * (max_id + 1)
    for obj_id in range(1, max_id + 1):
        offsets[obj_id] = len(out)
        out += f"{obj_id} 0 obj\n".encode("ascii")
        out += objects[obj_id]
        out += b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {max_id + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for obj_id in range(1, max_id + 1):
        out += f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii")
    out += f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    return bytes(out)


def _final_scrub(text: str) -> str:
    return scrub_text(_AGW1_RE.sub("agw1.[redacted]", text))


def _write_findings(src: Path, dest: Path, report: dict[str, Any]) -> Optional[Path]:
    """Scrubbed copy of the analyzer findings plus the gateway sections."""
    extra = {k: report[k] for k in ("toxic_combinations", "gateway_findings") if report.get(k)}
    if not src.is_file() and not extra:
        return None
    doc: Any = {"schema": "agent-gateway.audit-findings/1", "findings": []}
    if src.is_file():
        text = _final_scrub(src.read_text(encoding="utf-8"))
        if not extra:
            dest.write_text(text, encoding="utf-8")
            return dest
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = {"schema": "agent-gateway.audit-findings/1", "findings": [], "analyzer_findings_unparsed": True}
        if isinstance(doc, list):
            doc = {"findings": doc}
        elif not isinstance(doc, dict):
            doc = {"findings": []}
    doc.update(extra)
    dest.write_text(_final_scrub(json.dumps(doc, indent=2, ensure_ascii=False) + "\n"), encoding="utf-8")
    return dest


def _default_decision_log(input_dir: Path) -> Optional[Path]:
    for name in (DECISION_LOG_NAME, "alerts.jsonl"):
        path = input_dir / name
        if path.is_file():
            return path
    return None


def write_report(
    input_dir: Path, out_dir: Path, *, pdf: bool = True, decision_log: Optional[Path] = None,
    tool_inventory: Optional[Path] = None, sarif: Optional[Path] = None,
) -> dict[str, Any]:
    """Compile ``input_dir`` into HTML, JSON, and (unless disabled) a text PDF.

    Also copies a scrubbed ``findings.json`` and the hash-chained decision log
    (byte for byte, so the chain still verifies), then writes
    ``audit_manifest.json`` over every output file.

    A tool inventory (``tool_inventory`` or ``<input_dir>/tool-inventory.json``)
    adds the toxic-combination section, and allows a tool-list-only audit with
    no analyzer outputs.
    """
    inv_src = tool_inventory
    if inv_src is None and (input_dir / INVENTORY_NAME).is_file():
        inv_src = input_dir / INVENTORY_NAME
    loaded = load_audit_dir(input_dir, allow_empty=inv_src is not None)
    report = compile_report(loaded)
    if inv_src is not None:
        try:
            report["toxic_combinations"] = toxic_combinations.load_inventory_file(inv_src)
        except (OSError, ValueError) as exc:
            raise AuditInputError(f"tool inventory {inv_src}: {exc}") from exc
    log_src = decision_log if decision_log is not None else _default_decision_log(input_dir)
    if log_src is not None and log_src.is_file():
        report["gateway_findings"] = summarize_decision_log(log_src)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_text = _final_scrub(render_html(report))
    html_path = out_dir / "audit-report.html"
    html_path.write_text(html_text, encoding="utf-8")
    pdf_path: Optional[Path] = None
    if pdf:
        pdf_path = out_dir / "audit-report.pdf"
        pdf_path.write_bytes(render_pdf(render_pdf_lines(report)))
    replay_out: Optional[Path] = None
    if loaded.replay_text is not None:
        replay_out = out_dir / "replay.html"
        replay_out.write_text(_final_scrub(loaded.replay_text), encoding="utf-8")
    findings_out = _write_findings(input_dir / "findings.json", out_dir / "findings.json", report)
    if inv_src is not None:
        (out_dir / INVENTORY_NAME).write_text(_final_scrub(inv_src.read_text(encoding="utf-8")), encoding="utf-8")
    log_out: Optional[Path] = None
    if log_src is not None and log_src.is_file():
        # Copied unchanged: lines are scrubbed when the PEP writes them, and any
        # rewrite here would break entry_hash.
        log_out = out_dir / DECISION_LOG_NAME
        log_out.write_bytes(log_src.read_bytes())
    report["replay"] = replay_out.name if replay_out else None
    report["outputs"] = {
        "html": str(html_path),
        "pdf": str(pdf_path) if pdf_path else None,
        "json": str(out_dir / "audit-report.json"),
        "replay": str(replay_out) if replay_out else None,
        "findings": str(findings_out) if findings_out else None,
        "decision_log": str(log_out) if log_out else None,
        "manifest": str(out_dir / "audit_manifest.json"),
    }
    sarif_out: Optional[Path] = None
    if sarif is not None:
        sarif_out = sarif if sarif.is_absolute() or sarif.parent != Path(".") else out_dir / sarif.name
        doc = sarif_export.build_sarif(report, source_log=loaded.source_log)
        problems = sarif_export.validate_sarif(doc)
        if problems:
            raise AuditInputError("SARIF build failed validation: " + "; ".join(problems[:5]))
        sarif_out.write_text(_final_scrub(json.dumps(doc, indent=2, ensure_ascii=False) + "\n"), encoding="utf-8")
        report["outputs"]["sarif"] = str(sarif_out)
    json_path = out_dir / "audit-report.json"
    json_text = _final_scrub(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    json_path.write_text(json_text, encoding="utf-8")
    # The manifest only covers files inside the audit directory.
    write_manifest(out_dir, decision_log=log_out)
    return json.loads(json_path.read_text(encoding="utf-8"))
