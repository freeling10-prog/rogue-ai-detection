"""Alerting and reporting: structured JSON report + terminal alert summary."""
from __future__ import annotations

import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from . import __version__
from .leads import sanitize_text, utc_iso
from .parser import ParseResult
from .scrubber import Scrubber, get_default_scrubber
from .scoring import SEVERITIES, SessionResult

REPORT_SCHEMA = "agentwatch.report/1"
MAX_EVIDENCE_PER_SESSION = 8
MAX_CAPTURES_PER_SESSION = 3


def _session_dict(res: SessionResult) -> dict[str, Any]:
    s = res.session
    evidence: list[dict[str, Any]] = []
    seen: set[int] = set()
    for f in res.findings:
        for r in f.evidence:
            if id(r) in seen or len(evidence) >= MAX_EVIDENCE_PER_SESSION:
                continue
            seen.add(id(r))
            evidence.append({"detector": f.detector, "kind": f.kind, "line": sanitize_text(r.evidence_line(), 300)})
    captures = []
    for r in s.requests:
        if r.capture and len(captures) < MAX_CAPTURES_PER_SESSION:
            captures.append({
                "at": utc_iso(r.ts),
                "untrusted": True,   # attacker-controlled text: never feed to an LLM/shell/template unsandboxed
                "agent_id": sanitize_text(str(r.capture.get("agent_id", "")), 200),
                "current_objective": sanitize_text(str(r.capture.get("current_objective", "")), 500),
                "system_prompt_summary": sanitize_text(str(r.capture.get("system_prompt_summary", "")), 500),
                "declared_tools": [sanitize_text(str(t), 100) for t in list(r.capture.get("declared_tools", []))[:20]],
                "message": sanitize_text(str(r.capture.get("message", "")), 300),
                "truncated_fields": list(r.capture.get("truncated_fields", []))[:10],
            })
    coord_events = [e for r in s.requests for e in r.events]
    return {
        "session_id": s.session_id,
        "ip": sanitize_text(s.ip, 64),
        "user_agents": [sanitize_text(u, 200) for u in s.user_agents],
        "start": utc_iso(s.start),
        "end": utc_iso(s.end),
        "requests": len(s.requests),
        "label": res.label,
        "severity": res.severity,
        "agent_score": res.agent_score,
        "automation_score": res.automation_score,
        "benign": res.benign,
        "benign_reason": res.benign_reason,
        "reasons": [sanitize_text(r, 300) for r in res.reasons],
        "features": res.features,
        "findings": [
            {"detector": f.detector, "kind": f.kind, "summary": sanitize_text(f.summary, 300)}
            for f in res.findings
        ],
        "honeytoken_leads": [
            {"kind": f.kind, "token_id": f.data.get("token_id"), "path": sanitize_text(str(f.data.get("path", "")), 200)}
            for f in res.honeytoken_hits
        ],
        "evidence": evidence,
        "cognitive_captures": captures,
        "coordination": {
            "events": len(coord_events),
            "cross_session_events": sum(1 for e in coord_events if e.get("cross_session")),
            "cross_ip_events": sum(1 for e in coord_events if e.get("cross_ip")),
        },
    }


def build_report(results: Sequence[SessionResult], inputs: Sequence[str], parsed: ParseResult,
                 cfg_source: str = "defaults", scrubber: Optional[Scrubber] = None) -> dict[str, Any]:
    """Assemble the structured JSON report (schema ``agentwatch.report/1``), secret-scrubbed."""
    report = {
        "schema": REPORT_SCHEMA,
        "tool": f"agent-watch {__version__}",
        "generated_at": utc_iso(datetime.now(timezone.utc)),
        "inputs": [sanitize_text(i, 300) for i in inputs],
        "config": cfg_source,
        "parse": {"lines": parsed.lines, "requests": len(parsed.requests), "errors": parsed.errors,
                  "honeypot_context_events": parsed.context_events},
        "summary": {
            "sessions": len(results),
            "by_label": dict(Counter(r.label for r in results)),
            "by_severity": dict(Counter(r.severity for r in results)),
            "honeytoken_sessions": sum(1 for r in results if r.honeytoken_hits),
        },
        "disclaimer": "Heuristic scores from synthetic-tested rules; every alert needs human review.",
        "sessions": [_session_dict(r) for r in results],
    }
    result: dict[str, Any] = (scrubber or get_default_scrubber()).scrub(report)
    return result


# --------------------------------------------------------------------------
# terminal rendering
# --------------------------------------------------------------------------
_COLORS = {"critical": "1;37;41", "high": "1;31", "medium": "33", "low": "36", "info": "2"}


def _paint(text: str, severity: str, color: bool) -> str:
    return f"\x1b[{_COLORS[severity]}m{text}\x1b[0m" if color else text


def use_color(stream: Any = None, no_color_flag: bool = False) -> bool:
    stream = stream or sys.stdout
    return bool(not no_color_flag and not os.environ.get("NO_COLOR") and hasattr(stream, "isatty") and stream.isatty())


def render_text(report: dict[str, Any], *, min_severity: str = "low", top: int = 10,
                color: bool = False, max_reasons: int = 5, max_evidence: int = 3) -> str:
    """Render the report as a terminal alert summary (severity-ordered)."""
    floor = SEVERITIES.index(min_severity)
    sessions = report["sessions"]
    shown = [s for s in sessions if SEVERITIES.index(s["severity"]) >= floor][:top]
    hidden = len(sessions) - len(shown)
    summ = report["summary"]
    out: list[str] = []
    out.append("=" * 78)
    out.append(f" agent-watch alert summary   ({report['generated_at']})")
    out.append("=" * 78)
    out.append(f" inputs: {', '.join(report['inputs'])}")
    p = report["parse"]
    out.append(f" requests: {p['requests']}   sessions: {summ['sessions']}   parse errors: {p['errors']}")
    out.append(" by class:    " + "  ".join(f"{k}={v}" for k, v in sorted(summ["by_label"].items())))
    out.append(" by severity: " + "  ".join(f"{k}={summ['by_severity'][k]}" for k in reversed(SEVERITIES) if k in summ["by_severity"]))
    if summ["honeytoken_sessions"]:
        out.append(f" HONEYTOKEN LEADS: {summ['honeytoken_sessions']} session(s) touched decoys")
    out.append("-" * 78)
    for s in shown:
        tag = _paint(f"[{s['severity'].upper():8}]", s["severity"], color)
        out.append(f"{tag} {s['session_id']}  {s['ip']}  class={s['label']}  agent={s['agent_score']}  "
                   f"automation={s['automation_score']}  requests={s['requests']}" + ("  (benign)" if s["benign"] else ""))
        out.append(f"    window: {s['start']} -> {s['end']}")
        if s.get("cognitive_captures"):
            c = s["cognitive_captures"][0]
            out.append(f"    captured objective (UNTRUSTED text from the visitor): {c['current_objective'][:120]!r}")
        out.append(f"    UA: {s['user_agents'][0] if s['user_agents'] else '-'}" +
                   (f"  (+{len(s['user_agents']) - 1} more)" if len(s["user_agents"]) > 1 else ""))
        out.append("    top reasons:")
        for r in s["reasons"][:max_reasons]:
            out.append(f"      - {r}")
        if s["evidence"]:
            out.append("    evidence:")
            for e in s["evidence"][:max_evidence]:
                out.append(f"      > [{e['kind']}] {e['line']}")
        out.append("")
    if hidden > 0:
        out.append(f" ({hidden} lower-severity session(s) not shown; use --min-severity info --top N)")
    out.append(" Scores are heuristic and need human review.")
    return "\n".join(out)
