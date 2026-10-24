"""Native OASIS SARIF 2.1.0 exporter for GitHub Code Scanning.

Turns a compiled audit ``report`` (analyzer matches, toxic-combination paths,
and the gateway decision-log summary) into a single SARIF 2.1.0 run. The
output is self-contained and offline; GitHub code scanning ingests it as is.

SARIF shape produced:

- ``version`` ``"2.1.0"`` and the 2.1.0 ``$schema``
- one ``run`` with a ``tool.driver`` (name, version, informationUri, rules)
- one ``reportingDescriptor`` per finding kind, with its approximate ATLAS id
  in ``properties.tags``
- one ``result`` per finding, each with a ``ruleId``, a ``level``
  (``error`` / ``warning`` / ``note``), a ``message``, a
  ``partialFingerprints`` entry, and a ``location`` (a logical location, or
  the source-log artifact) so the result is anchorable

The report carries no line numbers, so results use logical locations rather
than invented source regions. Severities are a lab triage aid, not a
certification, and ATLAS ids are approximate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DRIVER_NAME = "AgentGate"
DRIVER_URI = "https://github.com/freeling10-prog/rogue-ai-detection"
DRIVER_VERSION = "1.0.0"

_LEVELS = {"error", "warning", "note", "none"}

# Finding kind -> (SARIF level, short name, approximate ATLAS ids, help text)
RULES: dict[str, tuple[str, str, tuple[str, ...], str]] = {
    "toxic_combination": ("warning", "Toxic tool-flow combination", ("AML.T0086",),
                          "An untrusted read can reach a data-egress sink with no agw1. capability boundary."),
    "confused_deputy_delegation_blocked": ("error", "Confused-deputy delegation", ("AML.T0051", "AML.T0086"),
                                           "A delegated agent attempted egress its delegating chain was barred from."),
    "tool_output_injection": ("error", "Tool-output injection", ("AML.T0051",),
                              "Untrusted tool output carried injection or smuggling markers."),
    "ssrf_boundary_violation": ("error", "SSRF / metadata URI", ("AML.T0053",),
                                "A tool argument targeted an internal or cloud-metadata address."),
    "covert_side_channel_suspected": ("error", "Covert side channel", ("AML.T0086",),
                                      "Post-taint call pattern resembled an oracle or timing beacon."),
    "deobfuscated_exfil_detected": ("error", "Cross-step exfiltration", ("AML.T0086",),
                                    "A sensitive value surfaced across steps or encodings in outbound arguments."),
    "mcp_rug_pull_detected": ("error", "MCP rug pull", ("AML.T0051",),
                              "A pinned MCP tool definition changed mid-session."),
    "canary_watermark_exfil": ("error", "Canary / credential exfiltration", ("AML.T0086",),
                               "A watermarked sensitive read or tracked credential surfaced in an outbound call."),
    "arg_firewall_violation": ("error", "Argument firewall", ("AML.T0051", "AML.T0053"),
                               "A tool argument attempted path, command, header, or query escalation."),
    "analyzer_match": ("warning", "Offline analyzer match", (),
                       "A match reported by the offline agentwatch-analyzer."),
}
# decision-log kinds that map straight onto a rule id
_LOG_KIND_RULES = frozenset({
    "tool_output_injection", "ssrf_boundary_violation", "covert_side_channel_suspected",
    "deobfuscated_exfil_detected", "mcp_rug_pull_detected",
})


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:16]


def _logical(name: str, kind: str = "") -> dict:
    loc: dict[str, Any] = {"logicalLocations": [{"fullyQualifiedName": name[:200] or "agent-gateway"}]}
    if kind:
        loc["logicalLocations"][0]["kind"] = kind
    return loc


def _result(rule_id: str, text: str, location: dict, fp: str, props: Optional[dict] = None) -> dict:
    level = RULES.get(rule_id, ("warning",))[0]
    out = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": text[:1000]},
        "locations": [location],
        "partialFingerprints": {"agentgate/v1": fp},
    }
    if props:
        out["properties"] = props
    return out


def _driver_rules(used: set[str]) -> list[dict]:
    rules = []
    for rid in sorted(used):
        level, name, atlas, help_text = RULES.get(rid, ("warning", rid, (), ""))
        tags = ["security", "agentgate"] + [f"ATLAS/{a} (approximate)" for a in atlas]
        rules.append({
            "id": rid,
            "name": "".join(w.capitalize() for w in rid.split("_")),
            "shortDescription": {"text": name},
            "fullDescription": {"text": help_text},
            "helpUri": DRIVER_URI,
            "defaultConfiguration": {"level": level},
            "properties": {"tags": tags, "atlas_approximate": True},
        })
    return rules


def build_sarif(report: dict, *, source_log: str = "") -> dict:
    """Build a SARIF 2.1.0 document from a compiled audit report."""
    results: list[dict] = []
    used: set[str] = set()
    artifact = (source_log or report.get("source_log") or "agent-gateway/audit").strip() or "agent-gateway/audit"

    toxic = report.get("toxic_combinations")
    if isinstance(toxic, dict):
        for p in toxic.get("paths", []):
            if not p.get("toxic"):
                continue
            used.add("toxic_combination")
            chain = " -> ".join(p.get("path", []))
            results.append(_result(
                "toxic_combination",
                f"[{p.get('severity')}] {p.get('hops')}-hop toxic flow: {chain} "
                f"(classes: {' -> '.join(p.get('classes', []))})",
                _logical(chain, "tool-flow"),
                _fingerprint("toxic", chain),
                {"severity": p.get("severity"), "channel": p.get("channel"), "hops": p.get("hops")},
            ))

    gateway = report.get("gateway_findings")
    if isinstance(gateway, dict):
        for row in gateway.get("rows", []):
            kind = row.get("kind")
            rid = kind if kind in _LOG_KIND_RULES else "analyzer_match"
            if kind == "toxic_combinations":
                continue  # already represented as per-path results
            used.add(rid)
            results.append(_result(
                rid,
                f"{kind}: {row.get('detail') or ''} (tool={row.get('tool') or '-'})",
                _logical(row.get("tool") or kind, "tool"),
                _fingerprint("log", kind, row.get("tool"), row.get("session"), row.get("detail")),
                {"session": row.get("session"), "atlas": row.get("atlas")},
            ))

    for finding in report.get("findings_preview", []):
        used.add("analyzer_match")
        rid_text = finding.get("rule_id") or "analyzer"
        atlas = ", ".join(finding.get("atlas") or []) or "n/a"
        results.append(_result(
            "analyzer_match",
            f"[{rid_text}] {finding.get('title') or finding.get('summary') or 'analyzer match'} (ATLAS {atlas})",
            _logical(finding.get("session") or artifact, "session"),
            _fingerprint("analyzer", rid_text, finding.get("session"), finding.get("title")),
            {"analyzer_rule": rid_text, "atlas": finding.get("atlas")},
        ))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": DRIVER_NAME,
                "informationUri": DRIVER_URI,
                "version": DRIVER_VERSION,
                "rules": _driver_rules(used),
            }},
            "results": results,
            "properties": {
                "lab_only": True,
                "atlas_approximate": True,
                "note": "Lab triage aid. Not a certification and not a penetration test.",
            },
        }],
    }


def write_sarif(report: dict, path: Path, *, source_log: str = "") -> dict:
    doc = build_sarif(report, source_log=source_log)
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc


def validate_sarif(doc: Any) -> list[str]:
    """Minimal structural SARIF 2.1.0 check. Returns a list of problems (empty = clean)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["document is not an object"]
    if doc.get("version") != SARIF_VERSION:
        errors.append("version must be '2.1.0'")
    if "$schema" not in doc:
        errors.append("missing $schema")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return errors + ["runs must be a non-empty array"]
    for ri, run in enumerate(runs):
        driver = (((run or {}).get("tool") or {}).get("driver")) if isinstance(run, dict) else None
        if not isinstance(driver, dict) or not driver.get("name"):
            errors.append(f"runs[{ri}].tool.driver.name is required")
            continue
        rule_ids = {r.get("id") for r in driver.get("rules", []) if isinstance(r, dict)}
        for r in driver.get("rules", []):
            if not isinstance(r, dict) or not r.get("id"):
                errors.append(f"runs[{ri}] has a rule without an id")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"runs[{ri}].results must be an array")
            continue
        for xi, res in enumerate(results):
            where = f"runs[{ri}].results[{xi}]"
            if not isinstance(res, dict):
                errors.append(f"{where} is not an object")
                continue
            if not (((res.get("message") or {}).get("text"))):
                errors.append(f"{where}.message.text is required")
            level = res.get("level")
            if level is not None and level not in _LEVELS:
                errors.append(f"{where}.level '{level}' is not a SARIF level")
            rid = res.get("ruleId")
            if rid and rule_ids and rid not in rule_ids:
                errors.append(f"{where}.ruleId '{rid}' is not declared in tool.driver.rules")
            for li, loc in enumerate(res.get("locations") or []):
                if not isinstance(loc, dict) or not (loc.get("physicalLocation") or loc.get("logicalLocations")):
                    errors.append(f"{where}.locations[{li}] needs a physical or logical location")
    return errors
