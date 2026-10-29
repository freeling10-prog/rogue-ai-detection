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
    "schema_drift_denied": ("error", "MCP schema digest drift", ("AML.T0051",),
                            "A pinned tool schema's SHA-256 digest changed without a signed manifest update."),
    "tool_shadowing_denied": ("error", "MCP tool-name collision", ("AML.T0051",),
                              "A second server registered a tool name within one edit of a pinned tool."),
    "gui_region_denied": ("error", "GUI reserved-region action", ("AML.T0053",),
                          "A pointer action landed in a reserved screen region or outside the viewport."),
    "gui_keychord_denied": ("error", "GUI denied shortcut", ("AML.T0053",),
                            "A keyboard action used a denied system shortcut or a raw control character."),
    "provenance_tamper_denied": ("error", "Resource lineage record tampered", ("AML.T0080.000",),
                                 "A shared resource's HMAC-signed lineage record failed verification on read."),
    "sharded_exfil_denied": ("error", "Sharded exfiltration across calls", ("AML.T0086",),
                             "A protected value or watermark accumulated across released calls to one destination."),
    # PHP Defense Guard (php_defense_guard.php / .py): request input checks on a PHP application.
    "PHP_PATH_TRAVERSAL": ("error", "PHP path traversal", (),
                           "A request parameter carried a directory traversal sequence (../ or ..\\)."),
    "PHP_DESERIALIZE_DENIED": ("error", "PHP object injection", (),
                               "A request parameter carried a serialized PHP object (O:<len>:\"...\" or "
                               "C:<len>:\"...\") for unserialize()."),
    "PHP_RCE_EVAL": ("error", "PHP code execution", (),
                     "A request parameter called a PHP code or command execution primitive such as eval(), "
                     "assert(), system(), passthru(), or shell_exec()."),
    "PHP_SQLI_UNION": ("error", "SQL injection (UNION SELECT)", (),
                       "A request parameter carried a UNION SELECT SQL injection payload."),
    "PHP_SQLI_TAUTOLOGY": ("error", "SQL injection (tautology)", (),
                           "A request parameter carried a boolean tautology SQL injection payload such as ' OR '1'='1."),
    # v12 evasion guards.
    "MCP_DEFINITION_DRIFT": ("error", "MCP tool definition drift", ("AML.T0051",),
                             "A pinned MCP tool's description or input schema changed mid-session without a "
                             "re-approval token."),
    "MCP_TOOL_SHADOWING": ("error", "MCP tool shadowing", ("AML.T0051",),
                           "A server registered a tool name owned by another active server or a core built-in."),
    "MCP_DESCRIPTION_POISONING": ("error", "MCP tool description poisoning", ("AML.T0051",),
                                  "A tool or parameter description carried hidden instructions: an HTML comment, "
                                  "an instruction tag, invisible characters, or a credential-file directive."),
    "WORKSPACE_CONFIG_WRITE": ("error", "Agent instruction / config file write", ("AML.T0051",),
                               "A tool call or shell command wrote, renamed, or deleted an agent instruction, skill, "
                               "MCP, or IDE configuration file."),
    "WORKSPACE_HOOK_TAMPER": ("error", "Execution hook tampering", ("AML.T0053",),
                              "A tool call or shell command modified a git hook, git config, CI workflow, or shell "
                              "start-up file, or changed its permissions."),
    "WORKSPACE_SYMLINK_ESCAPE": ("error", "Symlink to a protected path", ("AML.T0053",),
                                 "A symlink was created to or from a protected configuration or credential path."),
    "WORKSPACE_HIDDEN_DIRECTIVE": ("error", "Hidden directive in an instruction file", ("AML.T0051",),
                                   "An agent instruction file carried an HTML comment or invisible Unicode "
                                   "characters before the agent read it."),
    "CFI_TAINTED_PRIVILEGED_SINK": ("error", "Privileged sink after untrusted input", ("AML.T0051",),
                                    "After reading untrusted data, the session called a privileged sink that the "
                                    "pre-taint capability manifest does not grant."),
    "CFI_UNENDORSED_TARGET": ("error", "Privileged call to an unendorsed target", ("AML.T0051",),
                              "After reading untrusted data, a granted privileged sink targeted a resource outside "
                              "the pre-taint capability manifest."),
    "STEGO_SECRET_SHINGLE_LEAK": ("error", "Secret shingles in an outbound identifier", ("AML.T0086",),
                                  "An outbound argument or side-effect identifier (branch, package, DNS label, URL "
                                  "part) shared k-gram shingles with a protected secret."),
    "STEGO_SUBSEQUENCE_EXFIL": ("error", "Secret subsequence in an outbound identifier", ("AML.T0086",),
                                "An outbound side-effect identifier contained a protected secret as a dense ordered "
                                "subsequence."),
    # v12.2 reference middleware validators.
    "REGISTRY_PIN_DRIFT": ("error", "Descriptor pin revoked", ("AML.T0051",),
                           "A pinned provider descriptor changed, failed metadata lint, or disappeared: the pin is "
                           "revoked for the rest of the session and calls to it are refused."),
    "REGISTRY_ALIAS_AMBIGUOUS": ("error", "Ambiguous tool alias", ("AML.T0051",),
                                 "Two providers advertised the same bare tool name. The alias never resolves by "
                                 "arrival order or last-writer-wins; qualified calls stay distinguishable."),
    "WORKSPACE_EFFECT_DENIED": ("error", "Protected path in a modelled shell effect", ("AML.T0053",),
                                "A literal-subset shell command had an effect on a reserved namespace entry or a "
                                "shared inode, or used syntax outside the modelled subset (fail closed)."),
    "FLOW_MANIFEST_DENIED": ("error", "Call outside the pinned workflow manifest", ("AML.T0051",),
                             "A call did not match an unused precommitted manifest step on provider, method, pin, "
                             "resource roles, path pattern, or argument digest."),
    "SIMILARITY_LEAK_DENIED": ("error", "Protected string in an outbound identifier", ("AML.T0086",),
                               "An outbound argument shared a rolling shingle or dense subsequence coverage with a "
                               "protected string under the pinned normalization profile."),
    "analyzer_match": ("warning", "Offline analyzer match", (),
                       "A match reported by the offline agentwatch-analyzer."),
}
# Rule id -> approximate OWASP Top 10 for Agentic Applications category (v11 and v12 rules).
OWASP_ASI: dict[str, tuple[str, ...]] = {
    "schema_drift_denied": ("ASI04",),
    "tool_shadowing_denied": ("ASI04",),
    "gui_region_denied": ("ASI02",),
    "gui_keychord_denied": ("ASI02",),
    "provenance_tamper_denied": ("ASI06",),
    "sharded_exfil_denied": ("ASI02",),
    "MCP_DEFINITION_DRIFT": ("ASI04",),
    "MCP_TOOL_SHADOWING": ("ASI04",),
    "MCP_DESCRIPTION_POISONING": ("ASI01", "ASI04"),
    "WORKSPACE_CONFIG_WRITE": ("ASI06",),
    "WORKSPACE_HOOK_TAMPER": ("ASI05",),
    "WORKSPACE_SYMLINK_ESCAPE": ("ASI02",),
    "WORKSPACE_HIDDEN_DIRECTIVE": ("ASI01", "ASI06"),
    "CFI_TAINTED_PRIVILEGED_SINK": ("ASI01", "ASI02"),
    "CFI_UNENDORSED_TARGET": ("ASI02",),
    "STEGO_SECRET_SHINGLE_LEAK": ("ASI02",),
    "STEGO_SUBSEQUENCE_EXFIL": ("ASI02",),
    "REGISTRY_PIN_DRIFT": ("ASI04",),
    "REGISTRY_ALIAS_AMBIGUOUS": ("ASI04",),
    "WORKSPACE_EFFECT_DENIED": ("ASI05",),
    "FLOW_MANIFEST_DENIED": ("ASI01",),
    "SIMILARITY_LEAK_DENIED": ("ASI02",),
}
# Rule id -> approximate OWASP Top 10 for LLM Applications (2025) category.
OWASP_LLM: dict[str, tuple[str, ...]] = {
    "MCP_DEFINITION_DRIFT": ("LLM03:2025",),
    "MCP_TOOL_SHADOWING": ("LLM03:2025",),
    "MCP_DESCRIPTION_POISONING": ("LLM01:2025",),
    "WORKSPACE_CONFIG_WRITE": ("LLM06:2025",),
    "WORKSPACE_HOOK_TAMPER": ("LLM06:2025",),
    "WORKSPACE_SYMLINK_ESCAPE": ("LLM06:2025",),
    "WORKSPACE_HIDDEN_DIRECTIVE": ("LLM01:2025",),
    "CFI_TAINTED_PRIVILEGED_SINK": ("LLM01:2025", "LLM06:2025"),
    "CFI_UNENDORSED_TARGET": ("LLM06:2025",),
    "STEGO_SECRET_SHINGLE_LEAK": ("LLM02:2025",),
    "STEGO_SUBSEQUENCE_EXFIL": ("LLM02:2025",),
    "REGISTRY_PIN_DRIFT": ("LLM03:2025",),
    "REGISTRY_ALIAS_AMBIGUOUS": ("LLM03:2025",),
    "WORKSPACE_EFFECT_DENIED": ("LLM06:2025",),
    "FLOW_MANIFEST_DENIED": ("LLM01:2025",),
    "SIMILARITY_LEAK_DENIED": ("LLM02:2025",),
}
# Rule id -> CWE ids and OWASP Top 10 (2021) category, for web-application rules.
CWE: dict[str, tuple[str, ...]] = {
    "PHP_PATH_TRAVERSAL": ("CWE-22",),
    "PHP_DESERIALIZE_DENIED": ("CWE-502",),
    "PHP_RCE_EVAL": ("CWE-94", "CWE-78"),
    "PHP_SQLI_UNION": ("CWE-89",),
    "PHP_SQLI_TAUTOLOGY": ("CWE-89",),
    "MCP_DEFINITION_DRIFT": ("CWE-345", "CWE-494"),
    "MCP_TOOL_SHADOWING": ("CWE-706",),
    "MCP_DESCRIPTION_POISONING": ("CWE-1427",),
    "WORKSPACE_CONFIG_WRITE": ("CWE-15",),
    "WORKSPACE_HOOK_TAMPER": ("CWE-15", "CWE-829"),
    "WORKSPACE_SYMLINK_ESCAPE": ("CWE-59",),
    "WORKSPACE_HIDDEN_DIRECTIVE": ("CWE-1427",),
    "CFI_TAINTED_PRIVILEGED_SINK": ("CWE-807", "CWE-1427"),
    "CFI_UNENDORSED_TARGET": ("CWE-807", "CWE-285"),
    "STEGO_SECRET_SHINGLE_LEAK": ("CWE-201",),
    "STEGO_SUBSEQUENCE_EXFIL": ("CWE-201", "CWE-514"),
    "REGISTRY_PIN_DRIFT": ("CWE-345", "CWE-494"),
    "REGISTRY_ALIAS_AMBIGUOUS": ("CWE-706",),
    "WORKSPACE_EFFECT_DENIED": ("CWE-59",),
    "FLOW_MANIFEST_DENIED": ("CWE-807", "CWE-285"),
    "SIMILARITY_LEAK_DENIED": ("CWE-201",),
}
OWASP_WEB: dict[str, tuple[str, ...]] = {
    "PHP_PATH_TRAVERSAL": ("A01:2021",),
    "PHP_DESERIALIZE_DENIED": ("A08:2021",),
    "PHP_RCE_EVAL": ("A03:2021",),
    "PHP_SQLI_UNION": ("A03:2021",),
    "PHP_SQLI_TAUTOLOGY": ("A03:2021",),
}
# Alternate names for the same findings -> the rule id the guards emit.
RULE_ALIASES: dict[str, str] = {
    "PHP_OBJECT_INJECTION": "PHP_DESERIALIZE_DENIED",
    "PHP_CODE_EXEC": "PHP_RCE_EVAL",
}
# decision-log kinds that map straight onto a rule id
_LOG_KIND_RULES = frozenset({
    "tool_output_injection", "ssrf_boundary_violation", "covert_side_channel_suspected",
    "deobfuscated_exfil_detected", "mcp_rug_pull_detected",
    "schema_drift_denied", "tool_shadowing_denied", "gui_region_denied", "gui_keychord_denied",
    "provenance_tamper_denied", "sharded_exfil_denied",
    "PHP_PATH_TRAVERSAL", "PHP_DESERIALIZE_DENIED", "PHP_RCE_EVAL", "PHP_SQLI_UNION", "PHP_SQLI_TAUTOLOGY",
    "MCP_DEFINITION_DRIFT", "MCP_TOOL_SHADOWING", "MCP_DESCRIPTION_POISONING", "WORKSPACE_CONFIG_WRITE",
    "WORKSPACE_HOOK_TAMPER", "WORKSPACE_SYMLINK_ESCAPE", "WORKSPACE_HIDDEN_DIRECTIVE", "CFI_TAINTED_PRIVILEGED_SINK",
    "CFI_UNENDORSED_TARGET", "STEGO_SECRET_SHINGLE_LEAK", "STEGO_SUBSEQUENCE_EXFIL",
    "REGISTRY_PIN_DRIFT", "REGISTRY_ALIAS_AMBIGUOUS", "WORKSPACE_EFFECT_DENIED",
    "FLOW_MANIFEST_DENIED", "SIMILARITY_LEAK_DENIED",
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
        tags += [f"OWASP-Agentic/{a} (approximate)" for a in OWASP_ASI.get(rid, ())]
        tags += [f"external/cwe/{c.lower()}" for c in CWE.get(rid, ())]
        tags += [f"OWASP-Top10/{a}" for a in OWASP_WEB.get(rid, ())]
        tags += [f"OWASP-LLM/{a} (approximate)" for a in OWASP_LLM.get(rid, ())]
        rules.append({
            "id": rid,
            "name": "".join(w.capitalize() for w in rid.lower().split("_")),
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
            kind = RULE_ALIASES.get(row.get("kind"), row.get("kind"))
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
