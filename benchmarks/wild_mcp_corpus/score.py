#!/usr/bin/env python3
"""Score the wild MCP corpus with the gateway's existing static checks.

Python 3.12 standard library, plus the gateway modules themselves (those
modules are also standard-library only). No network. No new predicates.

The fourteen predicates are the validators named in
``docs/AgentGate_Validator_Specification.md``:

    R W F I P T S V D Z C E B A

R's cold path (descriptor lint, local schema profile, method-name rule,
canonical digest) can run on one published tool descriptor. Its hot path
cannot: pin equality, sticky revocation, and cross-provider alias
ambiguity need a previous pin or a second provider. The other thirteen
predicates need a call, a session, a workflow, or a filesystem snapshot.
They are counted in ``skipped`` and are not scored.

Other static checks that already exist and do apply to a tool list are
scored beside R, each named after the function or rule code that implements
it. Quick Check's four words (read, write, send, credential use) are not a
separate classifier. ``tool_class`` returns six classes, and unrecognized
names fail closed to ``write`` (or ``credential_use`` when the name looks
sensitive). Declared OAuth scopes are not scored: nothing in the gateway
decides that a scope is over-broad.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "agent-gateway"))

from agent_gateway.common import Denied  # noqa: E402
from agent_gateway.mcp_capability_manifest_guard import (  # noqa: E402
    McpCapabilityManifestGuard,
    NAMESPACE_FLOOD,
    OVERPRIVILEGED,
    PURPOSE_MISMATCH,
)
from agent_gateway.mcp_rugpull_guard import (  # noqa: E402
    DRIFT,
    McpRugPullGuard,
    POISONING,
    SHADOWING,
)
from agent_gateway.registry_pin_validator import make_pin  # noqa: E402
from agent_gateway.taint import SENSITIVE_READ_TOOLS, TOOL_EGRESS  # noqa: E402
from agent_gateway.toxic_combinations import (  # noqa: E402
    _NAME_RULES,
    _SENSITIVE_WORDS,
    analyze,
    tool_class,
)

Z95 = Decimal("1.959963984540054")  # N(0,1) inverse CDF at 0.975
Q6 = Decimal("0.000001")

PREDICATES_14 = (
    {"id": "R", "module": "registry_pin_validator.py",
     "static": "cold path only (lint, local schema profile, method name, digest)"},
    {"id": "W", "module": "workspace_path_validator.py",
     "static": "no", "needs": "a concrete path or command and a filesystem snapshot"},
    {"id": "F", "module": "lattice_flow_validator.py",
     "static": "no", "needs": "a workflow manifest and a call"},
    {"id": "I", "module": "shingle_similarity_validator.py",
     "static": "no", "needs": "protected strings and an outbound argument"},
    {"id": "P", "module": "linear_obligation_validator.py",
     "static": "no", "needs": "a Petri-net workflow and a transition"},
    {"id": "T", "module": "symbolic_fs_transducer.py",
     "static": "no", "needs": "file operations and labels"},
    {"id": "S", "module": "canonical_argument_confinement.py",
     "static": "no", "needs": "a concrete argument object"},
    {"id": "V", "module": "fork_join_vector_validator.py",
     "static": "no", "needs": "a live fork/join session"},
    {"id": "D", "module": "dynamic_ingression_validator.py",
     "static": "no", "needs": "a tool result and a later outbound string"},
    {"id": "Z", "module": "transform_invariant_validator.py",
     "static": "no", "needs": "protected values and an outbound string"},
    {"id": "C", "module": "causality_laundering_validator.py",
     "static": "no", "needs": "observed filesystem effects"},
    {"id": "E", "module": "event_channel_capacity_validator.py",
     "static": "no", "needs": "a live event stream"},
    {"id": "B", "module": "blindfold_opaque_fault_validator.py",
     "static": "no", "needs": "a request and remembered refusals"},
    {"id": "A", "module": "reachability_confinement_validator.py",
     "static": "no", "needs": "an authored workflow DAG"},
)

# Scored policy predicates. Classes are reported separately; they are labels.
APPLIED = (
    {"id": "R_cold_path", "letter": "R",
     "source": "registry_pin_validator.make_pin",
     "needs_published_schema": True,
     "meaning": "make_pin denies the published descriptor (first reason only)"},
    {"id": "toxic_2hop", "letter": None,
     "source": "toxic_combinations.analyze totals.toxic_2hop",
     "needs_published_schema": True,
     "meaning": "at least one unprotected external_read → read → sink path"},
    {"id": "toxic_3hop", "letter": None,
     "source": "toxic_combinations.analyze totals.toxic_3hop",
     "needs_published_schema": True,
     "meaning": "at least one unprotected external_read → read → read → sink path"},
    {"id": "MCP_FIRST_SEEN_OVERPRIVILEGED", "letter": None,
     "source": "mcp_capability_manifest_guard.register_listing",
     "needs_published_schema": True,
     "meaning": "unverified profile (the guard's default) refuses a credential or exec parameter"},
    {"id": "MCP_SCHEMA_PURPOSE_MISMATCH", "letter": None,
     "source": "mcp_capability_manifest_guard.register_listing",
     "needs_published_schema": True,
     "meaning": "a read-like tool name declares a side-effecting parameter; first-match, after overprivileged"},
    {"id": "MCP_TOOL_NAMESPACE_FLOOD", "letter": None,
     "source": "mcp_capability_manifest_guard.register_listing",
     "needs_published_schema": False,
     "meaning": "more than 32 named tools in the listing"},
    {"id": "MCP_DESCRIPTION_POISONING", "letter": None,
     "source": "mcp_rugpull_guard.register_listing",
     "needs_published_schema": False,
     "meaning": "scan_definition finds a hidden-instruction marker; checked before shadowing"},
    {"id": "MCP_TOOL_SHADOWING", "letter": None,
     "source": "mcp_rugpull_guard.register_listing",
     "needs_published_schema": False,
     "meaning": "normalized name is a core built-in; one server at a time, so no cross-server hits"},
)

CLASSES = (
    "external_read", "internal_read", "sensitive_read", "write", "send", "credential_use",
)

SKIPPED_EXTRA = (
    {"id": "R_hot_path", "letter": "R",
     "reason": "Pin equality, sticky revocation, and alias ambiguity need an earlier pin or a second provider."},
    {"id": "MCP_DEFINITION_DRIFT", "letter": None,
     "reason": "mcp_rugpull_guard drift compares a new fingerprint to a pin. One listing has no pin."},
    {"id": "SCHEMA_DRIFT_DENIED", "letter": None,
     "reason": "schema_integrity_guard drift needs a second registration of the same tool."},
    {"id": "TOOL_SHADOWING_DENIED_CROSS_SERVER", "letter": None,
     "reason": (
         "schema_integrity_guard distance-1 shadowing is for servers co-installed in one session. "
         "It was not run across unrelated corpus rows."
     )},
    {"id": "over_broad_scopes", "letter": None,
     "reason": "No gateway function decides that a declared OAuth scope is over-broad. Scopes were only recorded."},
    {"id": "untrusted_read_plus_write_or_send", "letter": None,
     "reason": (
         "No function flags mere co-occurrence of an untrusted read and a write or send. "
         "The coded rule is toxic_combinations, which also requires an internal or sensitive read "
         "and a free-text sink channel with no agw1 boundary."
     )},
)


def wilson(k: int, n: int) -> tuple[str, str] | None:
    """95% Wilson score interval, bounds quantized to 6 decimal places."""
    if n <= 0 or k < 0 or k > n:
        raise ValueError("wilson expects 0 <= k <= n and n > 0")
    z = Z95
    nd = Decimal(n)
    phat = Decimal(k) / nd
    z2 = z * z
    denom = Decimal(1) + z2 / nd
    center = (phat + z2 / (Decimal(2) * nd)) / denom
    radicand = phat * (Decimal(1) - phat) / nd + z2 / (Decimal(4) * nd * nd)
    margin = z * radicand.sqrt() / denom
    lo = center - margin
    hi = center + margin
    if lo < 0:
        lo = Decimal(0)
    if hi > 1:
        hi = Decimal(1)
    return (_q(lo), _q(hi))


def _q(value: Decimal) -> str:
    return format(value.quantize(Q6, rounding=ROUND_HALF_EVEN), "f")


def _name_norm(name: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return "_" + "_".join(t for t in re.split(r"[^a-z0-9]+", spaced) if t) + "_"


def classification_basis(tool: dict) -> str:
    """Which branch of ``tool_class`` fired. The class itself is still ``tool_class``."""
    from agent_gateway.toxic_combinations import _label

    if _label(tool):
        return "declared"
    name = str(tool.get("name") or "")
    if name in SENSITIVE_READ_TOOLS:
        return "sensitive_table"
    if name in TOOL_EGRESS:
        return "egress_table"
    norm = _name_norm(name)

    def has(word: str) -> bool:
        return "_" + word.rstrip("_") in norm

    if any(has(w) for w in _SENSITIVE_WORDS):
        # May still be a name-rule class (sensitive_read / credential_use) or the default.
        pass
    for _cls, words in _NAME_RULES:
        if any(has(w) for w in words):
            return "name_rule"
    return "default"


def _r_reason(tool: dict) -> str | None:
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return None
    name = str(tool.get("name") or "")
    doc: dict = {"inputSchema": schema}
    for field in ("description", "title"):
        value = tool.get(field)
        if isinstance(value, str) and value:
            doc[field] = value
    for field in ("outputSchema", "annotations"):
        value = tool.get(field)
        if isinstance(value, dict):
            doc[field] = value
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        make_pin("corpus", name, raw)
    except Denied as exc:
        return str(exc.args[0]) if exc.args else "DENIED"
    return None


def _tools(record: dict) -> list[dict]:
    return [t for t in record.get("tools") or [] if isinstance(t, dict) and t.get("name")]


def toxic_path_exists(tools: list[dict]) -> tuple[bool, bool]:
    """Whether ``analyze`` would count a toxic 2-hop and a toxic 3-hop.

    Same nodes and same path shape as ``toxic_combinations.analyze``. Stops at
    the first path. On this corpus that boolean matches the full enumeration.
    """
    from agent_gateway.toxic_combinations import build_nodes, load_inventory

    loaded, boundary = load_inventory({"tools": tools})
    nodes = build_nodes(loaded, boundary)
    sources = [n for n in nodes if n.is_source]
    reads = [n for n in nodes if n.is_read]
    sinks = [n for n in nodes if n.is_sink and not n.boundary]
    hop2 = any(sink.name != read.name for _src in sources for read in reads for sink in sinks)
    hop3 = False
    if sources and len(reads) >= 2 and sinks:
        for first in reads:
            for second in reads:
                if first.name == second.name:
                    continue
                for sink in sinks:
                    if sink.name not in (first.name, second.name):
                        hop3 = True
                        break
                if hop3:
                    break
            if hop3:
                break
    return hop2, hop3


def score_server(record: dict) -> dict[str, str]:
    """Map predicate id and ``class:<name>`` to ``hit``, ``miss``, or ``na``."""
    tools = _tools(record)
    published = record.get("schema_policy") == "published"
    verdicts: dict[str, str] = {}

    classes = {tool_class(t) for t in tools}
    for name in CLASSES:
        verdicts[f"class:{name}"] = "hit" if name in classes else "miss"

    if published:
        report = analyze({"tools": tools})
        totals = report.totals
        verdicts["toxic_2hop"] = "hit" if totals.get("toxic_2hop", 0) else "miss"
        verdicts["toxic_3hop"] = "hit" if totals.get("toxic_3hop", 0) else "miss"
        reasons = [r for r in (_r_reason(t) for t in tools) if r]
        verdicts["R_cold_path"] = "na" if not any(isinstance(t.get("inputSchema"), dict) for t in tools) else (
            "hit" if reasons else "miss"
        )
        cap = McpCapabilityManifestGuard().register_listing("srv", tools)
        codes = {v.code for v in cap if not v.ok}
        verdicts["MCP_FIRST_SEEN_OVERPRIVILEGED"] = "hit" if OVERPRIVILEGED in codes else "miss"
        verdicts["MCP_SCHEMA_PURPOSE_MISMATCH"] = "hit" if PURPOSE_MISMATCH in codes else "miss"
    else:
        verdicts["toxic_2hop"] = "na"
        verdicts["toxic_3hop"] = "na"
        verdicts["R_cold_path"] = "na"
        verdicts["MCP_FIRST_SEEN_OVERPRIVILEGED"] = "na"
        verdicts["MCP_SCHEMA_PURPOSE_MISMATCH"] = "na"

    cap_all = McpCapabilityManifestGuard().register_listing("srv", tools)
    flood = any((not v.ok) and v.code == NAMESPACE_FLOOD for v in cap_all)
    verdicts["MCP_TOOL_NAMESPACE_FLOOD"] = "hit" if flood else "miss"

    rug = McpRugPullGuard().register_listing("srv", tools)
    rug_codes = {v.code for v in rug if not v.ok}
    verdicts["MCP_DESCRIPTION_POISONING"] = "hit" if POISONING in rug_codes else "miss"
    verdicts["MCP_TOOL_SHADOWING"] = "hit" if SHADOWING in rug_codes else "miss"
    if DRIFT in rug_codes:  # one listing cannot drift; keep it visible if it ever does
        verdicts["MCP_DEFINITION_DRIFT"] = "hit"
    return verdicts


def _proportion(k: int, n: int) -> dict:
    if n == 0:
        return {"hits": 0, "n": 0, "prevalence": None, "wilson95": None}
    return {
        "hits": k,
        "n": n,
        "prevalence": _q(Decimal(k) / Decimal(n)),
        "wilson95": list(wilson(k, n)),
    }


def _aggregate(rows: list[dict], key: str) -> dict:
    applicable = [r for r in rows if r["verdicts"].get(key) in {"hit", "miss"}]
    hits = sum(1 for r in applicable if r["verdicts"][key] == "hit")
    out = _proportion(hits, len(applicable))
    out["id"] = key
    return out


def _default_branch_sensitivity(records: list[dict]) -> dict:
    """Toxic-path existence after dropping tools ``tool_class`` did not name or tabulate.

    Not a separate predicate. It asks how much of the toxic-path count is the
    fail-closed default (unrecognised name becomes ``write``).
    """
    hop2 = hop3 = n = 0
    for record in records:
        if record.get("stratum") != "smithery_list_order":
            continue
        n += 1
        kept = [t for t in _tools(record) if classification_basis(t) != "default"]
        a, b = toxic_path_exists(kept)
        hop2 += a
        hop3 += b
    return {
        "stratum": "smithery_list_order",
        "n": n,
        "toxic_2hop_without_default_branch_tools": hop2,
        "toxic_3hop_without_default_branch_tools": hop3,
        "note": (
            "Tools on the default branch of tool_class were removed and the same "
            "node and path rules were applied. This is a sensitivity check, not a predicate."
        ),
    }


def score_records(records: list[dict]) -> dict:
    scored = []
    for record in records:
        scored.append({
            "stratum": record.get("stratum"),
            "schema_policy": record.get("schema_policy"),
            "verdicts": score_server(record),
            "tools": _tools(record),
        })

    strata = sorted({r["stratum"] for r in scored})
    applied = []
    classes = []
    for stratum in strata:
        rows = [r for r in scored if r["stratum"] == stratum]
        for spec in APPLIED:
            row = _aggregate(rows, spec["id"])
            row.update({"stratum": stratum, "source": spec["source"], "meaning": spec["meaning"],
                        "letter": spec["letter"]})
            applied.append(row)
        for name in CLASSES:
            row = _aggregate(rows, f"class:{name}")
            row.update({"stratum": stratum, "class": name,
                        "source": "toxic_combinations.tool_class"})
            classes.append(row)

    basis = {"declared": 0, "sensitive_table": 0, "egress_table": 0, "name_rule": 0, "default": 0}
    tool_class_counts = {name: 0 for name in CLASSES}
    readonly_true = 0
    readonly_and_sink = 0
    tools_total = 0
    tools_with_schema = 0
    r_reasons: dict[str, int] = {}
    sinks = {"write", "send", "credential_use"}
    for record, scored_row in zip(records, scored):
        if record.get("schema_policy") != "published":
            continue
        for tool in scored_row["tools"]:
            tools_total += 1
            cls = tool_class(tool)
            tool_class_counts[cls] = tool_class_counts.get(cls, 0) + 1
            basis[classification_basis(tool)] += 1
            if isinstance(tool.get("inputSchema"), dict):
                tools_with_schema += 1
            reason = _r_reason(tool)
            if reason:
                r_reasons[reason] = r_reasons.get(reason, 0) + 1
            ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
            if ann.get("readOnlyHint") is True:
                readonly_true += 1
                if cls in sinks:
                    readonly_and_sink += 1

    over_cap = sum(
        1 for r in records
        if r.get("schema_policy") == "published" and len(_tools(r)) > 400
    )
    use_counts = [
        r["use_count"] for r in records
        if r.get("stratum") == "smithery_list_order" and isinstance(r.get("use_count"), int)
    ]
    use_counts.sort()

    skipped = []
    for spec in PREDICATES_14:
        if spec["id"] == "R":
            continue
        skipped.append({
            "id": spec["id"], "module": spec["module"], "reason": f"Needs {spec['needs']}. Not applied.",
        })
    for spec in SKIPPED_EXTRA:
        skipped.append({"id": spec["id"], "module": None, "reason": spec["reason"]})

    return {
        "schema": "agentgate.wild-mcp-corpus-score/1",
        "predicates_14": [dict(p) for p in PREDICATES_14],
        "applied_note": (
            "Server-level. A hit means at least one tool on that server tripped the check. "
            "Wilson bounds are the 95% score interval for that observed count under an iid "
            "Bernoulli model. This corpus is not a random sample, so the interval is not a "
            "confidence interval for all public MCP servers."
        ),
        "strata": {name: sum(1 for r in scored if r["stratum"] == name) for name in strata},
        "applied": applied,
        "class_prevalence": classes,
        "skipped": skipped,
        "diagnostics_published_schemas_only": {
            "tools": tools_total,
            "tools_with_input_schema": tools_with_schema,
            "tool_class_counts": tool_class_counts,
            "classification_basis": basis,
            "r_cold_path_tool_reasons": dict(sorted(r_reasons.items())),
            "read_only_hint_true": readonly_true,
            "read_only_hint_true_and_classed_sink": readonly_and_sink,
            "published_servers_over_400_tools": over_cap,
            "analyzer_cap_note": (
                "toxic_combinations.load_inventory keeps the first 400 named tools. "
                "Servers above that cap are scored on that prefix, which is what analyze() does."
            ),
            "smithery_use_count": _use_summary(use_counts),
            "capability_note": (
                "MCP_FIRST_SEEN_OVERPRIVILEGED is the guard's result with no server profile. "
                "An unverified server is granted neither credential nor exec parameters, so any "
                "such parameter is a hit. That is the policy default, not a confirmed vulnerability."
            ),
            "tool_class_note": (
                "Unrecognised names are write, or credential_use when the name matches a sensitive word. "
                "MCP readOnlyHint is not an input to tool_class."
            ),
            "default_branch_sensitivity": _default_branch_sensitivity(records),
        },
    }


def _use_summary(values: list[int]) -> dict | None:
    if not values:
        return None
    mid = len(values) // 2
    median = values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) // 2
    return {"n": len(values), "min": values[0], "median": median, "max": values[-1]}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a wild MCP corpus JSONL")
    parser.add_argument("corpus", type=Path, nargs="?", default=HERE / "servers.jsonl")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    raw = args.corpus.read_bytes()
    result = score_records(load_jsonl(args.corpus))
    result["corpus_file"] = args.corpus.name
    result["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    result["corpus_servers"] = raw.count(b"\n")
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
