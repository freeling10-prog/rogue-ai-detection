#!/usr/bin/env python3
"""Server-level precision of the toxic 2-hop flag, from a single reviewer.

The draw is fixed before labels are applied. From each snapshot, the servers
whose ``score_server`` verdict for ``toxic_2hop`` is ``hit`` are sorted by
``server_id`` and ``random.Random(PRECISION_SEED).sample`` takes
``PER_STRATUM`` of them (or all of them, if fewer). No backfill across strata.
Case ids are assigned after the draw, list-order first, in sample order.

The reviewer reads tool names, descriptions, and schemas, and a public source
page only when the listing is not enough. The reviewer does not connect to a
deployment. The judgment is whether ``tool_class`` assigned the capability
the listing describes. The free-text channel rule and the param-egress sink
rule are the predicate; they are not relitigated. A path that still exists
after every tool the reviewer is sure was mislabeled is corrected, and after
every tool the reviewer cannot classify is removed, is a plausible real path
under that predicate. A flag that disappears even if uncertain tools keep the
scorer's class is a false positive. A flag that remains only while an
uncertain tool is kept is ``cant_tell``.

Labels are keyed by SHA-256 of the qualified name and of each tool name.
The public file has no server name, homepage, or source URL. It is a
reviewer judgment of a static class assignment, not a vulnerability finding.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent-gateway"))

from agent_gateway.toxic_combinations import CLASSES, MAX_TOOLS, build_nodes  # noqa: E402

from benchmarks.wild_mcp_corpus import score as S  # noqa: E402
from benchmarks.wild_mcp_corpus.compare import LIST_STRATUM, UNIFORM_STRATUM  # noqa: E402

PRECISION_SEED = 20261102
PER_STRATUM = 14
DECISIONS = ("agree", "disagree", "uncertain")
CAUSES = (
    "default_branch_sink",
    "name_rule_not_a_source",
    "name_rule_not_a_read",
    "name_rule_not_a_sink",
    "table_mismatch",
    "other_misclassification",
)
LABELS = ("plausible", "false_positive", "cant_tell")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def scored_tools(tools: list[dict]) -> list[dict]:
    """The prefix ``analyze`` scores. Later tools do not affect the flag."""
    named = [t for t in tools if isinstance(t, dict) and t.get("name")]
    return named[:MAX_TOOLS]


def graph_name(name: str) -> str:
    """The name ``build_nodes`` puts on the graph."""
    return str(name)[:120]


def participating_names(tools: list[dict]) -> list[str]:
    """Tool names that sit on a toxic 2-hop under the scorer's own classes."""
    nodes = build_nodes(tools, False)
    names = []
    for node in nodes:
        if node.is_source or node.is_read or node.is_sink:
            names.append(node.name)
    return names


def draw_review_cases(list_records: list[dict], uniform_records: list[dict],
                      seed: int = PRECISION_SEED, per_stratum: int = PER_STRATUM) -> list[dict]:
    """Stratified sample of servers with a toxic 2-hop hit. No server names in the result."""
    rng = random.Random(seed)
    grouped = {
        LIST_STRATUM: [r for r in list_records if r.get("stratum") == LIST_STRATUM],
        UNIFORM_STRATUM: [r for r in uniform_records if r.get("stratum") == UNIFORM_STRATUM],
    }
    drawn: list[tuple[str, dict]] = []
    for stratum in (LIST_STRATUM, UNIFORM_STRATUM):
        flagged = []
        for record in grouped[stratum]:
            if S.score_server(record).get("toxic_2hop") == "hit":
                flagged.append(record)
        flagged.sort(key=lambda r: str(r.get("server_id") or ""))
        k = min(per_stratum, len(flagged))
        picks = rng.sample(flagged, k) if k else []
        for record in picks:
            drawn.append((stratum, record))
    cases = []
    for index, (stratum, record) in enumerate(drawn, start=1):
        cases.append({
            "case_id": f"p{index:02d}",
            "stratum": stratum,
            "server_sha256": sha256_text(str(record.get("server_id") or "")),
        })
    return cases


def _judgment_map(judgments: list[dict]) -> dict[str, dict]:
    out = {}
    for item in judgments:
        if not isinstance(item, dict):
            raise ValueError("judgment must be an object")
        digest = str(item.get("tool_sha256") or "")
        decision = item.get("decision")
        if decision not in DECISIONS:
            raise ValueError(f"bad decision {decision!r}")
        if decision == "disagree":
            corrected = item.get("corrected_class")
            if corrected not in CLASSES:
                raise ValueError("disagree requires a corrected class")
            cause = item.get("cause")
            if cause not in CAUSES:
                raise ValueError(f"bad cause {cause!r}")
        elif item.get("corrected_class") not in (None, "") or item.get("cause") not in (None, ""):
            raise ValueError("agree and uncertain carry no correction")
        if digest in out:
            raise ValueError("duplicate tool hash in one case")
        out[digest] = item
    return out


def _apply(tools: list[dict], judgments: dict[str, dict], drop_uncertain: bool) -> list[dict]:
    rewritten = []
    for tool in tools:
        name = graph_name(tool.get("name") or "")
        item = judgments.get(sha256_text(name))
        if item is None:
            rewritten.append(tool)
            continue
        decision = item["decision"]
        if decision == "uncertain" and drop_uncertain:
            continue
        if decision == "disagree":
            copy = dict(tool)
            copy["class"] = item["corrected_class"]
            rewritten.append(copy)
            continue
        rewritten.append(tool)
    return rewritten


def label_from_judgments(tools: list[dict], judgments: list[dict]) -> dict:
    """Derive the server label from tool judgments. Raises if a participating tool is missing."""
    tools = scored_tools(tools)
    mapped = _judgment_map(judgments)
    needed = participating_names(tools)
    missing = [name for name in needed if sha256_text(graph_name(name)) not in mapped]
    if missing:
        raise ValueError(f"{len(missing)} participating tools have no judgment")
    extra = set(mapped) - {sha256_text(graph_name(name)) for name in needed}
    if extra:
        raise ValueError("judgment for a tool that is not on a 2-hop path")
    survives_without_uncertain, _ = S.toxic_path_exists(_apply(tools, mapped, drop_uncertain=True))
    survives_with_uncertain, _ = S.toxic_path_exists(_apply(tools, mapped, drop_uncertain=False))
    if survives_without_uncertain:
        label = "plausible"
    elif survives_with_uncertain:
        label = "cant_tell"
    else:
        label = "false_positive"
    disagreed = [item for item in judgments if item["decision"] == "disagree"]
    cause_counts: dict[str, int] = {}
    for item in disagreed:
        cause_counts[item["cause"]] = cause_counts.get(item["cause"], 0) + 1
    primary = None
    if label == "false_positive" and cause_counts:
        best = max(cause_counts.values())
        for cause in CAUSES:
            if cause_counts.get(cause) == best:
                primary = cause
                break
    elif label == "false_positive":
        primary = "other_misclassification"
    return {
        "label": label,
        "primary_cause": primary,
        "tools_reviewed": len(needed),
        "tools_agreed": sum(1 for item in judgments if item["decision"] == "agree"),
        "tools_disagreed": len(disagreed),
        "tools_uncertain": sum(1 for item in judgments if item["decision"] == "uncertain"),
        "disagreement_causes": dict(sorted(cause_counts.items())),
    }


def precision_summary(cases: list[dict]) -> dict:
    """Wilson intervals for reviewer precision. ``cases`` already carry ``label``."""
    counts = {label: 0 for label in LABELS}
    by_stratum: dict[str, dict[str, int]] = {}
    primary: dict[str, int] = {}
    tool_causes: dict[str, int] = {}
    for case in cases:
        label = case.get("label")
        if label not in counts:
            raise ValueError(f"bad label {label!r}")
        counts[label] += 1
        stratum = str(case.get("stratum") or "")
        bucket = by_stratum.setdefault(stratum, {name: 0 for name in LABELS})
        bucket[label] += 1
        if label == "false_positive" and case.get("primary_cause"):
            cause = case["primary_cause"]
            primary[cause] = primary.get(cause, 0) + 1
        for cause, n in (case.get("disagreement_causes") or {}).items():
            tool_causes[cause] = tool_causes.get(cause, 0) + int(n)
    n = len(cases)
    decided = counts["plausible"] + counts["false_positive"]
    return {
        "schema": "agentgate.wild-mcp-corpus-precision-summary/1",
        "n_reviewed": n,
        "counts": counts,
        "by_stratum": by_stratum,
        "precision_among_decided": _rate(counts["plausible"], decided),
        "precision_counting_cant_tell_as_not_plausible": _rate(counts["plausible"], n),
        "primary_false_positive_causes": dict(sorted(primary.items(), key=lambda kv: (-kv[1], kv[0]))),
        "tool_disagreement_causes": dict(sorted(tool_causes.items(), key=lambda kv: (-kv[1], kv[0]))),
        "note": (
            "precision_among_decided excludes cant_tell from the denominator. "
            "precision_counting_cant_tell_as_not_plausible puts cant_tell in the "
            "denominator and not in the numerator. The reviewer is the project author, "
            "one rater, no second rater, so there is no inter-rater agreement. "
            "A plausible label is a static reading of names, descriptions, and schemas, "
            "not a confirmed vulnerability."
        ),
    }


def _rate(k: int, n: int) -> dict:
    if n <= 0:
        return {"hits": k, "n": 0, "prevalence": None, "wilson95": None}
    return S._proportion(k, n)


def attach_labels(drawn: list[dict], labeled_cases: list[dict]) -> list[dict]:
    """Copy reviewer fields onto the draw. The draw's ids and strata must match."""
    by_id = {case["case_id"]: case for case in labeled_cases}
    if set(by_id) != {case["case_id"] for case in drawn}:
        raise ValueError("label case ids do not match the draw")
    merged = []
    for case in drawn:
        label = by_id[case["case_id"]]
        if label.get("stratum") != case["stratum"] or label.get("server_sha256") != case["server_sha256"]:
            raise ValueError(f"{case['case_id']} does not match the draw")
        judgments = label.get("judgments")
        if not isinstance(judgments, list):
            raise ValueError(f"{case['case_id']} is missing judgments")
        merged.append({
            "case_id": case["case_id"],
            "stratum": case["stratum"],
            "server_sha256": case["server_sha256"],
            "judgments": judgments,
        })
    return merged


def records_by_hash(records: list[dict]) -> dict[str, dict]:
    return {sha256_text(str(r.get("server_id") or "")): r for r in records if r.get("server_id")}


def verify_labels(cases: list[dict], by_hash: dict[str, dict]) -> list[dict]:
    """Recompute each label from the corpus and the judgments."""
    verified = []
    for case in cases:
        record = by_hash.get(case["server_sha256"])
        if record is None:
            raise ValueError(f"{case['case_id']} is not in the scored corpora")
        derived = label_from_judgments(S._tools(record), case["judgments"])
        verified.append({**case, **derived})
    return verified


def write_review_packets(directory: Path, list_records: list[dict], uniform_records: list[dict]) -> list[dict]:
    """Write one JSON packet per drawn server. Packets name the server.

    They are a review worksheet. Do not commit the directory.
    """
    directory.mkdir(parents=True, exist_ok=True)
    rng_records = {
        LIST_STRATUM: [r for r in list_records if r.get("stratum") == LIST_STRATUM],
        UNIFORM_STRATUM: [r for r in uniform_records if r.get("stratum") == UNIFORM_STRATUM],
    }
    by_hash = {}
    for records in rng_records.values():
        by_hash.update(records_by_hash(records))
    cases = draw_review_cases(list_records, uniform_records)
    written = []
    for case in cases:
        record = by_hash[case["server_sha256"]]
        tools = scored_tools(S._tools(record))
        needed = set(participating_names(tools))
        brief = []
        for tool in tools:
            name = graph_name(tool.get("name") or "")
            if name not in needed:
                continue
            schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            fields = []
            for prop, spec in list(props.items())[:16]:
                typ = spec.get("type") if isinstance(spec, dict) else None
                enum = isinstance(spec, dict) and "enum" in spec
                fields.append({"name": prop, "type": typ, "enum": bool(enum)})
            brief.append({
                "name": name,
                "tool_sha256": sha256_text(name),
                "class": S.tool_class(tool),
                "basis": S.classification_basis(tool),
                "description": (tool.get("description") or "")[:700],
                "fields": fields,
            })
        packet = {
            **case,
            "server_id": record.get("server_id"),
            "homepage": record.get("homepage"),
            "source_url": record.get("source_url"),
            "description": (record.get("description") or "")[:700],
            "tools": brief,
        }
        (directory / f"{case['case_id']}.json").write_text(
            json.dumps(packet, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        written.append(case["case_id"])
    return cases


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Summarize toxic-2-hop precision labels")
    parser.add_argument("--labels", type=Path, default=HERE / "precision_labels.json")
    parser.add_argument("--list", type=Path, default=HERE / "servers.jsonl")
    parser.add_argument("--uniform", type=Path, default=HERE / "random_servers.jsonl")
    parser.add_argument("--out", type=Path, default=HERE / "precision_summary.json")
    args = parser.parse_args(argv)
    labels = load_json(args.labels)
    listed = S.load_jsonl(args.list)
    uniform = S.load_jsonl(args.uniform)
    # The labelled draw was made with the PR #40 classifier; the draw depends on it.
    with S.classifier("pr40"):
        drawn = draw_review_cases(listed, uniform, labels.get("seed", PRECISION_SEED),
                                  labels.get("per_stratum", PER_STRATUM))
        merged = attach_labels(drawn, labels["cases"])
        verified = verify_labels(merged, records_by_hash(listed + uniform))
    summary = precision_summary(verified)
    summary["seed"] = labels.get("seed", PRECISION_SEED)
    summary["per_stratum"] = labels.get("per_stratum", PER_STRATUM)
    summary["reviewer"] = "project author, single rater"
    for case, got in zip(labels["cases"], verified):
        if "label" in case and case["label"] != got["label"]:
            raise SystemExit(f"{case['case_id']} stored label does not match the judgments")
        if "primary_cause" in case and case["primary_cause"] != got["primary_cause"]:
            raise SystemExit(f"{case['case_id']} stored cause does not match the judgments")
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("n_reviewed", "counts", "precision_among_decided",
                                              "precision_counting_cant_tell_as_not_plausible",
                                              "primary_false_positive_causes")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
