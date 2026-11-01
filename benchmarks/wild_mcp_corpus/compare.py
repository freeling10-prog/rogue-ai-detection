#!/usr/bin/env python3
"""Side-by-side prevalence for the list-order slice and the uniform sample.

Uses ``score.wilson`` and ``score.score_server``. No predicate is reimplemented.
The difference interval is Newcombe's hybrid score interval (method 10, 1998)
for the difference of two independent binomial proportions, quantized like
the Wilson bounds. The list-order slice is not a random sample, so that
interval is not a confidence interval for a difference of two population
parameters. It is reported as the interval the procedure yields for these
two observed proportions, and the uniform sample's own Wilson interval is
the one that refers to the schema-publishing Smithery frame.
"""
from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.wild_mcp_corpus import score as S  # noqa: E402

Q6 = S.Q6
LIST_STRATUM = "smithery_list_order"
UNIFORM_STRATUM = "smithery_uniform"


def _q(value: Decimal) -> str:
    return format(value.quantize(Q6, rounding=ROUND_HALF_EVEN), "f")


def newcombe(k1: int, n1: int, k2: int, n2: int) -> dict:
    """95% Newcombe hybrid score interval for ``p1 - p2``.

    ``p1 = k1/n1`` is the first sample (the uniform sample in this study)
    and ``p2 = k2/n2`` is the second (the list-order slice). Bounds are
    clamped to [-1, 1] and quantized to 6 decimal places, half-even.
    """
    if min(n1, n2) <= 0 or not (0 <= k1 <= n1) or not (0 <= k2 <= n2):
        raise ValueError("newcombe expects 0 <= k <= n and n > 0 for both samples")
    lo1, hi1 = (Decimal(x) for x in S.wilson(k1, n1))
    lo2, hi2 = (Decimal(x) for x in S.wilson(k2, n2))
    p1 = Decimal(k1) / Decimal(n1)
    p2 = Decimal(k2) / Decimal(n2)
    diff = p1 - p2
    lower = diff - ((p1 - lo1) ** 2 + (hi2 - p2) ** 2).sqrt()
    upper = diff + ((hi1 - p1) ** 2 + (p2 - lo2) ** 2).sqrt()
    if lower < -1:
        lower = Decimal(-1)
    if upper > 1:
        upper = Decimal(1)
    return {
        "difference": _q(diff),
        "newcombe95": [_q(lower), _q(upper)],
        "direction": "uniform_minus_list_order",
    }


def _quartile_summary(values: list[int]) -> dict | None:
    """min, index quartile, median (same rule as ``score._use_summary``), max."""
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    base = S._use_summary(ordered)
    return {
        "n": n,
        "min": ordered[0],
        "p25": ordered[n // 4],
        "median": base["median"],
        "p75": ordered[(3 * n) // 4],
        "max": ordered[-1],
        "zeros": sum(1 for v in ordered if v == 0),
        "quartile_index": "order statistic at n//4 and (3*n)//4; median matches score._use_summary",
    }


def _hits(records: list[dict], key: str) -> tuple[int, int]:
    applicable = []
    hits = 0
    for record in records:
        verdict = record["_verdicts"].get(key)
        if verdict not in {"hit", "miss"}:
            continue
        applicable.append(record)
        if verdict == "hit":
            hits += 1
    return hits, len(applicable)


def _sensitivity(records: list[dict]) -> dict:
    hop2 = hop3 = 0
    for record in records:
        kept = [t for t in S._tools(record) if S.classification_basis(t) != "default"]
        a, b = S.toxic_path_exists(kept)
        hop2 += int(a)
        hop3 += int(b)
    return {
        "n": len(records),
        "toxic_2hop_without_default_branch_tools": hop2,
        "toxic_3hop_without_default_branch_tools": hop3,
    }


def _metric_ids() -> list[str]:
    ids = [spec["id"] for spec in S.APPLIED]
    ids.extend(f"class:{name}" for name in S.CLASSES)
    return ids


def _row(key: str, uniform: list[dict], listed: list[dict]) -> dict:
    k1, n1 = _hits(uniform, key)
    k2, n2 = _hits(listed, key)
    left = S._proportion(k1, n1)
    right = S._proportion(k2, n2)
    diff = newcombe(k1, n1, k2, n2) if n1 and n2 else None
    return {
        "id": key,
        "uniform": left,
        "list_order": right,
        "difference": diff,
    }


def compare_records(list_records: list[dict], uniform_records: list[dict]) -> dict:
    listed = [r for r in list_records if r.get("stratum") == LIST_STRATUM]
    uniform = [r for r in uniform_records if r.get("stratum") == UNIFORM_STRATUM]
    for record in listed + uniform:
        record["_verdicts"] = S.score_server(record)
    overlap = {r.get("server_id", "").casefold() for r in listed} & {
        r.get("server_id", "").casefold() for r in uniform
    }
    rows = [_row(key, uniform, listed) for key in _metric_ids()]
    sens_u = _sensitivity(uniform)
    sens_l = _sensitivity(listed)
    return {
        "schema": "agentgate.wild-mcp-corpus-comparison/1",
        "uniform_stratum": UNIFORM_STRATUM,
        "list_order_stratum": LIST_STRATUM,
        "n_uniform": len(uniform),
        "n_list_order": len(listed),
        "server_id_overlap": len(overlap),
        "use_count_uniform": _quartile_summary(
            [r["use_count"] for r in uniform if isinstance(r.get("use_count"), int)]
        ),
        "use_count_list_order": _quartile_summary(
            [r["use_count"] for r in listed if isinstance(r.get("use_count"), int)]
        ),
        "default_branch_sensitivity": {
            "uniform": sens_u,
            "list_order": sens_l,
            "toxic_2hop_difference": newcombe(
                sens_u["toxic_2hop_without_default_branch_tools"], sens_u["n"],
                sens_l["toxic_2hop_without_default_branch_tools"], sens_l["n"],
            ) if sens_u["n"] and sens_l["n"] else None,
            "toxic_3hop_difference": newcombe(
                sens_u["toxic_3hop_without_default_branch_tools"], sens_u["n"],
                sens_l["toxic_3hop_without_default_branch_tools"], sens_l["n"],
            ) if sens_u["n"] and sens_l["n"] else None,
            "note": (
                "Tools on the default branch of tool_class were removed and "
                "toxic_path_exists was applied. Sensitivity check, not a predicate."
            ),
        },
        "metrics": rows,
        "interval_note": (
            "wilson95 is score.wilson, the 95% Wilson score interval. "
            "newcombe95 is Newcombe's 1998 hybrid score interval for "
            "uniform prevalence minus list-order prevalence. "
            "The list-order slice is a convenience prefix, so newcombe95 is not "
            "a confidence interval for a difference of population parameters. "
            "The uniform Wilson interval refers to Smithery servers that published "
            "a tool schema, under the simple random sample in sample_random.py, "
            "without a finite-population correction."
        ),
    }


def render_markdown(comparison: dict) -> str:
    lines = [
        "| Metric | Uniform | 95% Wilson | List order | 95% Wilson | Uniform − list order | 95% Newcombe |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in comparison["metrics"]:
        u, o = row["uniform"], row["list_order"]
        diff = row["difference"] or {}
        u_w = "–".join(u["wilson95"]) if u.get("wilson95") else ""
        o_w = "–".join(o["wilson95"]) if o.get("wilson95") else ""
        d_w = "–".join(diff.get("newcombe95") or []) 
        lines.append(
            f"| {row['id']} | {u['hits']}/{u['n']} ({u['prevalence']}) | {u_w} "
            f"| {o['hits']}/{o['n']} ({o['prevalence']}) | {o_w} "
            f"| {diff.get('difference', '')} | {d_w} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare list-order and uniform wild MCP samples")
    parser.add_argument("--list", type=Path, default=HERE / "servers.jsonl")
    parser.add_argument("--uniform", type=Path, default=HERE / "random_servers.jsonl")
    parser.add_argument("--out", type=Path, default=HERE / "comparison.json")
    args = parser.parse_args(argv)
    result = compare_records(S.load_jsonl(args.list), S.load_jsonl(args.uniform))
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sys.stdout.write(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
