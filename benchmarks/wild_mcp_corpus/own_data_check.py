#!/usr/bin/env python3
"""Measure the opt-in own-data lookup rule (``score.own_data_lookup``).

Two measurements, both deterministic, standard library only, no network:

1. The 28 servers hand-checked in PR #40 (``precision_labels.json``): for each
   case, does ``toxic_2hop`` survive after the rule? A false positive whose
   flag disappears is eliminated; a plausible hit whose flag disappears is a
   regression. Tool-level: each relabelled tool is compared with the PR #40
   reviewer judgment for that tool, where one exists.
2. Corpus-wide: ``toxic_2hop`` hit counts per stratum before and after.

IMPORTANT CAVEAT. The rule was written after reading these same 28 cases, so
(1) is an in-sample check, not an estimate of out-of-sample precision. The
reviewer labels are one rater (the project author). Output is keyed by case
id and SHA-256 only, like ``precision_labels.json``; it names no server.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent-gateway"))

from benchmarks.wild_mcp_corpus import precision as P  # noqa: E402
from benchmarks.wild_mcp_corpus import score as S  # noqa: E402


def check_cases(labels: dict, by_hash: dict[str, dict]) -> dict:
    rows = []
    tool_vs_reviewer = {"reviewer_disagreed_to_internal_read": 0,
                        "reviewer_agreed_external_read": 0,
                        "reviewer_other_or_none": 0}
    for case in labels["cases"]:
        record = by_hash[case["server_sha256"]]
        tools = P.scored_tools(S._tools(record))
        siblings = frozenset(str(t.get("name") or "") for t in tools)
        judged = {j["tool_sha256"]: j for j in case["judgments"]}
        relabelled = [t for t in tools if S.own_data_lookup(t, siblings)]
        for tool in relabelled:
            item = judged.get(P.sha256_text(P.graph_name(tool["name"])))
            if item and item["decision"] == "disagree" and item.get("corrected_class") == "internal_read":
                tool_vs_reviewer["reviewer_disagreed_to_internal_read"] += 1
            elif item and item["decision"] == "agree":
                tool_vs_reviewer["reviewer_agreed_external_read"] += 1
            else:
                tool_vs_reviewer["reviewer_other_or_none"] += 1
        before = S.score_server(record)["toxic_2hop"]
        after = S.toxic_2hop_own_data_refined(record)
        rows.append({
            "case_id": case["case_id"],
            "stratum": case["stratum"],
            "label": case["label"],
            "toxic_2hop_before": before,
            "toxic_2hop_after": after,
            "tools_relabelled": len(relabelled),
        })
    fps = [r for r in rows if r["label"] == "false_positive"]
    plaus = [r for r in rows if r["label"] == "plausible"]
    kept = sum(1 for r in plaus if r["toxic_2hop_after"] == "hit")
    remaining = len(plaus) + sum(1 for r in fps if r["toxic_2hop_after"] == "hit")
    return {
        "cases": rows,
        "false_positives": len(fps),
        "false_positives_eliminated": sum(1 for r in fps if r["toxic_2hop_after"] == "miss"),
        "eliminated_case_ids": [r["case_id"] for r in fps if r["toxic_2hop_after"] == "miss"],
        "plausible": len(plaus),
        "plausible_preserved": kept,
        "precision_among_still_flagged": S._proportion(kept, remaining),
        "relabelled_tools_vs_reviewer": tool_vs_reviewer,
    }


def corpus_effect(records: list[dict], strata: tuple[str, ...]) -> dict:
    out = {}
    for stratum in strata:
        rows = [r for r in records if r.get("stratum") == stratum and r.get("schema_policy") == "published"]
        before = sum(1 for r in rows if S.score_server(r)["toxic_2hop"] == "hit")
        after = sum(1 for r in rows if S.toxic_2hop_own_data_refined(r) == "hit")
        out[stratum] = {"n": len(rows), "toxic_2hop_before": before, "toxic_2hop_after": after}
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=HERE / "own_data_rule_check.json")
    parser.add_argument("--skip-corpus", action="store_true")
    args = parser.parse_args(argv)
    listed = S.load_jsonl(HERE / "servers.jsonl")
    uniform = S.load_jsonl(HERE / "random_servers.jsonl")
    labels = json.loads((HERE / "precision_labels.json").read_text(encoding="utf-8"))
    result = {
        "schema": "agentgate.wild-mcp-own-data-rule-check/1",
        "rule": S.OWN_DATA_RULE_ID,
        "hand_checked": check_cases(labels, P.records_by_hash(listed + uniform)),
        "caveats": [
            "In-sample: the rule was written after reading these 28 PR #40 cases.",
            "Reviewer labels are one rater (the project author); no inter-rater agreement.",
            "A remaining flag is a static reading of a published listing, not a confirmed vulnerability.",
            "score_server is unchanged; the rule is opt-in via toxic_2hop_own_data_refined.",
        ],
    }
    if not args.skip_corpus:
        result["corpus_effect"] = corpus_effect(listed + uniform, ("smithery_list_order", "smithery_uniform"))
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hc = result["hand_checked"]
    print(json.dumps({k: hc[k] for k in ("false_positives_eliminated", "false_positives", "plausible_preserved",
                                         "plausible", "eliminated_case_ids", "relabelled_tools_vs_reviewer")}))
    if "corpus_effect" in result:
        print(json.dumps(result["corpus_effect"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
