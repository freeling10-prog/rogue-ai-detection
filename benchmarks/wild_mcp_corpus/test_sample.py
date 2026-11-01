"""Tests for the uniform draw, the Newcombe contrast, and precision labels."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.wild_mcp_corpus import compare as C
from benchmarks.wild_mcp_corpus import precision as P
from benchmarks.wild_mcp_corpus import sample_random as R
from benchmarks.wild_mcp_corpus.collect import new_counter

HERE = Path(__file__).resolve().parent


def test_permutation_is_a_deterministic_permutation():
    assert R.permutation(8, 20261101) == [7, 2, 5, 4, 6, 3, 0, 1]
    assert R.permutation(8, 20261101) == R.permutation(8, 20261101)
    assert sorted(R.permutation(50, 20261101)) == list(range(50))
    assert R.permutation(20, 1) != R.permutation(20, 2)


def test_eligible_frame_exclusions_and_first_seen_order():
    rows = [
        {"qualifiedName": "A", "unlisted": False, "inactive": False, "useCount": 3, "_list_page": 1},
        {"qualifiedName": "a", "unlisted": False, "inactive": False, "useCount": 9},
        {"qualifiedName": "B", "unlisted": True, "inactive": True},
        {"qualifiedName": "C", "inactive": True},
        {"qualifiedName": "  ", "inactive": False},
        {"qualifiedName": "D", "unlisted": False, "inactive": False, "useCount": 0, "homepage": "https://ex.example"},
        "not-a-row",
    ]
    frame, stats = R.eligible_frame(rows)
    assert [row["qualified_name"] for row in frame] == ["A", "D"]
    assert frame[0]["use_count"] == 3
    assert frame[0]["list_page"] == 1
    assert frame[1]["homepage"] == "https://ex.example"
    assert stats["unlisted"] == 1
    assert stats["inactive"] == 1
    assert stats["duplicate"] == 1
    assert stats["missing_name"] == 2
    assert stats["eligible"] == 2


def test_walk_stops_at_the_target_success_in_permutation_order():
    outcomes = {0: "no_named_tool", 1: "kept", 2: "no_object_schema", 3: "kept", 4: "kept"}
    decisions = R.walk_permutation(5, 20261101, outcome_of=outcomes, target=2)
    assert [d["outcome"] for d in decisions if d["outcome"] == "kept"] 
    assert sum(d["outcome"] == "kept" for d in decisions) == 2
    assert decisions[-1]["outcome"] == "kept"
    assert R.decisions_follow_permutation(5, 20261101, decisions, 2)
    order = R.permutation(5, 20261101)
    assert [d["frame_index"] for d in decisions] == order[: len(decisions)]


def test_classify_detail_requires_an_object_schema_and_redacts():
    counter = new_counter()
    outcome, tools, meta = R.classify_detail({"tools": []}, counter)
    assert outcome == "no_named_tool"
    outcome, tools, meta = R.classify_detail(
        {"tools": [{"name": "lookup", "inputSchema": None}]}, counter
    )
    assert outcome == "no_object_schema"
    assert tools == []
    outcome, tools, meta = R.classify_detail(
        {"tools": [{
            "name": "lookup",
            "description": "token AKIAIOSFODNN7EXAMPLE in the text",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}},
        }]},
        counter,
    )
    assert outcome == "kept"
    assert len(tools) == 1
    assert isinstance(tools[0]["inputSchema"], dict)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(tools)
    assert counter["findings"] == 1
    assert meta["tools_seen"] == 1


def test_newcombe_difference_contains_zero_when_equal_and_excludes_it_at_the_extreme():
    same = C.newcombe(40, 100, 40, 100)
    assert same["difference"] == "0.000000"
    lo, hi = same["newcombe95"]
    assert Decimal_lt(lo, "0") and Decimal_lt("0", hi)
    zeros = C.newcombe(0, 100, 0, 100)
    assert zeros["difference"] == "0.000000"
    assert Decimal_lt(zeros["newcombe95"][0], "0") and Decimal_lt("0", zeros["newcombe95"][1])
    apart = C.newcombe(0, 200, 200, 200)
    assert apart["difference"] == "-1.000000"
    assert Decimal_lt(apart["newcombe95"][1], "0")
    swapped = C.newcombe(200, 200, 0, 200)
    assert swapped["difference"] == "1.000000"
    assert Decimal_lt("0", swapped["newcombe95"][0])
    with pytest.raises(ValueError):
        C.newcombe(2, 1, 0, 1)


def Decimal_lt(left: str, right: str) -> bool:
    from decimal import Decimal
    return Decimal(left) < Decimal(right)


def test_newcombe_negates_when_the_samples_are_swapped():
    from decimal import Decimal
    forward = C.newcombe(30, 80, 10, 80)
    backward = C.newcombe(10, 80, 30, 80)
    assert Decimal(forward["difference"]) == -Decimal(backward["difference"])
    assert Decimal(forward["newcombe95"][0]) == -Decimal(backward["newcombe95"][1])
    assert Decimal(forward["newcombe95"][1]) == -Decimal(backward["newcombe95"][0])


def _tool(name, schema=None, description=""):
    if schema is None:
        schema = {"type": "object", "properties": {"body": {"type": "string"}}}
    return {"name": name, "description": description, "inputSchema": schema}


def _toxic_server(server_id, stratum):
    return {
        "stratum": stratum,
        "schema_policy": "published",
        "server_id": server_id,
        "use_count": 5,
        "tools": [
            _tool("fetch_url", {"type": "object", "properties": {"url": {"type": "string"}}}, "fetch a page"),
            _tool("lookup_order", {"type": "object", "properties": {"id": {"type": "integer"}}}, "read an order"),
            _tool("send_email", {"type": "object", "properties": {"body": {"type": "string"}}}, "send mail"),
        ],
    }


def _quiet_server(server_id, stratum):
    return {
        "stratum": stratum,
        "schema_policy": "published",
        "server_id": server_id,
        "use_count": 1,
        "tools": [_tool("add", {"type": "object", "properties": {"a": {"type": "integer"}}}, "add")],
    }


def test_compare_uses_the_scorer_and_only_the_two_strata():
    listed = [
        _toxic_server("popular", C.LIST_STRATUM),
        _quiet_server("quiet", C.LIST_STRATUM),
        _toxic_server("reference", "reference_repo"),
    ]
    uniform = [
        _quiet_server("tail", C.UNIFORM_STRATUM),
        _toxic_server("popular", C.UNIFORM_STRATUM),
    ]
    result = C.compare_records(listed, uniform)
    assert result["n_list_order"] == 2
    assert result["n_uniform"] == 2
    assert result["server_id_overlap"] == 1
    by_id = {row["id"]: row for row in result["metrics"]}
    assert set(by_id) == {spec["id"] for spec in C.S.APPLIED} | {f"class:{name}" for name in C.S.CLASSES}
    assert by_id["toxic_2hop"]["list_order"]["hits"] == 1
    assert by_id["toxic_2hop"]["uniform"]["hits"] == 1
    assert by_id["toxic_2hop"]["difference"]["difference"] == "0.000000"
    text = C.render_markdown(result)
    assert "toxic_2hop" in text and "Newcombe" in text


def _judgment(name, decision, corrected=None, cause=None):
    item = {"tool_sha256": P.sha256_text(name), "decision": decision}
    if decision == "disagree":
        item["corrected_class"] = corrected
        item["cause"] = cause
    return item


def _path_tools():
    return [
        _tool("fetch_url", {"type": "object", "properties": {"url": {"type": "string"}}}, "fetch a page"),
        _tool("lookup_order", {"type": "object", "properties": {"id": {"type": "integer"}}}, "read an order"),
        _tool("send_email", {"type": "object", "properties": {"body": {"type": "string"}}}, "send mail"),
    ]


def test_label_from_judgments_plausible_false_positive_and_uncertain():
    tools = _path_tools()
    agreed = [
        _judgment("fetch_url", "agree"),
        _judgment("lookup_order", "agree"),
        _judgment("send_email", "agree"),
    ]
    assert P.label_from_judgments(tools, agreed)["label"] == "plausible"
    false_positive = [
        _judgment("fetch_url", "disagree", "write", "name_rule_not_a_source"),
        _judgment("lookup_order", "agree"),
        _judgment("send_email", "disagree", "internal_read", "name_rule_not_a_sink"),
    ]
    derived = P.label_from_judgments(tools, false_positive)
    assert derived["label"] == "false_positive"
    assert derived["primary_cause"] == "name_rule_not_a_source"
    uncertain = [
        _judgment("fetch_url", "uncertain"),
        _judgment("lookup_order", "agree"),
        _judgment("send_email", "agree"),
    ]
    assert P.label_from_judgments(tools, uncertain)["label"] == "cant_tell"
    with pytest.raises(ValueError):
        P.label_from_judgments(tools, agreed[:2])
    with pytest.raises(ValueError):
        P.label_from_judgments(tools, agreed + [_judgment("other", "agree")])


def test_draw_is_stratified_deterministic_and_anonymous():
    listed = [_toxic_server(f"p{i}", C.LIST_STRATUM) for i in range(6)]
    listed.append(_quiet_server("quiet", C.LIST_STRATUM))
    uniform = [_toxic_server(f"u{i}", C.UNIFORM_STRATUM) for i in range(5)]
    first = P.draw_review_cases(listed, uniform, seed=20261102, per_stratum=3)
    second = P.draw_review_cases(listed, uniform, seed=20261102, per_stratum=3)
    assert first == second
    assert [c["case_id"] for c in first] == ["p01", "p02", "p03", "p04", "p05", "p06"]
    assert [c["stratum"] for c in first].count(C.LIST_STRATUM) == 3
    assert [c["stratum"] for c in first].count(C.UNIFORM_STRATUM) == 3
    assert first != P.draw_review_cases(listed, uniform, seed=7, per_stratum=3)
    for case in first:
        assert set(case) == {"case_id", "stratum", "server_sha256"}
        assert len(case["server_sha256"]) == 64


def test_precision_summary_wilson_and_cause_counts():
    cases = [
        {"label": "plausible", "stratum": "a", "primary_cause": None, "disagreement_causes": {}},
        {"label": "plausible", "stratum": "a", "primary_cause": None, "disagreement_causes": {}},
        {"label": "false_positive", "stratum": "b", "primary_cause": "default_branch_sink",
         "disagreement_causes": {"default_branch_sink": 2}},
        {"label": "cant_tell", "stratum": "b", "primary_cause": None, "disagreement_causes": {}},
    ]
    summary = P.precision_summary(cases)
    assert summary["counts"] == {"plausible": 2, "false_positive": 1, "cant_tell": 1}
    assert summary["precision_among_decided"]["hits"] == 2
    assert summary["precision_among_decided"]["n"] == 3
    assert summary["precision_counting_cant_tell_as_not_plausible"]["n"] == 4
    assert summary["precision_among_decided"]["wilson95"] == list(C.S.wilson(2, 3))
    assert summary["primary_false_positive_causes"]["default_branch_sink"] == 1


def test_review_uses_the_analyzer_prefix_not_tools_past_it():
    tools = _path_tools()
    filler = [
        _tool(f"add_{i}", {"type": "object", "properties": {"a": {"type": "integer"}}}, "add")
        for i in range(397)
    ]
    extra = _tool("fetch_extra", {"type": "object", "properties": {"url": {"type": "string"}}}, "fetch")
    scored = P.scored_tools(tools + filler + [extra])
    assert len(scored) == 400
    assert "fetch_extra" not in P.participating_names(scored)
    agreed = [
        _judgment(name, "agree")
        for name in P.participating_names(scored)
    ]
    assert P.label_from_judgments(tools + filler + [extra], agreed)["label"] == "plausible"


def test_constants_are_the_precommitted_design():
    assert R.SAMPLE_SEED == 20261101
    assert R.ENUM_SEED == 20261101
    assert R.TARGET_N == 250
    assert R.PAGE_SIZE == 100
    assert P.PRECISION_SEED == 20261102
    assert P.PER_STRATUM == 14
    assert "tools/call" not in Path(R.__file__).read_text(encoding="utf-8")


def test_committed_random_snapshot_matches_its_log_and_scores():
    sample = HERE / "random_servers.jsonl"
    log_path = HERE / "random_collection_log.json"
    results = HERE / "random_results.json"
    if not sample.is_file() or not log_path.is_file() or not results.is_file():
        pytest.skip("uniform snapshot not built")
    log = json.loads(log_path.read_text(encoding="utf-8"))
    rows = C.S.load_jsonl(sample)
    assert len(rows) == log["draw"]["kept"]
    assert all(row["stratum"] == R.STRATUM and row["schema_policy"] == "published" for row in rows)
    assert R.decisions_follow_permutation(
        log["frame"]["eligible"], R.SAMPLE_SEED, log["decisions"], R.TARGET_N, R.MAX_EXAMINED,
    )
    kept_positions = [d["draw_position"] for d in log["decisions"] if d["outcome"] == "kept"]
    assert [row["draw_position"] for row in rows] == kept_positions
    frame = C.S.load_jsonl(HERE / "smithery_frame.jsonl")
    assert len(frame) == log["frame"]["eligible"]
    assert R.frame_sha256(frame) == log["frame_sha256_names"]
    for row in rows:
        assert frame[row["frame_index"]]["qualified_name"] == row["server_id"]
        assert all(isinstance(tool.get("inputSchema"), dict) for tool in row["tools"])
    blob = sample.read_text(encoding="utf-8")
    assert "AKIA" not in blob and "ghp_" not in blob and "-----BEGIN" not in blob
    fresh = C.S.score_records(rows)
    stored = json.loads(results.read_text(encoding="utf-8"))
    for key in ("applied", "class_prevalence", "diagnostics_published_schemas_only", "strata"):
        assert fresh[key] == stored[key]


def test_committed_labels_recompute_and_name_no_server():
    path = HERE / "precision_labels.json"
    if not path.is_file():
        pytest.skip("precision labels not written")
    labels = json.loads(path.read_text(encoding="utf-8"))
    forbidden = {"server_id", "qualified_name", "qualifiedName", "source_url", "homepage", "description", "name"}

    def keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)

    assert forbidden.isdisjoint(set(keys(labels)))
    listed = C.S.load_jsonl(HERE / "servers.jsonl")
    uniform = C.S.load_jsonl(HERE / "random_servers.jsonl")
    drawn = P.draw_review_cases(listed, uniform, labels["seed"], labels["per_stratum"])
    merged = P.attach_labels(drawn, labels["cases"])
    verified = P.verify_labels(merged, P.records_by_hash(listed + uniform))
    assert len(verified) == len(drawn)
    for case, got in zip(labels["cases"], verified):
        assert case["label"] == got["label"]
        assert case["primary_cause"] == got["primary_cause"]
        assert case["label"] in P.LABELS
    summary = P.precision_summary(verified)
    stored = json.loads((HERE / "precision_summary.json").read_text(encoding="utf-8"))
    for key in ("n_reviewed", "counts", "precision_among_decided",
                "precision_counting_cant_tell_as_not_plausible", "primary_false_positive_causes"):
        assert summary[key] == stored[key]
