"""Tests for the opt-in own-data lookup rule (PR #42). Stdlib and the gateway only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.wild_mcp_corpus import own_data_check as O
from benchmarks.wild_mcp_corpus import precision as P
from benchmarks.wild_mcp_corpus import score as S

HERE = Path(__file__).resolve().parent


def _tool(name, desc, props=("query", "limit"), **extra):
    return {"name": name, "description": desc,
            "inputSchema": {"type": "object", "properties": {p: {"type": "string"} for p in props}}, **extra}


@pytest.mark.parametrize("tool", [
    _tool("search_crm", "Search across CRM accounts and contacts by name, email, or phone."),
    _tool("search_docs", "Search the vendor API documentation for an endpoint.", ("query",)),
    _tool("search_books", "Search our human-curated catalog by book title or author name."),
])
def test_own_data_lookups_are_reclassified(tool):
    assert S.tool_class(tool) == "external_read"
    assert S.own_data_lookup(tool)
    assert S.apply_own_data_rule([tool])[0]["class"] == "internal_read"


@pytest.mark.parametrize("tool", [
    _tool("search_web", "General web document search across the index."),           # web word
    _tool("search_posts", "Search the catalog of community posts by keyword."),     # open content
    _tool("search_catalog", "Search the product catalog.", ("query", "url")),       # URL param
    _tool("fetch_search", "Search our catalog and fetch results."),                 # fetch token
    _tool("search_entities", "Search verified entities; keys unlock full records."),  # no scope marker
    _tool("search", "Search Europe PMC, a broad biomedical corpus of papers."),
])
def test_external_or_unclear_searches_stay_external(tool):
    assert not S.own_data_lookup(tool, frozenset({"get_entity"}))


def test_declared_label_is_respected():
    tool = _tool("search_crm", "Search CRM accounts.", **{"class": "external_read"})
    assert not S.own_data_lookup(tool)


def test_id_resolver_needs_a_named_sibling():
    tool = _tool("ferry_search_landings", "Search landings by name. Use this to find landing IDs for ferry_get_arrivals.")
    assert not S.own_data_lookup(tool)
    assert S.own_data_lookup(tool, frozenset({tool["name"], "ferry_get_arrivals"}))
    # Naming itself is not a sibling.
    assert not S.own_data_lookup(tool, frozenset({tool["name"]}))


def test_default_scoring_is_unchanged_and_refined_score_is_opt_in():
    record = {"schema_policy": "published", "tools": [
        _tool("search_crm", "Search across CRM accounts and contacts by name."),
        _tool("get_invoice", "Read one invoice.", ("invoice_id",)),
        _tool("send_email", "Send an email.", ("to", "body")),
    ]}
    assert S.score_server(record)["toxic_2hop"] == "hit"
    assert S.toxic_2hop_own_data_refined(record) == "miss"
    assert S.toxic_2hop_own_data_refined({"schema_policy": "not_published_as_json", "tools": []}) == "na"


def test_rule_on_the_pr40_hand_checked_servers():
    """In-sample check on the 28 PR #40 servers: 5 of 10 false positives go, all 18 plausible stay."""
    labels = json.loads((HERE / "precision_labels.json").read_text(encoding="utf-8"))
    listed = S.load_jsonl(HERE / "servers.jsonl")
    uniform = S.load_jsonl(HERE / "random_servers.jsonl")
    got = O.check_cases(labels, P.records_by_hash(listed + uniform))
    assert (got["false_positives"], got["plausible"]) == (10, 18)
    assert got["plausible_preserved"] == 18
    assert got["false_positives_eliminated"] == 5
    assert got["eliminated_case_ids"] == ["p02", "p08", "p09", "p10", "p12"]
    assert got["relabelled_tools_vs_reviewer"] == {
        "reviewer_disagreed_to_internal_read": 11,
        "reviewer_agreed_external_read": 3,
        "reviewer_other_or_none": 0,
    }
    stored = HERE / "own_data_rule_check.json"
    if stored.is_file():
        assert json.loads(stored.read_text(encoding="utf-8"))["hand_checked"] == got


def test_outreach_listing_is_names_only_and_scored_as_such():
    rows = S.load_jsonl(HERE / "outreach_round1_listings.jsonl")
    assert len(rows) == 1 and rows[0]["schema_policy"] == "not_published_as_json"
    verdicts = S.score_server(rows[0])
    assert verdicts["toxic_2hop"] == "na" and verdicts["R_cold_path"] == "na"
    assert not any("inputSchema" in t for t in rows[0]["tools"])
