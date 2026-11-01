"""Own-data search vs untrusted external input (wild MCP corpus precision check, PR #40).

A tool whose only external-read name signal is "search" is a source of
untrusted input unless its name or description shows it searches the
server's own records and nothing shows external or third-party content.
"""
from __future__ import annotations

import pytest

from agent_gateway.toxic_combinations import analyze, own_data_search, tool_class


def t(name: str, description: str = "", **extra) -> dict:
    return {"name": name, "description": description, **extra}


OWN_DATA = [
    t("search_docs_index", "Search the product documentation by keyword."),
    t("search_catalog", "Search the human-curated catalog by title or author."),
    t("search", "Search our database of SEC filings by ticker."),
    t("search_crm", "Search across CRM accounts and contacts by name, email, or phone."),
    t("search_members", "Search and filter members/accounts by tier and tags."),
    t("search_site", "Keyword search across every page body on this site."),
    t("search", "Search champion names and aliases across all site locales."),
    t("searchKb", "Find answers."),  # name token "kb"
    t("search_inventory", ""),  # name token "inventory"
]

EXTERNAL = [
    t("search_web", "Search the web."),  # "web" is a second external word
    t("search", "Search the internet for pages."),
    t("search_news", "Search recent articles."),  # "news" token is not own-data
    t("search", "Search Google and return result snippets."),
    t("search_catalog", "Search public product reviews in the catalog."),  # external wins
    t("search_docs", "Search documentation hosted at any domain."),
    t("search_items", "Search the catalog.", inputSchema={"type": "object", "properties": {"url": {"type": "string"}}}),
    t("search_posts", "Search social posts in our database."),  # "social" and "posts" win
    t("search_stations", "Search for stations by name or line."),  # no evidence: fail closed
    t("search", ""),  # no evidence: fail closed
    t("search", "Search the datasets of a third-party registry."),  # whole-word own-data, external wins
    t("search", "Search every colour by name."),  # "colour" is not "our"
]


@pytest.mark.parametrize("tool", OWN_DATA, ids=lambda x: f"{x['name']}:{x['description'][:24]}")
def test_own_data_search_is_internal_read(tool):
    assert own_data_search(tool)
    assert tool_class(tool) == "internal_read"


@pytest.mark.parametrize("tool", EXTERNAL, ids=lambda x: f"{x['name']}:{x['description'][:24]}")
def test_external_or_unproven_search_stays_external_read(tool):
    assert not own_data_search(tool)
    assert tool_class(tool) == "external_read"


def test_rule_needs_search_to_be_the_only_external_word():
    for name in ("fetch_catalog", "browse_docs", "download_catalog", "search_and_fetch_docs"):
        assert tool_class(t(name, "Search our catalog.")) == "external_read", name


def test_declared_label_and_sensitive_words_take_precedence():
    assert tool_class(t("search_catalog", "Search our catalog.", tool_class="external_read")) == "external_read"
    assert tool_class(t("search_secrets", "Search our internal vault.")) == "sensitive_read"


def test_own_data_search_does_not_start_a_toxic_path():
    sink = t("send_email", "Send an email.")
    secret = t("read_secret", "Read a secret.")
    own = analyze({"tools": [t("search_catalog", "Search our curated catalog."), secret, sink]})
    ext = analyze({"tools": [t("search_web", "Search the web."), secret, sink]})
    assert own.totals["toxic_2hop"] == 0
    assert ext.totals["toxic_2hop"] > 0


def test_deterministic():
    tools = OWN_DATA + EXTERNAL
    assert [tool_class(x) for x in tools] == [tool_class(dict(x)) for x in reversed(tools)][::-1]
