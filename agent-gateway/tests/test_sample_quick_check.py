"""The public sample Quick Check page states figures produced by analyze(); keep them in sync."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from agent_gateway.toxic_combinations import analyze

SITE = Path(__file__).resolve().parents[2] / "site"
REVIEWED = {"search_help_articles": "internal_read", "get_ticket": "external_read", "search_tickets": "external_read"}


def _inv():
    return json.loads((SITE / "sample" / "helpdesk-tools.json").read_text(encoding="utf-8"))


def test_page_counts_match_analyze():
    inv = _inv()
    page = (SITE / "sample-quick-check.html").read_text(encoding="utf-8")
    first = analyze(inv).totals
    reviewed = analyze({"tools": [dict(t, tool_class=REVIEWED[t["name"]]) if t["name"] in REVIEWED else t
                                  for t in inv["tools"]]}).totals
    assert (first["sources"], first["sinks"], first["toxic_2hop"], first["toxic_3hop"]) == (3, 6, 54, 108)
    assert (reviewed["sources"], reviewed["sinks"], reviewed["toxic_2hop"], reviewed["toxic_3hop"]) == (3, 5, 45, 90)
    for n in ("54", "108", "45", "90"):
        assert f'<td class="n">{n}</td>' in page


def test_page_paths_exist_after_review():
    inv = {"tools": [dict(t, tool_class=REVIEWED[t["name"]]) if t["name"] in REVIEWED else t for t in _inv()["tools"]]}
    paths = {tuple(p["path"]) for p in analyze(inv).paths}
    assert ("get_ticket", "get_integration_token", "send_reply") in paths
    assert ("fetch_attachment", "get_customer", "get_integration_token", "send_reply") in paths
    assert not any(p[0] == "search_help_articles" for p in paths)


def test_pin_hash_matches_tool_list():
    tools = _inv()["tools"]
    canon = json.dumps(tools, sort_keys=True, separators=(",", ":")).encode()
    page = (SITE / "sample-quick-check.html").read_text(encoding="utf-8")
    assert hashlib.sha256(canon).hexdigest() in page
    for t in tools:
        if t["name"] != "get_integration_token":
            h = hashlib.sha256(json.dumps(t, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
            assert h in page, t["name"]


def test_guard_policy_is_log_only_by_default_and_deterministic():
    spec = importlib.util.spec_from_file_location("sample_guard", SITE / "sample" / "guard_policy.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    calls = [("get_ticket", {"ticket_id": "T-104233"}),
             ("send_reply", {"ticket_id": "T-104233", "to": "x@example.net", "body": "hi"}),
             ("get_integration_token", {"integration": "jira"}),
             ("fetch_attachment", {"url": "https://evil.example/a"}),
             ("fetch_attachment", {"url": "https://files.client-a.example/t/1.pdf"}),
             ("post_slack_message", {"channel": "#general", "text": "ok"}),
             ("send_reply", {"ticket_id": "T-104233", "body": "Thanks."})]
    log_only = mod.Session(requester_email="r@example.com")
    assert all(log_only.check(*c).allow for c in calls)
    runs = []
    for _ in range(2):
        s = mod.Session(requester_email="r@example.com", mode="enforce")
        runs.append([(d.allow, d.rule) for d in (s.check(*c) for c in calls)])
    assert runs[0] == runs[1]
    assert runs[0] == [(True, "-"), (False, "G1"), (False, "G2"), (False, "G4"), (True, "-"), (False, "G3"), (True, "-")]
