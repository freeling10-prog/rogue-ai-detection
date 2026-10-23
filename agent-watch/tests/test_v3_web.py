"""v3: mimic detectors, link graph, mirrored access stream, score floors, camouflaged schema parameter, MCP decoy, JA4 field,
accidental-scraper labelling, web export and the extended demo.

The simulated clients here were written by the same author as the detectors.  These are regression tests of intended behaviour
(including the documented failures: ``mimic_assets`` evades, ``human_no_assets`` is a false positive), not benchmarks."""
import json
import random
import re
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from agentwatch.cli import main
from agentwatch.config import DEFAULTS, load_config
from agentwatch.honeypot import create_honeypot_app
from agentwatch.models import Request
from agentwatch.parser import parse_lines
from agentwatch.pipeline import run_pipeline
from agentwatch.scoring import SEVERITIES, score_session
from agentwatch.synthetic import generate_demo
from agentwatch.webdetectors import (detect_asset_starvation, detect_unlinked_jump, run_web_detectors, transitions)
from helpers import CFG, T0, UA, mk, sess

BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
SEC_OK = {"sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "same-origin"}


def page(t, path="/", links=(), ua=BROWSER, headers=None, referer="", ip="192.0.2.77", content_type="text/html", status=200):
    r = mk(t, path, ua=ua, ip=ip, headers=headers, referer=referer, status=status)
    r.served_links = list(links)
    r.content_type = content_type
    r.headers_logged = headers is not None
    return r


def asset(t, path="/static/site.css", ip="192.0.2.77", ua=BROWSER):
    r = mk(t, path, ua=ua, ip=ip)
    r.content_type = "text/css"
    return r


def ips(c):
    return {"REMOTE_ADDR": c}


def leads_of(path):
    p = Path(path)
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


@pytest.fixture
def pot(tmp_path):
    log = tmp_path / "pot.jsonl"
    app = create_honeypot_app(log, seed="t", registry_path=tmp_path / "reg.json")
    return app, log


# =========================== (i) asset starvation ===========================
def starving(n=5, with_headers=None, ua=BROWSER):
    return [page(i * 3, f"/p{i}", links=[f"/p{i + 1}"], ua=ua, headers=with_headers, referer=f"http://127.0.0.1/p{i - 1}" if i else "") for i in range(n)]


def test_asset_starvation_fires_at_five_pages():
    f = detect_asset_starvation(sess(starving(5)), CFG)
    assert len(f) == 1 and f[0].kind == "asset_starvation" and f[0].data["pages"] == 5
    assert "not in this log format" in f[0].summary                        # honest: Sec-Fetch not checked without headers


def test_asset_starvation_needs_five_pages_and_zero_assets():
    assert detect_asset_starvation(sess(starving(4)), CFG) == []
    # v4 (deliberate change): the v3 assertion here was `starving(8) + [favicon] == []` ("any single asset exempts").  That let a
    # client that fetched ONE favicon or image slip through; v4 exempts only .css/.js (core resources), see tests/test_v4_web.py
    assert detect_asset_starvation(sess(starving(8) + [asset(30, "/static/site.css")]), CFG) == []
    assert len(detect_asset_starvation(sess(starving(8) + [asset(30, "/favicon.ico")]), CFG)) == 1


def test_asset_starvation_not_for_declared_scripts():
    assert detect_asset_starvation(sess(starving(8, ua="python-requests/2.31")), CFG) == []
    assert detect_asset_starvation(sess(starving(8, ua="curl/8.4")), CFG) == []


def test_asset_starvation_sec_fetch_mismatch_is_reported():
    f = detect_asset_starvation(sess(starving(6, with_headers={})), CFG)
    assert f[0].data["sec_fetch"] is True and f[0].data["sec_fetch_mismatch"] == 6
    # v4 (deliberate change): coherent Sec-Fetch navigate/document headers on every starved page no longer make a scoring
    # `asset_starvation` finding; it is advisory only (a person with styles+scripts blocked sends exactly this)
    ok = detect_asset_starvation(sess(starving(6, with_headers=SEC_OK)), CFG)
    assert [f.kind for f in ok] == ["asset_starvation_coherent"] and ok[0].detector == "web_advisory"


def test_asset_starvation_is_not_diluted_by_padding():
    """Not a session average: 300 non-page requests (JSON API calls) do not hide five starving page loads."""
    pad = [mk(100 + i * 2, f"/api/v1/items/{i}", ip="192.0.2.77", ua=BROWSER) for i in range(300)]
    for p in pad:
        p.content_type = "application/json"
    assert len(detect_asset_starvation(sess(starving(5) + pad), CFG)) == 1


def test_asset_starvation_text_mode_browser_is_an_admitted_false_positive():
    """A person with styles AND scripts blocked and NO Sec-Fetch evidence in the log looks identical: contact/behaviour evidence
    only.  v4 (deliberate change): with coherent Sec-Fetch headers it is advisory and scores 0 (it used to alert at medium)."""
    r = score_session(sess(starving(8, with_headers={})), CFG)
    assert r.agent_score > 0 and r.label != "agent" and r.actor_type == "possible_mimic"
    assert SEVERITIES.index(r.severity) <= SEVERITIES.index("medium")
    r2 = score_session(sess(starving(8, with_headers=SEC_OK)), CFG)
    assert r2.agent_score == 0 and r2.actor_type != "possible_mimic" and SEVERITIES.index(r2.severity) <= SEVERITIES.index("low")


# =========================== (ii) unlinked jump / link graph ===========================
def test_unlinked_jump_flags_a_url_the_previous_page_never_linked():
    s = sess([page(0, "/", ["/a", "/b"]), page(3, "/a", ["/"]), page(6, "/secret-guess", ["/"], referer="")])
    f = detect_unlinked_jump(s, CFG)
    assert len(f) == 1 and f[0].data["to"] == "/secret-guess" and f[0].data["offered_earlier"] is False


def test_linked_move_is_not_flagged():
    assert detect_unlinked_jump(sess([page(0, "/", ["/a"]), page(3, "/a", ["/"])]), CFG) == []


def test_valid_referer_from_a_served_page_that_linked_the_target_is_accepted():
    # the client moves /a -> /b but sends the Referer of /, which DID link /b (pressing Back then clicking)
    s = sess([page(0, "/", ["/a", "/b"]), page(3, "/a", []), page(6, "/b", [], referer="http://127.0.0.1/")])
    assert detect_unlinked_jump(s, CFG) == []
    st = [x[2] for x in transitions(s, CFG)]
    assert st == ["entry", "linked", "linked"]


def test_forged_referer_naming_a_page_that_did_not_link_the_target_is_not_valid():
    s = sess([page(0, "/", ["/a"]), page(3, "/a", []), page(6, "/guess", [], referer="http://127.0.0.1/a")])
    assert len(detect_unlinked_jump(s, CFG)) == 1
    s2 = sess([page(0, "/", ["/a"]), page(3, "/a", []), page(6, "/guess", [], referer="http://evil.invalid/unknown")])
    assert len(detect_unlinked_jump(s2, CFG)) == 1


def test_entry_paths_revisits_and_well_known_are_exempt():
    s = sess([page(0, "/x", ["/a"]), page(3, "/robots.txt", []), page(6, "/", ["/a"]), page(9, "/a", ["/"]),
              page(12, "/x", []), page(15, "/.well-known/mcp.json", [])])
    assert detect_unlinked_jump(s, CFG) == []


def test_breadth_first_queue_moves_are_weak_offered_earlier():
    s = sess([page(0, "/", ["/a", "/b", "/c"]), page(1, "/a", []), page(2, "/c", [])])      # /c was offered by "/"
    f = detect_unlinked_jump(s, CFG)
    assert len(f) == 1 and f[0].data["offered_earlier"] is True and "earlier page offered it" in f[0].summary


def test_unlinked_jump_abstains_without_a_link_graph():
    plain = [mk(0, "/", ua=BROWSER), mk(3, "/a", ua=BROWSER), mk(6, "/zzz", ua=BROWSER)]       # ordinary access log: served_links None
    assert detect_unlinked_jump(sess(plain), CFG) == []
    assert all(x[2] in ("entry", "unknown") for x in transitions(sess(plain), CFG))


def test_unlinked_jump_findings_are_capped():
    reqs = [page(0, "/", ["/a"])] + [page(3 + i * 2, f"/g{i}", []) for i in range(60)]
    assert len(detect_unlinked_jump(sess(reqs), CFG)) == CFG["web"]["unlinked_jump"]["max_findings"]


def test_unlinked_weights_distinguish_never_offered_from_offered_earlier():
    never = sess([page(0, "/", ["/a"])] + [page(3 + i, f"/g{i}", []) for i in range(6)])
    early = sess([page(0, "/", [f"/q{i}" for i in range(6)])] + [page(3 + i, f"/q{i}", []) for i in range(6)])
    assert score_session(never, CFG).agent_score > score_session(early, CFG).agent_score


# =========================== (iii) max-pooling / score floors ===========================
def decoy_hit(t, kind="canary_follow", ip="192.0.2.77", tags=()):
    r = mk(t, "/x/decoy", ip=ip, ua=BROWSER)
    r.source, r.decoy_kind, r.token_id, r.tags = "honeypot", kind, "ht-1", list(tags)
    return r


def benign_padding(n, ip="192.0.2.77", t0=100.0):
    rng = random.Random(5)
    out = []
    t = t0
    for i in range(n):
        t += rng.lognormvariate(2, 0.8) + 1
        out.append(page(t, f"/products/{i}", [f"/products/{i + 1}", "/"], headers=SEC_OK, referer="http://127.0.0.1/", ip=ip))
        out.append(asset(t + 0.1, "/static/site.css", ip))
        out.append(asset(t + 0.2, "/static/logo.png", ip))
    return out


@pytest.mark.parametrize("n", [0, 20, 200, 600])
def test_single_strong_event_floor_is_not_diluted_by_benign_padding(n):
    s = sess([decoy_hit(5.0)] + benign_padding(n))
    r = score_session(s, CFG)
    floor = CFG["floors"]["agent"]["canary_follow"]
    assert r.agent_score >= floor, (n, r.agent_score)
    assert any("floor" in x for x in r.reasons)


def test_floor_can_be_switched_off_and_then_padding_dilutes_nothing_either_way():
    cfg = load_config()
    cfg["floors"]["enabled"] = False
    r_off = score_session(sess([decoy_hit(5.0)] + benign_padding(20)), cfg)
    r_on = score_session(sess([decoy_hit(5.0)] + benign_padding(20)), CFG)
    assert r_on.agent_score >= r_off.agent_score and r_off.floors == []


@pytest.mark.parametrize("tag,floor_key", [("mcp_list_then_call", "mcp_list_then_call")])
def test_mcp_flow_floor_is_highest(tag, floor_key):
    r = score_session(sess([decoy_hit(5.0, "mcp_decoy_tool_call", tags=["mcp_tools_call", tag])] + benign_padding(50)), CFG)
    assert r.agent_score >= CFG["floors"]["agent"][floor_key]


def test_human_plausible_passive_contact_gets_no_machine_floor():
    r = score_session(sess([decoy_hit(5.0, "robots_disallow")] + benign_padding(30)), CFG)
    assert r.label == "human" and r.floors == []


# =========================== (iv) camouflaged schema parameter ===========================
def test_openapi_advertises_required_looking_param_with_default(pot):
    app, _ = pot
    doc = app.test_client().get("/openapi.json", environ_overrides=ips("192.0.2.5")).get_json()
    op = doc["paths"]["/api/v1/status"]["get"]
    p = [x for x in op["parameters"] if x["name"] == "client_schema_rev"][0]
    assert p["required"] is True and p["in"] == "query" and p["schema"]["default"] == "2026.04-ai"


def test_using_the_schema_param_creates_a_lead_and_is_flagged(pot):
    app, log = pot
    c = app.test_client()
    c.get("/api/v1/status?client_schema_rev=2026.04-ai", environ_overrides=ips("192.0.2.6"), headers={"User-Agent": BROWSER})
    rows = [r for r in leads_of(log) if r.get("event_type") == "honeytoken_hit"]
    assert any("schema_param_use" in (r.get("tags") or []) for r in rows)
    results, _ = run_pipeline([log, str(log) + ".access.jsonl"], CFG)
    r = [x for x in results if x.session.ip == "192.0.2.6"][0]
    assert any(f.kind == "schema_param" for f in r.findings)
    assert r.agent_score >= CFG["floors"]["agent"]["schema_param"]


def test_ordinary_request_without_the_param_is_not_flagged(pot):
    app, log = pot
    app.test_client().get("/api/v1/status", environ_overrides=ips("192.0.2.7"), headers={"User-Agent": BROWSER})
    assert not any("schema_param_use" in (r.get("tags") or []) for r in leads_of(log))


def test_session_canary_param_from_machine_readable_doc_is_flagged(pot):
    app, log = pot
    c = app.test_client()
    doc = c.get("/openapi.json", environ_overrides=ips("192.0.2.8"), headers={"User-Agent": BROWSER}).get_json()
    canary = re.search(r"trace=(sc-[0-9a-f]{10})", doc["info"]["description"]).group(1)
    c.get(f"/api/v1/status?trace={canary}", environ_overrides=ips("192.0.2.8"), headers={"User-Agent": BROWSER})
    assert any("session_canary_param" in (r.get("tags") or []) for r in leads_of(log))
    # per-session: another client's canary differs, and an invented one is not a canary
    other = c.get("/openapi.json", environ_overrides=ips("192.0.2.9"), headers={"User-Agent": BROWSER}).get_json()
    assert canary not in json.dumps(other)


# =========================== mirror stream ===========================
def test_every_request_is_mirrored_with_links_and_scrubbed_query(pot):
    app, log = pot
    c = app.test_client()
    h = {"User-Agent": BROWSER, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
    c.get("/", environ_overrides=ips("192.0.2.11"), headers=h)
    c.get("/about?contact=jane.doe.fake@example.com&k=sk-FAKEFAKEFAKEFAKEFAKE1234567890abcd", environ_overrides=ips("192.0.2.11"), headers=h)
    c.get("/static/site.css", environ_overrides=ips("192.0.2.11"), headers=h)
    mirror = leads_of(str(log) + ".access.jsonl")
    assert [m["path"] for m in mirror] == ["/", "/about", "/static/site.css"]
    assert all(m["schema"] == "agentwatch.access/1" for m in mirror)
    assert "/about" in mirror[0]["links"] and "/kb/" in mirror[0]["links"]
    assert mirror[0]["headers"].get("sec-fetch-mode", mirror[0]["headers"].get("Sec-Fetch-Mode")) == "navigate"
    raw = (Path(str(log) + ".access.jsonl")).read_text()
    assert "jane.doe.fake@example.com" not in raw and "sk-FAKEFAKEFAKEFAKEFAKE1234567890abcd" not in raw


def test_decoy_hits_in_the_mirror_point_at_their_lead_and_are_merged_not_double_counted(pot):
    app, log = pot
    c = app.test_client()
    home = c.get("/", environ_overrides=ips("192.0.2.12"), headers={"User-Agent": BROWSER}).get_data(as_text=True)
    hidden = re.search(r"href='(/staff-portal-[0-9a-f]+)'", home).group(1)
    c.get(hidden, environ_overrides=ips("192.0.2.12"), headers={"User-Agent": BROWSER})
    mirror = leads_of(str(log) + ".access.jsonl")
    assert mirror[-1]["lead_event_id"]
    results, parsed = run_pipeline([log, str(log) + ".access.jsonl"], CFG)
    assert parsed.mirror_merged >= 1
    r = [x for x in results if x.session.ip == "192.0.2.12"][0]
    assert len(r.session.requests) == 2                                   # home + the hidden link, once each


def test_mirror_can_be_disabled(tmp_path):
    app = create_honeypot_app(tmp_path / "p.jsonl", seed="t", registry_path=tmp_path / "r.json", mirror_access=False)
    app.test_client().get("/", environ_overrides=ips("192.0.2.13"))
    assert not Path(str(tmp_path / "p.jsonl") + ".access.jsonl").exists()


def test_site_references_assets_that_are_served(pot):
    app, _ = pot
    c = app.test_client()
    home = c.get("/", environ_overrides=ips("192.0.2.14")).get_data(as_text=True)
    for a in ("/static/site.css", "/static/site.js", "/favicon.ico", "/static/logo.svg"):
        assert a in home
        assert c.get(a, environ_overrides=ips("192.0.2.14")).status_code == 200


# =========================== decoy MCP endpoint ===========================
def rpc(c, method, params=None, ip="192.0.2.20", i=1, raw=None):
    if raw is not None:
        r = c.post("/mcp", data=raw, content_type="application/json", environ_overrides=ips(ip))
    else:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}, environ_overrides=ips(ip))
    return r.status_code, r.get_json()


def test_mcp_methods_and_decoy_tools(pot):
    app, _ = pot
    c = app.test_client()
    st, init = rpc(c, "initialize")
    assert st == 200 and init["jsonrpc"] == "2.0" and init["result"]["serverInfo"]["name"]
    st, lst = rpc(c, "tools/list")
    names = {t["name"] for t in lst["result"]["tools"]}
    assert {"query_customer_backup", "read_internal_notes", "claim_coordination_task"} <= names
    for t in lst["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"


def test_mcp_tools_call_returns_decoy_with_canary_and_logs_scrubbed_args(pot):
    app, log = pot
    c = app.test_client()
    st, res = rpc(c, "tools/call", {"name": "query_customer_backup",
                                    "arguments": {"customer_id": "C-1 sk-FAKEFAKEFAKEFAKEFAKE1234567890abcd jane.doe.fake@example.com"}})
    assert st == 200 and res["result"]["isError"] is False
    text = res["result"]["content"][0]["text"]
    assert "AWCANARY-" in text and "synthetic" in text.lower() and "example.invalid" in text
    assert "sk-FAKE" not in text and "jane.doe.fake" not in text          # nothing from the request is reflected
    raw = Path(log).read_text()
    assert "sk-FAKEFAKEFAKEFAKEFAKE1234567890abcd" not in raw and "jane.doe.fake@example.com" not in raw
    hit = [r for r in leads_of(log) if r.get("event_type") == "honeytoken_hit"][-1]
    assert hit["decoy"]["kind"] == "mcp_decoy_tool_call" and "mcp_tools_call" in hit["tags"]


def test_mcp_each_tool_has_its_own_canary_that_is_detected_when_echoed(pot):
    app, log = pot
    c = app.test_client()
    phrases = {}
    for name, args in (("query_customer_backup", {"customer_id": "C-1"}), ("read_internal_notes", {"note_id": "n-1"}),
                       ("claim_coordination_task", {"task_id": "t-1"})):
        _, res = rpc(c, "tools/call", {"name": name, "arguments": args})
        phrases[name] = re.search(r"AWCANARY-[0-9a-f]{8}-[a-z]+", json.dumps(res)).group(0)
    assert len(set(phrases.values())) == 3
    c.post("/api/v1/chat", json={"message": f"I found {phrases['read_internal_notes']} in the notes"}, environ_overrides=ips("192.0.2.20"))
    c.get(f"/search?q={phrases['read_internal_notes']}", environ_overrides=ips("192.0.2.20"))
    kinds = {r["decoy"]["kind"] for r in leads_of(log) if r.get("event_type") == "honeytoken_hit"}
    assert "canary_phrase_echo" in kinds


def test_mcp_list_then_valid_call_is_tagged_but_call_alone_is_not(pot):
    app, log = pot
    c = app.test_client()
    rpc(c, "tools/list", ip="192.0.2.21")
    rpc(c, "tools/call", {"name": "read_internal_notes", "arguments": {"note_id": "n-9"}}, ip="192.0.2.21")
    rpc(c, "tools/call", {"name": "read_internal_notes", "arguments": {"note_id": "n-9"}}, ip="192.0.2.22")       # never listed first
    tagged = {r["source_ip"]: "mcp_list_then_call" in (r.get("tags") or []) for r in leads_of(log) if r.get("event_type") == "honeytoken_hit"}
    assert tagged["192.0.2.21"] is True and tagged["192.0.2.22"] is False


def test_mcp_invalid_args_and_bad_json_are_rejected_cleanly(pot):
    app, log = pot
    c = app.test_client()
    _, bad = rpc(c, "tools/call", {"name": "query_customer_backup", "arguments": {}}, ip="192.0.2.23")
    assert bad["error"]["code"] == -32602
    _, lst = rpc(c, "tools/list", ip="192.0.2.23")
    _, bad2 = rpc(c, "tools/call", {"name": "query_customer_backup", "arguments": {"customer_id": 5}}, ip="192.0.2.23")
    assert bad2["error"]["code"] == -32602
    st, junk = rpc(c, None, raw="{not json", ip="192.0.2.23")
    assert junk["error"]["code"] in (-32700, -32600)
    st, unk = rpc(c, "resources/read", ip="192.0.2.23")
    assert "error" in unk and unk["error"]["code"] == -32601
    assert not any("mcp_list_then_call" in (r.get("tags") or []) and r["source_ip"] == "192.0.2.23" for r in leads_of(log)
                   if r.get("event_type") == "honeytoken_hit")       # an invalid call does not count as a valid call after a list


def test_mcp_is_rate_capped_per_client(pot):
    app, _ = pot
    c = app.test_client()
    codes = [c.post("/mcp", json={"jsonrpc": "2.0", "id": i, "method": "tools/list"}, environ_overrides=ips("192.0.2.30")).status_code for i in range(60)]
    assert 429 in codes and codes[0] == 200 and codes.count(200) <= 31
    assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, environ_overrides=ips("192.0.2.31")).status_code == 200   # other clients unaffected


def test_mcp_is_size_limited_and_read_only(pot):
    app, _ = pot
    c = app.test_client()
    r = c.post("/mcp", data=b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":"' + b"A" * 200000 + b'"}}}',
               content_type="application/json", environ_overrides=ips("192.0.2.32"))
    assert r.status_code in (400, 413) or r.get_json().get("error")
    assert len(r.get_data()) < 5000
    descr = {x["name"]: x["description"].lower() for x in rpc(c, "tools/list")[1]["result"]["tools"]}
    assert "read-only" in descr["query_customer_backup"] and "read-only" in descr["read_internal_notes"]
    # no filesystem/network side effects are reachable: all state lives in the lead log and the in-memory rate counter
    assert c.get("/mcp", environ_overrides=ips("192.0.2.32")).status_code in (200, 405)


def test_mcp_is_advertised_in_well_known_and_llms_txt(pot):
    app, _ = pot
    c = app.test_client()
    card = c.get("/.well-known/mcp.json", environ_overrides=ips("192.0.2.33")).get_json()
    assert card["endpoint"] == "/mcp" and card["synthetic"] is True
    assert {"query_customer_backup", "read_internal_notes", "claim_coordination_task"} <= {t["name"] for t in card["tools"]}
    llms = c.get("/llms.txt", environ_overrides=ips("192.0.2.33")).get_data(as_text=True)
    assert "/mcp" in llms and "/.well-known/mcp.json" in llms


def test_mcp_list_then_call_is_strong_goal_directed_evidence_not_intent(pot):
    app, log = pot
    c = app.test_client()
    h = {"User-Agent": "agent-sdk/0.9"}
    rpc(c, "tools/list", ip="192.0.2.40")
    rpc(c, "tools/call", {"name": "claim_coordination_task", "arguments": {"task_id": "T1"}}, ip="192.0.2.40")
    results, _ = run_pipeline([log, str(log) + ".access.jsonl"], CFG)
    r = [x for x in results if x.session.ip == "192.0.2.40"][0]
    assert any(f.kind == "mcp_list_then_call" for f in r.findings)
    assert r.agent_score >= CFG["floors"]["agent"]["mcp_list_then_call"] and r.actor_type == "goal_directed_agent"
    assert "not intent" in " ".join(f.summary for f in r.findings if f.kind == "mcp_list_then_call")


# =========================== accidental scraper vs goal-directed ===========================
def test_lone_hidden_link_hit_is_not_high_and_not_called_human():
    """The v2 bug: severity 'high' with label 'human'."""
    hit = decoy_hit(30.0, "hidden_link")
    r = score_session(sess([hit] + benign_padding(0)[:6]), CFG)
    assert r.actor_type in ("accidental_scraper", "static_bot")
    assert not (r.label == "human" and r.severity in ("high", "critical"))
    assert SEVERITIES.index(r.severity) <= SEVERITIES.index("medium")


def test_goal_directed_agent_is_still_critical():
    reqs = [decoy_hit(10.0, "mcp_decoy_tool_call", tags=["mcp_tools_call", "mcp_list_then_call"]), decoy_hit(12.0, "fake_credential_use")]
    r = score_session(sess(reqs), CFG)
    assert r.actor_type == "goal_directed_agent" and r.severity in ("high", "critical")


# =========================== JA4 (field only; capture NOT implemented) ===========================
JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"
JA4H = "ge11cn20enus_60ca1d00fd10_000000000000_000000000000"


def test_optional_ja4_field_is_parsed_when_well_formed():
    line = json.dumps({"schema": "agentwatch.access/1", "timestamp": "2026-10-22T10:00:00Z", "client_ip": "192.0.2.50", "method": "GET",
                       "path": "/", "status": 200, "user_agent": BROWSER, "ja4": JA4, "ja4h": JA4H})
    res = parse_lines([line])
    assert res.requests[0].ja4 == JA4 and res.requests[0].ja4h == JA4H


@pytest.mark.parametrize("bad", ["", "t13d1516h2", "<script>", "x" * 500, "T13D1516H2_8DAAF6152771_B186095E22B6"])
def test_malformed_or_missing_ja4_is_dropped_not_fatal(bad):
    line = json.dumps({"timestamp": "2026-10-22T10:00:00Z", "client_ip": "192.0.2.50", "method": "GET", "path": "/", "status": 200, "ja4": bad})
    res = parse_lines([line])
    assert res.errors == 0 and res.requests[0].ja4 == ""


def test_ja4_is_never_used_for_scoring():
    base = [page(i * 3, f"/p{i}", [f"/p{i + 1}"]) for i in range(6)]
    a = score_session(sess(base), CFG)
    with_ja4 = [replace(r, ja4=JA4, ja4h=JA4H) for r in base]
    b = score_session(sess(with_ja4), CFG)
    assert (a.agent_score, a.automation_score, a.label) == (b.agent_score, b.automation_score, b.label)


def test_ja4_header_is_ignored_unless_behind_a_trusted_proxy(pot):
    app, log = pot
    app.test_client().get("/", environ_overrides=ips("192.0.2.51"), headers={"X-JA4": JA4})
    assert "ja4" not in leads_of(str(log) + ".access.jsonl")[0]


# =========================== simulated web clients / extended demo ===========================
@pytest.fixture(scope="module")
def ext(tmp_path_factory):
    out = tmp_path_factory.mktemp("ext")
    art = generate_demo(out, seed=7, extended=True)
    files = [art["access_log"], art["gateway_log"], art["leads"], art["access_mirror"]]
    results, parsed = run_pipeline(files, load_config())
    best = {}
    for r in results:
        if r.session.ip not in best or len(r.session.requests) > len(best[r.session.ip].session.requests):
            best[r.session.ip] = r
    groups = {}
    for t in art["truth"]:
        if t.name.startswith("web:"):
            groups.setdefault(t.name.split(" #")[0], []).append((t, best.get(t.ip)))
    return {"art": art, "results": results, "parsed": parsed, "best": best, "groups": groups, "files": files, "out": out}


def test_extended_demo_leaves_the_original_actors_untouched(tmp_path, ext):
    base = generate_demo(tmp_path / "base", seed=7)
    assert Path(base["access_log"]).read_bytes() == Path(ext["art"]["access_log"]).read_bytes()
    assert Path(base["gateway_log"]).read_bytes() == Path(ext["art"]["gateway_log"]).read_bytes()
    for t in base["truth"]:
        assert ext["best"][t.ip].label == t.label, t.name


def test_extended_demo_parses_cleanly(ext):
    assert ext["parsed"].errors == 0 and ext["parsed"].mirror_merged > 0


def test_naive_scraper_is_no_longer_high_severity_labelled_human(ext):
    for t, r in ext["groups"]["web:scraper_naive"]:
        assert r.label == "static_bot" and r.actor_type == "accidental_scraper"
        assert SEVERITIES.index(r.severity) <= SEVERITIES.index("medium")


def test_humans_are_not_alerted(ext):
    for t, r in ext["groups"]["web:human"]:
        assert r.label == "human" and r.severity == "info"


def test_mimic_basic_and_mimic_schema_are_detected_as_agents(ext):
    for name in ("web:mimic_basic", "web:mimic_schema"):
        for t, r in ext["groups"][name]:
            assert r.label == "agent" and r.actor_type == "goal_directed_agent", (name, r.label, r.actor_type)


def test_mimic_linked_is_alerted_but_not_labelled_agent(ext):
    for t, r in ext["groups"]["web:mimic_linked"]:
        assert r.actor_type == "possible_mimic" and SEVERITIES.index(r.severity) >= SEVERITIES.index("medium")
        assert r.label != "agent"


def test_known_failures_are_documented_by_tests(ext):
    """The honest negatives.  If a future change makes these pass, update the README limits too."""
    # v4 (deliberate change): in v3 mimic_assets evaded and human_no_assets was a false positive.  v4 catches the first (it fetches
    # the script but never runs it, so no beacon) and no longer alerts on the second (coherent Sec-Fetch -> advisory).  The v4
    # evaders/false positives are asserted in tests/test_v4_web.py.
    for t, r in ext["groups"]["web:mimic_assets"]:
        assert r.actor_type == "possible_mimic" and r.label != "agent" and SEVERITIES.index(r.severity) >= SEVERITIES.index("medium")
    for t, r in ext["groups"]["web:human_no_assets"]:
        assert r.label == "human" and r.severity == "info"


def test_without_the_mirror_the_v2_blind_spot_returns(ext):
    results, _ = run_pipeline([ext["art"]["access_log"], ext["art"]["gateway_log"], ext["art"]["leads"]], load_config())
    seen = {r.session.ip for r in results}
    for name in ("web:mimic_basic", "web:mimic_linked", "web:mimic_assets"):
        for t, _r in ext["groups"][name]:
            assert t.ip not in seen                                      # zero leads, no alert: exactly the live-demo finding


def test_demo_cli_extended_prints_variant_table(tmp_path, capsys):
    assert main(["demo", "--extended", "--out", str(tmp_path), "--no-color", "--top", "0"]) == 0
    out = capsys.readouterr().out
    assert "web:mimic_basic" in out and "WITHOUT the mirrored access stream" in out and "NOT benchmarks" in out


# =========================== export-web ===========================
def test_export_web_emits_strict_derived_facts(ext, tmp_path):
    out = tmp_path / "web.jsonl"
    assert main(["export-web", str(ext["art"]["leads"]), str(ext["art"]["access_mirror"]), "--out", str(out), "--label-synthetic"]) == 0
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    allowed = {"user_agent", "content_kind", "referer_valid", "linked_from_prev", "offered_earlier", "sec_fetch_mismatch",
               "strong_signal", "decoy_kind", "mcp", "ja4",
               # v4 (deliberate change: the allow-list grows with the new derived facts, nothing else)
               "asset_kind", "beacon", "beacon_offered", "referer_present", "referer_path", "sec_fetch_state",
               # v5 (deliberate change): the descriptive harness label from agentwatch.fingerprint
               "harness_archetype", "harness_confidence"}
    ev_keys = {"event_id", "ts", "source", "agent_id", "action", "status", "resource", "ip", "payload_bytes", "synthetic", "web"}
    assert rows and all(set(r) <= ev_keys and set(r["web"]) <= allowed and r["synthetic"] is True for r in rows)
    assert len({r["event_id"] for r in rows}) == len(rows)                   # unique ids (the pipeline quarantines duplicates)
    assert not any("?" in r["resource"] for r in rows)
    sigs = {r["web"].get("strong_signal") for r in rows}
    assert {"schema_param", "hidden_link"} <= sigs


def test_export_web_marks_unlinked_jumps_and_asset_requests(ext, tmp_path):
    out = tmp_path / "web.jsonl"
    main(["export-web", str(ext["art"]["leads"]), str(ext["art"]["access_mirror"]), "--out", str(out)])
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    ip = [t.ip for t, _ in ext["groups"]["web:mimic_basic"]][0]
    mine = [r for r in rows if r["ip"] == ip]
    assert sum(1 for r in mine if r["web"].get("linked_from_prev") is False and not r["web"].get("offered_earlier")) >= 3
    human = [t.ip for t, _ in ext["groups"]["web:human"]][0]
    assert any(r["web"]["content_kind"] == "asset" for r in rows if r["ip"] == human)


def test_export_web_missing_file_is_a_clean_error(tmp_path, capsys):
    assert main(["export-web", str(tmp_path / "nope.jsonl"), "--out", str(tmp_path / "o")]) == 2


def test_web_thresholds_in_config_file_match_defaults():
    assert json.loads((Path(__file__).resolve().parent.parent / "config" / "thresholds.json").read_text()) == json.loads(json.dumps(DEFAULTS))
