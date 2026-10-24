"""v4: sub-resource types (images-blocked humans are not starvation), ARIA canary, interaction beacon, headless_automation_signal,
browser-backed mimic cohorts.

Same honest caveat as v3: the simulated clients were written by the author of the detectors, so these are regression tests of
intended behaviour (including the documented evaders and false positives), not benchmarks.  Honeypot contact is not intent."""
import json
import re
from pathlib import Path

import pytest

from agentwatch.cli import main
from agentwatch.config import load_config
from agentwatch.honeypot import ARIA_LABEL, create_honeypot_app
from agentwatch.parser import parse_lines
from agentwatch.pipeline import run_pipeline
from agentwatch.scoring import SEVERITIES, score_session
from agentwatch.synthetic import generate_demo
from agentwatch.frontierdetect import detect_frontier
from agentwatch.webdetectors import asset_kind, detect_asset_starvation, detect_headless
from helpers import CFG, mk, sess
from test_v3_web import BROWSER, SEC_OK, asset, ips, leads_of, page, starving

BEACON = "/api/v1/telemetry/nav"
SEV = SEVERITIES.index


def beacon(t, ok=True, wd=False, ptr=True, props=False, ip="192.0.2.77", referer="http://127.0.0.1/p1"):
    r = mk(t, BEACON, ua=BROWSER, ip=ip, referer=referer)
    r.method = "POST"
    r.beacon = {"webdriver_present": wd, "pointer_trail_seen": ptr, "dom_automation_props": props} if ok else None
    return r


def browsing(n=5, offered=True, ua=BROWSER):
    """n click-through pages with Referer, each offering the beacon, plus the browser's css+js fetches."""
    pages = []
    for i in range(n):
        p = page(i * 10, f"/p{i}", links=[f"/p{i + 1}"], ua=ua, referer=f"http://127.0.0.1/p{i - 1}" if i else "")
        p.beacon_offered = offered
        pages.append(p)
    return pages


@pytest.fixture
def pot(tmp_path):
    log = tmp_path / "pot.jsonl"
    return create_honeypot_app(log, seed="v4", registry_path=tmp_path / "reg.json"), log


# =========================== (1) sub-resource types ===========================
def test_asset_kind_distinguishes_types():
    kinds = {p: asset_kind(mk(0, p), CFG) for p in ("/static/site.css", "/a/b.js", "/f/x.woff2", "/favicon.ico", "/x/logo.png",
                                                    "/x/p.WEBP", "/x/i.svg", "/api/v1/items", "/about")}
    assert kinds == {"/static/site.css": "css", "/a/b.js": "js", "/f/x.woff2": "font", "/favicon.ico": "favicon",
                     "/x/logo.png": "image", "/x/p.WEBP": "image", "/x/i.svg": "image", "/api/v1/items": None, "/about": None}


def test_images_blocked_with_css_js_favicon_is_not_starvation():
    reqs = starving(8) + [asset(30, "/static/site.css"), asset(31, "/static/site.js"), asset(32, "/favicon.ico")]
    assert detect_asset_starvation(sess(reqs), CFG) == []


def test_css_only_or_js_only_is_still_a_rendering_client():
    assert detect_asset_starvation(sess(starving(8) + [asset(30, "/static/site.css")]), CFG) == []
    assert detect_asset_starvation(sess(starving(8) + [asset(30, "/static/site.js")]), CFG) == []


def test_images_fonts_favicon_only_does_not_exempt():
    """Reserved for zero .css/.js: a client that fetched images/fonts/favicon but no stylesheet or script is still starved."""
    for extra in ("/static/logo.png", "/f/x.woff2", "/favicon.ico"):
        f = detect_asset_starvation(sess(starving(8) + [asset(30, extra)]), CFG)
        assert len(f) == 1 and f[0].kind == "asset_starvation" and f[0].data["reason"] == "no_core_subresources"


def test_four_pages_is_not_enough_and_declared_scripts_are_ignored():
    assert detect_asset_starvation(sess(starving(4)), CFG) == []
    assert detect_asset_starvation(sess(starving(9, ua="python-requests/2.31")), CFG) == []


def test_coherent_sec_fetch_makes_starvation_advisory_only():
    f = detect_asset_starvation(sess(starving(8, with_headers=SEC_OK)), CFG)
    assert [(x.detector, x.kind) for x in f] == [("web_advisory", "asset_starvation_coherent")]
    assert "advisory only" in f[0].summary


def test_missing_sec_fetch_on_logged_headers_is_still_starvation():
    f = detect_asset_starvation(sess(starving(8, with_headers={})), CFG)
    assert len(f) == 1 and f[0].data["sec_fetch"] is True


def test_contradictory_sec_fetch_triggers_even_with_assets():
    bad = {"sec-fetch-mode": "cors", "sec-fetch-dest": "document", "sec-fetch-site": "same-origin"}
    reqs = starving(4, with_headers=bad) + [asset(30, "/static/site.css"), asset(31, "/static/site.js")]
    f = detect_asset_starvation(sess(reqs), CFG)
    assert len(f) == 1 and f[0].data["reason"] == "contradictory_sec_fetch" and f[0].detector == "web"
    odd = {"sec-fetch-mode": "navigate", "sec-fetch-dest": "image", "sec-fetch-site": "none"}
    assert len(detect_asset_starvation(sess(starving(3, with_headers=odd) + [asset(30, "/static/site.js")]), CFG)) == 1
    # two page loads are not enough to call anything contradictory
    assert detect_asset_starvation(sess(starving(2, with_headers=bad)), CFG) == []


def test_mixed_coherent_and_absent_headers_stay_a_scoring_finding_when_not_all_coherent():
    pages = starving(6, with_headers=SEC_OK)
    for p in pages[:3]:
        p.headers = {}
    f = detect_asset_starvation(sess(pages), CFG)
    # 3 coherent of 3 checked (absent ones are not "checked") -> still advisory
    assert f[0].detector == "web_advisory"


# =========================== (2) ARIA canary ===========================
def test_aria_canary_on_home_and_kb_with_exact_attributes(pot):
    app, log = pot
    c = app.test_client()
    for path in ("/", "/kb/"):
        html = c.get(path, environ_overrides=ips("192.0.2.60")).get_data(as_text=True)
        m = re.search(r"<a [^>]*data-agent-action='fast-export'[^>]*>", html)
        assert m, path
        tag = m.group(0)
        assert "role='button'" in tag and f"aria-label='{ARIA_LABEL}'" in tag
        assert "href='/api/v1/kb-snapshot?mode=aria-fastpath'" in tag
        assert "opacity:.35" in tag and "display:none" not in tag            # muted, not hidden (the invisible link is a different decoy)
    assert ARIA_LABEL == "AI Assistant Fast-Path: Export Complete Knowledgebase JSON Snapshot"


def test_aria_target_is_not_advertised_anywhere_machine_readable(pot):
    app, _ = pot
    c = app.test_client()
    for path in ("/robots.txt", "/llms.txt", "/openapi.json", "/.well-known/mcp.json"):
        assert "kb-snapshot" not in c.get(path, environ_overrides=ips("192.0.2.61")).get_data(as_text=True), path


def test_kb_snapshot_is_a_scrubbed_read_only_decoy_with_a_canary(pot):
    app, log = pot
    c = app.test_client()
    r = c.get("/api/v1/kb-snapshot?mode=aria-fastpath&k=sk-" + "a" * 30 + "&email=bob%40example.com", environ_overrides=ips("192.0.2.62"))
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and json.loads(body)["synthetic"] is True
    assert "sk-" + "a" * 30 not in body and "bob" not in body                 # nothing reflected
    canary = json.loads(body)["snapshot_ref"]
    assert re.fullmatch(r"AWCANARY-[0-9a-f]{8}-\w+", canary)
    leads = leads_of(log)
    hit = [x for x in leads if x["decoy"]["kind"] == "aria_fastpath"]
    assert len(hit) == 1 and hit[0]["event_type"] == "honeytoken_hit" and "aria_mode" in hit[0]["tags"]
    blob = log.read_text() + Path(str(log) + ".access.jsonl").read_text()
    assert "sk-" + "a" * 30 not in blob and "bob%40example.com" not in blob and "bob@example.com" not in blob
    # echoing the canary later is its own, separate signal
    c.get("/about?q=" + canary, environ_overrides=ips("192.0.2.62"))
    assert any(x["decoy"]["kind"] == "canary_phrase_echo" or "canary_phrase_presented" in x["tags"] for x in leads_of(log))


def test_kb_snapshot_post_is_still_just_a_decoy(pot):
    app, _ = pot
    r = app.test_client().post("/api/v1/kb-snapshot", data="x=1", environ_overrides=ips("192.0.2.63"))
    assert r.status_code == 200 and json.loads(r.get_data())["synthetic"] is True


# =========================== (3) interaction beacon: server side ===========================
def test_pages_embed_a_same_origin_three_boolean_beacon_script(pot):
    app, _ = pot
    html = app.test_client().get("/about", environ_overrides=ips("192.0.2.64")).get_data(as_text=True)
    script = re.search(r"<script>\(function.*?</script>", html, re.S).group(0)
    assert BEACON in script and not re.search(r"https?://|//[a-z]", script.replace("'/api", ""))          # no third-party / absolute URL
    stringified = re.search(r"JSON\.stringify\(\{(.*?)\}\)\}\)", script).group(1)
    # v6 (deliberate edit): challenge proof + page path (verification only, not stored) + five booleans
    assert set(re.findall(r"(\w+):", stringified)) == {"proof", "page", "webdriver_present", "pointer_trail_seen", "dom_automation_props",
                                                       "kinematic_dwell_ok", "inertial_scroll_ok"}
    for forbidden in ("userAgent", "screen", "canvas", "localStorage", "document.cookie", "plugins", "language"):
        assert forbidden not in script, forbidden
    assert len(script) < 2600


def test_beacon_accepts_only_three_booleans_and_stores_nothing_else(pot):
    app, log = pot
    c = app.test_client()
    ok = {"webdriver_present": True, "pointer_trail_seen": False, "dom_automation_props": False}
    r = c.post(BEACON, json={**ok, "user_id": "u-123", "fingerprint": "abcdef", "ua": "x"}, environ_overrides=ips("192.0.2.65"))
    assert r.status_code == 204 and r.get_data() == b""
    rec = [x for x in leads_of(str(log) + ".access.jsonl") if x["path"] == BEACON][0]
    # v6 (deliberate edit): six booleans are stored; a v4-style body has no challenge proof -> challenge_proof_ok False, the
    # missing v6 booleans are null, and a low-severity beacon_forged lead is written (v4: no lead)
    assert rec["beacon"] == {"challenge_proof_ok": False, **ok, "kinematic_dwell_ok": None, "inertial_scroll_ok": None}
    assert "u-123" not in json.dumps(rec) and "abcdef" not in json.dumps(rec)
    lead = [x for x in leads_of(log) if x.get("decoy", {}).get("kind") == "beacon_forged"]
    assert len(lead) == 1 and "u-123" not in json.dumps(lead) and "abcdef" not in json.dumps(lead)


@pytest.mark.parametrize("payload", [{"webdriver_present": 1, "pointer_trail_seen": False, "dom_automation_props": False},
                                     {"webdriver_present": True}, [], "x", {"webdriver_present": "true", "pointer_trail_seen": 0,
                                                                            "dom_automation_props": None}])
def test_beacon_rejects_anything_that_is_not_exactly_three_booleans(pot, payload):
    app, log = pot
    assert app.test_client().post(BEACON, json=payload, environ_overrides=ips("192.0.2.66")).status_code == 400
    assert all("beacon" not in x for x in leads_of(str(log) + ".access.jsonl"))


def test_beacon_size_limited_and_get_not_allowed(pot):
    app, _ = pot
    c = app.test_client()
    # v6 (deliberate edit): the cap grew 256 -> 512 bytes (proof + page + five booleans)
    assert c.post(BEACON, data=b"{" + b" " * 600 + b"}", content_type="application/json", environ_overrides=ips("192.0.2.67")).status_code == 413
    assert c.post(BEACON, data=b"not json", content_type="application/json", environ_overrides=ips("192.0.2.67")).status_code == 400
    assert c.get(BEACON, environ_overrides=ips("192.0.2.67")).status_code == 405


def test_beacon_is_rate_capped_per_client(pot):
    app, log = pot
    c = app.test_client()
    body = {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False}
    codes = [c.post(BEACON, json=body, environ_overrides=ips("192.0.2.68")).status_code for _ in range(65)]
    assert codes[:60] == [204] * 60 and set(codes[60:]) == {429}
    assert c.post(BEACON, json=body, environ_overrides=ips("192.0.2.69")).status_code == 204          # other clients unaffected
    stored = [x for x in leads_of(str(log) + ".access.jsonl") if "beacon" in x]
    assert len(stored) == 61


def test_mirror_marks_html_responses_that_carry_the_beacon(pot):
    app, log = pot
    c = app.test_client()
    c.get("/about", environ_overrides=ips("192.0.2.70"))
    c.get("/static/site.css", environ_overrides=ips("192.0.2.70"))
    recs = {x["path"]: x for x in leads_of(str(log) + ".access.jsonl")}
    assert recs["/about"].get("beacon_script") is True and "beacon_script" not in recs["/static/site.css"]


def test_parser_keeps_only_strict_booleans_from_a_beacon_record():
    good = {"schema": "agentwatch.access/1", "timestamp": "2026-10-22T10:00:00Z", "client_ip": "192.0.2.5", "method": "POST", "path": BEACON,
            "status": 204, "headers": {}, "beacon": {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False}}
    bad = {**good, "beacon": {"webdriver_present": "no", "pointer_trail_seen": True, "dom_automation_props": False}}
    extra = {**good, "beacon": {**good["beacon"], "id": "u-1"}}
    res = parse_lines([json.dumps(good), json.dumps(bad), json.dumps(extra)])
    v6 = {**good["beacon"], "challenge_proof_ok": None, "kinematic_dwell_ok": None, "inertial_scroll_ok": None}   # v6: legacy -> null
    assert [r.beacon for r in res.requests] == [v6, None, v6]       # the extra key is dropped, not stored


# =========================== (3b) headless detector ===========================
def with_assets(reqs, js=True, css=True):
    out = list(reqs)
    if css:
        out.append(asset(1, "/static/site.css"))
    if js:
        out.append(asset(2, "/static/site.js"))
    return out


def test_aria_hit_from_a_browser_backed_client_is_a_high_confidence_signal():
    hit = mk(55, "/api/v1/kb-snapshot", query="mode=aria-fastpath", ua=BROWSER, ip="192.0.2.77", referer="http://127.0.0.1/p1")
    hit.decoy_kind, hit.source = "aria_fastpath", "honeypot"
    f = detect_headless(sess(with_assets(browsing(4)) + [hit]), CFG)
    strong = [x for x in f if x.data.get("strong")]
    assert [x.data["reason"] for x in strong] == ["aria_fastpath"] and strong[0].kind == "headless_automation_signal"


def test_aria_hit_without_browser_behaviour_is_only_passive_contact():
    hit = mk(55, "/api/v1/kb-snapshot", query="mode=aria-fastpath", ua="NaiveScraper/1.0", ip="192.0.2.77")
    hit.decoy_kind, hit.source = "aria_fastpath", "honeypot"
    assert [x for x in detect_headless(sess(browsing(4, ua="NaiveScraper/1.0") + [hit]), CFG) if x.detector == "web"] == []
    r = score_session(sess(browsing(4, ua="NaiveScraper/1.0") + [hit]), CFG)
    assert r.actor_type == "accidental_scraper" and SEV(r.severity) <= SEV("medium")


@pytest.mark.parametrize("kw,reason", [({"wd": True}, "webdriver_present"), ({"props": True}, "dom_automation_props")])
def test_automation_booleans_in_the_beacon_are_high_confidence(kw, reason):
    f = detect_headless(sess(with_assets(browsing(3)) + [beacon(25, **kw)]), CFG)
    assert [x.data["reason"] for x in f if x.data.get("strong")] == [reason]


def test_missing_beacon_after_fetching_our_script_is_a_moderate_signal():
    # v6 (deliberate edit): the v4 beacon_missing finding is now frontierdetect's script_fetched_but_unexecuted (same moderate weight)
    assert [x for x in detect_headless(sess(with_assets(browsing(5))), CFG) if x.detector == "web"] == []
    f = [x for x in detect_frontier(sess(with_assets(browsing(5))), CFG) if x.detector == "web"]
    assert len(f) == 1 and f[0].kind == "script_fetched_but_unexecuted" and f[0].data["strong"] is False
    r = score_session(sess(with_assets(browsing(5))), CFG)
    assert r.label != "agent" and r.actor_type == "possible_mimic" and SEV(r.severity) >= SEV("medium") and not r.floors


def test_missing_beacon_needs_the_script_fetch_three_clicks_and_a_beacon_bearing_site():
    # v6 (deliberate edit): same cases, now against detect_frontier (where the rule lives)
    assert [x for x in detect_frontier(sess(with_assets(browsing(5), js=False)), CFG) if x.detector == "web"] == []         # JS off
    assert [x for x in detect_frontier(sess(with_assets(browsing(3))), CFG) if x.detector == "web"] == []                   # 2 click-throughs
    assert [x for x in detect_frontier(sess(with_assets(browsing(6, offered=False))), CFG) if x.detector == "web"] == []     # site never offered a beacon
    assert [x for x in detect_frontier(sess(with_assets(browsing(5)) + [beacon(60)]), CFG) if x.detector == "web"] == []     # (legacy) beacon present
    assert [x for x in detect_frontier(sess(with_assets(browsing(5), js=False, css=True)), CFG) if x.detector == "web"] == []


def test_js_disabled_is_advisory_only_and_scores_zero():
    f = detect_headless(sess(with_assets(browsing(6), js=False)), CFG)
    assert [(x.detector, x.kind) for x in f] == [("web_advisory", "beacon_absent_no_js")]
    r = score_session(sess(with_assets(browsing(6), js=False)), CFG)
    assert r.agent_score == 0 and r.actor_type != "possible_mimic"


def test_pointerless_beacons_are_advisory_only():
    reqs = with_assets(browsing(6)) + [beacon(20 + i, ptr=False) for i in range(4)]
    f = detect_headless(sess(reqs), CFG)
    assert [(x.detector, x.kind) for x in f] == [("web_advisory", "no_pointer_trail")]
    assert score_session(sess(reqs), CFG).agent_score == 0
    keyboard_and_mouse = with_assets(browsing(6)) + [beacon(20 + i, ptr=(i == 3)) for i in range(4)]
    assert detect_headless(sess(keyboard_and_mouse), CFG) == []


def test_strong_headless_signal_sets_a_floor_that_padding_cannot_dilute():
    pad = [mk(100 + i * 5, "/static/site.css", ua=BROWSER, ip="192.0.2.77") for i in range(200)]
    r = score_session(sess(with_assets(browsing(5)) + [beacon(25, wd=True)] + pad), CFG)
    assert r.agent_score >= CFG["floors"]["agent"]["headless_automation_signal"] and r.label == "agent" and r.severity == "critical"
    assert any(f.startswith("agent:headless_automation_signal") for f in r.floors)


def test_headless_detector_off_switch():
    cfg = load_config()
    cfg["web"]["enabled"] = False
    assert score_session(sess(with_assets(browsing(5)) + [beacon(25, wd=True)]), cfg).agent_score == 0


def test_a_site_without_the_beacon_never_triggers_beacon_missing():
    """Plain access logs (no mirror, no beacon on the site): the v4 rules abstain instead of flagging every browser."""
    reqs = with_assets([page(i * 10, f"/p{i}", referer=f"http://127.0.0.1/p{i - 1}" if i else "") for i in range(6)])
    assert [x for x in detect_headless(sess(reqs), CFG) if x.detector == "web"] == []


# =========================== (4) cohorts in the extended demo ===========================
@pytest.fixture(scope="module")
def ext(tmp_path_factory):
    out = tmp_path_factory.mktemp("ext4")
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
            groups.setdefault(t.name.split(" #")[0], []).append(best[t.ip])
    return {"art": art, "groups": groups, "files": files}


def alerted(r):
    return SEV(r.severity) >= SEV("medium")


@pytest.mark.parametrize("name", ["web:human", "web:human_images_blocked", "web:human_js_off", "web:human_no_assets"])
def test_humans_without_the_blocked_beacon_are_not_alerted(ext, name):
    for r in ext["groups"][name]:
        assert r.label == "human" and not alerted(r) and r.actor_type == "human", name


def test_human_with_blocked_beacon_is_a_documented_false_positive(ext):
    # v6 (deliberate edit): the v4/v5 false positive is gone - coherent navigation headers + no decoy contact exempt a missing beacon
    for r in ext["groups"]["web:human_beacon_blocked"]:
        assert not alerted(r) and r.actor_type == "human" and r.label == "human"


def test_mimic_assets_is_now_alerted_moderately(ext):
    # v6 (deliberate edit): DOM-order iteration hits the inversion link -> strong R11 -> agent (it also loses the no-decoy exemption)
    for r in ext["groups"]["web:mimic_assets"]:
        assert alerted(r) and r.label == "agent"
        assert {"dom_visual_inversion_hit", "script_fetched_but_unexecuted"} <= {f.kind for f in r.findings if f.detector == "web"}


@pytest.mark.parametrize("name", ["web:mimic_browser_webdriver", "web:mimic_aria"])
def test_browser_backed_agents_with_automation_tells_are_labelled_agents(ext, name):
    for r in ext["groups"][name]:
        assert r.label == "agent" and r.actor_type == "goal_directed_agent" and r.severity == "critical"
        assert any(f.kind == "headless_automation_signal" and f.data["strong"] for f in r.findings)


@pytest.mark.parametrize("name", ["web:mimic_browser_stealth", "web:mimic_header_forger"])
def test_documented_evaders_stay_invisible(ext, name):
    """v6 (deliberate edit): the v4/v5 evaders are now caught BY CONSTRUCTION (stealth: DOM-order inversion link; header forger: canned
    beacon -> beacon_forged).  Same author as the traps; README limits updated (real stealth browsers are an unmeasured FP/FN risk)."""
    want = {"web:mimic_browser_stealth": "dom_visual_inversion_hit", "web:mimic_header_forger": "beacon_forged"}[name]
    for r in ext["groups"][name]:
        assert r.label == "agent" and alerted(r) and any(f.kind == want and f.detector == "web" for f in r.findings)


def test_scrapers_that_follow_the_aria_anchor_stay_accidental(ext):
    for r in ext["groups"]["web:scraper_naive"]:
        kinds = {f.kind for f in r.findings if f.detector == "honeytoken"}
        assert "aria_fastpath" in kinds and r.actor_type == "accidental_scraper" and r.label == "static_bot"


def test_extended_demo_still_leaves_the_original_actors_untouched(tmp_path, ext):
    base = generate_demo(tmp_path / "base", seed=7)
    assert Path(base["access_log"]).read_bytes() == Path(ext["art"]["access_log"]).read_bytes()


def test_without_the_mirror_beacon_evidence_is_lost(ext):
    results, _ = run_pipeline([ext["art"]["access_log"], ext["art"]["gateway_log"], ext["art"]["leads"]], load_config())
    by_ip = {r.session.ip: r for r in results}
    for t in ext["art"]["truth"]:
        if t.name.startswith(("web:mimic_assets", "web:mimic_browser_stealth")):
            # v6 (deliberate edit): only the context-only inversion lead remains without the mirror; it scores nothing alone
            r = by_ip.get(t.ip)
            assert r is None or (r.label == "human" and not alerted(r))
        if t.name.startswith("web:mimic_header_forger"):
            assert by_ip[t.ip].label == "agent"           # v6: the beacon_forged LEAD survives without the mirror


def test_export_web_carries_the_v4_facts_and_never_more(ext, tmp_path):
    out = tmp_path / "web.jsonl"
    assert main(["export-web", str(ext["art"]["leads"]), str(ext["art"]["access_mirror"]), "--out", str(out), "--label-synthetic"]) == 0
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    beacons = [r["web"] for r in rows if r["web"]["content_kind"] == "beacon"]
    assert beacons and all(set(b["beacon"]) == {"challenge_proof_ok", "webdriver_present", "pointer_trail_seen", "dom_automation_props",
                                                "kinematic_dwell_ok", "inertial_scroll_ok"} for b in beacons)     # v6: six booleans
    kinds = {r["web"].get("asset_kind") for r in rows if r["web"]["content_kind"] == "asset"}
    assert {"css", "js", "image", "favicon"} <= kinds
    assert any(r["web"].get("strong_signal") == "aria_fastpath" for r in rows)
    assert any(r["web"].get("beacon_offered") for r in rows if r["web"]["content_kind"] == "html")
    assert {r["web"].get("sec_fetch_state") for r in rows} >= {"coherent", None}
