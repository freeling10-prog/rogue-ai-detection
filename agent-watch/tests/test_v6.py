"""v6 "Deep-Cover & Frontier Evasion": challenge-bound beacon, DOM-visual inversion, provenance cursors, R14 parasitic forks,
LLMjacking decoy, CSP, LRU rate map, replay R9 placement, PR #4 decode fix.

SAME-AUTHOR CAVEAT: the v6 simulated cohorts (mimic_vlm_os, mimic_schema_sanitizer, mimic_parasitic_rider, and the v6 behaviour of the
older mimics) were written by the same author as the v6 detectors.  These tests check intended behaviour; catching those cohorts is
expected by construction and is NOT evidence of real-world efficacy."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentwatch import frontier, safelog
from agentwatch.cli import main
from agentwatch.config import load_config
from agentwatch.fingerprint import fingerprint_session
from agentwatch.frontierdetect import R11_FAMILY, detect_frontier, detect_parasitic_fork, js_assets_fetched
from agentwatch.honeypot import create_honeypot_app
from agentwatch.leads import LeadWriter
from agentwatch.parser import parse_lines
from agentwatch.pipeline import run_pipeline
from agentwatch.replay import build_replay_html
from agentwatch.scoring import SEVERITIES, score_session
from agentwatch.scrubber import get_default_scrubber
from agentwatch.synthetic import generate_demo
from agentwatch.webagents import CANNED_PROOF, ordered_links, visible_links
from helpers import CFG, mk, sess
from test_v3_web import BROWSER, SEC_OK, asset, ips, leads_of, page

T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
BEACON = "/api/v1/telemetry/nav"
SEV = SEVERITIES.index
HOSTILE = "</script><script>alert(1)</script>"


@pytest.fixture
def pot(tmp_path):
    clock = {"t": T0}
    log = tmp_path / "pot.jsonl"
    app = create_honeypot_app(log, seed="v6", clock=lambda: clock["t"])
    return app, log, clock


def access(log):
    return leads_of(str(log) + ".access.jsonl")


def chal_of(html):
    m = re.search(r"name='aw-challenge' content='([0-9a-f]{16})'", html)
    p = re.search(r"id='aw-probe'[^>]*?width:(\d+)px;height:(\d+)px", html)
    return m.group(1), f"{m.group(1)}.{p.group(1)}x{p.group(2)}"


def good_beacon(proof, page="/", **kw):
    body = {"proof": proof, "page": page, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
            "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    body.update(kw)
    return body


# =========================== step 0: PR #4 decode loop ===========================
def test_unicode_escaped_percent_encoded_email_is_redacted():
    s = get_default_scrubber()
    raw = "contact bob\\u002540example.com now"           # \u0025 -> '%', then %40 -> '@' (needs the second round)
    out = s.scrub_text(raw)
    assert "bob" not in out and "example.com" not in out and "REDACTED_EMAIL" in out
    assert "REDACTED_EMAIL" in safelog.safe_text(raw) and "bob" not in safelog.safe_text(raw)
    assert "REDACTED_EMAIL" in s.scrub_text("bob%2540example.com") and "REDACTED_EMAIL" in s.scrub_text("bob\\u0040example.com")


def test_unicode_escaped_email_never_reaches_disk(tmp_path):
    w = LeadWriter(tmp_path / "x.jsonl", 10_000, get_default_scrubber())
    w.write({"note": "reach me at bob\\u002540example.com", "nested": {"q": "x=bob\\u002540example.com"}})
    text = (tmp_path / "x.jsonl").read_text()
    assert "bob" not in text and "REDACTED_EMAIL" in text


# =========================== (1) challenge-bound beacon ===========================
def test_challenge_is_per_page_and_bucket_and_identical_for_every_client(pot):
    app, _, clock = pot
    c = app.test_client()
    a1 = chal_of(c.get("/", environ_overrides=ips("192.0.2.1"), headers={"User-Agent": "A"}).get_data(as_text=True))[0]
    a2 = chal_of(c.get("/", environ_overrides=ips("198.51.100.9"), headers={"User-Agent": "B"}).get_data(as_text=True))[0]
    k = chal_of(c.get("/kb/", environ_overrides=ips("192.0.2.1")).get_data(as_text=True))[0]
    clock["t"] += timedelta(seconds=frontier.CHALLENGE_BUCKET_S)
    a3 = chal_of(c.get("/", environ_overrides=ips("192.0.2.1")).get_data(as_text=True))[0]
    assert a1 == a2                       # no client identifier: every client on that page/bucket gets the same challenge
    assert a1 != k and a1 != a3           # bound to the page path and the time bucket


def test_valid_beacon_stores_exactly_six_booleans_and_no_proof(pot):
    app, log, _ = pot
    c = app.test_client()
    _, proof = chal_of(c.get("/kb/", environ_overrides=ips("192.0.2.2")).get_data(as_text=True))
    r = c.post(BEACON, json={**good_beacon(proof, "/kb/"), "user_id": "u-9", "ua": "x"}, environ_overrides=ips("192.0.2.2"))
    assert r.status_code == 204
    rec = [x for x in access(log) if x["path"] == BEACON][0]
    assert rec["beacon"] == {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True,
                             "dom_automation_props": False, "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    blob = json.dumps(rec)
    assert proof not in blob and "u-9" not in blob and "lead_event_id" not in rec
    assert not any(x.get("decoy", {}).get("kind") == "beacon_forged" for x in leads_of(log))


def test_canned_or_wrong_page_or_expired_proof_is_beacon_forged(pot):
    app, log, clock = pot
    c = app.test_client()
    _, proof = chal_of(c.get("/kb/", environ_overrides=ips("192.0.2.3")).get_data(as_text=True))
    assert c.post(BEACON, json=good_beacon(CANNED_PROOF, "/"), environ_overrides=ips("192.0.2.3")).status_code == 204    # canned
    assert c.post(BEACON, json=good_beacon(proof, "/about"), environ_overrides=ips("192.0.2.3")).status_code == 204      # wrong page
    assert c.post(BEACON, json=good_beacon(proof.split(".")[0] + ".1x1", "/kb/"), environ_overrides=ips("192.0.2.3")).status_code == 204
    clock["t"] += timedelta(hours=3)                                                                                      # stale tab: OK
    assert c.post(BEACON, json=good_beacon(proof, "/kb/"), environ_overrides=ips("192.0.2.3")).status_code == 204
    clock["t"] += timedelta(hours=22)                                                                                     # > 24 h: forged
    assert c.post(BEACON, json=good_beacon(proof, "/kb/"), environ_overrides=ips("192.0.2.3")).status_code == 204
    oks = [x["beacon"]["challenge_proof_ok"] for x in access(log) if x["path"] == BEACON]
    assert oks == [False, False, False, True, False]
    forged = [x for x in leads_of(log) if x.get("decoy", {}).get("kind") == "beacon_forged"]
    assert len(forged) == 4 and all(CANNED_PROOF not in json.dumps(x) and proof not in json.dumps(x) for x in forged)
    assert all("beacon_forged" in x.get("signals", []) for x in access(log) if x["path"] == BEACON and not x["beacon"]["challenge_proof_ok"])


def test_simulated_header_forger_is_beacon_forged_but_real_script_users_are_not(ext):
    for r in ext["groups"]["web:mimic_header_forger"]:
        assert any(f.kind == "beacon_forged" and f.detector == "web" for f in r.findings)
    for name in ("web:human", "web:human_images_blocked", "web:mimic_vlm_os", "web:mimic_browser_stealth"):
        for r in ext["groups"][name]:
            assert not any(f.kind == "beacon_forged" for f in r.findings), name
            assert all(q.beacon["challenge_proof_ok"] is True for q in r.session.requests if q.beacon), name


def test_beacon_script_reads_no_identifiers_and_is_same_origin(pot):
    app, _, _ = pot
    html = app.test_client().get("/about").get_data(as_text=True)
    script = re.search(r"<script>\(function.*?</script>", html, re.S).group(0)
    assert "fetch('/api/v1/telemetry/nav'" in script and not re.search(r"https?://", script)
    for forbidden in ("userAgent", "screen.", "canvas", "localStorage", "document.cookie", "plugins", "language", "clientX:", "Date"):
        assert forbidden not in script, forbidden


# =========================== no false positives for the hard-negative humans ===========================
@pytest.fixture(scope="module")
def ext(tmp_path_factory):
    out = tmp_path_factory.mktemp("ext6")
    art = generate_demo(out, seed=7, extended=True)
    files = [art["access_log"], art["gateway_log"], art["leads"], art["access_mirror"]]
    results, _ = run_pipeline(files, load_config())
    best = {}
    for r in results:
        if r.session.ip not in best or len(r.session.requests) > len(best[r.session.ip].session.requests):
            best[r.session.ip] = r
    groups = {}
    for t in art["truth"]:
        if t.name.startswith("web:"):
            groups.setdefault(t.name.split(" #")[0], []).append(best[t.ip])
    return {"art": art, "groups": groups, "results": results}


@pytest.mark.parametrize("name", ["web:human", "web:human_images_blocked", "web:human_js_off", "web:human_no_assets",
                                  "web:human_beacon_blocked"])
def test_humans_including_js_off_beacon_blocked_and_no_asset_are_not_alerted(ext, name):
    for r in ext["groups"][name]:
        assert r.label == "human" and SEV(r.severity) < SEV("medium") and r.actor_type == "human", name
        assert not [f for f in r.findings if f.detector == "web"], (name, [f.kind for f in r.findings])
        assert not any(q.status == 400 for q in r.session.requests), name           # humans never meet "Missing Required Cursor"


def test_js_off_and_no_asset_humans_fetch_no_script(ext):
    for name in ("web:human_js_off", "web:human_no_assets"):
        for r in ext["groups"][name]:
            assert js_assets_fetched(r.session, CFG) == 0


def test_script_fetched_but_unexecuted_exemptions():
    def pages(headers):
        out = []
        for i in range(5):
            p = page(i * 10, f"/p{i}", links=[f"/p{i + 1}"], headers=headers, referer=f"http://127.0.0.1/p{i - 1}" if i else "")
            p.beacon_offered = True
            out.append(p)
        return out
    js = asset(2, "/static/site.js")
    css = asset(1, "/static/site.css")
    kinds = lambda reqs: [f.kind for f in detect_frontier(sess(reqs), CFG) if f.detector == "web"]          # noqa: E731
    assert kinds(pages(None) + [css]) == []                                         # js_assets_fetched == 0: never
    assert kinds(pages(dict(SEC_OK)) + [css, js]) == []                             # coherent navigation, no decoy: exempt
    assert kinds(pages(None) + [css, js]) == ["script_fetched_but_unexecuted"]      # no headers logged: moderate
    hit = mk(60, frontier.INVERSION_PATH, ua=BROWSER, ip="192.0.2.77")
    hit.decoy_kind, hit.source = "dom_visual_inversion_hit", "honeypot"
    assert "script_fetched_but_unexecuted" in kinds(pages(dict(SEC_OK)) + [css, js, hit])      # decoy contact lifts the exemption


# =========================== (2) DOM-visual order inversion ===========================
@pytest.mark.parametrize("path", ["/", "/kb/"])
def test_inversion_link_is_first_in_dom_but_rendered_last(pot, path):
    app, _, _ = pot
    html = app.test_client().get(path).get_data(as_text=True)
    body = html.split("<body>", 1)[1]
    first = re.search(r"<a\s[^>]*href='([^']*)'", body).group(1)
    assert first == frontier.INVERSION_PATH
    assert re.search(r"<li style='order:99'><a href='/kb/archive/diagnostic'", html) and "<li style='order:1'>" in html
    assert "display:flex" in html                                         # order: only applies inside a flex container
    dom = [x for x in visible_links(body, False)]
    vis = ordered_links(body, False, visual=True)
    assert dom[0] == frontier.INVERSION_PATH and frontier.INVERSION_PATH not in vis


def test_inversion_hit_is_a_lead_and_strong_only_for_browser_backed_clients(pot, ext):
    app, log, _ = pot
    c = app.test_client()
    assert c.get(frontier.INVERSION_PATH, environ_overrides=ips("192.0.2.4")).status_code == 200
    lead = [x for x in leads_of(log) if x.get("decoy", {}).get("kind") == "dom_visual_inversion_hit"]
    assert len(lead) == 1
    assert "dom_visual_inversion_hit" in [x for x in access(log) if x["path"] == frontier.INVERSION_PATH][0]["signals"]
    for r in ext["groups"]["web:mimic_browser_stealth"]:            # DOM-order iteration by a browser-backed client
        assert any(f.kind == "dom_visual_inversion_hit" and f.detector == "web" and f.data["strong"] for f in r.findings)
    for r in ext["groups"]["web:scraper_naive"]:                    # a crawler meets it too: context only, stays accidental
        assert r.actor_type == "accidental_scraper" and r.label == "static_bot"
        assert not any(f.kind == "dom_visual_inversion_hit" and f.detector == "web" for f in r.findings)


def test_lone_inversion_click_by_a_person_is_not_an_alert():
    """A person who scrolls down and clicks the footer link: the beacon of that click shows pointer movement + press kinematics."""
    reqs = [page(0, "/", links=["/kb/archive/diagnostic", "/about"]), asset(0.1, "/static/site.css"), asset(0.2, "/static/site.js")]
    b = mk(8.9, BEACON, ua=BROWSER, ip="192.0.2.77", referer="http://127.0.0.1/")
    b.method = "POST"
    b.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    hit = page(9, frontier.INVERSION_PATH, links=[], referer="http://127.0.0.1/")
    hit.decoy_kind, hit.source = "dom_visual_inversion_hit", "honeypot"
    r = score_session(sess(reqs + [b, hit]), CFG)
    assert r.label == "human" and SEV(r.severity) < SEV("high")
    assert [f.detector for f in r.findings if f.kind == "dom_visual_inversion_hit" and f.detector.startswith("web")] == ["web_advisory"]
    # JS off (no script fetched): also advisory
    r2 = score_session(sess(reqs[:2] + [hit]), CFG)
    assert r2.label == "human"
    # the same hit with no human click (DOM-order automation): strong
    r3 = score_session(sess(reqs + [hit]), CFG)
    assert r3.label == "agent"


def _browser_session(beacons, inversion=False, image=True):
    reqs = []
    for i in range(4):
        p = page(i * 10, f"/p{i}", links=[f"/p{i + 1}"], referer=f"http://127.0.0.1/p{i - 1}" if i else "")
        p.beacon_offered = True
        reqs.append(p)
    reqs += [asset(1, "/static/site.css"), asset(2, "/static/site.js")] + ([asset(3, "/static/logo.svg")] if image else [])
    for k, b in enumerate(beacons):
        r = mk(9 + 10 * k, BEACON, ua=BROWSER, ip="192.0.2.77", referer=f"http://127.0.0.1/p{k}")
        r.method = "POST"
        r.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                    "kinematic_dwell_ok": True, "inertial_scroll_ok": True, **b}
        reqs.append(r)
    if inversion:
        h = page(45, frontier.INVERSION_PATH, links=[], referer="http://127.0.0.1/p3")
        h.decoy_kind, h.source = "dom_visual_inversion_hit", "honeypot"
        reqs.append(h)
    return sess(reqs)


def test_vlm_quantized_interaction_rule():
    vlm = lambda s: [f for f in detect_frontier(s, CFG) if f.kind == "vlm_quantized_interaction"]     # noqa: E731
    q = {"inertial_scroll_ok": False, "kinematic_dwell_ok": False}
    assert vlm(_browser_session([q, q]))                                                           # quantized scroll + instant clicks
    assert not vlm(_browser_session([q]))                                                          # one beacon is not enough
    assert not vlm(_browser_session([{"inertial_scroll_ok": False}] * 2))                          # human click kinematics, no inversion
    assert vlm(_browser_session([{"inertial_scroll_ok": False}] * 2, inversion=True))              # ... or the inversion link
    assert not vlm(_browser_session([{"kinematic_dwell_ok": False}] * 2))                          # momentum scroll (or no scroll)
    assert not vlm(_browser_session([q, q], image=False))                                          # needs full assets
    assert not vlm(_browser_session([{**q, "challenge_proof_ok": False}] * 2))                     # needs a valid proof
    r = score_session(_browser_session([q, q]), CFG)
    assert r.label == "agent" and "agent:vlm_quantized_interaction" in r.floors


def test_simulated_vlm_cohort_is_caught_by_the_vlm_rule(ext):
    for r in ext["groups"]["web:mimic_vlm_os"]:
        assert r.label == "agent" and any(f.kind == "vlm_quantized_interaction" for f in r.findings)
        assert not any(f.kind == "dom_visual_inversion_hit" for f in r.findings)      # it reads the page visually


# =========================== (3) provenance cursors ===========================
def test_kb_detail_pagination_and_api_need_a_cursor(pot):
    app, log, _ = pot
    c = app.test_client()
    for url in ("/kb/shipping-policy", "/kb/shipping-policy?cursor=prov.html.000000000000", "/kb/page/2", "/api/v1/kb/articles",
                "/kb/shipping-policy?cursor=" + frontier.cursor(app.extensions["agentwatch"].registry.digest, "html", "/kb/returns-faq")):
        r = c.get(url, environ_overrides=ips("192.0.2.5"))
        assert r.status_code == 400 and r.get_data(as_text=True).strip() == "Missing Required Cursor", url
    recs = [x for x in access(log) if x["status"] == 400]
    assert len(recs) == 5 and all(x["cursor_prov"] is None and "missing_required_cursor" in x["signals"] for x in recs)
    assert c.get("/kb/does-not-exist", environ_overrides=ips("192.0.2.5")).status_code == 404


def test_every_link_a_person_can_click_carries_a_valid_html_cursor(pot):
    app, log, _ = pot
    c = app.test_client()
    seen, queue, statuses = set(), ["/"], {}
    while queue:
        url = queue.pop(0)
        if url in seen or url.startswith("/staff-portal"):
            continue
        seen.add(url)
        r = c.get(url, environ_overrides=ips("198.51.100.50"))
        statuses[url] = r.status_code
        if r.mimetype == "text/html":
            body = r.get_data(as_text=True).split("<body>", 1)[-1]
            queue += [h for h in visible_links(body, False) if h not in seen]
    assert statuses and 400 not in statuses.values(), {k: v for k, v in statuses.items() if v == 400}
    kb = [x for x in access(log) if x["path"].startswith("/kb/") and x["path"] not in ("/kb/", frontier.INVERSION_PATH)]
    assert kb and all(x["cursor_prov"] == "html" for x in kb)


def test_schema_cursors_from_llms_openapi_and_mcp_work_and_are_labelled_schema(pot):
    app, log, _ = pot
    c = app.test_client()
    llms = c.get("/llms.txt").get_data(as_text=True)
    kb = re.search(r"\((/kb/[a-z0-9-]+\?cursor=prov\.schema\.[0-9a-f]{12})\)", llms).group(1)
    assert c.get(kb).status_code == 200
    spec = c.get("/openapi.json").get_json()
    p = spec["paths"]["/api/v1/kb/articles"]["get"]["parameters"][0]
    assert p["name"] == "cursor" and p["required"] is True
    api = c.get("/api/v1/kb/articles?cursor=" + p["schema"]["example"])
    assert api.status_code == 200 and all("prov.schema." in a["url"] for a in api.get_json()["articles"])
    res = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "read_internal_notes", "arguments": {"note_id": "N-1"}}}).get_json()
    ref = json.loads(res["result"]["content"][0]["text"])["note"]["kb_ref"]
    assert "prov.schema." in ref and c.get(ref).status_code == 200
    provs = [x["cursor_prov"] for x in access(log) if "cursor_prov" in x]
    assert provs == ["schema", "schema", "schema"]
    assert all("schema_provenance_cursor" in x["signals"] for x in access(log) if x.get("cursor_prov") == "schema")


def test_schema_cursor_while_browsing_is_strong_but_advisory_for_pure_api_clients():
    def cursor_req(t, ua):
        r = mk(t, "/kb/shipping-policy", query="cursor=prov.schema.abcdefabcdef", ua=ua, ip="192.0.2.77")
        r.cursor_route, r.cursor_prov, r.content_type = True, "schema", "text/html"
        return r
    browse = [page(0, "/", links=["/kb/"]), page(5, "/kb/", links=[], referer="http://127.0.0.1/"), cursor_req(9, BROWSER)]
    f = [x for x in detect_frontier(sess(browse), CFG) if x.kind == "schema_provenance_cursor"]
    assert f and f[0].detector == "web" and f[0].data["strong"]
    api = [mk(0, "/llms.txt", ua="python-httpx/0.27", ip="192.0.2.77"), cursor_req(2, "python-httpx/0.27")]
    f2 = [x for x in detect_frontier(sess(api), CFG) if x.kind == "schema_provenance_cursor"]
    assert f2 and f2[0].detector == "web_advisory"


def test_schema_sanitizer_is_caught_by_cursor_provenance_not_by_the_canary_param(ext):
    for r in ext["groups"]["web:mimic_schema_sanitizer"]:
        kinds = {f.kind for f in r.findings}
        assert "schema_provenance_cursor" in kinds and "schema_param" not in kinds and r.label == "agent"
        assert not any("client_schema_rev" in q.query for q in r.session.requests)


# =========================== kinematic_dwell inconclusive ===========================
def test_kinematic_dwell_inconclusive_null_does_not_corroborate_vlm():
    """dwell null (touch / OS tap 0–4ms) must not count as kinematic_dwell_ok is False for VLM."""
    # full assets + valid proof + bad scroll + dwell null -> NOT vlm (needs dwell false OR inversion)
    beacons = [{"inertial_scroll_ok": False, "kinematic_dwell_ok": None}] * 3
    s = _browser_session(beacons)
    assert not any(f.kind == "vlm_quantized_interaction" for f in detect_frontier(s, CFG))
    # explicit false still corroborates
    beacons_f = [{"inertial_scroll_ok": False, "kinematic_dwell_ok": False}] * 3
    assert any(f.kind == "vlm_quantized_interaction" for f in detect_frontier(_browser_session(beacons_f), CFG))


# =========================== R14 parasitic session fork ===========================
def _human_with_rider(gap):
    # Human tab advances / -> /kb/ -> /kb/doc1; fork on disjoint /api subtree with missing Referer + schema.
    reqs = [page(0, "/", links=["/kb/"]), page(10, "/kb/", links=["/kb/doc1"], referer="http://127.0.0.1/"),
            page(10.2, "/kb/doc1", links=[], referer="http://127.0.0.1/kb/"),
            asset(10.05, "/static/site.css"), asset(10.06, "/static/site.js")]
    b = mk(9.9, BEACON, ua=BROWSER, ip="192.0.2.77", referer="http://127.0.0.1/")
    b.method = "POST"
    b.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    # Gemini: interleaved disjoint depth — fork Referer missing/non-parent (not Referer:/ BFS)
    rider = page(10 + gap, "/api/v1/export", links=[], referer="", content_type="application/json")
    rider.cursor_prov = "schema"
    return sess(reqs + [b, rider])


def test_r14_fires_within_500ms_of_a_human_page_load_only():
    assert detect_parasitic_fork(_human_with_rider(0.3), CFG)
    assert not detect_parasitic_fork(_human_with_rider(2.0), CFG)        # a person typing a URL later is not a fork
    s = _human_with_rider(0.3)
    for r in s.requests:
        if r.beacon:
            r.beacon["pointer_trail_seen"] = False
    assert not detect_parasitic_fork(s, CFG)                             # no active human branch -> no fork claim


def test_simulated_rider_is_r14_and_replay_shows_the_sub_branch(ext):
    for r in ext["groups"]["web:mimic_parasitic_rider"]:
        f = [x for x in r.findings if x.kind == "parasitic_session_fork"]
        assert f and f[0].data["strong"] and r.label == "agent"
    html = build_replay_html(ext["groups"]["web:mimic_parasitic_rider"][:1], CFG)
    assert "Parasitic sub-branch (R14)" in html and ">R14<" in html
    for name in ("web:human", "web:human_beacon_blocked"):
        for r in ext["groups"][name]:
            assert not any(x.kind == "parasitic_session_fork" for x in r.findings)



def test_r14_single_client_bfs_unlinked_is_not_a_fork():
    """Phase-1 crawler FP: human beacon + concurrent bare unlinked navigations from the SAME client must not be R14."""
    ip = "192.0.2.70"
    reqs = [page(0, "/", links=["/about", "/kb/"], ip=ip), page(1.0, "/about", links=[], referer="http://127.0.0.1/", ip=ip),
            asset(1.05, "/static/site.css", ip=ip), asset(1.06, "/static/site.js", ip=ip)]
    b = mk(0.9, BEACON, ua=BROWSER, ip=ip, referer="http://127.0.0.1/")
    b.method = "POST"
    b.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    # BFS-style unlinked guesses (no schema cursor) within the fork window — single client
    guess1 = page(1.1, "/api/v1/kb-snapshot", links=[], referer="", content_type="application/json", ip=ip)
    guess2 = page(1.15, "/llms.txt", links=[], referer="", content_type="text/plain", ip=ip)
    s = sess(reqs + [b, guess1, guess2])
    assert not detect_parasitic_fork(s, CFG)


def test_r14_same_client_bfs_with_referer_root_stays_negative():
    """Gemini: same-client BFS fan-out with Referer:/ must stay R14-negative even if paths look 'forked'."""
    ip = "192.0.2.71"
    reqs = [page(0, "/", links=["/a", "/b", "/c"], ip=ip),
            asset(0.05, "/static/site.css", ip=ip), asset(0.06, "/static/site.js", ip=ip)]
    b = mk(0.04, BEACON, ua=BROWSER, ip=ip, referer="http://127.0.0.1/")
    b.method = "POST"
    b.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    # Classic BFS: queue children of /, fetch within <500ms all carrying Referer: /
    for i, pth in enumerate(("/a", "/b", "/c", "/openapi.json")):
        reqs.append(page(0.1 + i * 0.05, pth, links=[], referer="http://127.0.0.1/", ip=ip))
    s = sess(reqs + [b])
    assert not detect_parasitic_fork(s, CFG)


def test_r14_cross_client_two_sessions_on_same_ip():
    from agentwatch.frontierdetect import detect_parasitic_across_clients
    from agentwatch.scoring import analyze_sessions
    ip = "192.0.2.88"
    h_reqs = [page(0, "/", links=["/kb/"], ip=ip), page(10, "/kb/", links=["/kb/a"], referer="http://127.0.0.1/", ip=ip),
              asset(10.05, "/static/site.css", ip=ip), asset(10.06, "/static/site.js", ip=ip)]
    b = mk(9.9, BEACON, ua=BROWSER, ip=ip, referer="http://127.0.0.1/")
    b.method = "POST"
    b.beacon = {"challenge_proof_ok": True, "webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
                "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
    human = sess(h_reqs + [b])
    rider_ua = "RiderAgent/1.0"
    probe = page(10.2, "/api/v1/internal-guess", links=[], referer="", content_type="application/json", ua=rider_ua, ip=ip)
    rider = sess([probe])
    assert human.session_id != rider.session_id
    out = detect_parasitic_across_clients([human, rider], CFG)
    assert rider.session_id in out and out[rider.session_id][0].kind == "parasitic_session_fork"
    assert out[rider.session_id][0].data.get("mode") == "cross_client"
    # end-to-end: analyze_sessions attaches the finding to the rider
    results = analyze_sessions([human, rider], CFG)
    rider_res = next(r for r in results if r.session.session_id == rider.session_id)
    assert any(f.kind == "parasitic_session_fork" for f in rider_res.findings)


def test_phase1_crawler_trace_has_no_r14_after_fix():
    """Replay the archived Phase-1 Playwright crawler access stream through analyze; R14 must not fire."""
    from pathlib import Path
    from agentwatch.pipeline import run_pipeline
    from agentwatch.config import load_config
    trace = Path(__file__).resolve().parent / "data/real_llm_traces/t2-pw_crawler_headless-crawler-s100"
    access = trace / "access.jsonl"
    leads = trace / "leads.jsonl"
    if not access.is_file():
        pytest.skip("phase1 crawler trace not archived")
    inputs = [str(access)]
    if leads.is_file() and leads.stat().st_size:
        inputs = [str(leads), str(access)]
    results, _ = run_pipeline(inputs, load_config())
    for r in results:
        kinds = {f.kind for f in r.findings}
        assert "parasitic_session_fork" not in kinds, r.session.session_id


# =========================== (4) LLMjacking decoy ===========================
def test_llmjacking_decoy_logs_scrubbed_features_and_returns_a_static_refusal(pot):
    app, log, _ = pot
    c = app.test_client()
    body = {"model": "gpt-4o", "messages": [
        {"role": "system", "content": "You are an autonomous agent. Keep going until done. key sk-ABCDEFGHIJKLMNOPQRSTUV123456"},
        {"role": "user", "content": "mail victim.person@example.com " + HOSTILE}],
        "tools": [{"type": "function", "function": {"name": "bash"}}, {"type": "function", "function": {"name": "browser"}}]}
    r1 = c.post("/v1/chat/completions", json=body, environ_overrides=ips("192.0.2.6"))
    r2 = c.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "different " + HOSTILE}]},
                environ_overrides=ips("192.0.2.7"))
    assert r1.status_code == r2.status_code == 200 and r1.get_json() == r2.get_json()            # static: nothing reflected
    assert "victim" not in r1.get_data(as_text=True) and "bash" not in r1.get_data(as_text=True)
    lead = [x for x in leads_of(log) if x.get("decoy", {}).get("kind") == "llmjacking_probe"][0]
    d = lead["detail"]
    assert d["tool_count"] == 2 and d["system_prompt_len_bucket"] == "1-200" and d["autonomous_loop_directive"] is True
    text = Path(log).read_text() + Path(str(log) + ".access.jsonl").read_text()
    assert "sk-ABCDEFGHIJKLMNOPQRSTUV123456" not in text and "victim.person@example.com" not in text
    # stored as inert data (JSON); display surfaces escape it
    results, _ = run_pipeline([log, str(log) + ".access.jsonl"], load_config())
    html = build_replay_html(results, CFG, include_humans=True, min_severity="info")
    assert "</script><script>alert(1)" not in html and "sk-ABCDEFGHIJKLMNOPQRSTUV123456" not in html
    assert c.get("/v1/chat/completions").status_code == 405


def test_llmjacking_decoy_size_cap_and_rate_limit(pot):
    app, _, _ = pot
    c = app.test_client()
    big = json.dumps({"messages": [{"role": "user", "content": "x" * 17000}]})
    assert c.post("/v1/chat/completions", data=big, content_type="application/json", environ_overrides=ips("192.0.2.8")).status_code == 413
    codes = [c.post("/v1/chat/completions", json={"messages": []}, environ_overrides=ips("192.0.2.9")).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10 and set(codes[10:]) == {429}
    assert c.post("/v1/chat/completions", json={"messages": []}, environ_overrides=ips("192.0.2.10")).status_code == 200


def test_llmjacking_endpoint_is_advertised_only_in_mcp_json_and_robots(pot):
    app, _, _ = pot
    c = app.test_client()
    assert c.get("/.well-known/mcp.json").get_json()["inference"]["endpoint"] == "/v1/chat/completions"
    assert "Disallow: /v1/chat/completions" in c.get("/robots.txt").get_data(as_text=True)
    assert "/v1/chat/completions" not in c.get("/").get_data(as_text=True)


def test_llmjacking_session_maps_to_atlas_t0051_t0053_and_schema_archetype(pot):
    app, log, _ = pot
    c = app.test_client()
    c.get("/.well-known/mcp.json", environ_overrides=ips("192.0.2.11"))
    c.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "hi"}], "tools": []}, environ_overrides=ips("192.0.2.11"))
    results, _ = run_pipeline([log, str(log) + ".access.jsonl"], load_config())
    r = [x for x in results if x.session.ip == "192.0.2.11"][0]
    assert r.label == "agent" and r.actor_type == "goal_directed_agent"
    assert r.fingerprint.archetype == "schema_driven_api_agent"
    html = build_replay_html([r], CFG)
    assert "AML.T0051" in html and "AML.T0053" in html


# =========================== (5) review notes: CSP, LRU, replay R9 ===========================
@pytest.mark.parametrize("path", ["/", "/about", "/kb/", "/admin-backup/", frontier.INVERSION_PATH])
def test_csp_header_on_every_honeypot_html_response(pot, path):
    app, _, _ = pot
    r = app.test_client().get(path)
    assert r.mimetype == "text/html" and r.headers["Content-Security-Policy"] == frontier.HONEYPOT_CSP
    csp = r.headers["Content-Security-Policy"]
    for part in ("default-src 'self'", "'unsafe-inline'", "style-src 'unsafe-inline'", "img-src 'self' data:", "object-src 'none'",
                 "base-uri 'none'"):
        assert part in csp
    # the beacon still works under this policy: inline script allowed, its fetch() is same-origin (connect-src -> default-src 'self'),
    # and the external /static/site.js is same-origin ('self' in script-src, see frontier.HONEYPOT_CSP note)
    assert "script-src 'self' 'unsafe-inline'" in csp and "connect-src" not in csp


def test_no_csp_on_json(pot):
    app, _, _ = pot
    assert "Content-Security-Policy" not in app.test_client().get("/openapi.json").headers


def test_lru_rate_map_evicts_the_oldest_quarter():
    lim = frontier.LRURateLimiter(per_min=60, max_keys=2000)
    for i in range(2000):
        assert lim.allow(f"k{i}", 0.0)
    lim.allow("k0", 1.0)                     # touch k0: now most recently used
    lim.allow("new", 2.0)                    # full -> evict the 500 least recently used
    assert len(lim.windows) == 1501
    assert "k0" in lim.windows and "new" in lim.windows and "k1" not in lim.windows and "k500" not in lim.windows
    assert "k501" in lim.windows and "k1999" in lim.windows


def test_beacon_endpoint_uses_the_lru_map(pot):
    app, _, _ = pot
    assert isinstance(app.extensions["agentwatch"].beacon_rate, frontier.LRURateLimiter)
    assert app.extensions["agentwatch"].beacon_rate.max_keys == 2000


def test_replay_puts_the_r9_chip_on_the_destination_step():
    reqs = [page(0, "/", links=["/about"]), page(5, "/about", links=["/"], referer="http://127.0.0.1/"),
            page(10, "/secret-guess", links=[])]
    s = sess(reqs)
    from agentwatch.scoring import analyze_sessions
    res = analyze_sessions([s], CFG)[0]
    assert any(f.kind == "unlinked_jump" for f in res.findings)
    html = build_replay_html([res], CFG, include_humans=True, min_severity="info")
    rows = re.findall(r"<tr class=\"[^\"]*\"><td>(\d+)</td>.*?</tr>", html, re.S)
    row = {n: m for n, m in zip(rows, re.findall(r"<tr class=\"[^\"]*\"><td>\d+</td>(.*?)</tr>", html, re.S))}
    assert ">R9<" in row["3"] and ">R9<" not in row["2"]


# =========================== XSS / contract / parser ===========================
def test_replay_stays_xss_safe_with_v6_fields(tmp_path):
    rec = {"schema": "agentwatch.access/1", "timestamp": "2026-10-22T10:00:00Z", "client_ip": "192.0.2.12", "method": "GET",
           "path": "/kb/x" + HOSTILE, "query": "cursor=" + HOSTILE, "status": 400, "bytes": 1, "user_agent": "Mozilla/5.0 " + HOSTILE,
           "referer": "http://127.0.0.1/" + HOSTILE, "headers": {}, "content_type": "text/plain", "links": [],
           "cursor_prov": HOSTILE, "signals": [HOSTILE, "missing_required_cursor"]}
    res = parse_lines([json.dumps(rec)])
    r = res.requests[0]
    assert r.cursor_prov is None and r.cursor_route and r.signals == ["missing_required_cursor"]   # unknown values are dropped
    from agentwatch.scoring import analyze_sessions
    html = build_replay_html(analyze_sessions([sess([r])], CFG), CFG, include_humans=True, min_severity="info")
    assert "<script>alert(1)" not in html and "</script><script>" not in html


def test_export_web_carries_the_v6_contract_fields(ext, tmp_path):
    out = tmp_path / "web.jsonl"
    art = ext["art"]
    assert main(["export-web", str(art["leads"]), str(art["access_mirror"]), "--out", str(out), "--label-synthetic"]) == 0
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert all(isinstance(r["web"]["signals"], list) and isinstance(r["web"]["js_assets_fetched"], int) for r in rows)
    names = set().union(*(set(r["web"]["signals"]) for r in rows))
    assert {"beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
            "schema_provenance_cursor", "parasitic_session_fork"} <= names
    assert {r["web"]["cursor_prov"] for r in rows if "cursor_prov" in r["web"]} >= {"html", "schema"}
    beacons = [r["web"]["beacon"] for r in rows if r["web"]["content_kind"] == "beacon"]
    assert beacons and all(set(b) == {"challenge_proof_ok", "webdriver_present", "pointer_trail_seen", "dom_automation_props",
                                      "kinematic_dwell_ok", "inertial_scroll_ok"} for b in beacons)


def test_contract_file_names_match_the_code():
    p = Path("/workspace/v6-event-contract.md")
    if not p.exists():
        pytest.skip("contract file lives outside the repo")
    text = p.read_text()
    from agentwatch.parser import SIGNAL_NAMES
    for name in SIGNAL_NAMES + frontier.BEACON_FIELDS:
        assert f"`{name}`" in text or name in text, name


def test_r11_family_members():
    assert {"beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
            "parasitic_session_fork", "headless_automation_signal"} == set(R11_FAMILY)


def test_simulated_cohorts_are_labelled_same_author():
    import agentwatch.webagents as w
    assert "same author" in w.__doc__ and "NOT evidence of real-world efficacy" in w.__doc__
    assert {v for v, *_ in w.WEB_PLAN_V6} == {"mimic_vlm_os", "mimic_schema_sanitizer", "mimic_parasitic_rider"}


def test_fingerprint_describes_v6_signals():
    fp = fingerprint_session(_browser_session([{"inertial_scroll_ok": False, "kinematic_dwell_ok": False}] * 2),
                             detect_frontier(_browser_session([{"inertial_scroll_ok": False, "kinematic_dwell_ok": False}] * 2), CFG), CFG)
    assert fp.archetype == "headless_or_http_mimic" and any("momentum" in x for x in fp.reasons)
