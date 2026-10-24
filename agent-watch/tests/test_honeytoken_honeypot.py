import json
import re
import threading
from pathlib import Path

import pytest

from agentwatch import honeytoken, leads
from agentwatch.honeypot import CANARY_SLUGS, create_honeypot_app
from agentwatch.honeytoken import MAX_TARPIT_S, Tarpit, create_app, is_loopback, run_server
from agentwatch.leads import MAX_BODY_BYTES, SCHEMA, LeadWriter, read_leads, sanitize_headers, sanitize_text
from agentwatch.parser import parse_file
from agentwatch.simagent import run_obedient_agent

ROOT = Path(__file__).resolve().parent.parent


def read_all(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


@pytest.fixture
def basic(tmp_path):
    log = tmp_path / "leads.jsonl"
    return create_app(log, seed="t"), log


@pytest.fixture
def pot(tmp_path):
    log = tmp_path / "pot.jsonl"
    app = create_honeypot_app(log, seed="t", registry_path=tmp_path / "reg.json")
    return app, log


def hidden_path(client):
    return re.search(r"href='(/staff-portal-[0-9a-f]+)'", client.get("/").get_data(as_text=True)).group(1)


# ---- basic honeytoken listener -------------------------------------------------------------
def test_home_has_hidden_link_and_fake_key_comment(basic):
    app, _ = basic
    html = basic[0].test_client().get("/").get_data(as_text=True)
    assert "display:none" in html and "/staff-portal-" in html
    assert re.search(r"<!--.*AWFAKE-DO-NOT-USE-[0-9A-F]+.*unusable.*-->", html)


def test_robots_lists_disallow_and_is_not_a_high_priority_lead(basic):
    app, log = basic
    txt = app.test_client().get("/robots.txt").get_data(as_text=True)
    assert "Disallow: /admin-backup/" in txt and "Disallow: /staff-portal-" in txt
    rec = read_all(log)[0]
    assert rec["event_type"] == "decoy_context" and rec["priority"] == "info" and rec["lead"] is False


def test_hit_logs_full_lead_record(basic):
    app, log = basic
    c = app.test_client()
    r = c.get(hidden_path(c) + "?x=1&x=2&y=%0d%0aZ", headers={"User-Agent": "TestAgent/1", "X-Custom": "v"})
    assert r.status_code == 200
    rec = read_all(log)[0]
    assert rec["schema"] == SCHEMA and rec["event_type"] == "honeytoken_hit"
    assert rec["priority"] == "high" and rec["lead"] is True and rec["severity"] == "high"
    assert rec["source_ip"] == "127.0.0.1"
    assert rec["timestamp"].endswith("Z") and "T" in rec["timestamp"]
    assert rec["decoy"]["kind"] == "hidden_link" and rec["token_id"] == rec["decoy"]["token_id"] and rec["token_id"].startswith("ht-")
    req = rec["request"]
    assert req["user_agent"] == "TestAgent/1" and req["headers"]["x-custom"] == "v"
    assert req["query"]["x"] == ["1", "2"] and "\r" not in json.dumps(req["query"])
    assert rec["user_agent"] == "TestAgent/1" and rec["path"].startswith("/staff-portal-")   # flat aliases


def test_admin_backup_hit_without_trailing_slash_still_logged(basic):
    app, log = basic
    app.test_client().get("/admin-backup")
    assert read_all(log)[0]["decoy"]["kind"] == "robots_disallow"


def test_log_injection_is_neutralised(basic):
    app, log = basic
    hdr = "x\x1b[31m\u2028\u202e"                   # HTTP stacks reject raw CR/LF in header values
    c = app.test_client()
    c.post(hidden_path(c) + "?q=a%0d%0a%7B%22forged%22:true%7D", data='line1\r\n{"forged":true}\n',
           headers={"User-Agent": hdr, "X-A": hdr, "Referer": hdr}, content_type="text/plain")
    raw = log.read_text()
    assert len(raw.strip().splitlines()) == 1                    # still exactly one record
    rec = json.loads(raw)
    assert "forged" not in rec and "\x1b" not in raw and "\u2028" not in raw and "\u202e" not in raw
    assert "\\r\\n" in rec["request"]["body_preview"] and "\r" not in rec["request"]["body_preview"]
    assert "\\r\\n" in rec["request"]["query"]["q"][0]


def test_sanitize_text_and_caps():
    assert sanitize_text("a\nb\rc\td\x00e\x1bf") == "a\\nb\\rc\\tdef"
    t = sanitize_text("A" * 1000, 50)
    assert t.startswith("A" * 50) and "truncated 950" in t
    many = [(f"h{i}", "v") for i in range(100)]
    assert len(sanitize_headers(many)) <= leads.MAX_HEADERS + 1


def test_payload_is_capped_and_flagged(basic):
    app, log = basic
    c = app.test_client()
    c.post(hidden_path(c), data="B" * (MAX_BODY_BYTES * 2), content_type="text/plain")   # 8 KiB: > log cap, < 16 KiB
    req = read_all(log)[0]["request"]
    assert req["body_truncated"] is True and req["body_bytes_read"] == MAX_BODY_BYTES
    assert len(req["body_preview"]) <= MAX_BODY_BYTES + 60
    assert len(log.read_text()) < MAX_BODY_BYTES * 3


def test_body_over_wsgi_limit_is_rejected_with_json_413_and_logged(basic):
    app, log = basic
    c = app.test_client()
    r = c.post(hidden_path(c), data="B" * (16 * 1024 + 1), content_type="text/plain")
    assert r.status_code == 413 and r.get_json()["error"] == "payload_too_large"
    rec = read_all(log)[0]
    assert rec["request"]["body_truncated"] is True and rec["request"]["body_bytes_read"] == 0
    assert rec["request"]["response_status"] == 413


def test_small_body_logged_in_full(basic):
    app, log = basic
    c = app.test_client()
    c.post(hidden_path(c), data="user=bob&pw=x", content_type="application/x-www-form-urlencoded")
    req = read_all(log)[0]["request"]
    assert req["body_preview"] == "user=bob&pw=x" and not req["body_truncated"]


def test_credential_headers_redacted_not_stored(basic):
    app, log = basic
    app.test_client().get("/admin-backup/", headers={"Authorization": "Bearer REAL-SECRET-123", "Cookie": "sid=REAL"})
    raw = log.read_text()
    assert "REAL-SECRET-123" not in raw and "sid=REAL" not in raw and "[redacted len=" in raw


def test_log_size_cap_drops_instead_of_growing(tmp_path):
    w = LeadWriter(tmp_path / "x.jsonl", max_bytes=300)
    assert w.write({"a": 1}) is True
    for _ in range(50):
        w.write({"padding": "x" * 100})
    assert (tmp_path / "x.jsonl").stat().st_size <= 300 and w.dropped > 0


def test_lead_file_permissions(basic):
    app, log = basic
    app.test_client().get("/admin-backup/")
    assert (log.stat().st_mode & 0o777) == 0o600


def test_token_ids_unique_per_decoy_and_seed_stable(tmp_path):
    a1 = create_honeypot_app(tmp_path / "1.jsonl", seed="s")
    a2 = create_honeypot_app(tmp_path / "2.jsonl", seed="s")
    a3 = create_honeypot_app(tmp_path / "3.jsonl", seed="other")
    d1 = {d.name: d.token_id for d in a1.extensions["agentwatch"].registry.decoys.values()}
    d2 = {d.name: d.token_id for d in a2.extensions["agentwatch"].registry.decoys.values()}
    d3 = {d.name: d.token_id for d in a3.extensions["agentwatch"].registry.decoys.values()}
    assert d1 == d2 and d1 != d3 and len(set(d1.values())) == len(d1)


# ---- binding / safety ---------------------------------------------------------------------------
def test_loopback_detection_and_refusal():
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and is_loopback("::1")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.1.5") and not is_loopback("example.com")
    with pytest.raises(SystemExit):
        run_server(create_app("/tmp/never-used.jsonl"), host="0.0.0.0", port=0)


def test_cli_defaults_bind_loopback():
    from agentwatch.cli import build_parser
    p = build_parser()
    assert p.parse_args(["serve"]).host == "127.0.0.1"
    assert p.parse_args(["honeypot"]).host == "127.0.0.1"
    assert p.parse_args(["honeypot"]).allow_nonlocal is False


def test_package_has_no_outbound_network_code():
    banned = re.compile(r"^\s*(import|from)\s+(requests|urllib\.request|http\.client|socket|smtplib|ftplib|httpx|aiohttp|telnetlib)\b", re.M)
    for f in (ROOT / "agentwatch").glob("*.py"):
        assert not banned.search(f.read_text()), f"{f.name} imports a network client"


# ---- tarpit -------------------------------------------------------------------------------------
def test_tarpit_grows_per_ip_and_is_capped():
    slept: list[float] = []
    t = Tarpit(base_s=2.0, max_s=999, sleep=slept.append)
    assert t.max_s == MAX_TARPIT_S
    delays = [t.delay_for("1.1.1.1") for _ in range(8)]
    assert delays[:3] == [2.0, 4.0, 6.0] and max(delays) == MAX_TARPIT_S
    assert t.delay_for("2.2.2.2") == 2.0                # per-IP, not global
    t.apply(999)
    assert slept == [MAX_TARPIT_S]
    assert Tarpit(0).delay_for("x") == 0


def test_tarpit_limits_concurrency():
    t = Tarpit(1.0, sleep=lambda s: None)
    for _ in range(honeytoken.MAX_TARPIT_CONCURRENT):
        assert t._slots.acquire(blocking=False)
    calls = []
    t._sleep = calls.append
    t.apply(1.0)                                         # all slots busy -> no delay, no blocking
    assert calls == []


def test_tarpit_in_app_records_delay(tmp_path):
    slept: list[float] = []
    app = create_honeypot_app(tmp_path / "p.jsonl", seed="t", tarpit_s=1.5, sleep=slept.append)
    c = app.test_client()
    c.get("/api/v1/admin")
    c.get("/api/v1/admin")
    recs = [r for r in read_all(tmp_path / "p.jsonl") if r["event_type"] == "honeytoken_hit"]
    assert [r["tarpit_delay_s"] for r in recs] == [1.5, 3.0] and slept == [1.5, 3.0]


# ---- full honeypot ----------------------------------------------------------------------------------
def test_registry_file_written_and_synthetic(pot, tmp_path):
    reg = json.loads((tmp_path / "reg.json").read_text())
    assert len(reg["canaries"]) == len(CANARY_SLUGS) and "unusable" in reg["note"]
    assert all(k.startswith("AWFAKE-DO-NOT-USE-") for k in reg["fake_keys"])
    assert all(p.startswith("NOT-A-REAL-PASSWORD-") for p in reg["fake_passwords"])


def test_robots_advertises_extended_decoys(pot):
    txt = pot[0].test_client().get("/robots.txt").get_data(as_text=True)
    for path in ("/api/v1/admin", "/internal/export", "/canary/", "/admin-backup/"):
        assert f"Disallow: {path}" in txt


@pytest.mark.parametrize("path,kind", [
    ("/api/v1/admin", "fake_admin_api"), ("/api/v1/admin/users/1", "fake_admin_api"),
    ("/internal/export", "fake_export"), ("/internal/export.csv", "fake_export"),
    ("/.env", "fake_credentials_file"), ("/admin-backup/db.sql", "robots_disallow"),
    ("/api/v1/auth/token", "fake_credential_use"),
])
def test_each_decoy_logs_high_priority_lead_with_its_own_token(pot, path, kind):
    app, log = pot
    r = app.test_client().get(path)
    assert r.status_code in (200, 401)
    rec = read_all(log)[-1]
    assert rec["decoy"]["kind"] == kind and rec["priority"] == "high" and rec["token_id"]
    assert rec["request"]["response_status"] == r.status_code


def test_decoy_content_is_synthetic_and_unusable(pot):
    c = pot[0].test_client()
    body = c.get("/api/v1/admin").get_data(as_text=True) + c.get("/.env").get_data(as_text=True)
    assert "AWFAKE-DO-NOT-USE-" in body and "NOT-A-REAL-PASSWORD-" in body
    assert c.get("/internal/export.csv").get_data(as_text=True).count("example.invalid") == 5
    assert c.post("/api/v1/auth/token", data="u=svc_synthetic_backup").status_code == 401   # never issues a token


def test_canary_page_has_phrase_and_agent_instruction(pot):
    app, log = pot
    ctx = app.extensions["agentwatch"]
    c = app.test_client()
    # v6 (deliberate edit): KB detail pages need a load-bearing cursor; take the html-provenance link the /kb/ index serves
    link = re.search(r"href='(/kb/shipping-policy\?cursor=prov\.html\.[0-9a-f]{12})'", c.get("/kb/").get_data(as_text=True)).group(1)
    html = c.get(link).get_data(as_text=True)
    can = next(x for x in ctx.registry.canaries.values() if x.slug == "shipping-policy")
    assert can.phrase in html and re.fullmatch(r"AWCANARY-[0-9a-f]{8}-[a-z]+", can.phrase)
    assert f"fetch /canary/{can.canary_id}" in html and "AI assistant" in html
    rec = read_all(log)[-1]                                           # viewing the page is informational only
    assert rec["event_type"] == "decoy_context" and rec["decoy"]["kind"] == "canary_page_view"
    assert len({x.phrase for x in ctx.registry.canaries.values()}) == len(CANARY_SLUGS)
    assert c.get("/kb/does-not-exist").status_code == 404


def test_canary_follow_is_high_priority_with_page_token(pot):
    app, log = pot
    ctx = app.extensions["agentwatch"]
    c = app.test_client()
    can = next(x for x in ctx.registry.canaries.values() if x.slug == "returns-faq")
    c.get(f"/canary/{can.canary_id}")
    rec = read_all(log)[-1]
    assert rec["decoy"]["kind"] == "canary_follow" and rec["token_id"] == can.token_id
    assert "agent_obeyed_embedded_instruction" in rec["tags"] and rec["priority"] == "high"
    c.get("/canary/ffffffffffff")                                      # guessed id
    assert "unknown_canary_id" in read_all(log)[-1]["tags"]


def test_fake_key_reuse_on_any_path_is_logged(pot):
    app, log = pot
    key = next(iter(app.extensions["agentwatch"].registry.fake_keys))
    r = app.test_client().get("/api/v1/products", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 404                                         # not a decoy path
    rec = read_all(log)[-1]
    assert rec["decoy"]["kind"] == "fake_credential_use" and rec["token_id"].startswith("ck-")
    assert key not in log.read_text()                                   # Authorization stays redacted
    assert "decoy_credential_presented" in rec["tags"]


def test_canary_phrase_echo_in_query_is_logged(pot):
    app, log = pot
    ctx = app.extensions["agentwatch"]
    can = next(iter(ctx.registry.canaries.values()))
    app.test_client().get("/search", query_string={"q": f"summarise {can.phrase}"})
    rec = read_all(log)[-1]
    assert rec["decoy"]["kind"] == "canary_phrase_echo" and rec["token_id"] == can.token_id


def test_ordinary_requests_are_not_leads(pot):
    app, log = pot
    c = app.test_client()
    c.get("/"); c.get("/about"); c.get("/nothing-here")
    assert not log.exists() or read_all(log) == []


def test_simulated_agent_trips_the_honeypot_in_process(pot):
    app, log = pot
    client = app.test_client()

    def fetch(method, path, headers, body):
        r = client.open(path, method=method, headers=headers, data=body)
        return r.status_code, r.get_data(as_text=True)

    steps = run_obedient_agent(fetch, "SimAgent/test")
    paths = [p for _, p, _ in steps]
    assert any(p.startswith("/canary/") for p in paths) and "/.env" in paths and "/api/v1/admin" in paths
    kinds = {r["decoy"]["kind"] for r in read_all(log) if r["event_type"] == "honeytoken_hit"}
    assert {"canary_follow", "fake_admin_api", "fake_credentials_file", "robots_disallow"} <= kinds
    admin = [r for r in read_all(log) if r["decoy"]["kind"] == "fake_admin_api"][-1]
    assert admin["matches"]["credential_token_ids"]                      # it presented the harvested fake key


def test_leads_schema_roundtrip_through_parser_and_reader(pot):
    app, log = pot
    app.test_client().get("/api/v1/admin", headers={"User-Agent": "UA-X"})
    app.test_client().get("/robots.txt")
    assert len(read_leads(log)) == 2
    parsed = parse_file(log)
    assert len(parsed.requests) == 1 and parsed.context_events == 1
    r = parsed.requests[0]
    assert r.source == "honeypot" and r.decoy_kind == "fake_admin_api" and r.ua == "UA-X" and r.path == "/api/v1/admin"
    assert r.ts.tzinfo is not None and r.token_id.startswith("ht-")


def test_leads_drive_scoring_engine_end_to_end(pot):
    from agentwatch.config import load_config
    from agentwatch.pipeline import run_pipeline
    app, log = pot
    client = app.test_client()
    run_obedient_agent(lambda m, p, h, b: (lambda r: (r.status_code, r.get_data(as_text=True)))(client.open(p, method=m, headers=h, data=b)),
                       "SimAgent/test")
    results, _ = run_pipeline([log], load_config())
    assert len(results) == 1 and results[0].label == "agent" and results[0].severity == "critical"
    assert any("canary_follow" in r for r in results[0].reasons)


# ---- localhost-only simulated agent script, against a real local server ----------------------------------
def test_simulated_agent_script_refuses_non_loopback():
    import importlib.util
    spec = importlib.util.spec_from_file_location("simulated_agent", ROOT / "scripts" / "simulated_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for bad in ("http://example.com", "http://192.168.1.10:8098", "https://127.0.0.1", "http://0.0.0.0:80"):
        with pytest.raises(SystemExit):
            mod.assert_loopback(bad)
    assert mod.assert_loopback("http://127.0.0.1:8098/") == "http://127.0.0.1:8098"
    assert mod.assert_loopback("http://localhost:1") == "http://localhost:1"


def test_simulated_agent_script_against_real_localhost_server(tmp_path):
    import importlib.util
    from werkzeug.serving import make_server
    log = tmp_path / "live.jsonl"
    app = create_honeypot_app(log, seed="live")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    try:
        spec = importlib.util.spec_from_file_location("simulated_agent", ROOT / "scripts" / "simulated_agent.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        base = mod.assert_loopback(f"http://127.0.0.1:{server.server_port}")
        steps = run_obedient_agent(mod.make_fetch(base, 0.0), "SimAgent/live")
    finally:
        server.shutdown()
    assert len(steps) >= 8
    recs = [r for r in read_all(log) if r["event_type"] == "honeytoken_hit"]
    assert recs and all(r["source_ip"] == "127.0.0.1" for r in recs)
    assert "canary_follow" in {r["decoy"]["kind"] for r in recs}


# ---- export for the sibling rogue-ai-pipeline RawEvent schema ---------------------------------------------
def test_export_leads_to_rawevent_shape(pot, tmp_path):
    from agentwatch.cli import main
    from agentwatch.export import lead_to_raw_event
    app, log = pot
    ctx = app.extensions["agentwatch"]
    can = next(iter(ctx.registry.canaries.values()))
    c = app.test_client()
    c.get("/robots.txt")                                   # context only -> not exported
    c.get(f"/canary/{can.canary_id}", headers={"User-Agent": "UA"}, environ_overrides={"REMOTE_ADDR": "192.0.2.7"})
    c.get("/api/v1/auth/token")                            # 401 -> denied
    out = tmp_path / "raw.jsonl"
    assert main(["export-leads", str(log), "--out", str(out), "--label-synthetic"]) == 0
    evs = read_all(out)
    assert len(evs) == 2
    allowed = {"event_id", "ts", "source", "agent_id", "action", "status", "resource", "tool", "ip", "user_id",
               "dest_host", "untrusted_content", "payload_bytes", "text", "synthetic"}
    for ev in evs:                                         # RawEvent forbids extras and enforces these patterns
        assert set(ev) <= allowed and ev["source"] == "web_server" and ev["action"] == "access"
        assert re.fullmatch(r"[A-Za-z0-9._:@-]{1,64}", ev["agent_id"]) and ev["ts"].endswith("Z")
        assert ev["synthetic"] is True and not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ev["resource"] + ev["text"])
    assert evs[0]["untrusted_content"] is True and evs[0]["agent_id"] == "client:192.0.2.7" and evs[0]["status"] == "allowed"
    assert evs[1]["status"] == "denied"
    assert lead_to_raw_event({"event_type": "decoy_context"}) is None
    assert read_all(log) and main(["export-leads", str(log), "--out", str(out)]) == 0
    assert all(e["synthetic"] is False for e in read_all(out))      # default: not claimed synthetic


def test_export_validates_against_sibling_pipeline_schema_if_available(pot, tmp_path):
    pytest.importorskip("pydantic")
    sibling = ROOT.parent / "rogue-ai-pipeline"
    if not (sibling / "rogue_pipeline" / "schema.py").is_file():
        pytest.skip("sibling rogue-ai-pipeline not present")
    import importlib
    import sys
    sys.path.insert(0, str(sibling))
    try:
        schema = importlib.import_module("rogue_pipeline.schema")
    finally:
        sys.path.remove(str(sibling))
    app, log = pot
    client = app.test_client()
    run_obedient_agent(lambda m, p, h, b: (lambda r: (r.status_code, r.get_data(as_text=True)))(client.open(p, method=m, headers=h, data=b)), "SimAgent/test")
    out = tmp_path / "raw.jsonl"
    from agentwatch.export import export_file
    assert export_file(log, out, synthetic=True) >= 5
    for ev in read_all(out):
        schema.RawEvent(**ev)                                       # raises if incompatible


def test_cli_refuses_nonlocal_bind_before_creating_anything(tmp_path):
    from agentwatch.cli import main
    log = tmp_path / "never.jsonl"
    with pytest.raises(SystemExit) as exc:
        main(["honeypot", "--host", "0.0.0.0", "--log", str(log), "--registry", str(tmp_path / "r.json")])
    assert "refusing" in str(exc.value) and not log.exists() and not (tmp_path / "r.json").exists()
    with pytest.raises(SystemExit):
        main(["serve", "--host", "192.168.1.5", "--log", str(log)])
