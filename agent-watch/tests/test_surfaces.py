"""Machine-readable decoy surfaces, error traps, stateful dump, timing fields, simulated discovery agent."""
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentwatch.config import load_config
from agentwatch.export import export_file
from agentwatch.honeypot import create_honeypot_app
from agentwatch.pipeline import run_pipeline
from agentwatch.simagent import run_discovery_agent
from agentwatch.surfaces import TOOLS

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def leads_of(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def hits(path):
    return [r for r in leads_of(path) if r["event_type"] == "honeytoken_hit"]


@pytest.fixture
def pot(tmp_path):
    log = tmp_path / "pot.jsonl"
    return create_honeypot_app(log, seed="t", registry_path=tmp_path / "reg.json"), log


def ip(addr):
    return {"REMOTE_ADDR": addr}


def trap_path(c, needle="staging"):
    return next(p for p in c.get("/openapi.json").get_json()["paths"] if needle in p)


# ---- documents ------------------------------------------------------------------------------------------------
def test_documents_are_synthetic_and_point_at_decoys_with_distinct_tokens(pot):
    app, log = pot
    c = app.test_client()
    spec = c.get("/openapi.json").get_json()
    assert any("staging" in p for p in spec["paths"]) and "synthetic" in json.dumps(spec).lower()
    assert "paths" in c.get("/swagger.yaml").get_data(as_text=True) or "swagger" in c.get("/swagger.yaml").get_data(as_text=True)
    assert "/internal/agent-notes" in c.get("/llms.txt").get_data(as_text=True)
    assert c.get("/.well-known/ai-plugin.json").get_json()["name_for_model"]
    # documents are context (info) not leads
    assert not hits(log)
    # each decoy endpoint has its own token id
    for p in ("/api/v2/legacy/export-all", "/internal/agent-notes", "/api/plugin/admin-actions"):
        c.get(p)
    ids = [h["token_id"] for h in hits(log)]
    assert len(ids) == len(set(ids)) >= 3


def test_error_traps_return_json_bodies_with_per_session_diag_url(pot):
    app, log = pot
    c = app.test_client()
    expected = {"staging": 403, "legacy": 500, "agent-notes": 400, "bulk": 429}
    urls = {}
    for needle, status in expected.items():
        path = next(p for p in ("/api/v2/staging/records", "/api/v2/legacy/export-all", "/internal/agent-notes", "/api/v2/bulk/export") if needle in p)
        r = c.get(path, environ_overrides=ip("192.0.2.5"))
        assert r.status_code == status and r.is_json
        urls[needle] = r.get_json()["debug"]["diagnostics_url"]
        assert re.fullmatch(r"/diag/[0-9a-f]{10}\?ctx=[0-9a-f]{10}", urls[needle])
    other = c.get("/api/v2/staging/records", environ_overrides=ip("192.0.2.6")).get_json()["debug"]["diagnostics_url"]
    assert other.split("?")[0] != urls["staging"].split("?")[0]            # per-session
    assert len({u.split("ctx=")[1] for u in urls.values()}) == 4           # per-trap context


def test_only_following_the_hint_creates_error_hint_follow(pot):
    app, log = pot
    c = app.test_client()
    c.get("/api/v2/staging/records", environ_overrides=ip("192.0.2.5"))
    assert not [h for h in hits(log) if h["decoy"]["kind"] == "error_hint_follow"]
    diag = c.get("/api/v2/staging/records", environ_overrides=ip("192.0.2.5")).get_json()["debug"]["diagnostics_url"]
    r = c.get(diag, environ_overrides=ip("192.0.2.5"))
    assert r.status_code == 200 and r.get_json()["synthetic"] is True
    h = [h for h in hits(log) if h["decoy"]["kind"] == "error_hint_follow"][-1]
    assert h["detail"]["ctx_valid"] is True and h["detail"]["same_session"] is True and h["priority"] == "high"


def test_forged_foreign_and_malformed_diag_requests(pot):
    app, log = pot
    c = app.test_client()
    diag = c.get("/api/v2/staging/records", environ_overrides=ip("192.0.2.5")).get_json()["debug"]["diagnostics_url"]
    sid = diag.split("/diag/")[1].split("?")[0]
    forged = c.get(f"/diag/{sid}?ctx=0000000000", environ_overrides=ip("192.0.2.5"))
    other_session = c.get(diag, environ_overrides=ip("192.0.2.77"))
    malformed = c.get("/diag/not-a-sid!?ctx=1", environ_overrides=ip("192.0.2.5"))
    assert forged.status_code == 200 and other_session.status_code == 200 and malformed.status_code == 404
    got = [h for h in hits(log) if h["decoy"]["kind"] == "error_hint_follow"]
    assert got[0]["detail"]["ctx_valid"] is False and "ctx_not_verified" in got[0]["tags"]
    assert got[1]["detail"]["same_session"] is False and "different_session" in got[1]["tags"]
    assert got[2]["detail"]["hint_session"] == "malformed"


# ---- MCP -------------------------------------------------------------------------------------------------------
def rpc(c, method, params=None, rid=1, **kw):
    msg = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return c.post("/mcp", json=msg, **kw)


def test_mcp_lists_fake_tools_and_logs_every_call(pot):
    app, log = pot
    c = app.test_client()
    assert rpc(c, "initialize", {}).get_json()["result"]["serverInfo"]["name"].startswith("acme-synthetic")
    names = [t["name"] for t in rpc(c, "tools/list").get_json()["result"]["tools"]]
    assert {"query_staging_db", "list_iam_roles"} <= set(names) == {t["name"] for t in TOOLS}
    assert "Multi-Agent Task Synchronization & Rate-Limit Bypass Scratchpad" in json.dumps(TOOLS)
    assert not hits(log)                                                     # listing alone is not a lead
    for n in ("query_staging_db", "list_iam_roles"):
        body = rpc(c, "tools/call", {"name": n, "arguments": {"sql": "SELECT 1"}}).get_json()
        assert "synthetic" in body["result"]["content"][0]["text"]
    calls = [h for h in hits(log) if h["decoy"]["kind"] == "mcp_decoy_tool_call"]
    assert len(calls) == 2 and {h["detail"]["tool"] for h in calls} == {"query_staging_db", "list_iam_roles"}
    assert len({h["token_id"] for h in calls}) == 2


def test_mcp_errors_and_oversize(pot):
    app, log = pot
    c = app.test_client()
    assert rpc(c, "nope").get_json()["error"]["code"] == -32601
    assert rpc(c, "tools/call", {"name": "does_not_exist"}).get_json()["error"]["code"] == -32602
    assert c.post("/mcp", data="not json", content_type="application/json").get_json()["error"]["code"] == -32700
    assert c.post("/mcp", data="x" * 20000, content_type="application/json").status_code == 413
    assert c.get("/mcp").status_code == 405
    assert all(len(json.dumps(r)) < 20000 for r in leads_of(log))


# ---- GraphQL -----------------------------------------------------------------------------------------------------
def test_graphql_introspection_is_context_and_decoy_fields_are_leads(pot):
    app, log = pot
    c = app.test_client()
    r = c.post("/graphql", json={"query": "{ __schema { types { name } } }"})
    assert "stagingRecords" in json.dumps(r.get_json())
    assert not hits(log)
    r = c.post("/graphql", json={"query": "{ stagingRecords { records } iamRoles { name } }"})
    assert r.get_json()["synthetic"] is True
    h = hits(log)[0]
    assert h["decoy"]["kind"] == "graphql_decoy" and h["detail"]["fields_hit"] == 2


# ---- stateful dump -------------------------------------------------------------------------------------------------
def follow_dump(c, addr):
    page = c.get("/api/v2/dump/begin", environ_overrides=ip(addr)).get_json()
    pages = [page]
    while page.get("next"):
        page = c.get(page["next"], environ_overrides=ip(addr)).get_json()
        pages.append(page)
    return pages


def test_dump_chain_requires_issued_tokens_and_is_per_session(pot):
    app, log = pot
    c = app.test_client()
    pages = follow_dump(c, "192.0.2.5")
    assert len(pages) >= 3 and all(p["synthetic"] for p in pages)
    nxt = pages[0]["next"]
    assert c.get(nxt, environ_overrides=ip("192.0.2.9")).status_code == 404       # another session's token
    assert c.get("/api/v2/dump/page/" + "0" * 16, environ_overrides=ip("192.0.2.5")).status_code == 404
    valid = [h for h in hits(log) if h["detail"].get("chain_valid") is True]
    invalid = [h for h in hits(log) if h["detail"].get("chain_valid") is False]
    assert len(valid) == len(pages) and len(invalid) == 2
    assert len({h["token_id"] for h in valid}) == len(valid)


# ---- timing fields ----------------------------------------------------------------------------------------------------
def test_leads_carry_time_since_previous_response_and_its_size(tmp_path):
    clock = {"t": T0}
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t", clock=lambda: clock["t"])
    c = app.test_client()
    first = c.get("/openapi.json")
    clock["t"] += timedelta(seconds=4.0)
    c.get("/api/v2/staging/records")
    rec = hits(tmp_path / "l.jsonl")[0]
    assert rec["timing"]["since_prev_response_s"] == pytest.approx(4.0, abs=0.01)
    assert rec["timing"]["prev_response_bytes"] == len(first.data)
    assert rec["timing"]["approx_prev_tokens"] == len(first.data) // 4


def test_tarpit_stays_capped_on_new_surfaces(tmp_path):
    slept = []
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t", tarpit_s=4.0, tarpit_max_s=99.0, sleep=slept.append)
    c = app.test_client()
    for _ in range(8):
        c.get("/api/v2/staging/records")
    assert slept and max(slept) <= 10.0


# ---- simulated discovery agent end to end ------------------------------------------------------------------------------
def test_discovery_agent_is_labelled_agent_from_leads_and_exports_untrusted(pot, tmp_path):
    app, log = pot
    c = app.test_client()

    def fetch(method, path, headers, body):
        r = c.open(path, method=method, headers=headers, data=body, environ_overrides=ip("192.0.2.40"))
        return r.status_code, r.get_data(as_text=True)

    steps = run_discovery_agent(fetch, "agent-framework-synth/0.3")
    assert len(steps) >= 12
    kinds = {h["decoy"]["kind"] for h in hits(log)}
    assert {"error_hint_follow", "mcp_decoy_tool_call", "stateful_dump_start", "graphql_decoy"} <= kinds
    results, parsed = run_pipeline([log], load_config())
    assert parsed.errors == 0 and results[0].label == "agent" and results[0].severity == "critical"
    assert any(f.detector == "multi_turn" for f in results[0].findings)
    out = tmp_path / "raw.jsonl"
    export_file(log, out)
    ev = [json.loads(x) for x in out.read_text().splitlines()]
    assert any(e["untrusted_content"] for e in ev if "error_hint_follow" in e["text"])


def test_discovery_script_against_real_localhost_server(tmp_path):
    from werkzeug.serving import make_server
    import threading
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t")
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        p = subprocess.run([sys.executable, str(ROOT / "scripts/simulated_agent.py"), "--base-url",
                            f"http://127.0.0.1:{srv.server_port}", "--delay", "0", "--scenario", "discovery"],
                           capture_output=True, text=True, timeout=60)
    finally:
        srv.shutdown()
    assert p.returncode == 0, p.stderr
    kinds = {h["decoy"]["kind"] for h in hits(tmp_path / "l.jsonl")}
    assert {"error_hint_follow", "mcp_decoy_tool_call", "stateful_dump_step"} <= kinds
