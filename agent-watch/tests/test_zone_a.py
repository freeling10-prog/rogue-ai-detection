"""Zone A hardening: WSGI limits, proxy handling, multi-worker consistency, deploy files."""
import importlib
import json
import re
import runpy
from datetime import datetime
from pathlib import Path

import pytest

from agentwatch.coordination import BOARD_PATH
from agentwatch.honeypot import create_honeypot_app
from agentwatch.honeytoken import MAX_CONTENT_LENGTH
from agentwatch.parser import parse_json_line, parse_lines

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
UA = "agent-framework-synth/0.3"


def hits(path):
    return [r for r in (json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()) if r["event_type"] == "honeytoken_hit"]


# ---- 16 KiB limit ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path,kw", [
    (BOARD_PATH, {"content_type": "application/json"}),
    ("/mcp", {"content_type": "application/json"}),
    ("/graphql", {"content_type": "application/json"}),
    ("/api/v1/admin", {"content_type": "text/plain"}),
    ("/definitely/not/a/route", {"content_type": "text/plain"}),
])
def test_bodies_over_16kib_get_json_413_everywhere(tmp_path, path, kw):
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t")
    assert app.config["MAX_CONTENT_LENGTH"] == MAX_CONTENT_LENGTH == 16 * 1024
    c = app.test_client()
    r = c.post(path, data=b"{" + b"a" * (16 * 1024 + 10), **kw)
    assert r.status_code == 413 and r.is_json and r.get_json()["error"] == "payload_too_large"
    assert r.get_json()["max_bytes"] == 16384
    r2 = c.post(path, data=b"x" * 100, **kw)                      # small bodies are not 413
    assert r2.status_code != 413
    log = tmp_path / "l.jsonl"
    for rec in (json.loads(x) for x in (log.read_text().splitlines() if log.exists() else [])):
        assert len(json.dumps(rec)) < 16000                       # the oversized body is never stored


def test_exactly_at_the_limit_is_accepted(tmp_path):
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t")
    c = app.test_client()
    ok = c.post(BOARD_PATH, data=b"{" + b" " * (16 * 1024 - 2) + b"}", content_type="application/json")
    assert ok.status_code == 403                                   # parsed as JSON, rejected for the missing token only


# ---- proxy handling ---------------------------------------------------------------------------------------------------------
def source_ips(log):
    return [h["source_ip"] for h in hits(log)]


def test_spoofed_xff_is_ignored_when_not_behind_proxy(tmp_path):
    log = tmp_path / "l.jsonl"
    app = create_honeypot_app(log, seed="t")
    app.test_client().get("/internal/export", headers={"X-Forwarded-For": "203.0.113.99", "X-Forwarded-Proto": "https",
                                                        "X-Forwarded-Host": "evil.invalid", "X-Real-IP": "203.0.113.98"},
                          environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
    assert source_ips(log) == ["172.18.0.9"]


def test_behind_proxy_uses_exactly_one_hop(tmp_path):
    log = tmp_path / "l.jsonl"
    app = create_honeypot_app(log, seed="t", behind_proxy=True)
    c = app.test_client()
    # nginx overwrites XFF with the real peer
    c.get("/internal/export", headers={"X-Forwarded-For": "198.51.100.7"}, environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
    # a client that smuggled its own XFF in front: only the LAST (proxy-added) hop is trusted
    c.get("/internal/export", headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.8"}, environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
    assert source_ips(log) == ["198.51.100.7", "198.51.100.8"]


def test_env_var_controls_proxy_trust_and_defaults_off(tmp_path, monkeypatch):
    def ip_for(env):
        for k in ("AGENT_WATCH_BEHIND_PROXY",):
            monkeypatch.delenv(k, raising=False)
        if env is not None:
            monkeypatch.setenv("AGENT_WATCH_BEHIND_PROXY", env)
        log = tmp_path / f"l-{env}.jsonl"
        app = create_honeypot_app(log, seed="t")
        app.test_client().get("/internal/export", headers={"X-Forwarded-For": "198.51.100.7"}, environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
        return source_ips(log)[0]
    assert ip_for(None) == "172.18.0.9" and ip_for("0") == "172.18.0.9" and ip_for("true") == "172.18.0.9"
    assert ip_for("1") == "198.51.100.7"


def test_test_hook_is_separate_off_by_default_and_never_stacks_with_proxyfix(tmp_path):
    h = {"X-Forwarded-For": "198.51.100.7"}
    peer = {"REMOTE_ADDR": "172.18.0.9"}
    a, b, c_ = (tmp_path / n for n in ("a.jsonl", "b.jsonl", "c.jsonl"))
    create_honeypot_app(a, seed="t").test_client().get("/internal/export", headers=h, environ_overrides=peer)
    create_honeypot_app(b, seed="t", trust_forwarded_for=True, behind_proxy=False).test_client().get("/internal/export", headers=h, environ_overrides=peer)
    # both enabled: ProxyFix already rewrote REMOTE_ADDR; the hook must not re-read XFF on top of it
    create_honeypot_app(c_, seed="t", trust_forwarded_for=True, behind_proxy=True).test_client().get(
        "/internal/export", headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.7"}, environ_overrides=peer)
    assert source_ips(a) == ["172.18.0.9"] and source_ips(b) == ["198.51.100.7"] and source_ips(c_) == ["198.51.100.7"]


# ---- WSGI entry point / multi-worker consistency ----------------------------------------------------------------------------------
def wsgi_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_WATCH_DATA", str(tmp_path))
    monkeypatch.setenv("AGENT_WATCH_BEHIND_PROXY", "1")
    monkeypatch.delenv("AGENT_WATCH_SEED", raising=False)
    import agentwatch.wsgi as w
    w = importlib.reload(w)
    return w.build()


def test_two_gunicorn_workers_serve_the_same_decoys_and_share_board_state(tmp_path, monkeypatch):
    w1, w2 = wsgi_app(tmp_path, monkeypatch), wsgi_app(tmp_path, monkeypatch)       # two worker processes
    r1 = w1.test_client().get("/robots.txt").get_data(as_text=True)
    r2 = w2.test_client().get("/robots.txt").get_data(as_text=True)
    assert r1 == r2 and "/staff-portal-" in r1
    s1 = w1.test_client().get("/openapi.json").get_data()
    assert s1 == w2.test_client().get("/openapi.json").get_data()
    peer = {"REMOTE_ADDR": "172.18.0.9"}
    xff = {"X-Forwarded-For": "198.51.100.5"}
    token = w1.test_client().get(BOARD_PATH, headers=xff, environ_overrides=peer).get_json()["handoff_token"]
    r = w2.test_client().post(BOARD_PATH, json={"handoff_token": token, "agent_id": "x"}, headers=xff, environ_overrides=peer)
    assert r.status_code == 200 and "verification_nonce" in r.get_json()           # token issued by worker 1 valid on worker 2
    nonce = r.get_json()["verification_nonce"]
    assert w1.test_client().get(BOARD_PATH + "/claim-shard", query_string={"token": token, "nonce": nonce}, headers=xff,
                                environ_overrides=peer).status_code == 200
    assert w2.test_client().get(BOARD_PATH + "/claim-shard", query_string={"token": token, "nonce": nonce}, headers=xff,
                                environ_overrides=peer).status_code == 403          # single-use across workers
    assert (tmp_path / "registry.seed").stat().st_mode & 0o777 == 0o600
    assert {h["source_ip"] for h in hits(tmp_path / "leads.jsonl")} == {"198.51.100.5"}


def test_wsgi_never_enables_the_test_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_WATCH_TRUST_FORWARDED_FOR", "1")
    app = wsgi_app(tmp_path, monkeypatch)
    app.test_client().get("/internal/export", headers={"X-Forwarded-For": "198.51.100.7"}, environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
    # behind_proxy=1 with a single hop: ProxyFix result is the XFF value, hook plays no part
    assert source_ips(tmp_path / "leads.jsonl") == ["198.51.100.7"]
    monkeypatch.setenv("AGENT_WATCH_BEHIND_PROXY", "0")
    import agentwatch.wsgi as w
    app2 = importlib.reload(w).build()
    app2.test_client().get("/internal/export", headers={"X-Forwarded-For": "198.51.100.7"}, environ_overrides={"REMOTE_ADDR": "172.18.0.9"})
    assert source_ips(tmp_path / "leads.jsonl")[-1] == "172.18.0.9"


# ---- gunicorn config: the non-loopback guard is satisfied explicitly ----------------------------------------------------------------
def load_gunicorn_conf(monkeypatch, **env):
    for k in ("AGENT_WATCH_BIND", "AGENT_WATCH_ALLOW_NONLOCAL"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return runpy.run_path(str(DEPLOY / "gunicorn.conf.py"))


def test_gunicorn_conf_defaults_to_loopback_and_refuses_unflagged_nonlocal_bind(monkeypatch):
    assert load_gunicorn_conf(monkeypatch)["bind"] == "127.0.0.1:8000"
    with pytest.raises(SystemExit):
        load_gunicorn_conf(monkeypatch, AGENT_WATCH_BIND="0.0.0.0:8000")
    with pytest.raises(SystemExit):
        load_gunicorn_conf(monkeypatch, AGENT_WATCH_BIND="0.0.0.0:8000", AGENT_WATCH_ALLOW_NONLOCAL="0")
    ns = load_gunicorn_conf(monkeypatch, AGENT_WATCH_BIND="0.0.0.0:8000", AGENT_WATCH_ALLOW_NONLOCAL="1")
    assert ns["bind"] == "0.0.0.0:8000" and ns["accesslog"] is None


# ---- Dockerfile ------------------------------------------------------------------------------------------------------------------------
def test_dockerfile_contents():
    text = (DEPLOY / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.(1[0-9])-slim", text, re.M)
    assert "useradd --uid 10001" in text and re.search(r"^USER 10001:10001", text, re.M) and "agentwatch" in text
    for flag in ("--workers\", \"2\"", "--threads\", \"4\"", "--timeout\", \"10\"", "--limit-request-line\", \"4094\"",
                 "--limit-request-fields\", \"50\""):
        assert flag in text
    assert "0.0.0.0" not in re.sub(r"(?m)^\s*#.*$", "", text)                 # the image itself defaults to loopback
    assert "AGENT_WATCH_BIND=127.0.0.1:8000" in text and "agentwatch.wsgi:app" in text
    assert "ADD http" not in text and "curl" not in text and "wget" not in text


# ---- docker compose ---------------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def compose():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((DEPLOY / "docker-compose.zone-a.yml").read_text())


def test_compose_isolation_properties(compose):
    nets, svcs = compose["networks"], compose["services"]
    assert nets["internal"]["internal"] is True and not nets["edge"].get("internal")
    aw, ng = svcs["agentwatch"], svcs["nginx"]
    assert aw["networks"] == ["internal"] and "ports" not in aw                    # no egress, nothing published
    assert set(ng["networks"]) == {"edge", "internal"}
    for s in (aw, ng):
        assert s["read_only"] is True and s["cap_drop"] == ["ALL"] and "no-new-privileges:true" in s["security_opt"]
        assert any(str(t).startswith("/tmp") for t in s["tmpfs"])
    assert aw["mem_limit"] == "512m" and aw["user"] == "10001:10001"
    assert aw["environment"]["AGENT_WATCH_BIND"] == "0.0.0.0:8000" and aw["environment"]["AGENT_WATCH_ALLOW_NONLOCAL"] == "1"
    assert aw["environment"]["AGENT_WATCH_BEHIND_PROXY"] == "1"
    assert len(ng["ports"]) == 1 and ng["ports"][0].startswith("${AGENT_WATCH_PUBLISH:-127.0.0.1}:")
    assert "leads:/data" in aw["volumes"] and not any(v.startswith("leads") for v in ng["volumes"])
    assert any(v.endswith(":ro") for v in ng["volumes"] if "nginx.conf" in v)
    assert set(compose["volumes"]) == {"leads", "nginx-logs"}


# ---- nginx -------------------------------------------------------------------------------------------------------------------------------
NGINX = (DEPLOY / "nginx.conf").read_text()


def test_nginx_conf_structure_and_required_directives():
    assert NGINX.count("{") == NGINX.count("}")
    stripped = re.sub(r"#.*", "", NGINX)
    for d in ("proxy_buffering         off;", "proxy_request_buffering on;", "client_max_body_size        16k;",
              "limit_req_zone $binary_remote_addr zone=aw_ceiling:10m rate=100r/s;", "log_format agentwatch_json escape=json",
              "proxy_set_header X-Forwarded-For   $remote_addr;", "server_tokens off;", "listen 8080"):
        assert d in stripped, d
    assert "$proxy_add_x_forwarded_for" not in stripped                           # client XFF is overwritten, not appended
    assert "$http_authorization" not in stripped and "$http_cookie" not in stripped
    rate = int(re.search(r"rate=(\d+)r/s", stripped).group(1))
    burst = int(re.search(r"burst=(\d+)", stripped).group(1))
    assert rate >= 50 and burst >= 200                                            # far above an agent's normal burst


def nginx_json_line(values):
    """Render the log_format from nginx.conf exactly as nginx would (escape=json), for sample values."""
    fmt = re.search(r"log_format agentwatch_json escape=json\s+((?:'[^']*'\s*)+);", NGINX).group(1)
    template = "".join(re.findall(r"'([^']*)'", fmt))
    def esc(v):
        return json.dumps(v)[1:-1]
    return re.sub(r"\$(\w+)", lambda m: esc(values[m.group(1)]) if m.group(1) in values else m.group(0), template)


SAMPLE = {"time_iso8601": "2026-10-22T10:15:30+00:00", "remote_addr": "198.51.100.23", "request_method": "GET",
          "aw_path": "/api/v1/search", "aw_args": "q=a&page=2", "status": "200", "body_bytes_sent": "1234",
          "request_time": "0.042", "aw_ua": UA, "aw_ref": "-"}


def test_nginx_json_log_line_parses_with_agentwatch_gateway_parser():
    line = nginx_json_line(SAMPLE)
    obj = json.loads(line)                                                       # valid JSON
    assert set(obj) == {"timestamp", "client_ip", "method", "path", "query", "status", "bytes", "request_time", "user_agent", "referer"}
    req, ctx = parse_json_line(line, 1)
    assert not ctx and req is not None
    assert req.ip == "198.51.100.23" and req.method == "GET" and req.path == "/api/v1/search"
    assert req.query == "q=a&page=2" and req.status == 200 and req.size == 1234 and req.ua == UA
    assert req.latency_ms == pytest.approx(42.0) and req.ts == datetime.fromisoformat("2026-10-22T10:15:30+00:00")
    parsed = parse_lines([line, line.replace("10:15:30", "10:15:33")])
    assert parsed.errors == 0 and len(parsed.requests) == 2


def test_nginx_json_log_survives_hostile_values_and_non_utc_offsets():
    hostile = {**SAMPLE, "aw_ua": 'evil"\\ua\n{"status":500}', "aw_args": 'a="b"&c=\\', "time_iso8601": "2026-10-22T03:15:30-07:00"}
    line = nginx_json_line(hostile)
    assert "\n" not in line
    req, _ = parse_json_line(line, 1)
    assert req is not None and req.status == 200 and '"status":500' in req.ua       # data stays data
    assert req.ts == datetime.fromisoformat("2026-10-22T10:15:30+00:00")


def secret_regexes():
    maps = re.findall(r'"~\*\((.*?)\)"\s+(?:1|"\[REDACTED_SECRET_LIKE_PATH\]");', NGINX)
    assert len(maps) == 2
    return [re.compile(m, re.I) for m in maps]


def test_nginx_redaction_maps_match_secret_shapes_and_not_benign_traffic():
    args_rx, path_rx = secret_regexes()
    for s in ("api_key=sk-ABCDEFGHIJKLMNOP0123456", "t=ghp_" + "A" * 24, "k=AKIA" + "B" * 16, "jwt=eyJhbGciOiJub25l.eyJzdWIiOiJ4",
              "mail=jane@example.com", "mail=jane%40example.com", "auth=Bearer abcdefgh12345", "x=Bearer%20abcdefgh12345"):
        assert args_rx.search(s), s
    for s in ("q=laptops&page=2", "id=12345&sort=asc", "ref=google", "Mozilla/5.0 (X11; Linux x86_64)", "curl/8.4.0"):
        assert not args_rx.search(s), s
    assert path_rx.search("/api/sk-ABCDEFGHIJKLMNOP0123456/x") and not path_rx.search("/api/v1/items/42")


# ---- real gunicorn (skipped when gunicorn is not installed; it is NOT a dependency of the library) --------------------------------------
def test_real_gunicorn_two_workers_on_loopback(tmp_path):
    pytest.importorskip("gunicorn")
    import os
    import socket
    import subprocess
    import sys
    import time
    import urllib.error
    import urllib.request
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "AGENT_WATCH_DATA": str(tmp_path), "AGENT_WATCH_SALT_FILE": str(tmp_path / "scrub.salt"),
           "AGENT_WATCH_BEHIND_PROXY": "1", "AGENT_WATCH_BIND": f"127.0.0.1:{port}", "PYTHONPATH": str(ROOT)}
    proc = subprocess.Popen([sys.executable, "-m", "gunicorn", "-c", str(DEPLOY / "gunicorn.conf.py"), "--workers", "2", "--threads", "4",
                             "--timeout", "10", "--limit-request-line", "4094", "--limit-request-fields", "50",
                             "--worker-tmp-dir", str(tmp_path), "agentwatch.wsgi:app"],
                            env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{port}"

    def call(path, data=None, headers=None):
        req = urllib.request.Request(base + path, data=data, headers={"X-Forwarded-For": "198.51.100.5", **(headers or {})})
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
    try:
        for _ in range(50):
            try:
                call("/robots.txt")
                break
            except OSError:
                time.sleep(0.2)
        token = json.loads(call(BOARD_PATH)[1])["handoff_token"]
        body = json.dumps({"handoff_token": token, "agent_id": "a"}).encode()
        codes = [call(BOARD_PATH, body, {"Content-Type": "application/json"})[0] for _ in range(6)]
        assert codes == [200] + [409] * 5                       # consistent whichever worker answers
        assert call(BOARD_PATH, b"x" * 20000, {"Content-Type": "application/json"})[0] == 413
        assert call("/" + "a" * 5000)[0] == 400                 # --limit-request-line 4094
    finally:
        proc.terminate()
        proc.wait(timeout=15)
    assert {h["source_ip"] for h in hits(tmp_path / "leads.jsonl")} == {"198.51.100.5"}
