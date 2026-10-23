"""Tests for redteam/llm_agent.py.  ONLY A STUB MODEL IS USED: the harness has never been run against a real LLM.

Everything runs on loopback; any attempt to open a non-loopback connection fails the test."""
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "redteam"))
import llm_agent as L  # noqa: E402
from agentwatch.config import load_config  # noqa: E402
from agentwatch.honeypot import create_honeypot_app  # noqa: E402
from agentwatch.pipeline import run_pipeline  # noqa: E402


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    """Any socket connection to a non-loopback address fails the test (belt and braces over the harness's own checks)."""
    real = socket.socket.connect
    attempts = []

    def guarded(self, addr, *a, **k):
        host = addr[0] if isinstance(addr, tuple) else str(addr)
        if host not in ("127.0.0.1", "::1", "localhost") and not str(host).startswith("127."):
            attempts.append(host)
            raise AssertionError(f"non-loopback connection attempted: {host}")
        return real(self, addr, *a, **k)

    real_gai = socket.getaddrinfo

    def no_dns(host, *a, **k):
        if host not in ("127.0.0.1", "::1", "localhost", None) and not str(host).startswith("127."):
            attempts.append(f"DNS:{host}")
            raise AssertionError(f"DNS lookup attempted for {host}")
        return real_gai(host, *a, **k)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    yield attempts
    assert not attempts


def stub(script):
    """A stub 'LLM': replays scripted tool calls, then answers."""
    it = iter(script)

    def llm(msgs, tools):
        try:
            return {"content": "", "tool_calls": [next(it)]}
        except StopIteration:
            return {"content": "final answer", "tool_calls": []}
    return llm


def call(url, method="GET", body=None):
    a = {"url": url, "method": method}
    if body:
        a["body"] = body
    return {"name": "fetch_url", "arguments": a}


@pytest.mark.parametrize("url", ["http://127.0.0.1:8098/", "http://localhost:8098/x", "http://[::1]:80/", "http://127.5.5.5/", "https://127.0.0.1/"])
def test_loopback_urls_are_allowed(url):
    assert L.check_loopback(url) == url


@pytest.mark.parametrize("url", [
    "http://example.com/", "http://203.0.113.5/", "http://10.0.0.1/", "http://192.168.1.1/", "http://0.0.0.0/", "http://169.254.169.254/latest",
    "http://127.0.0.1@evil.example/", "http://localhost.evil.example/", "http://evil.example/127.0.0.1", "http://127.1/", "http://2130706433/",
    "file:///etc/passwd", "ftp://127.0.0.1/", "gopher://127.0.0.1/", "//127.0.0.1/", "127.0.0.1", "", "http://user:pw@127.0.0.1/", "http://localtest.me/"])
def test_everything_else_is_refused_without_dns_or_connection(url):
    with pytest.raises(L.Refused):
        L.check_loopback(url)
    res = L.fetch_url(url)
    assert res["status"] == 0 and res.get("refused") is True      # returned to the model as data; no DNS, no connect (autouse guard)


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.9/steal")
            self.end_headers()
        elif self.path == "/big":
            body = b"A" * 100000
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            body = b"hello"
            self.send_response(200); self.send_header("Content-Length", "5"); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        body = f"got {len(data)}".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_fetch_url_get_post_and_caps(local_server):
    assert L.fetch_url(local_server + "/") == {"status": 200, "body": "hello"}
    assert L.fetch_url(local_server + "/x", "POST", "A" * 100000)["body"] == f"got {L.MAX_BODY}"
    assert len(L.fetch_url(local_server + "/big")["body"]) == L.MAX_RESP
    assert L.fetch_url(local_server + "/", "DELETE")["status"] == 200        # unknown verbs are downgraded to GET


def test_redirect_to_a_non_loopback_host_is_refused_before_connecting(local_server):
    res = L.fetch_url(local_server + "/redir")                                # the autouse guard fails the test if 203.0.113.9 is contacted
    assert res["status"] in (0, 302) and "steal" not in res["body"]


def test_proxy_environment_variables_are_ignored(local_server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.7:3128")
    monkeypatch.setenv("http_proxy", "http://203.0.113.7:3128")
    assert L.fetch_url(local_server + "/")["status"] == 200


def test_step_cap_is_hard(local_server):
    n = {"calls": 0}

    def forever(msgs, tools):
        n["calls"] += 1
        return {"content": "", "tool_calls": [call(local_server + "/")]}
    msgs = L.run_agent(forever, L.PROMPTS["benign_summarizer"], local_server, max_steps=5)
    assert n["calls"] == 5 and sum(m["role"] == "tool" for m in msgs) == 5
    n["calls"] = 0
    L.run_agent(forever, L.PROMPTS["benign_summarizer"], local_server, max_steps=10**6)
    assert n["calls"] == L.MAX_STEPS_HARD                                      # the model/caller cannot raise the ceiling


def test_model_asking_for_external_hosts_gets_a_refusal_and_nothing_is_fetched(local_server):
    script = [call("http://203.0.113.5/"), call("http://example.com/api"), call("http://127.0.0.1@evil.example/"), call(local_server + "/")]
    msgs = L.run_agent(stub(script), L.PROMPTS["aggressive_audit"], local_server, max_steps=10)
    tool_out = [json.loads(m["content"]) for m in msgs if m["role"] == "tool"]
    assert [t.get("refused", False) for t in tool_out] == [True, True, True, False] and tool_out[-1]["status"] == 200


def test_unknown_tool_and_garbage_arguments_do_not_crash(local_server):
    script = [{"name": "run_shell", "arguments": {"cmd": "id"}}, {"name": "fetch_url", "arguments": "not-a-dict"}, {"name": "fetch_url", "arguments": {}}]
    msgs = L.run_agent(stub(script), L.PROMPTS["benign_summarizer"], local_server)
    assert [json.loads(m["content"])["status"] for m in msgs if m["role"] == "tool"] == [0, 0, 0]


def test_non_loopback_target_is_refused_at_start():
    with pytest.raises(L.Refused):
        L.run_agent(stub([]), L.PROMPTS["benign_summarizer"], "http://example.com")


def test_three_prompts_exist_and_name_the_local_target():
    assert set(L.PROMPTS) == {"benign_summarizer", "aggressive_audit", "stealth_mimic"}
    for p in L.PROMPTS.values():
        assert "{base}" in p and "http" not in p


def test_ollama_backend_talks_to_loopback_and_normalises_tool_calls(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    seen = {}

    def post(url, payload, headers=None):
        seen["url"], seen["payload"] = url, payload
        return {"message": {"content": "", "tool_calls": [{"function": {"name": "fetch_url", "arguments": {"url": "http://127.0.0.1:1/"}}}]}}
    r = L.ollama_backend("some-local-model", post)([{"role": "user", "content": "hi"}], [L.TOOL])
    assert seen["url"] == "http://127.0.0.1:11434/api/chat" and seen["payload"]["stream"] is False
    assert r["tool_calls"] == [{"name": "fetch_url", "arguments": {"url": "http://127.0.0.1:1/"}}]


def test_ollama_host_override_must_still_be_loopback(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://203.0.113.5:11434")
    with pytest.raises(L.Refused):
        L.ollama_backend("m")


def test_openai_compatible_backend_is_off_by_default(monkeypatch):
    monkeypatch.delenv("AGENTWATCH_LLM_API_BASE", raising=False)
    with pytest.raises(SystemExit):
        L.openai_backend("m")


def test_openai_backend_only_contacts_the_configured_endpoint_and_fetch_url_stays_loopback(monkeypatch, local_server):
    monkeypatch.setenv("AGENTWATCH_LLM_API_BASE", "https://llm-gateway.example/v1")
    monkeypatch.setenv("AGENTWATCH_LLM_API_KEY", "FAKE-KEY-FOR-TEST")
    urls = []

    def post(url, payload, headers=None):
        urls.append((url, headers))
        return {"choices": [{"message": {"content": "", "tool_calls": [
            {"function": {"name": "fetch_url", "arguments": json.dumps({"url": "http://203.0.113.5/"})}}]}}]}
    llm = L.openai_backend("m", post)
    msgs = L.run_agent(llm, L.PROMPTS["benign_summarizer"], local_server, max_steps=2)
    assert {u for u, _ in urls} == {"https://llm-gateway.example/v1/chat/completions"}
    assert urls[0][1]["Authorization"].startswith("Bearer ")
    assert all(json.loads(m["content"]).get("refused") for m in msgs if m["role"] == "tool")        # the model-chosen external URL was refused


def test_cli_reports_unreachable_ollama_without_fetching(monkeypatch, local_server, tmp_path, capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("OLLAMA_HOST", f"http://127.0.0.1:{port}")           # a closed LOCAL port: never talks to a real model
    rc = L.main(["--target", local_server, "--prompt", "benign_summarizer", "--model", "none"])
    assert rc == 2 and "model backend error" in capsys.readouterr().err


def test_cli_refuses_a_non_loopback_target(monkeypatch, capsys):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:9")
    assert L.main(["--target", "http://example.com", "--prompt", "benign_summarizer", "--model", "x"]) == 2
    assert "refused" in capsys.readouterr().err


def test_end_to_end_with_stub_model_against_the_real_honeypot_and_agent_watch(tmp_path):
    """Stub 'stealth mimic' browses the live loopback honeypot; its requests reach the mirror stream and agent-watch analyzes them."""
    log = tmp_path / "pot.jsonl"
    app = create_honeypot_app(log, seed="t", registry_path=tmp_path / "r.json")
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        script = [call(base + "/"), call(base + "/about"), call(base + "/kb/"), call(base + "/products"), call(base + "/pricing"),
                  call(base + "/api/v1/items"), call(base + "/docs")]
        transcript = []
        L.run_agent(stub(script), L.PROMPTS["stealth_mimic"], base, max_steps=12, log=transcript.append)
    finally:
        srv.shutdown()
    assert len(transcript) == 7 and transcript[0]["status"] == 200
    results, parsed = run_pipeline([str(log) + ".access.jsonl"], load_config())     # no decoy was touched, so only the mirror exists
    assert parsed.errors == 0 and results
    s = max(results, key=lambda r: len(r.session.requests))
    assert len(s.session.requests) >= 7 and s.session.ip == "127.0.0.1"
    # urllib's default User-Agent: honest note - the stub does not imitate a browser, so asset starvation (browser-UA only) abstains
    assert not any(f.kind == "asset_starvation" for f in s.findings)
