"""v3 item 1: no log sink may print raw query strings, fake keys, e-mails or coordination tokens/nonces.

A live demo showed the Flask development server printing its request line (with the query string) to the console.  These
tests START REAL SERVERS on a loopback port (the dev server as ``python -m agentwatch honeypot`` and, when installed,
gunicorn with the shipped config), send requests that carry fake secrets in the query string, the path and headers (plus
malformed raw-socket requests that make the servers log errors), stop them with SIGINT and grep the captured stdout and
stderr.  The tests also assert that the servers DID log something, so an empty capture cannot pass vacuously.
"""
import importlib.util
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agentwatch import safelog
from agentwatch.honeypot import create_honeypot_app

ROOT = Path(__file__).resolve().parent.parent

# Fake secrets (shapes the scrubber knows).  NOTHING here is a real credential.
FAKE_SK = "sk-FAKEFAKEFAKEFAKEFAKE1234567890abcd"
FAKE_AWS = "AKIAFAKEFAKEFAKE1234"
FAKE_MAIL = "jane.doe.fake@example.com"
FAKE_BEARER = "Bearer FAKEFAKEFAKEFAKEFAKEFAKE12345678"
FAKE_CARD = "tok_FAKE_TOKEN_0123456789"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(port: int, proc: subprocess.Popen, timeout: float = 20.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise AssertionError(f"server exited early with {proc.returncode}")
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("server did not start")


def get(port: int, target: str, headers=None, data=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{target}", headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def raw(port: int, payload: bytes) -> None:
    with socket.create_connection(("127.0.0.1", port), 3) as s:
        s.sendall(payload)
        s.settimeout(1.5)
        try:
            while s.recv(4096):
                pass
        except (socket.timeout, OSError):
            pass


def exercise(port: int) -> list[str]:
    """Send traffic loaded with fake secrets; return every secret-ish string that must never be echoed to a console."""
    _, home = get(port, "/")
    fake_decoy_key = re.search(r"AWFAKE-DO-NOT-USE-[A-Za-z0-9]+", home)
    _, board = get(port, "/api/v1/coordination-board?client_schema_rev=2026.04-ai", {"User-Agent": "Mozilla/5.0 test"})
    handoff = (re.search(r'"handoff_token":\s*"([^"]+)"', board) or re.search(r"([a-z]{2}-[0-9a-f]{8,})", board))
    secrets = [FAKE_SK, FAKE_AWS, FAKE_MAIL, FAKE_CARD]
    q = f"api_key={FAKE_SK}&aws={FAKE_AWS}&contact={FAKE_MAIL}&access_token={FAKE_CARD}"
    get(port, f"/api/v1/status?{q}")
    get(port, f"/search?q={FAKE_MAIL}&next=/admin")
    get(port, f"/admin-backup/?{q}")
    if fake_decoy_key:
        secrets.append(fake_decoy_key.group(0))
        get(port, f"/api/v1/status?key={fake_decoy_key.group(0)}", {"X-API-Key": fake_decoy_key.group(0)})
    if handoff:
        secrets.append(handoff.group(1))
        get(port, f"/api/v1/coordination-board?token={handoff.group(1)}&nonce={handoff.group(1)}&client_schema_rev=2026.04-ai")
        get(port, "/api/v1/coordination-board", {"Content-Type": "application/json"},
            data=json.dumps({"handoff_token": handoff.group(1), "agent_id": "x"}).encode())
    get(port, "/definitely-missing?" + q)                                  # 404 path
    get(port, f"/api/v2/dump/page/{'a1b2c3d4' * 4}?{q}")                  # opaque path segment
    get(port, "/", {"Authorization": FAKE_BEARER, "Referer": f"http://127.0.0.1/?{q}"})
    secrets.append(FAKE_BEARER.split()[1])
    # malformed requests: make the servers write their own ERROR lines (these echo the request line in stock werkzeug/gunicorn)
    raw(port, f"GET /?api_key={FAKE_SK}&contact={FAKE_MAIL} HTTP/9.9\r\n\r\n".encode())
    raw(port, f"GET /?aws={FAKE_AWS} HTTP/1.1\r\nHost: x\r\nBadHeader\r\n\r\n".encode())
    raw(port, f"BREW /?token={FAKE_CARD} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    raw(port, b"GET /" + b"A" * 70000 + f"?k={FAKE_SK} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    raw(port, f"POST /mcp?k={FAKE_SK} HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Type: application/json\r\n\r\n{{bad".encode())
    return secrets


def stop(proc: subprocess.Popen) -> tuple[str, str]:
    proc.send_signal(signal.SIGINT)                 # the werkzeug dev server ignores SIGTERM in some setups; SIGINT is clean
    try:
        out, err = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=5)
    return out, err


def assert_clean(out: str, err: str, secrets: list[str]) -> None:
    blob = out + "\n" + err
    for s in secrets:
        assert s not in blob, f"raw secret reached the console: {s[:12]}..."
    # percent-encoded forms too
    from urllib.parse import quote
    for s in secrets:
        assert quote(s, safe="") not in blob or quote(s, safe="") == s
    assert "api_key=" not in blob and "access_token=" not in blob and "token=" not in blob


@pytest.fixture
def env(tmp_path):
    e = {**os.environ, "PYTHONUNBUFFERED": "1", "AGENT_WATCH_SALT_FILE": str(tmp_path / "salt"), "PYTHONPATH": str(ROOT)}
    for k in ("AGENT_WATCH_BEHIND_PROXY", "AGENT_WATCH_SCRUB_SALT"):
        e.pop(k, None)
    return e


def test_dev_server_console_has_no_raw_secrets(tmp_path, env):
    port = free_port()
    proc = subprocess.Popen([sys.executable, "-m", "agentwatch", "honeypot", "--host", "127.0.0.1", "--port", str(port),
                             "--log", str(tmp_path / "leads.jsonl"), "--registry", str(tmp_path / "reg.json"), "--seed", "console-test"],
                            env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_up(port, proc)
        secrets = exercise(port)
    finally:
        out, err = stop(proc)
    blob = out + err
    assert '"GET /api/v1/status HTTP/1.1" 200' in blob, "the server logged nothing for normal requests - the test would be vacuous"
    assert_clean(out, err, secrets)
    # the werkzeug request line must not carry a query string at all
    for line in blob.splitlines():
        if '"GET ' in line or '"POST ' in line:
            assert "?" not in line.split('"')[1].replace("?[query-redacted]", ""), line
    assert "127.0.0.1" in blob                                              # still bound to loopback only


@pytest.mark.skipif(importlib.util.find_spec("gunicorn") is None, reason="gunicorn not installed")
def test_gunicorn_console_has_no_raw_secrets(tmp_path, env):
    port = free_port()
    env = {**env, "AGENT_WATCH_DATA": str(tmp_path), "AGENT_WATCH_SEED": "console-test", "AGENT_WATCH_BIND": f"127.0.0.1:{port}"}
    proc = subprocess.Popen([sys.executable, "-m", "gunicorn", "-c", str(ROOT / "deploy" / "gunicorn.conf.py"), "--workers", "1", "--threads", "2",
                             "--timeout", "10", "--limit-request-line", "4094", "--limit-request-fields", "50",
                             "--access-logfile", "-", "--log-level", "debug",      # even FORCING the access log on must stay silent
                             "--worker-tmp-dir", str(tmp_path), "agentwatch.wsgi:app"],
                            env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_up(port, proc)
        secrets = exercise(port)
        time.sleep(0.5)
    finally:
        out, err = stop(proc)
    blob = out + err
    assert "Listening at: http://127.0.0.1" in blob, "gunicorn did not log startup - test would be vacuous"
    assert_clean(out, err, secrets)
    assert not re.search(r"\" \d{3} ", blob)           # no access-log lines (host, request line, status) even though --access-logfile - was forced
    assert "0.0.0.0" not in blob


def test_logging_filter_scrubs_every_stdlib_logger(capsys):
    safelog.install_safe_logging()
    safelog.install_safe_logging()                  # idempotent
    for name in ("werkzeug", "flask.app", "gunicorn.error", "gunicorn.access", "agentwatch"):
        lg = logging.getLogger(name)
        h = logging.StreamHandler(sys.stderr)
        lg.addHandler(h)
        lg.propagate = False
        lg.setLevel(logging.INFO)
        lg.info('127.0.0.1 - - "GET /x?api_key=%s&m=%s HTTP/1.1" 200 -', FAKE_SK, FAKE_MAIL)
        lg.error("failure for %s", f"/y?token={FAKE_CARD}")
        lg.removeHandler(h)
    err = capsys.readouterr().err
    assert err.count("[query-redacted]") >= 10
    for s in (FAKE_SK, FAKE_MAIL, FAKE_CARD, "api_key=", "token="):
        assert s not in err


def test_exception_traceback_goes_through_the_scrubber(tmp_path, capsys):
    app = create_honeypot_app(tmp_path / "l.jsonl", seed="t", registry_path=tmp_path / "r.json")

    @app.route("/boom-test")
    def boom():
        raise RuntimeError(f"upstream said api_key={FAKE_SK} for {FAKE_MAIL}")

    app.config["PROPAGATE_EXCEPTIONS"] = False
    r = app.test_client().get(f"/boom-test?api_key={FAKE_SK}")
    assert r.status_code == 500 and FAKE_SK not in r.get_data(as_text=True)
    cap = capsys.readouterr()
    assert FAKE_SK not in cap.out + cap.err and FAKE_MAIL not in cap.out + cap.err


def test_safe_text_masks_decoy_keys_canaries_and_opaque_segments():
    t = safelog.safe_text("GET /api/v2/dump/page/0123456789abcdef0123456789abcdef?x=AWFAKE-DO-NOT-USE-AB12CD&y=sc-0123456789 HTTP/1.1 AWCANARY-ab12cd34-tundra")
    assert "AWFAKE" not in t and "AWCANARY" not in t and "0123456789abcdef0123456789abcdef" not in t and "x=" not in t
    assert "[query-redacted]" in t and "[id]" in t


def test_request_handler_logs_query_free_path():
    handler_cls = safelog.make_request_handler()
    h = handler_cls.__new__(handler_cls)
    h.requestline = f"GET /a?api_key={FAKE_SK} HTTP/1.1"
    h.path = f"/a?api_key={FAKE_SK}"
    h.client_address = ("127.0.0.1", 1)
    h.command = "GET"
    h.request_version = "HTTP/1.1"
    h.headers = {}
    captured = []
    logging.getLogger("werkzeug").addHandler(type("H", (logging.Handler,), {"emit": lambda self, rec: captured.append(self.format(rec))})())
    safelog.install_safe_logging()
    h.log_request(200, 10)
    h.log("error", "code 400, message Bad request syntax (%r)", f"GET /?api_key={FAKE_SK} HTTP/9")
    assert captured and all(FAKE_SK not in c for c in captured)
