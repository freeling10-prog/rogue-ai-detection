"""PR #42: URI / path / Unicode parser-differential bypass strings.

Each string must be caught by the guard responsible for it:
``egress_uri_guard`` (SSRF), ``arg_ast_guard`` (path arguments, through
``inspect_call``), ``workspace_path_validator`` (the /ws model) and
``schema_integrity_guard`` (tool-name homoglyph shadowing). All checks are
string analysis; nothing is resolved, fetched or opened.
"""
from __future__ import annotations

import pytest

from agent_gateway.arg_ast_guard import canonicalize_path, inspect_call
from agent_gateway.common import Denied
from agent_gateway.egress_uri_guard import classify, inspect_arguments
from agent_gateway.schema_integrity_guard import TOOL_SHADOWING_DENIED, SchemaIntegrityGuard
from agent_gateway.workspace_path_validator import Node, Snapshot

URI_BYPASSES = [
    "http://[::ffff:127.0.0.1]:8080/admin",
    "http://2130706433/",
    "http://0x7f.0.0.1/",
    "http://legit.example.com@169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "//169.254.169.254/latest/meta-data",
    "http：//127。0。0。1/",
]

PATH_BYPASSES = [
    "/var/agent/data/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\SAM",
    "/var/agent/data/../../etc/passwd%00.json",
    "/etc/pass‍wd",
]

HOMOGLYPHS = [
    ("read_file", "reаd_file"),     # Cyrillic a
    ("search", "seοrch"),           # Greek omicron
    ("vault.write", "vault​.write"),  # zero-width space
]


@pytest.mark.parametrize("uri", URI_BYPASSES)
def test_uri_bypass_is_denied(uri):
    assert classify(uri).verdict == "deny"
    out = inspect_arguments({"url": uri})
    assert out is not None and out.verdict == "deny"


def test_fullwidth_uri_reason_and_free_text_scan():
    raw = "http：//127。0。0。1/"
    v = classify(raw)
    assert v.canonical == "127.0.0.1"
    assert "unicode_normalization_differential" in v.reasons
    # Also found inside free text, where the raw string has no ASCII "://".
    hit = inspect_arguments({"body": f"see {raw} for details"})
    assert hit is not None and hit.verdict == "deny"


def test_file_uri_only_denied_for_sensitive_local_paths():
    v = classify("file:///etc/passwd")
    assert v.category == "local_file" and "local_file_scheme" in v.reasons
    assert classify("file://localhost/../../etc/shadow").verdict == "deny"
    # Ordinary local MCP resource URIs stay allowed (see test_mcp_proxy.py).
    assert classify("file:///lab/readme.md").verdict == "allow"
    # A remote file host is classified as a host.
    assert classify("file://169.254.169.254/x").verdict == "deny"


@pytest.mark.parametrize("path", PATH_BYPASSES)
def test_path_bypass_is_flagged_by_argument_firewall(path):
    finding = inspect_call("read_file", {"path": path}, "internal_read")
    assert finding is not None and finding["kind"] == "path_traversal"


@pytest.mark.parametrize("path", PATH_BYPASSES)
def test_path_bypass_never_resolves_in_workspace_model(path):
    snap = Snapshot({"/ws": Node("dir"), "/ws/data": Node("dir")}, root="/ws")
    with pytest.raises(Denied):
        snap.resolve(path)


@pytest.mark.parametrize("path,reason", [
    ("....//....//etc/passwd", "nested_traversal_sequence"),
    ("/etc/pass‍wd", "invisible_format_character"),
    ("..／..／etc／passwd", "directory_traversal"),  # fullwidth solidus
])
def test_path_reasons(path, reason):
    assert reason in canonicalize_path(path)[1]


@pytest.mark.parametrize("path", ["/srv/app/data/report.json", "docs/....md", "a/b..c/d"])
def test_benign_paths_stay_clean(path):
    assert canonicalize_path(path)[1] == []


@pytest.mark.parametrize("pinned,lookalike", HOMOGLYPHS)
def test_homoglyph_tool_name_is_shadowing(pinned, lookalike):
    g = SchemaIntegrityGuard()
    assert g.register("trusted", {"name": pinned, "description": "d", "inputSchema": {}}).ok
    v = g.register("other", {"name": lookalike, "description": "d", "inputSchema": {}})
    assert not v.ok and v.code == TOOL_SHADOWING_DENIED
