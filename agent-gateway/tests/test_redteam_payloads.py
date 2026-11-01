"""Red-team bypass strings against the URI, path and tool-name guards.

16 payloads (7 URI, 6 path, 3 tool name), plus controls that must stay allowed.
"""
from __future__ import annotations

import pytest

from agent_gateway.arg_ast_guard import canonicalize_path, inspect_call
from agent_gateway.egress_uri_guard import classify, fold_unicode, inspect_arguments
from agent_gateway.schema_integrity_guard import SchemaIntegrityGuard

URI_PAYLOADS = [
    "http://[::ffff:127.0.0.1]:8080/admin",
    "http://2130706433/",
    "http://0x7f.0.0.1/",
    "http://legit.example.com@169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "//169.254.169.254/latest/meta-data",
    "http：//127。0。0。1/",
]

PATH_PAYLOADS = [
    "/var/agent/data/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\SAM",
    "/var/agent/data/../../etc/passwd%00.json",
    "/etc/pass‍wd",
]

NAME_PAYLOADS = [
    ("reаd_file", "read_file"),   # Cyrillic a
    ("seοrch", "search"),         # Greek omicron in place of "a": one edit from "search"
    ("vault​.write", "vault.write"),  # zero-width space
]


@pytest.mark.parametrize("uri", URI_PAYLOADS)
def test_uri_payload_denied(uri):
    assert classify(uri).verdict == "deny"
    assert inspect_arguments({"url": uri}).verdict == "deny"


def test_fullwidth_and_ideographic_dots_found_in_free_text():
    v = inspect_arguments({"note": "see http：//127。0。0。1/admin"})
    assert v is not None and v.verdict == "deny" and "unicode_confusable_spelling" in v.reasons
    assert fold_unicode("a​b。c．d") == "ab.c.d"


@pytest.mark.parametrize("path", PATH_PAYLOADS)
def test_path_payload_flagged(path):
    _canon, reasons = canonicalize_path(path)
    assert reasons
    finding = inspect_call("read_file", {"path": path}, "internal_read")
    assert finding is not None and finding["kind"] == "path_traversal"


@pytest.mark.parametrize("name,original", NAME_PAYLOADS)
def test_homoglyph_tool_name_shadowing_denied(name, original):
    g = SchemaIntegrityGuard()
    assert g.register("server-a", {"name": original, "description": "x"}).ok
    v = g.register("server-b", {"name": name, "description": "x"})
    assert not v.ok and v.code == "TOOL_SHADOWING_DENIED"


@pytest.mark.parametrize("uri", [
    "https://example.com/docs",
    "file:///lab/readme.md",
    "http://127.0.0.1:8080/",        # lab allowlist
    "https://xn--bcher-kva.example/",
])
def test_controls_stay_allowed(uri):
    assert classify(uri).verdict == "allow"


def test_file_uri_with_remote_host_or_traversal_denied():
    assert classify("file://evil.example/share/x").verdict == "deny"
    assert classify("file:///lab/../etc/shadow").verdict == "deny"


@pytest.mark.parametrize("path", ["data/report.json", "/var/agent/data/a...b.txt", "notes/v1.2/readme.md"])
def test_ordinary_paths_pass(path):
    assert canonicalize_path(path)[1] == []
    assert inspect_call("read_file", {"path": path}, "internal_read") is None


def test_deterministic():
    runs = [[classify(u).verdict for u in URI_PAYLOADS] + [tuple(canonicalize_path(p)[1]) for p in PATH_PAYLOADS]
            for _ in range(2)]
    assert runs[0] == runs[1]
