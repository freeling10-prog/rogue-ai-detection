"""Canonical SSRF / cloud-metadata URI guard. No DNS, no sockets."""
from __future__ import annotations

import ipaddress
import socket

import pytest
from hypothesis import given, settings, strategies as st

from agent_gateway import approve
from agent_gateway.egress_uri_guard import classify, inspect_arguments, parse_inet_aton
from agent_gateway.pep import PolicyEngine
from tests.conftest import KEY_A, KEY_B

DENY = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "https://allowed.com@169.254.169.254/latest/meta-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[fd00:ec2::254]/latest/meta-data",
    "http://100.100.100.200/latest/meta-data",
    "http://169.254.170.2/v2/credentials",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0x7f.0.0.1/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[64:ff9b::a9fe:a9fe]/",
    "http://%31%32%37.0.0.1/",
    "http://127.0.0.1.nip.io/admin",
    "http://allowed.com\\@10.0.0.1/",
    "http://user:pw@192.168.0.1/",
    "http://127.0.0.2/",
    "http://0/",
    "http://[::]/",
    "http://2852039166/",  # dword 169.254.169.254
]
HOLD = ["http://10.0.0.5/admin", "http://192.168.1.1", "http://172.16.4.4:8080/x", "10.1.2.3:8080",
        "http://[fe80::1%25eth0]/", "http://100.64.0.9/", "http://build.internal/"]
ALLOW = ["https://example.com/a?q=1", "http://127.0.0.1/x", "http://127.0.0.1:18098/kb/?q=x",
         "http://localhost:8080/", "http://[::1]/", "8.8.8.8", "https://1.1.1.1@example.com/",
         "https://docs.python.org/3/library/ipaddress.html"]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(*_a, **_k):
        raise AssertionError("guard touched the network")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "gethostbyname", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.mark.parametrize("url", DENY)
def test_deny(url):
    v = classify(url)
    assert v.verdict == "deny", v.as_dict()
    assert v.as_dict()["atlas_approximate"] is True


@pytest.mark.parametrize("url", HOLD)
def test_hold(url):
    assert classify(url).verdict == "hold", classify(url).as_dict()


@pytest.mark.parametrize("url", ALLOW)
def test_allow(url):
    assert classify(url).verdict == "allow", classify(url).as_dict()


def test_inet_aton_forms():
    for form in ("127.0.0.1", "2130706433", "0x7f000001", "0177.0.0.01", "127.1", "127.0.1", "0x7f.1"):
        assert parse_inet_aton(form) == ipaddress.IPv4Address("127.0.0.1"), form
    for bad in ("256.1.1.1", "1.2.3.4.5", "abc", "1..2", "4294967296"):
        assert parse_inet_aton(bad) is None, bad


def test_candidates_in_nested_and_free_text_args():
    assert inspect_arguments({"host": 2130706433}).verdict == "deny"
    assert inspect_arguments({"opts": {"callback_url": "http://169.254.169.254/"}}).verdict == "deny"
    assert inspect_arguments({"body": "see http://0x7f000001/ for details"}).verdict == "deny"
    assert inspect_arguments({"urls": ["https://example.com", "http://10.0.0.2/"]}).verdict == "hold"
    assert inspect_arguments({"body": "ordinary status update", "url": "https://example.com"}) is None
    # An intranet link in an email body is not a request target; an obfuscated one still is denied.
    assert inspect_arguments({"body": "wiki: http://10.0.0.5/runbook"}) is None
    assert inspect_arguments({"body": "wiki: http://0x0a000005/runbook"}).verdict == "deny"


def test_engine_denies_metadata_and_logs_finding(engine: PolicyEngine):
    out = engine.evaluate_call(KEY_A, "ssrf-1", "web.fetch",
                               {"url": "https://allowed.com@169.254.169.254/latest/meta-data"})
    assert out["ok"] is False and out["error"] == "ssrf_boundary_violation"
    assert out["atlas"] == "AML.T0053" and out["uri"]["category"] == "cloud_metadata"
    assert any(f["kind"] == "ssrf_boundary_violation" for f in engine.findings)
    # Not a freeze, and a denied fetch does not taint the session.
    assert not engine.registry.is_frozen_key(KEY_A, engine.now())
    assert engine.sessions["ssrf-1"].tainted is False
    log = engine.alert_path.read_text(encoding="utf-8")
    assert "ssrf_boundary_violation" in log


def test_engine_private_target_hold_released_by_bound_oob(engine: PolicyEngine):
    sid = "ssrf-2"
    args = {"url": "http://10.0.0.5/admin"}
    held = engine.evaluate_call(KEY_B, sid, "web.fetch", args)
    assert held["error"] == "ssrf_internal_target_hold"
    rec = approve.mint(sid, held["step_index"], "web.fetch", args)
    ok = engine.evaluate_call(KEY_B, sid, "web.fetch", args, approval_token=rec["token"],
                              bound_step_index=held["step_index"])
    assert ok["ok"] is True
    # A bound approval never releases a metadata target.
    meta = {"url": "http://169.254.169.254/"}
    denied = engine.evaluate_call(KEY_B, sid, "web.fetch", meta)
    rec2 = approve.mint(sid, denied["step_index"], "web.fetch", meta, taint_source_id=engine.sessions[sid].taint_source_id)
    again = engine.evaluate_call(KEY_B, sid, "web.fetch", meta, approval_token=rec2["token"],
                                 bound_step_index=denied["step_index"])
    assert again["error"] == "ssrf_boundary_violation"


def test_lab_loopback_fixtures_still_work(engine: PolicyEngine):
    assert engine.evaluate_call(KEY_A, "ssrf-3", "read_external_url", {"url": "http://127.0.0.1:18098/kb/x"})["ok"]


_octet = st.integers(min_value=0, max_value=255)


def _spell(ip: ipaddress.IPv4Address, form: str) -> str:
    o = [int(x) for x in str(ip).split(".")]
    n = int(ip)
    if form == "dword":
        return str(n)
    if form == "hex":
        return hex(n)
    if form == "hex_dotted":
        return ".".join(hex(x) for x in o)
    if form == "octal":
        return ".".join("0" + oct(x)[2:] for x in o)
    if form == "short":
        return f"{o[0]}.{(o[1] << 16) | (o[2] << 8) | o[3]}"
    if form == "mapped":
        return f"[::ffff:{ip}]"
    if form == "mapped_hex":
        return f"[::ffff:{n >> 16:x}:{n & 0xFFFF:x}]"
    raise ValueError(form)


@settings(max_examples=300, deadline=None, database=None)
@given(
    net=st.sampled_from(["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]),
    offset=st.integers(min_value=0, max_value=2**24),
    form=st.sampled_from(["dword", "hex", "hex_dotted", "octal", "short", "mapped", "mapped_hex"]),
    userinfo=st.sampled_from(["", "allowed.com@", "user:pw@"]),
    scheme=st.sampled_from(["http", "https", "HTTP", "gopher"]),
)
def test_property_obfuscated_internal_never_allowed(net, offset, form, userinfo, scheme):
    network = ipaddress.ip_network(net)
    ip = network.network_address + (offset % network.num_addresses)
    url = f"{scheme}://{userinfo}{_spell(ip, form)}/path"
    v = classify(url)
    assert v.verdict == "deny", (url, v.as_dict())
    assert v.canonical == str(ip)


@settings(max_examples=200, deadline=None, database=None)
@given(a=_octet, b=_octet, c=_octet, d=_octet)
def test_property_plain_dotted_quad_matches_ipaddress(a, b, c, d):
    ip = ipaddress.IPv4Address(f"{a}.{b}.{c}.{d}")
    v = classify(f"http://{ip}/")
    if str(ip) == "127.0.0.1":
        assert v.verdict == "allow"  # lab allowlist literal
    elif ip.is_global and not ip.is_multicast:
        assert v.verdict == "allow", v.as_dict()
    else:
        assert v.verdict in ("hold", "deny"), v.as_dict()
