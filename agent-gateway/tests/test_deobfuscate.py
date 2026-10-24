"""Cross-step smuggling and encoding de-obfuscation (approximate AML.T0086). Zero compute."""
from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from agent_gateway.deobfuscate import DeobfuscationGuard, secret_candidates
from agent_gateway.pep import PolicyEngine
from tests.conftest import KEY_A, KEY_B, CHILD_KEY

LAB_SECRET = "secret_value_123"


def _chunks(text: str, size: int) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


def _leaks(guard: DeobfuscationGuard, sid: str, pieces: list[dict]) -> bool:
    for args in pieces:
        if guard.scan(sid, "send_email", args) is not None:
            return True
        guard.commit(sid, "send_email", args)
    return False


def test_guard_keeps_only_digests():
    g = DeobfuscationGuard()
    assert g.register(LAB_SECRET, session_id="s")
    blob = repr(vars(g))
    for form in (LAB_SECRET, base64.b64encode(LAB_SECRET.encode()).decode(), LAB_SECRET.encode().hex()):
        assert form not in blob
        assert form[:8] not in blob


@pytest.mark.parametrize("encode", [
    lambda s: s,
    lambda s: base64.b64encode(s.encode()).decode(),
    lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="),
    lambda s: s.encode().hex(),
    lambda s: s.encode().hex().upper(),
    lambda s: urllib.parse.quote(s, safe=""),
    lambda s: " ".join(s),
], ids=["raw", "b64", "b64url", "hex", "HEX", "url", "spaced"])
def test_whole_encoded_secret_caught(encode):
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    assert g.scan("s", "send_email", {"body": f"report: {encode(LAB_SECRET)}"}) is not None


@pytest.mark.parametrize("size", [4, 5, 6])
def test_split_raw_chunks_caught(size):
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    assert _leaks(g, "s", [{"q": c} for c in _chunks(LAB_SECRET, size)])


def test_encode_then_split_caught():
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    b64 = base64.b64encode(LAB_SECRET.encode()).decode()
    assert _leaks(g, "s", [{"memo": c} for c in _chunks(b64, 5)])


@pytest.mark.parametrize("enc", ["b64", "hex", "url"])
def test_split_then_encode_each_chunk_caught(enc):
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    pieces = []
    for c in _chunks(LAB_SECRET, 4):
        if enc == "b64":
            pieces.append({"body": base64.b64encode(c.encode()).decode()})
        elif enc == "hex":
            pieces.append({"body": c.encode().hex()})
        else:
            pieces.append({"body": "".join(f"%{b:02X}" for b in c.encode())})
    assert _leaks(g, "s", pieces)


def test_interleaved_fields_use_per_key_stream():
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    pieces = [{"to": "team@internal.local", "subject": f"note {i}", "body": c}
              for i, c in enumerate(_chunks(LAB_SECRET, 4))]
    assert _leaks(g, "s", pieces)


def test_benign_traffic_and_other_sessions_not_flagged():
    g = DeobfuscationGuard()
    g.register(LAB_SECRET, session_id="s")
    benign = [{"to": "team@internal.local", "body": t} for t in (
        "Status OK", "secret santa is friday", "value: 123", "the order shipped",
    )]
    assert not _leaks(g, "s", benign)
    # Session-scoped fingerprints do not leak into another session.
    assert g.scan("other", "send_email", {"body": LAB_SECRET}) is None
    # A global canary applies everywhere.
    g.register("canary-ZX81-qq-lab", label="canary")
    assert g.scan("other", "send_email", {"body": "canary-ZX81"}) is not None


def test_short_values_ignored_and_free_text_tokenized():
    g = DeobfuscationGuard()
    assert g.register("abc", session_id="s") is False
    assert secret_candidates("your key is sk-abcdefghijklmnop ok") == ["sk-abcdefghijklmnop"]
    assert secret_candidates(json.dumps({"password": "hunter2hunter2"})) == ["hunter2hunter2"]


def test_engine_split_exfil_freezes_registered_root(engine: PolicyEngine):
    sid = "d1"
    assert engine.evaluate_call(KEY_A, sid, "read_internal_secrets", {})["ok"]
    first = engine.evaluate_call(KEY_A, sid, "send_email", {"to": "x@lab.local", "body": "secr"})
    assert first["ok"] is True
    out = engine.evaluate_call(KEY_A, sid, "send_email", {"to": "x@lab.local", "body": "et_v"})
    assert out["ok"] is False
    assert out["error"] == "deobfuscated_exfil_detected"
    assert out["atlas"] == "AML.T0086" and out["leak"]["atlas_approximate"] is True
    assert set(out["frozen_agents"]) == {"lab-assistant-1", "lab-worker-child"}
    now = engine.now()
    assert engine.registry.is_frozen_key(KEY_A, now)
    assert engine.registry.is_frozen_key(CHILD_KEY, now)
    assert not engine.registry.is_frozen_key(KEY_B, now)
    assert engine.sessions[sid].allow_egress is False
    rec = engine.registry.get(KEY_A)
    assert rec.frozen_until - now == pytest.approx(900, abs=2)
    assert any(f["kind"] == "deobfuscated_exfil_detected" for f in engine.findings)


def test_engine_denied_calls_do_not_fill_the_window(engine: PolicyEngine):
    sid = "d2"
    assert engine.evaluate_call(KEY_B, sid, "read_internal_secrets", {})["ok"]
    assert engine.evaluate_call(KEY_B, sid, "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]
    # Tainted: send is held, so nothing leaves and nothing joins the window.
    for c in _chunks(LAB_SECRET, 4):
        held = engine.evaluate_call(KEY_B, sid, "send_email", {"to": "x@lab.local", "body": c})
        assert held["error"] == "post_taint_outbound_gated"
    assert not engine.registry.is_frozen_key(KEY_B, engine.now())


def test_engine_canary_registration(engine: PolicyEngine):
    assert engine.register_canary("AGW-CANARY-7f3e91")
    enc = base64.b64encode(b"AGW-CANARY-7f3e91").decode()
    out = engine.evaluate_call(KEY_B, "d3", "send_webhook", {"url": "http://127.0.0.1/h", "payload": enc})
    assert out["error"] == "deobfuscated_exfil_detected"
    assert engine.registry.is_frozen_key(KEY_B, engine.now())
