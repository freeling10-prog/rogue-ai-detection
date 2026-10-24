"""Forensic canary watermark + credential tracker (approximate AML.T0086)."""
from __future__ import annotations


import pytest
from hypothesis import given, settings, strategies as st

from agent_gateway.canary_watermark import (
    CanaryRegistry,
    canary_tag,
    find_credentials,
)
from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState
from tests.conftest import KEY_A, KEY_B, REG

HMAC = "test-hmac-key-agent-gateway-lab!!"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", HMAC)


def _visible(text: str) -> str:
    return "".join(c for c in text if not (0x200b <= ord(c) <= 0x200f or 0x2060 <= ord(c) <= 0x2064))


CREDS = [
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_access_key", "ASIAZ7XMPLE4Q2EXAMPLE"[:20]),
    ("github_token", "ghp_" + "a" * 36),
    ("github_token", "github_pat_" + "B" * 22),
    ("anthropic_key", "sk-ant-api03-" + "x" * 40),
    ("openai_key", "sk-proj-" + "y" * 40),
    ("google_api_key", "AIza" + "b" * 35),
    # Built by concatenation and deliberately non-numeric so no real-token literal sits in the file
    # (secret-scanning push protection); still matches the xox[baprs]- detector regex.
    ("slack_token", "xox" + "b-" + "EXAMPLEONLY-" + "NOTAREALTOKEN"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM"),
    ("pem_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"),
]


@pytest.mark.parametrize("kind,value", CREDS)
def test_credential_patterns_detected(kind, value):
    kinds = {k for k, _ in find_credentials(value)}
    assert kind in kinds, (kind, kinds)


def test_benign_text_has_no_credentials():
    for text in ["the order shipped on tuesday", "status: ok", "AKIA is an airport code", "sk- is a prefix"]:
        assert find_credentials(text) == []


def test_watermark_invisible_and_traced():
    r = CanaryRegistry()
    out = r.watermark_output("s1", 4, "read_internal_secrets", "DB creds attached")
    assert _visible(out) == "DB creds attached"  # nothing visible changed
    assert out != "DB creds attached"  # but zero-width watermark is present
    prov = r.scan_outbound("s1", {"body": "forwarding: " + out})
    assert prov is not None
    assert prov.origin_step_index == 4 and prov.origin_tool_name == "read_internal_secrets"
    assert prov.kind == "watermark"
    assert prov.as_dict()["atlas"] == "AML.T0086"


def test_watermark_survives_prefix_copy():
    r = CanaryRegistry()
    out = r.watermark_output("s", 1, "vault.read", "token value here")
    # The watermark rides after the first space, so copying "token <mark>value" still carries it.
    first_two = out.split("value")[0] + "value"
    assert r.scan_outbound("s", {"q": first_two}) is not None


def test_credential_retyped_without_watermark_still_caught():
    r = CanaryRegistry()
    r.watermark_output("s", 2, "secrets.get", "key is AKIAIOSFODNN7EXAMPLE ok")
    # Attacker strips the watermark but leaks the credential verbatim.
    prov = r.scan_outbound("s", {"url": "https://x/?k=AKIAIOSFODNN7EXAMPLE"})
    assert prov is not None and prov.kind == "credential:aws_access_key"
    assert prov.origin_step_index == 2 and prov.origin_tool_name == "secrets.get"


def test_sessions_isolated_and_benign_clean():
    r = CanaryRegistry()
    out = r.watermark_output("s1", 1, "vault.read", "secret AKIAIOSFODNN7EXAMPLE")
    assert r.scan_outbound("s2", {"body": out}) is None          # other session
    assert r.scan_outbound("s1", {"body": "status ok, nothing to see"}) is None  # benign


def test_canary_tag_is_deterministic_and_bound():
    assert canary_tag("s", 3, "t") == canary_tag("s", 3, "t")
    assert canary_tag("s", 3, "t") != canary_tag("s", 4, "t")
    assert canary_tag("s", 3, "t") != canary_tag("s2", 3, "t")


# --- engine integration ------------------------------------------------------

@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", HMAC)
    cfg = PepConfig(registry_path=tmp_path and REG, alert_log=tmp_path / "alerts.jsonl")
    return PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)


def test_engine_watermark_exfil_denied_and_frozen(engine: PolicyEngine):
    read = engine.evaluate_call(KEY_A, "sess", "read_internal_secrets", {})
    marked = read["result"]["secret"]
    assert _visible(marked) == "secret_value_123"
    step = read["step_index"]
    # Session is now sensitive + (after a fetch) tainted; approve a send that leaks the watermark.
    out = engine.evaluate_call(KEY_A, "sess", "send_email",
                               {"to": "x@lab.local", "body": "summary " + marked})
    # The send is held while tainted; use a bound OOB so we reach the canary gate, which still denies.
    from agent_gateway import approve
    if out["error"] != "canary_watermark_exfil":
        rec = approve.mint("sess", out["step_index"], "send_email",
                           {"to": "x@lab.local", "body": "summary " + marked},
                           taint_source_id=engine.sessions["sess"].taint_source_id)
        out = engine.evaluate_call(KEY_A, "sess", "send_email", {"to": "x@lab.local", "body": "summary " + marked},
                                   approval_token=rec["token"], bound_step_index=out["step_index"])
    assert out["ok"] is False and out["error"] == "canary_watermark_exfil"
    assert out["provenance"]["origin_tool_name"] == "read_internal_secrets"
    assert out["provenance"]["origin_step_index"] == step
    assert set(out["frozen_agents"]) == {"lab-assistant-1", "lab-worker-child"}
    assert engine.registry.is_frozen_key(KEY_A, engine.now())
    assert not engine.registry.is_frozen_key(KEY_B, engine.now())
    # Provenance is in the hash-chained decision log.
    log = engine.alert_path.read_text(encoding="utf-8")
    assert "canary_watermark_exfil" in log and "read_internal_secrets" in log


def test_engine_credential_fixture_exfil(engine: PolicyEngine):
    engine.cfg.lab_fixture_outputs["vault.read"] = "db url with key AKIAIOSFODNN7EXAMPLE embedded"
    engine.evaluate_call(KEY_B, "s", "vault.read", {"path": "db"})
    out = engine.evaluate_call(KEY_B, "s", "send_webhook",
                               {"url": "http://127.0.0.1/h", "payload": "AKIAIOSFODNN7EXAMPLE"})
    assert out["error"] in ("canary_watermark_exfil",)
    assert out["provenance"]["match_kind"] == "credential:aws_access_key"
    assert engine.registry.is_frozen_key(KEY_B, engine.now())


_B32 = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", min_size=30, max_size=50)


@settings(max_examples=150, deadline=None, database=None)
@given(prefix=st.text(max_size=30), step=st.integers(min_value=0, max_value=50), tail=st.text(max_size=30))
def test_property_watermark_roundtrips(prefix, step, tail):
    r = CanaryRegistry()
    out = r.watermark_output("sess", step, "read_internal_secrets", prefix + " body " + tail)
    # Whatever the surrounding text, the woven watermark is detectable with its provenance.
    prov = r.scan_outbound("sess", {"body": "leak: " + out})
    assert prov is not None and prov.origin_step_index == step


@settings(max_examples=150, deadline=None, database=None)
@given(secret=_B32, carrier=st.text(max_size=40))
def test_property_tracked_credential_always_flagged(secret, carrier):
    cred = "AKIA" + secret[:16]
    r = CanaryRegistry()
    r.register_credentials("s", 7, "vault.read", f"the key is {cred}")
    prov = r.scan_outbound("s", {"body": f"{carrier} {cred} {carrier}"})
    assert prov is not None and prov.kind == "credential:aws_access_key"
