"""Multi-agent confused-deputy / delegation guard. Taint cannot be laundered across hand-offs."""
from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from agent_gateway import capability
from agent_gateway.delegation_guard import (
    CapProfile,
    DelegationLedger,
    attenuate_for_handoff,
    profile_from_token,
    taint_source_hash,
)
from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState
from tests.conftest import KEY_A, KEY_B, REG

HMAC = "test-hmac-key-agent-gateway-lab!!"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", HMAC)


def _tok(session, agent, *, deny=False, sampling=False, taint=""):
    cap = capability.mint(session, agent, sampling=sampling)
    if deny:
        cap = capability.attenuate(cap, capability.CAVEAT_DENY_EGRESS)
    if taint:
        cap = capability.attenuate(cap, capability.taint_source_caveat(taint))
    return capability.serialize(cap)


def test_meet_is_monotonic():
    tainted = CapProfile(allow_egress=False, sensitive_read=True, taint_sources=frozenset({"h1"}))
    clean = CapProfile(allow_egress=True, allow_sampling=True)
    meet = tainted & clean
    assert meet.allow_egress is False and meet.allow_sampling is False
    assert meet.sensitive_read is True and meet.taint_sources == frozenset({"h1"})
    # meet never climbs back up, in either order
    assert (clean & tainted) == meet
    assert meet.restricts_at_least(tainted) and meet.restricts_at_least(clean)
    assert not clean.restricts_at_least(tainted)


def test_profile_from_token_reads_caveats():
    p = profile_from_token(_tok("s", KEY_A, deny=True, taint="web.fetch:2"), sensitive_read=True)
    assert p.allow_egress is False and p.sensitive_read is True
    assert p.taint_sources == frozenset({taint_source_hash("web.fetch:2")})
    assert profile_from_token("agw1.not.valid") is None
    clean = profile_from_token(_tok("s2", KEY_A, sampling=True))
    assert clean.allow_egress and clean.allow_sampling and not clean.tainted


def test_attenuate_for_handoff_cannot_be_laundered():
    parent = _tok("p", KEY_A, deny=True, taint="untrusted:1")
    child = _tok("c", KEY_B, sampling=True)  # clean peer with sampling
    handed = attenuate_for_handoff(parent, child)
    cap = capability.verify(handed)
    assert cap is not None and cap.allows_egress is False
    assert capability.allows_sampling(cap) is False  # sampling revoked by parent restriction
    assert cap.session_id == "c"  # recipient keeps its own binding
    # A recipient without the root key cannot strip the inherited deny caveat.
    forged = capability.serialize(capability.Capability(cap.session_id, cap.caveats[:3], cap.signature))
    assert capability.verify(forged) is None


def test_ledger_delegation_blocks_confused_deputy():
    led = DelegationLedger()
    led.observe("A", profile_from_token(_tok("pa", KEY_A, deny=True, taint="x"), sensitive_read=True))
    led.observe("B", profile_from_token(_tok("pb", KEY_B)))  # clean orchestrator
    assert led.check_egress("B", "send_email") is None  # not delegated yet
    led.delegate("A", "B")
    assert led.is_delegated("B")
    finding = led.check_egress("B", "send_email")
    assert finding and finding["kind"] == "confused_deputy_delegation_blocked"
    assert finding["atlas"] == ["AML.T0051", "AML.T0086"]
    # An internal read is not an egress class, so it is not blocked.
    assert led.check_egress("B", "lookup_order_status") is None
    assert led.would_launder("A", "B") is False  # after delegate, B already carries A's deny


# --- engine integration ------------------------------------------------------

@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATEWAY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", HMAC)
    cfg = PepConfig(registry_path=REG, alert_log=tmp_path / "alerts.jsonl")
    return PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)


def test_engine_delegate_task_laundering_blocked(engine: PolicyEngine):
    # Parent session gets tainted and reads a secret.
    assert engine.evaluate_call(KEY_A, "parent", "read_internal_secrets", {})["ok"]
    assert engine.evaluate_call(KEY_A, "parent", "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]
    assert engine.sessions["parent"].allow_egress is False
    # Parent hands off to a clean peer agent B. The clean peer must inherit the deny.
    out = engine.evaluate_call(KEY_A, "parent", "delegate_task",
                               {"to_agent_key": KEY_B, "to_session_id": "peer"})
    assert out["ok"] and out["delegation"]["allow_egress"] is False
    peer = engine.sessions["peer"]
    assert peer.allow_egress is False and peer.tainted
    assert capability.verify(peer.capability_token).allows_egress is False
    # The handed session itself is egress-closed by the inherited caveat (ordinary taint gate).
    blocked = engine.evaluate_call(KEY_B, "peer", "send_email", {"to": "x@lab.local", "body": "secret"})
    assert blocked["ok"] is False and blocked["error"] == "post_taint_outbound_gated"
    # A *fresh* clean session of the delegated principal B is caught by the confused-deputy gate:
    # its token looks clean, but B's principal was barred upstream.
    deputy = engine.evaluate_call(KEY_B, "peer_fresh", "send_email", {"to": "x@lab.local", "body": "hi"})
    assert deputy["ok"] is False and deputy["error"] == "confused_deputy_delegation_blocked"
    assert deputy["atlas"] == "AML.T0086"
    assert any(f["kind"] == "confused_deputy_delegation_blocked" for f in engine.findings)


def test_engine_clean_delegation_still_allows_egress(engine: PolicyEngine):
    # A clean parent delegating to a clean peer leaves the peer able to send.
    out = engine.evaluate_call(KEY_A, "p2", "delegate_task", {"to_agent_key": KEY_B, "to_session_id": "peer2"})
    assert out["delegation"]["allow_egress"] is True
    assert engine.evaluate_call(KEY_B, "peer2", "send_email", {"to": "a@b.c", "body": "hi"})["ok"] is True


def test_engine_independent_sessions_not_conflated(engine: PolicyEngine):
    # Two independent sessions of KEY_A: tainting one must not block the other (no hand-off).
    assert engine.evaluate_call(KEY_A, "s_taint", "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]
    assert engine.evaluate_call(KEY_A, "s_clean", "send_email", {"to": "a@b.c", "body": "ok"})["ok"] is True


# --- Hypothesis: taint never launders across a random delegation DAG ---------

AGENTS = ["A", "B", "C", "D"]


class DelegationDagMachine(RuleBasedStateMachine):
    """Random delegation edges and taint events. The ledger must mirror a
    monotonic meet: a delegation folds the sender's *current* restrictions
    into the recipient, and nothing ever regains egress."""

    @initialize()
    def setup(self):
        self._prev = os.environ.get("AGENT_GATEWAY_HMAC_KEY")
        os.environ["AGENT_GATEWAY_HMAC_KEY"] = HMAC
        self.led = DelegationLedger()
        self.expect_egress = {a: True for a in AGENTS}
        self.expect_sources: dict[str, frozenset] = {a: frozenset() for a in AGENTS}
        self.delegated: set[str] = set()
        for a in AGENTS:
            self.led.observe(a, CapProfile(allow_egress=True))

    def teardown(self):
        if getattr(self, "_prev", None) is None:
            os.environ.pop("AGENT_GATEWAY_HMAC_KEY", None)
        else:
            os.environ["AGENT_GATEWAY_HMAC_KEY"] = self._prev

    @rule(agent=st.sampled_from(AGENTS), src=st.sampled_from(["web.fetch", "scratchpad", "bus"]))
    def taint(self, agent, src):
        h = taint_source_hash(src)
        self.led.observe(agent, CapProfile(allow_egress=False, taint_sources=frozenset({h})))
        self.expect_egress[agent] = False
        self.expect_sources[agent] = self.expect_sources[agent] | {h}

    @rule(data=st.data())
    def delegate(self, data):
        src = data.draw(st.sampled_from(AGENTS))
        dst = data.draw(st.sampled_from([a for a in AGENTS if a != src]))
        self.led.delegate(src, dst)
        self.delegated.add(dst)
        self.expect_egress[dst] = self.expect_egress[dst] and self.expect_egress[src]
        self.expect_sources[dst] = self.expect_sources[dst] | self.expect_sources[src]

    @invariant()
    def ledger_matches_meet(self):
        for a in AGENTS:
            prof = self.led.profile(a)
            assert prof.allow_egress == self.expect_egress[a], a
            assert prof.taint_sources == self.expect_sources[a], a
            # A delegated, egress-closed principal is always blocked on an egress class,
            # never on an internal read; an open one is never blocked.
            if self.led.is_delegated(a) and not prof.allow_egress:
                assert self.led.check_egress(a, "send_email") is not None
                assert self.led.check_egress(a, "lookup_order_status") is None
            if prof.allow_egress:
                assert self.led.check_egress(a, "send_email") is None
            # Monotonic: no principal regains egress once it is closed.
            assert not (prof.allow_egress and not self.expect_egress[a])


TestDelegationDag = DelegationDagMachine.TestCase
TestDelegationDag.settings = settings(
    max_examples=120, stateful_step_count=24, deadline=None, database=None,
    suppress_health_check=[HealthCheck.too_slow],
)
