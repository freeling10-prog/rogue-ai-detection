"""Post-taint boolean-oracle and timing side-channel guard (approximate AML.T0086)."""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from hypothesis import HealthCheck, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test

from agent_gateway import approve
from agent_gateway.pep import PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.side_channel_guard import SideChannelGuard, SideChannelPolicy, interval_stats
from agent_gateway.taint import SharedState
from tests.conftest import CHILD_KEY, KEY_A, KEY_B, REG

HMAC = "test-hmac-key-agent-gateway-lab!!"


class _Clock:
    def __init__(self, t: float = 0.0):
        # Start at real time: OOB approval tokens expire against the wall clock.
        self.t = t or time.time()

    def __call__(self) -> float:
        return self.t


def _trifecta(engine: PolicyEngine, sid: str, key: str = KEY_A) -> None:
    assert engine.evaluate_call(key, sid, "read_internal_secrets", {})["ok"]
    assert engine.evaluate_call(key, sid, "read_external_url", {"url": "http://127.0.0.1/p"})["ok"]
    assert engine.sessions[sid].tainted and engine.sessions[sid].sensitive_read


def _fetch(engine, sid, path, key=KEY_A):
    return engine.evaluate_call(key, sid, "read_external_url", {"url": f"http://127.0.0.1/o/{path}"})


def test_interval_stats():
    assert interval_stats([0, 2, 4, 6]) == (2.0, 0.0, 3)
    mean, cv, n = interval_stats([0, 1, 9, 10])
    assert n == 3 and cv > 0.5
    assert interval_stats([5]) == (None, None, 0)


def test_branching_oracle_held_and_frozen(engine: PolicyEngine):
    clock = _Clock()
    engine._clock = clock
    sid = "sc-branch"
    _trifecta(engine, sid)  # the tainting fetch is variant 1
    outs, times = [], []
    for i in range(6):
        clock.t += [3, 11, 1, 7, 2, 13][i]  # irregular, so only branching can fire
        times.append(clock.t)
        outs.append(_fetch(engine, sid, f"bit{i}"))
    assert [o["ok"] for o in outs[:3]] == [True, True, True]
    held = outs[3]
    assert held["error"] == "covert_side_channel_suspected" and held["atlas"] == "AML.T0086"
    assert held["side_channel"]["reason"] == "branching" and held["side_channel"]["atlas_approximate"] is True
    assert set(held["frozen_agents"]) == {"lab-assistant-1", "lab-worker-child"}
    now = engine.now()
    assert engine.registry.is_frozen_key(CHILD_KEY, now) and not engine.registry.is_frozen_key(KEY_B, now)
    assert engine.registry.get(KEY_A).frozen_until == times[3] + 900
    assert engine.sessions[sid].review_hold == "covert_side_channel_suspected"
    assert outs[4]["error"] == "agent_frozen"
    # After the 15-minute freeze lifts, the session is still held for a person.
    clock.t += 901
    after = _fetch(engine, sid, "bit0")
    assert after["error"] == "session_review_hold" and after.get("approval_webhook")


def test_two_symbol_oracle_bounded_by_cardinality(engine: PolicyEngine):
    clock = _Clock()
    engine._clock = clock
    sid = "sc-card"
    _trifecta(engine, sid)
    gaps = [1.3, 4.1, 0.7, 9.0, 2.2, 6.5, 0.9, 3.3]
    released = 0
    for i in range(30):
        clock.t += gaps[i % len(gaps)] * (1 + i % 3)
        out = _fetch(engine, sid, "1" if i % 3 else "0")
        if not out["ok"]:
            assert out["side_channel"]["reason"] == "cardinality"
            break
        released += 1
    assert released + 1 == 16  # the tainting fetch counted as the first


def test_timing_beacon_held(engine: PolicyEngine):
    clock = _Clock()
    engine._clock = clock
    sid = "sc-beacon"
    _trifecta(engine, sid)
    results = []
    for _ in range(8):
        clock.t += 5.0
        results.append(_fetch(engine, sid, "same"))
    oks = [r["ok"] for r in results]
    assert False in oks
    held = results[oks.index(False)]
    assert held["side_channel"]["reason"] == "timing_beacon"
    assert held["side_channel"]["interval_cv"] == 0.0


def test_machine_speed_burst_is_not_a_beacon():
    guard = SideChannelGuard()
    t = 0.0
    for _ in range(10):
        t += 0.001
        assert guard.check("s", "read_external_url", {"url": "u"}, t) is None
        guard.commit("s", "read_external_url", {"url": "u"}, t)


def test_benign_workflows_pass(engine: PolicyEngine):
    clock = _Clock()
    engine._clock = clock
    # Clean session: no trifecta, any number of varied fetches.
    for i in range(30):
        clock.t += 2.0
        assert _fetch(engine, "clean", f"page{i}", key=KEY_B)["ok"]
    # Trifecta session doing a normal amount of follow-up work with human-ish timing.
    _trifecta(engine, "busy")
    for i, gap in enumerate([4, 31, 2, 17, 8]):
        clock.t += gap
        assert engine.evaluate_call(KEY_A, "busy", "update_ticket_status", {"order_id": 7, "status": "shipped"})["ok"]
    assert not engine.findings or all(f["kind"] != "covert_side_channel_suspected" for f in engine.findings)


def test_oob_approved_calls_not_counted(engine: PolicyEngine):
    clock = _Clock()
    engine._clock = clock
    sid = "sc-oob"
    _trifecta(engine, sid)
    for i in range(6):
        clock.t += 5.0
        args = {"to": "team@internal.local", "body": f"approved report {i}"}
        held = engine.evaluate_call(KEY_A, sid, "send_email", args)
        assert held["error"] == "post_taint_outbound_gated"
        rec = approve.mint(sid, held["step_index"], "send_email", args,
                           taint_source_id=engine.sessions[sid].taint_source_id)
        ok = engine.evaluate_call(KEY_A, sid, "send_email", args, approval_token=rec["token"],
                                  bound_step_index=held["step_index"])
        assert ok["ok"] is True, ok
    assert engine.side_channel.stats(sid)["post_taint_calls"] == 1


POLICY = SideChannelPolicy()


class SideChannelMachine(RuleBasedStateMachine):
    """Safety bounds on what a tainted + sensitive session can release.

    - at most ``max_calls`` released post-trifecta outbound calls
    - at most ``max_distinct`` distinct argument variants released
    - never ``beacon_min_intervals`` equal intervals (>= 0.5 s) in a row released
    - a held session never releases again; a clean session is never held
    """

    @initialize()
    def init_engine(self):
        self._prev = {k: os.environ.get(k) for k in ("AGENT_GATEWAY_STATE_DIR", "AGENT_GATEWAY_HMAC_KEY")}
        self._td = tempfile.TemporaryDirectory()
        os.environ["AGENT_GATEWAY_STATE_DIR"] = self._td.name
        os.environ["AGENT_GATEWAY_HMAC_KEY"] = HMAC
        cfg = PepConfig(registry_path=REG, alert_log=Path(self._td.name) / "alerts.jsonl")
        self.engine = PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)
        self.clock = _Clock()
        self.engine._clock = self.clock
        _trifecta(self.engine, "oracle")
        self.released = 1
        self.variants = {"http://127.0.0.1/p"}
        self.last_dt = None
        self.equal_run = 0
        self.held = False

    def teardown(self):
        td = getattr(self, "_td", None)
        if td is not None:
            td.cleanup()
        for k, v in getattr(self, "_prev", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _oracle(self, symbol: int, dt: float):
        self.clock.t += dt
        url = f"http://127.0.0.1/o/{symbol}"
        out = self.engine.evaluate_call(KEY_A, "oracle", "read_external_url", {"url": url})
        if self.held:
            assert out["ok"] is False
            return
        if out["ok"]:
            self.released += 1
            self.variants.add(url)
            same = self.last_dt is not None and abs(dt - self.last_dt) < 1e-9 and dt >= POLICY.beacon_min_mean_s
            self.equal_run = self.equal_run + 1 if same else 1
            self.last_dt = dt
            return
        assert out["error"] == "covert_side_channel_suspected", out
        sig = out["side_channel"]
        if sig["reason"] == "branching":
            assert sig["distinct_variants"] == POLICY.max_distinct + 1
        elif sig["reason"] == "cardinality":
            assert sig["post_taint_calls"] == POLICY.max_calls + 1
        else:
            assert sig["reason"] == "timing_beacon" and sig["interval_cv"] <= POLICY.beacon_max_cv
            assert sig["interval_mean_s"] >= POLICY.beacon_min_mean_s
        self.held = True

    @rule(symbol=st.integers(min_value=0, max_value=1), dt=st.floats(min_value=0.001, max_value=60))
    def jittered_bit(self, symbol, dt):
        self._oracle(symbol, dt)

    @rule(symbol=st.integers(min_value=0, max_value=7), dt=st.sampled_from([1.0, 2.5, 30.0]))
    def rhythmic_symbol(self, symbol, dt):
        self._oracle(symbol, dt)

    @rule(page=st.integers(min_value=0, max_value=1000), dt=st.floats(min_value=0.01, max_value=60))
    def clean_session_fetch(self, page, dt):
        self.clock.t += dt
        out = self.engine.evaluate_call(KEY_B, "clean", "read_external_url", {"url": f"http://127.0.0.1/c/{page}"})
        assert out["ok"] is True

    @invariant()
    def bounds(self):
        assert self.released <= POLICY.max_calls
        assert len(self.variants) <= POLICY.max_distinct
        assert self.equal_run <= POLICY.beacon_min_intervals  # n equal gaps need n+1 calls
        now = self.engine.now()
        assert self.engine.registry.is_frozen_key(KEY_A, now) == self.held or (
            self.held and self.engine.registry.get(KEY_A).frozen_until <= now)
        assert not self.engine.registry.is_frozen_key(KEY_B, now)
        assert self.engine.sessions["clean"].review_hold == "" if "clean" in self.engine.sessions else True


def test_side_channel_state_machine():
    run_state_machine_as_test(SideChannelMachine, settings=settings(
        max_examples=60, stateful_step_count=30, deadline=None, database=None,
        suppress_health_check=[HealthCheck.too_slow],
    ))
