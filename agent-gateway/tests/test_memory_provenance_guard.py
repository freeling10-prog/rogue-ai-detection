"""Hypothesis state machine for MemoryProvenanceGuard."""

from __future__ import annotations

from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from agent_gateway.memory_provenance_guard import MemoryProvenanceGuard


class MemoryProvenanceStateMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.guard = MemoryProvenanceGuard(hmac_key=b"hyp-key")
        self.taint = {"s1": 0, "s2": 0, "s3": 0}
        self.caps = {"s1": 0xFF, "s2": 0xFF, "s3": 0xFF}
        self.res_taint: dict[str, int] = {}
        self.res_caps: dict[str, int] = {}

    @rule(s=st.sampled_from(["s1", "s2", "s3"]), t=st.integers(0, 5), m=st.integers(0, 0xFF))
    def taint_session(self, s: str, t: int, m: int) -> None:
        self.taint[s] = max(self.taint[s], t)
        self.caps[s] &= m

    @rule(s=st.sampled_from(["s1", "s2", "s3"]), u=st.sampled_from(["m://1", "m://2"]))
    def write_res(self, s: str, u: str) -> None:
        self.guard.record_write(u, s, self.taint[s], self.caps[s])
        self.res_taint[u] = max(self.res_taint.get(u, 0), self.taint[s])
        self.res_caps[u] = self.res_caps.get(u, 0xFF) & self.caps[s]

    @rule(s=st.sampled_from(["s1", "s2", "s3"]), u=st.sampled_from(["m://1", "m://2"]))
    def read_res(self, s: str, u: str) -> None:
        r = self.guard.evaluate_read(u, self.taint[s], self.caps[s])
        assert r.allowed is True
        self.taint[s], self.caps[s] = r.effective_taint, r.effective_capability_mask
        if u in self.res_taint:
            assert self.taint[s] >= self.res_taint[u]
            assert (self.caps[s] & ~self.res_caps[u]) == 0


TestMemoryProvenanceMachine = MemoryProvenanceStateMachine.TestCase
TestMemoryProvenanceMachine.settings = settings(max_examples=50, stateful_step_count=15)
