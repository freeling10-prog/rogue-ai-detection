"""Unit tests and Hypothesis state machine for MemoryProvenanceGuard."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from agent_gateway.memory_provenance_guard import MAX_TAINT_LEVEL, MemoryProvenanceGuard, canonical_resource_id


def test_write_then_read_inherits_taint_and_keeps_origin_writer() -> None:
    guard = MemoryProvenanceGuard(hmac_key=b"unit-key")
    guard.record_write("memory://shared/notes", "tainted-writer", taint_level=3, capability_mask=0b0011)
    # A later clean write neither lowers the taint nor replaces the taint origin.
    rec = guard.record_write("memory://shared/notes", "clean-writer", taint_level=0, capability_mask=0b1111)
    assert rec.taint_level == 3 and rec.capability_mask == 0b0011
    assert rec.writer_session_id == "tainted-writer"

    res = guard.evaluate_read("memory://shared/notes", reader_taint=0, reader_capability_mask=0b1111)
    assert res.allowed is True
    assert res.verdict_code == "PROVENANCE_TAINT_INHERITED"
    assert res.effective_taint == 3 and res.effective_capability_mask == 0b0011
    assert res.writer_session_id == "tainted-writer"


def test_bool_inputs_raise_type_error() -> None:
    guard = MemoryProvenanceGuard(hmac_key=b"unit-key")
    with pytest.raises(TypeError):
        guard.record_write("memory://x", "s1", taint_level=True)
    with pytest.raises(TypeError):
        guard.record_write("memory://x", "s1", taint_level=0, capability_mask=False)
    with pytest.raises(TypeError):
        guard.evaluate_read("memory://x", reader_taint=True)
    with pytest.raises(TypeError):
        guard.evaluate_read("memory://x", reader_taint=0, reader_capability_mask=True)
    assert guard.export_ledger()["records"] == []


def test_tampered_record_denied_and_ledger_round_trip() -> None:
    guard = MemoryProvenanceGuard(hmac_key=b"unit-key")
    guard.record_write("memory://a", "s1", taint_level=2, capability_mask=0xF0)
    guard.record_write("memory://b", "s2", taint_level=0)
    exported = guard.export_ledger()

    restored = MemoryProvenanceGuard(hmac_key=b"unit-key")
    restored.load_ledger(exported)
    assert restored.export_ledger() == exported
    assert restored.evaluate_read("memory://a", reader_taint=0).effective_taint == 2
    # The sequence counter continues after the loaded records.
    assert restored.record_write("memory://c", "s3", taint_level=0).seq_num == exported["seq"] + 1

    # A record lowered in memory fails its HMAC on read.
    res_hash = canonical_resource_id("memory://a")
    guard._ledger[res_hash] = dataclasses.replace(guard._ledger[res_hash], taint_level=0)
    res = guard.evaluate_read("memory://a", reader_taint=1)
    assert res.allowed is False and res.verdict_code == "PROVENANCE_TAMPER_DENIED"
    assert res.effective_taint == MAX_TAINT_LEVEL and res.effective_capability_mask == 0

    # A tampered export is refused as a whole; a wrong key is refused too.
    bad = guard.export_ledger()
    target = MemoryProvenanceGuard(hmac_key=b"unit-key")
    target.load_ledger(exported)
    with pytest.raises(ValueError):
        target.load_ledger(bad)
    assert target.export_ledger() == exported
    with pytest.raises(ValueError):
        MemoryProvenanceGuard(hmac_key=b"other-key").load_ledger(exported)


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
