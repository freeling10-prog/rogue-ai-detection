"""Tests and Hypothesis state machine for TemporalAccumulatorGuard."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from agent_gateway.temporal_accumulator_guard import TemporalAccumulatorGuard


def test_benign_calls_and_session_isolation() -> None:
    guard = TemporalAccumulatorGuard(protected_tokens=["SECRET_TOKEN_987654"])
    assert guard.evaluate_call("s1", "api", {"q": "SECRET_"}).allowed is True
    # Each piece is shorter than one 8-gram; joined ("SECRET_TOKEN_9") they would trip,
    # so this shows the two sessions' windows are not merged.
    assert guard.evaluate_call("s2", "api", {"q": "TOKEN_9"}).allowed is True


def test_hex_base64_and_watermark_accumulation() -> None:
    guard = TemporalAccumulatorGuard(protected_tokens=["ALPHA_KEY_42"], watermark_threshold=3)
    # Hex chunks of ALPHA_KEY_42 ("414c5048415f4b45595f3432")
    assert guard.evaluate_call("s1", "net", {"p": "414c5048415f"}).allowed is True
    res = guard.evaluate_call("s1", "net", {"p": "4b45595f3432"})
    assert res.allowed is False and res.matched_rule == "HEX_STREAM_MATCH"

    for _ in range(2):
        assert guard.evaluate_call("s2", "net", {"w": "ok\u200b"}).allowed is True
    w_res = guard.evaluate_call("s2", "net", {"w": "end\u200c"})
    assert w_res.allowed is False and w_res.matched_rule == "CUMULATIVE_WATERMARK_THRESHOLD"


@given(step=st.integers(min_value=2, max_value=5))
@settings(max_examples=30)
def test_chunked_token_caught_across_calls(step: int) -> None:
    token = "PROTECTED_CANARY_882190"
    guard = TemporalAccumulatorGuard(protected_tokens=[token], ngram_size=8)
    denied = False
    for i in range(0, len(token), step):
        d = guard.evaluate_call("s1", "out", {"frag": token[i : i + step]})
        if not d.allowed:
            denied = True
            assert d.verdict_code == "SHARDED_EXFIL_DENIED"
            break
    assert denied is True


class TemporalAccumulatorStateMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.token = "SENTINEL_MARKER_774123"
        self.guard = TemporalAccumulatorGuard(protected_tokens=[self.token], ngram_size=8)
        self.cursor = 0
        self.tripped = False

    @rule(word=st.sampled_from(["status", "ping", "list", "health"]))
    def benign_call(self, word: str) -> None:
        if not self.tripped:
            d = self.guard.evaluate_call("s-clean", "out", {"cmd": word})
            assert d.allowed is True

    @rule(width=st.integers(min_value=3, max_value=6))
    def emit_piece(self, width: int) -> None:
        piece = self.token[self.cursor : self.cursor + width]
        self.cursor += width
        d = self.guard.evaluate_call("s-stream", "out", {"part": piece})
        if not d.allowed:
            self.tripped = True
        if self.cursor >= len(self.token):
            assert self.tripped is True


TestTemporalAccumulatorMachine = TemporalAccumulatorStateMachine.TestCase
TestTemporalAccumulatorMachine.settings = settings(max_examples=40, stateful_step_count=12)
