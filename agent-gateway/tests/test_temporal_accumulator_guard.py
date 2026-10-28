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


def test_zero_width_joiner_in_compound_emoji_is_not_a_watermark() -> None:
    guard = TemporalAccumulatorGuard(watermark_threshold=2)
    family = "\U0001F468‍\U0001F469‍\U0001F467‍\U0001F466"
    for _ in range(5):
        assert guard.evaluate_call("s1", "chat", {"text": f"team photo {family}"}).allowed is True


def test_no_plaintext_token_is_held() -> None:
    token = "PLAINTEXT_CANARY_5531"
    guard = TemporalAccumulatorGuard(protected_tokens=[token])
    held = repr(vars(guard))
    for form in (token, "UExBSU5URVhUX0NBTkFSWV81NTMx", token.encode().hex(), token[:8]):
        assert form not in held
    other = TemporalAccumulatorGuard(protected_tokens=[token])
    assert other._scopes[None].digests != guard._scopes[None].digests  # salted per instance


def test_session_scoped_token_applies_only_to_that_session() -> None:
    guard = TemporalAccumulatorGuard()
    guard.register_protected_token("SCOPED_SECRET_4410", session_id="s1")
    assert guard.protected_count("s1") == 1 and guard.protected_count("s2") == 0
    assert guard.evaluate_call("s2", "out", {"b": "SCOPED_SECRET_4410"}).allowed is True
    assert guard.evaluate_call("s1", "out", {"b": "SCOPED_SECRET_4410"}).allowed is False


def test_single_ngram_is_not_enough() -> None:
    guard = TemporalAccumulatorGuard(protected_tokens=["PROTECTED_CANARY_882190"], ngram_size=8)
    assert guard.evaluate_call("s1", "out", {"x": "PROTECTE"}).allowed is True  # one 8-gram
    res = guard.evaluate_call("s1", "out", {"x": "D"})  # second distinct 8-gram
    assert res.allowed is False and res.matched_rule == "NGRAM_STREAM_MATCH"


def test_denied_call_does_not_poison_the_window() -> None:
    guard = TemporalAccumulatorGuard(protected_tokens=["ALPHA_KEY_42"], watermark_threshold=3)
    assert guard.evaluate_call("s1", "net", {"p": "ALPHA_KEY_42"}).allowed is False
    assert guard.evaluate_call("s1", "net", {"p": "status ok"}).allowed is True
    assert guard.evaluate_call("s1", "net", {"w": "​​‌"}).allowed is False
    assert guard.evaluate_call("s1", "net", {"w": "fine​"}).allowed is True
