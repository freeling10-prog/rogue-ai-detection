"""Stateful Hypothesis checks for ``agentwatch.safelog.safe_text``.

Settings (hypothesis==6.170.9): max_examples=80, stateful_step_count=8.

The machine appends configured secret patterns (API keys, emails, bearer
tokens, decoy markers), percent-encoded and zero-width copies, and query
strings. ``safe_text`` must not emit those patterns. This does not change
honeypot blocking; public visitors stay human-review only.
"""
from __future__ import annotations

import os
from urllib.parse import quote

from hypothesis import HealthCheck, settings, strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    rule,
    run_state_machine_as_test,
)

from agentwatch.safelog import _DECOY, _QUERY, safe_text
from agentwatch.scrubber import PATTERNS, _match_view, reset_default_scrubber

SALT = "hypothesis-safelog-salt!!"
SAFELOG_SETTINGS = settings(
    max_examples=80,
    stateful_step_count=8,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _render_secret(kind: str, salt: str) -> str:
    if kind == "sk":
        return "sk-" + salt[:20]
    if kind == "gh":
        return "ghp_" + salt[:20]
    if kind == "akia":
        return "AKIA" + salt[:16].upper()
    if kind == "email":
        return f"user{salt[:8].lower()}@example.com"
    if kind == "bearer":
        return "Bearer " + salt[:18]
    if kind == "decoy":
        return "AWFAKE-DO-NOT-USE-" + salt[:8]
    if kind == "canary":
        return "AWCANARY-" + salt[:8].lower() + "-tundra"
    if kind == "password":
        return "NOT-A-REAL-PASSWORD-" + salt[:8]
    if kind == "session":
        return "sc-" + "0123456789"
    raise ValueError(kind)


class SafelogMachine(RuleBasedStateMachine):
    @initialize()
    def init_log(self):
        self._prev_salt = os.environ.get("AGENT_WATCH_SCRUB_SALT")
        os.environ["AGENT_WATCH_SCRUB_SALT"] = SALT
        reset_default_scrubber()
        self.chunks: list[str] = []
        self.secrets: list[str] = []

    def teardown(self):
        if not hasattr(self, "_prev_salt"):
            return
        if self._prev_salt is None:
            os.environ.pop("AGENT_WATCH_SCRUB_SALT", None)
        else:
            os.environ["AGENT_WATCH_SCRUB_SALT"] = self._prev_salt
        reset_default_scrubber()

    @rule(
        kind=st.sampled_from(["sk", "gh", "akia", "email", "bearer", "decoy", "canary", "password", "session"]),
        salt=st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=20, max_size=20),
    )
    def plant_raw(self, kind, salt):
        secret = _render_secret(kind, salt)
        self.secrets.append(secret)
        self.chunks.append(f"note {secret} end")

    @rule(
        kind=st.sampled_from(["sk", "gh", "akia", "email", "bearer"]),
        salt=st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=20, max_size=20),
    )
    def plant_percent_encoded(self, kind, salt):
        secret = _render_secret(kind, salt)
        self.secrets.append(secret)
        encoded = quote(secret, safe="")
        self.chunks.append("enc " + encoded)
        self.chunks.append("enc2 " + quote(encoded, safe=""))

    @rule(
        kind=st.sampled_from(["sk", "email", "bearer"]),
        salt=st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=20, max_size=20),
    )
    def plant_split_and_zero_width(self, kind, salt):
        secret = _render_secret(kind, salt)
        self.secrets.append(secret)
        cut = max(1, len(secret) // 2)
        self.chunks.append(secret[:cut] + "\n" + secret[cut:])
        self.chunks.append("\u200b".join(secret))

    @rule(
        kind=st.sampled_from(["sk", "akia", "email", "decoy"]),
        salt=st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=20, max_size=20),
    )
    def plant_query(self, kind, salt):
        secret = _render_secret(kind, salt)
        self.secrets.append(secret)
        self.chunks.append(f"GET /search?q={secret}&token=1 HTTP/1.1")

    @rule()
    def benign(self):
        self.chunks.append("status ok local note")

    @invariant()
    def scrubbed_log_has_no_configured_pattern(self):
        if not self.chunks:
            return
        out = safe_text("\n".join(self.chunks))
        view, _spans = _match_view(out)
        for secret in self.secrets:
            assert secret not in out
            assert secret not in view
        for _name, rx in PATTERNS:
            assert rx.search(out) is None
            assert rx.search(view) is None
        assert _DECOY.search(out) is None
        for match in _QUERY.finditer(out):
            assert match.group(0) == "?[query-redacted]"


def test_safelog_state_machine():
    reset_default_scrubber()
    try:
        run_state_machine_as_test(SafelogMachine, settings=SAFELOG_SETTINGS)
    finally:
        os.environ.pop("AGENT_WATCH_SCRUB_SALT", None)
        reset_default_scrubber()
