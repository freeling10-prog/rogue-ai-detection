"""Bounded sliding-window stream validator for multi-call token and watermark checks.

Protected tokens are never held in plaintext. Registration keeps only salted
SHA-256 digests (salt drawn per instance) of each token, its Base64 and hex
spellings, and its ``ngram_size``-character n-grams. A token is registered
for every session or for one ``session_id``. A window is persisted
only when the call is allowed (``STREAM_CLEAN``), so a denied call does not
leave its fragment behind to poison later benign calls in the same window.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# U+200D (zero-width joiner) is left out: it joins compound emoji, so counting it
# would let ordinary text trip the watermark threshold.
ZERO_WIDTH_CHARS: Set[str] = {"​", "‌", "⁠", "﻿"}

_DIRECT = "DIRECT_STREAM_MATCH"
_BASE64 = "BASE64_STREAM_MATCH"
_HEX = "HEX_STREAM_MATCH"
_NGRAM = "NGRAM_STREAM_MATCH"
_MIN_NGRAM_HITS = 2


def _count_watermarks(text: str) -> int:
    return sum(1 for ch in text if ch in ZERO_WIDTH_CHARS or (0xE0020 <= ord(ch) <= 0xE007F))


def _extract_fragments(args: Any) -> Tuple[str, str]:
    raw_parts: List[str] = []
    norm_parts: List[str] = []

    def _walk(val: Any) -> None:
        if isinstance(val, bool) or val is None:
            return
        if isinstance(val, str):
            raw_parts.append(val)
            norm_parts.append("".join(ch for ch in val if 32 <= ord(ch) <= 126))
        elif isinstance(val, int) and 32 <= val <= 126:
            norm_parts.append(chr(val))
        elif isinstance(val, (list, tuple)):
            for item in val:
                _walk(item)
        elif isinstance(val, dict):
            for k in sorted(val.keys()):
                _walk(val[k])

    _walk(args)
    return "".join(raw_parts), "".join(norm_parts)


@dataclass(frozen=True)
class AccumulatorDecision:
    allowed: bool
    verdict_code: str
    matched_rule: Optional[str] = None
    window_length: int = 0


@dataclass
class _Scope:
    """Salted digests for one registration scope (all sessions, or one session)."""
    digests: Dict[str, Set[str]] = field(default_factory=lambda: {_DIRECT: set(), _BASE64: set(), _HEX: set()})
    lengths: Dict[str, Set[int]] = field(default_factory=lambda: {_DIRECT: set(), _BASE64: set(), _HEX: set()})
    ngrams: Set[str] = field(default_factory=set)


@dataclass
class _Window:
    raw: str = ""
    norm: str = ""
    total: int = 0  # normalized characters ever appended to this window
    grams: Dict[str, int] = field(default_factory=dict)  # matched n-gram digest -> absolute start


class TemporalAccumulatorGuard:
    """Per-(session, destination) rolling window validator for split tokens and watermarks."""

    def __init__(
        self,
        protected_tokens: Optional[Iterable[str]] = None,
        max_window_chars: int = 4096,
        ngram_size: int = 8,
        watermark_threshold: int = 4,
    ) -> None:
        if not isinstance(max_window_chars, int) or isinstance(max_window_chars, bool) or max_window_chars < 64:
            raise ValueError("max_window_chars must be an int >= 64")
        self._max_window = max_window_chars
        self._ngram_size = max(4, ngram_size)
        self._watermark_threshold = max(1, watermark_threshold)
        self._salt = secrets.token_bytes(16)
        self._windows: Dict[Tuple[str, str], _Window] = {}
        self._scopes: Dict[Optional[str], _Scope] = {None: _Scope()}
        for tok in protected_tokens or ():
            self.register_protected_token(tok)

    def _digest(self, text: str) -> str:
        return hashlib.sha256(self._salt + text.encode("utf-8")).hexdigest()

    def register_protected_token(self, token: str, session_id: Optional[str] = None) -> None:
        """Protect ``token`` in every session, or only in ``session_id``."""
        if not isinstance(token, str) or not token:
            return
        scope = self._scopes.setdefault(None if session_id is None else str(session_id), _Scope())
        raw = token.encode("utf-8")
        for rule, form in ((_DIRECT, token),
                           (_BASE64, base64.b64encode(raw).decode("ascii").rstrip("=")),
                           (_HEX, binascii.hexlify(raw).decode("ascii"))):
            scope.digests[rule].add(self._digest(form))
            scope.lengths[rule].add(len(form))
        n = self._ngram_size
        for i in range(len(token) - n + 1):
            scope.ngrams.add(self._digest(token[i : i + n]))

    def protected_count(self, session_id: Optional[str] = None) -> int:
        """Distinct protected tokens that apply to ``session_id`` (global ones only when None)."""
        return sum(len(s.digests[_DIRECT]) for s in self._applicable(session_id))

    def _applicable(self, session_id: Optional[str]) -> List[_Scope]:
        scopes = [self._scopes[None]]
        if session_id is not None and str(session_id) in self._scopes:
            scopes.append(self._scopes[str(session_id)])
        return scopes

    def reset_session(self, session_id: str) -> None:
        for key in [k for k in self._windows if k[0] == session_id]:
            self._windows.pop(key, None)

    def _match_stream(
        self, scopes: List[_Scope], window: str, new_start: int, win_start: int, grams: Dict[str, int],
    ) -> Optional[str]:
        """Check every substring that ends inside the newly appended text.

        Substrings wholly inside the persisted part were checked when it was
        allowed, so they cannot match now. ``grams`` is updated in place.
        """
        for rule in (_DIRECT, _BASE64, _HEX):
            digests = set().union(*(s.digests[rule] for s in scopes))
            for length in set().union(*(s.lengths[rule] for s in scopes)):
                for i in range(max(0, new_start - length + 1), len(window) - length + 1):
                    sub = window[i : i + length]
                    if self._digest(sub.lower() if rule == _HEX else sub) in digests:
                        return rule
        ngrams = set().union(*(s.ngrams for s in scopes))
        if ngrams:
            n = self._ngram_size
            for i in range(max(0, new_start - n + 1), len(window) - n + 1):
                d = self._digest(window[i : i + n])
                if d in ngrams:
                    grams[d] = win_start + i
            if len(grams) >= _MIN_NGRAM_HITS:
                return _NGRAM
        return None

    def evaluate_call(self, session_id: str, destination_class: str, tool_args: Any) -> AccumulatorDecision:
        key = (str(session_id), str(destination_class))
        prev = self._windows.get(key) or _Window()
        raw_frag, norm_frag = _extract_fragments(tool_args)
        raw_win = (prev.raw + raw_frag)[-self._max_window :]
        norm_win = (prev.norm + norm_frag)[-self._max_window :]
        total = prev.total + len(norm_frag)
        win_start = total - len(norm_win)
        new_start = max(0, len(norm_win) - len(norm_frag))
        grams = {d: pos for d, pos in prev.grams.items() if pos >= win_start}

        if _count_watermarks(raw_win) >= self._watermark_threshold:
            return AccumulatorDecision(False, "SHARDED_EXFIL_DENIED", "CUMULATIVE_WATERMARK_THRESHOLD", len(norm_win))
        matched = self._match_stream(self._applicable(session_id), norm_win, new_start, win_start, grams)
        if matched is not None:
            return AccumulatorDecision(False, "SHARDED_EXFIL_DENIED", matched, len(norm_win))
        self._windows[key] = _Window(raw_win, norm_win, total, grams)
        return AccumulatorDecision(True, "STREAM_CLEAN", None, len(norm_win))
