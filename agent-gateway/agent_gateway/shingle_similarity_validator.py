"""Bounded rolling-shingle + exact bit-parallel LCS matcher.

No runtime dependencies. Audit fields contain only keyed content hashes,
fixed reason codes and booleans. The private index remains sensitive state.
"""
from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass, field

from .common import Denied, scalar_text

MASK = (1 << 64) - 1
BASE = 1315423911
SEPARATORS = frozenset("-_./ ")
MAX_PATTERNS = 16
MAX_LENGTH = 256
NORMALIZATION_VERSION = "nfkc-casefold-filter-fixedpoint-v2"


def _stable_view(text: str, *, compact: bool) -> str:
    # Filtering can expose combining sequences. Require a fixed point instead
    # of assuming that one normalize-then-filter pass is idempotent.
    for _ in range(4):
        normalized = unicodedata.normalize(
            "NFKC", unicodedata.normalize("NFKC", text).casefold())
        normalized = "".join(
            ch for ch in normalized if unicodedata.category(ch) != "Cf"
            and (not compact or (ch not in SEPARATORS and not ch.isspace())))
        if len(normalized) > MAX_LENGTH:
            raise Denied("NORMALIZED_LENGTH")
        if normalized == text:
            return normalized
        text = normalized
    raise Denied("NORMALIZATION_STABILITY")


def views(text: str) -> tuple[str, str]:
    scalar_text(text, 1024)
    # Finite, explicit transform family. Does not decode arbitrary encodings.
    base = _stable_view(text, compact=False)
    compact = _stable_view(base, compact=True)
    return base, compact


def rolling_hashes(text: str, k: int):
    """Yield (offset, hash) in O(len(text)) for one fixed k."""
    if k < 1:
        raise ValueError("positive k required")
    if len(text) < k:
        return
    high = pow(BASE, k - 1, 1 << 64)
    value = 0
    for ch in text[:k]:
        value = (value * BASE + ord(ch) + 1) & MASK
    yield 0, value
    for i in range(k, len(text)):
        value = ((value - (ord(text[i - k]) + 1) * high) * BASE
                 + ord(text[i]) + 1) & MASK
        yield i - k + 1, value


def bit_masks(text: str) -> dict[str, int]:
    masks = {}
    for i, ch in enumerate(text):
        masks[ch] = masks.get(ch, 0) | (1 << i)
    return masks


def lcs_length(masks: dict[str, int], query: str) -> int:
    state = 0
    for ch in query:
        x = masks.get(ch, 0) | state
        state = x & ~(x - ((state << 1) | 1))
    return state.bit_count()


@dataclass(frozen=True, slots=True)
class Decision:
    blocked: bool
    reason: str
    identifier_hash: str
    protected_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Pattern:
    audit_hash: str
    length: int
    masks: dict[str, int] = field(repr=False)


@dataclass(slots=True)
class GramIndex:
    rolling: set[int] = field(default_factory=set, repr=False)
    tags: dict[bytes, str] = field(default_factory=dict, repr=False)


class Matcher:
    def __init__(self, key: bytes, protected: tuple[str, ...], k=12,
                 threshold_percent=85, minimum_match=12):
        if not 16 <= len(key) <= 64 or not 1 <= len(protected) <= MAX_PATTERNS:
            raise Denied("MATCHER_CONFIG")
        if not 4 <= k <= 16 or not 1 <= threshold_percent <= 100 or not 1 <= minimum_match <= 256:
            raise Denied("MATCHER_THRESHOLDS")
        self._key = bytes(key)
        self.k = k
        self.threshold = threshold_percent
        self.minimum_match = minimum_match
        self._patterns: list[list[Pattern]] = [[], []]
        # Split the cheap membership filter from keyed equality confirmations.
        # Avoid one Python dict per individual shingle.
        self._indices: list[dict[int, GramIndex]] = [{}, {}]
        for text in protected:
            normalized = views(text)
            if min(map(len, normalized)) < 4:
                raise Denied("PROTECTED_STRING_TOO_SHORT")
            pid = self._tag(b"protected", text.encode("utf-8")).hex()
            for mode, norm in enumerate(normalized):
                self._patterns[mode].append(Pattern(pid, len(norm), bit_masks(norm)))
                length = min(k, len(norm))
                index = self._indices[mode].setdefault(length, GramIndex())
                for offset, rolling in rolling_hashes(norm, length):
                    tag = self._tag(b"gram", norm[offset:offset + length].encode("utf-8"))
                    index.rolling.add(rolling)
                    index.tags.setdefault(tag, pid)

    def _tag(self, domain: bytes, value: bytes) -> bytes:
        return hmac.digest(self._key, domain + b"\0" + value, hashlib.sha256)

    def check(self, text: str) -> Decision:
        normalized = views(text)  # Limits fail closed, never silently truncate.
        query_id = self._tag(b"identifier", text.encode("utf-8")).hex()
        for mode, norm in enumerate(normalized):
            for length, index in self._indices[mode].items():
                for offset, rolling in rolling_hashes(norm, length):
                    if rolling in index.rolling:
                        tag = self._tag(b"gram", norm[offset:offset + length].encode("utf-8"))
                        pid = index.tags.get(tag)
                        if pid is not None:
                            return Decision(True, "SHINGLE", query_id, pid)
        # No k-gram match is NOT evidence that LCS cannot match.
        for mode, norm in enumerate(normalized):
            for pattern in self._patterns[mode]:
                # This length upper bound cannot skip a possible hit.
                needed = max(min(self.minimum_match, pattern.length),
                             (self.threshold * pattern.length + 99) // 100)
                if min(len(norm), pattern.length) < needed:
                    continue
                matched = lcs_length(pattern.masks, norm)
                if matched >= needed:
                    return Decision(True, "LCS_COVERAGE", query_id, pattern.audit_hash)
        return Decision(False, "NO_MATCH", query_id)
