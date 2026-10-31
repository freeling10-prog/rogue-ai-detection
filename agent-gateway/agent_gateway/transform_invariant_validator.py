"""Predicate Z: protected values under a finite family of simple transforms.

Forward substring and subsequence matchers (Predicates I and D) miss a value
that leaves reversed, byte-shifted (+k mod 256), XOR-masked with one byte,
Caesar-shifted, spelled out as the initials of words, or cut into 4-byte
blocks and reordered. Each of these has a cheap invariant view:

* ``delta`` (successive differences mod 256) is unchanged by ``x + k``;
* ``xor_delta`` (successive XORs) is unchanged by ``x ^ k``;
* ``caesar_delta`` (successive differences mod 26 of a lowercased all-letter
  string) is unchanged by a Caesar shift and by case;
* ``initials`` (first letter of each word) exposes an acrostic;
* reversal is matched against a reversed copy of the value;
* block reordering is matched by counting the value's 4-byte aligned chunks.

For each pinned value ``TransformPin`` precomputes bit-parallel LCS masks for
the direct, reversed, additive, exclusive and alphabetic views, plus its block
multiset. ``TransformIndex.check`` denies a query when any view of the query
covers at least 85% of the matching pin view (``Z_TRANSFORM``) or the query
contains at least 80% of the value's bytes as aligned blocks (``Z_BLOCKS``).

Work is bounded before any view is computed: every pin is charged
``(6 * ceil(len / 30) + 4 * blocks) * len(query)`` credits, and a query whose
total exceeds ``CREDITS`` is denied (``Z_WORK``) rather than checked partially.
At most ``MAX_PATTERNS`` pins and ``MAX_QUERY`` query bytes.

This is a FINITE family. Compositions of two transforms, keyed ciphers,
compression and arbitrary encodings are out of scope; ``deobfuscate.py``
covers common encodings. Every denial raises ``Denied`` with a fixed reason
code; pin values never appear in reason codes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .common import Denied
from .dynamic_ingression_validator import Pattern

MAX_PATTERNS = 24
MAX_QUERY = 512
CREDITS = 32768
MIN_PIN = 4
MAX_PIN = 128
TRANSFORM_PERCENT = 85
BLOCK_PERCENT = 80
BLOCK = 4


def delta(b: bytes) -> bytes:
    return bytes((y - x) & 255 for x, y in zip(b, b[1:]))


def xor_delta(b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b, b[1:]))


def _letter(c: int) -> bool:
    return 65 <= c <= 90 or 97 <= c <= 122


def caesar_delta(b: bytes) -> bytes:
    if not b or not all(_letter(c) for c in b):
        return b""
    low = b.lower()
    return bytes((y - x) % 26 for x, y in zip(low, low[1:]))


def initials(b: bytes) -> bytes:
    """First byte of each maximal run of ASCII letters, case preserved."""
    out = bytearray()
    previous = False
    for c in b:
        current = _letter(c)
        if current and not previous:
            out.append(c)
        previous = current
    return bytes(out)


def _covers(pattern: Pattern, view: bytes, percent: int) -> bool:
    return 100 * pattern.lcs(view) >= percent * len(pattern.raw)


@dataclass(frozen=True, slots=True, repr=False)
class TransformPin:
    direct: Pattern
    reverse: Pattern
    additive: Pattern | None
    exclusive: Pattern | None
    alphabetic: Pattern | None
    blocks: tuple[tuple[bytes, int], ...] = field(repr=False)

    @classmethod
    def make(cls, p: Pattern) -> TransformPin:
        b = p.raw
        caesar = caesar_delta(b)
        counts: dict[bytes, int] = {}
        for i in range(0, len(b) - BLOCK + 1, BLOCK):  # whole aligned chunks only
            chunk = b[i:i + BLOCK]
            counts[chunk] = counts.get(chunk, 0) + 1
        return cls(
            direct=p,
            reverse=Pattern.make(b[::-1]),
            additive=Pattern.make(delta(b)) if len(b) >= 5 else None,
            exclusive=Pattern.make(xor_delta(b)) if len(b) >= 5 else None,
            alphabetic=Pattern.make(caesar) if len(caesar) >= 4 else None,
            blocks=tuple(counts.items()),
        )

    def cost(self, query_length: int) -> int:
        return (6 * ((len(self.direct.raw) + 29) // 30) + 4 * len(self.blocks)) * query_length


class TransformIndex:
    """ONE session's transform pins; additions are serialized and all or nothing."""

    def __init__(self, values=()):
        self.pins: tuple[TransformPin, ...] = ()
        self._lock = RLock()
        self.add(tuple(values))

    @property
    def used(self) -> int:
        with self._lock:
            return len(self.pins)

    def add(self, values) -> int:
        """Pin new values; a batch that would exceed MAX_PATTERNS pins nothing."""
        values = tuple(values)
        for v in values:
            if type(v) is not bytes or not MIN_PIN <= len(v) <= MAX_PIN:
                raise Denied("Z_PIN_SIZE")
        with self._lock:
            known = {p.direct.raw for p in self.pins}
            new = list(dict.fromkeys(v for v in values if v not in known))
            if len(self.pins) + len(new) > MAX_PATTERNS:
                raise Denied("Z_CAPACITY")
            self.pins = self.pins + tuple(TransformPin.make(Pattern.make(v)) for v in new)
            return len(new)

    def check(self, q: bytes) -> None:
        """Deny ``q`` when a transform view of it covers a pin; None when clean."""
        if type(q) is not bytes:
            raise Denied("Z_QUERY_TYPE")
        with self._lock:
            pins = self.pins
        if not pins:
            return
        if len(q) > MAX_QUERY:
            raise Denied("Z_QUERY_SIZE")
        if sum(p.cost(len(q)) for p in pins) > CREDITS:
            raise Denied("Z_WORK")
        a, x, ac, ca = delta(q), xor_delta(q), initials(q), caesar_delta(q)
        for p in pins:
            for pattern, view in ((p.direct, q), (p.reverse, q), (p.additive, a),
                                  (p.exclusive, x), (p.direct, ac), (p.alphabetic, ca)):
                if pattern is not None and _covers(pattern, view, TRANSFORM_PERCENT):
                    raise Denied("Z_TRANSFORM")
            covered = sum(BLOCK * min(count, q.count(chunk)) for chunk, count in p.blocks)
            if p.blocks and 100 * covered >= BLOCK_PERCENT * len(p.direct.raw):
                raise Denied("Z_BLOCKS")
