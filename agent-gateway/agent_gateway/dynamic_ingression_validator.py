"""Predicate D: secrets learned from tool responses, blocked on the way out.

A similarity matcher protects only strings known when the session starts. A
credential, internal host name or address that first appears in a tool
response is unknown to it. D scans each inbound response before the agent
sees it, enrolls sensitive fields and secret-looking tokens into a small
per-session store, and denies later outbound strings that cover an enrolled
value.

Enrollment, per ``receive`` batch:

* a field marked ``sensitive`` is enrolled whole (4..128 UTF-8 bytes);
* every maximal run of ``TOKEN`` bytes is a candidate. A run over 128 bytes
  fails the batch (``D_TOKEN_SIZE``). A run of 4+ bytes is enrolled when it
  has a credential prefix (``sk-``, ``ghp_``, ``AKIA``), an internal host
  suffix (``.internal``, ``.corp``), the shape of an e-mail address, or is at
  least 24 bytes with 16+ distinct byte values and Renyi-2 entropy of at least
  4 bits per byte, tested exactly in integers:
  ``16 * sum(count**2) <= len**2``.

Two stores, so an untrusted response cannot brick enrollment (round-2 audit):

* ``HARD_SLOTS`` (8) hold fields marked ``sensitive`` - set only by trusted
  sensitive-source adapters (credential stores, sensitive reads). They never
  evict. A batch that would need a ninth distinct hard value fails closed
  (``D_CAPACITY``) and enrolls nothing, so no response can flush a trusted
  secret out.
* ``SOFT_SLOTS`` (16) hold heuristic detections (prefix, host suffix, e-mail,
  entropy). When full they evict deterministically, oldest first, and never
  raise ``D_CAPACITY``. Residual: a response the attacker controls can rotate
  earlier heuristic values out; trusted secrets belong in the hard store.

Outbound check: each enrolled value is a 256-entry byte bitmask table. A
bit-parallel LCS recurrence over the query computes the longest common
subsequence with the value. The query is denied (``D_MATCH``) when that
covers at least 85% of the value's bytes, so separators, case-preserving
interleaving or partial edits do not hide it. Queries are capped at
``MAX_QUERY`` bytes.

Every denial raises ``Denied`` with a fixed reason code. Enrolled values are
sensitive state: they are never placed in reason codes or audit records.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .common import Denied

HARD_SLOTS = 8
SOFT_SLOTS = 16
SLOTS = HARD_SLOTS  # v12.7 name: the non-evicting capacity
MAX_TEXT = 4096
MAX_SECRET = 128
MIN_SECRET = 4
MAX_FIELDS = 32
MAX_QUERY = 512
COVERAGE_PERCENT = 85
TOKEN = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.@+/=")
PREFIXES = (b"sk-", b"ghp_", b"AKIA")
HOST_SUFFIXES = (b".internal", b".corp")


@dataclass(frozen=True, slots=True)
class Field:
    value: str
    sensitive: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class Pattern:
    raw: bytes = field(repr=False)
    masks: tuple[int, ...] = field(repr=False)

    @classmethod
    def compile(cls, raw: bytes) -> Pattern:
        masks = [0] * 256
        for i, byte in enumerate(raw):
            masks[byte] |= 1 << i
        return cls(bytes(raw), tuple(masks))

    make = compile  # the name Predicate Z uses

    def lcs(self, query: bytes) -> int:
        """Longest common subsequence length, bit-parallel over the pattern."""
        masks = self.masks
        state = 0
        for byte in query:
            x = masks[byte] | state
            state = x & ~(x - ((state << 1) | 1))
        return state.bit_count()

    def covered_by(self, query: bytes) -> bool:
        return 100 * self.lcs(query) >= COVERAGE_PERCENT * len(self.raw)


def high_entropy(b: bytes) -> bool:
    if len(b) < 24:
        return False
    freq = [0] * 256
    for byte in b:
        freq[byte] += 1
    if sum(1 for c in freq if c) < 16:
        return False
    # Renyi-2 entropy -log2(sum p^2) >= 4  <=>  sum c^2 / n^2 <= 1/16.
    return 16 * sum(c * c for c in freq) <= len(b) ** 2


def candidate(b: bytes) -> bool:
    """True when a TOKEN run looks like a secret worth enrolling."""
    if not MIN_SECRET <= len(b) <= MAX_SECRET:
        return False
    if b.startswith(PREFIXES) or b.endswith(HOST_SUFFIXES):
        return True
    if b.count(b"@") == 1:
        left, right = b.split(b"@")
        if left and b"." in right and not right.startswith(b"."):
            return True
    return high_entropy(b)


def token_runs(b: bytes):
    """Maximal runs of TOKEN bytes, in order."""
    start = None
    for i, byte in enumerate(b):
        if byte in TOKEN:
            if start is None:
                start = i
        elif start is not None:
            yield b[start:i]
            start = None
    if start is not None:
        yield b[start:]


def extract(fields) -> tuple[bytes, ...]:
    """Distinct values to enroll from one inbound batch, in first-seen order."""
    hard, soft = extract_split(fields)
    return tuple(dict.fromkeys(hard + soft))


def extract_split(fields) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    """(hard, soft) distinct values from one batch, each in first-seen order.

    A value marked sensitive anywhere in the batch is hard, never also soft.
    """
    fields = tuple(fields)
    if len(fields) > MAX_FIELDS:
        raise Denied("D_FIELDS")
    hard: dict[bytes, None] = {}
    soft: dict[bytes, None] = {}
    total = 0
    for f in fields:
        if type(f) is not Field or type(f.value) is not str or type(f.sensitive) is not bool:
            raise Denied("D_FIELD_TYPE")
        try:
            raw = f.value.encode("utf-8")
        except UnicodeError:
            raise Denied("D_ENCODING") from None
        total += len(raw)
        if total > MAX_TEXT:
            raise Denied("D_TEXT")
        if f.sensitive:
            if not MIN_SECRET <= len(raw) <= MAX_SECRET:
                raise Denied("D_SECRET_SIZE")
            hard.setdefault(raw, None)
        for run in token_runs(raw):
            if len(run) > MAX_SECRET:
                raise Denied("D_TOKEN_SIZE")
            if candidate(run):
                soft.setdefault(run, None)
    return tuple(hard), tuple(v for v in soft if v not in hard)


class Ingression:
    """ONE session's enrolled values; every change is serialized under the lock."""

    def __init__(self):
        self._hard: tuple[Pattern, ...] = ()
        self._soft: tuple[Pattern, ...] = ()
        self._lock = RLock()

    @property
    def _patterns(self) -> tuple[Pattern, ...]:
        """Every enrolled pattern: hard first (oldest first), then soft."""
        return self._hard + self._soft

    @property
    def used(self) -> int:
        with self._lock:
            return len(self._hard) + len(self._soft)

    @property
    def hard_used(self) -> int:
        with self._lock:
            return len(self._hard)

    @property
    def soft_used(self) -> int:
        with self._lock:
            return len(self._soft)

    def values(self) -> tuple[bytes, ...]:
        """Enrolled values, hard then soft. Sensitive: for trusted holders only."""
        with self._lock:
            return tuple(p.raw for p in self._patterns)

    def receive(self, fields, on_commit=None, on_soft=None) -> int:
        """Enroll a batch. Returns how many new values were enrolled.

        Hard values are all or nothing: a batch that would overflow
        ``HARD_SLOTS`` stores nothing (``D_CAPACITY``). Soft values never fail:
        the soft store keeps the newest ``SOFT_SLOTS``, evicting oldest first.

        ``on_commit(new_hard)`` runs under the lock after every check has passed
        and before anything is stored. If it raises, nothing is stored, so a
        second store fed from this one (Predicate Z) never runs ahead of the
        hard store or behind it. ``on_soft(new_soft)`` is told about new soft
        values after they are stored; it must not raise.
        """
        hard, soft = extract_split(fields)
        with self._lock:
            known_hard = {p.raw for p in self._hard}
            new_hard = [v for v in hard if v not in known_hard]
            if len(self._hard) + len(new_hard) > HARD_SLOTS:
                raise Denied("D_CAPACITY")
            if on_commit is not None and new_hard:
                on_commit(tuple(new_hard))
            self._hard = self._hard + tuple(Pattern.compile(v) for v in new_hard)
            # A value now hard leaves the soft store; known soft values keep their age.
            hard_now = known_hard | set(new_hard)
            kept = tuple(p for p in self._soft if p.raw not in hard_now)
            known_soft = {p.raw for p in kept}
            new_soft = [v for v in soft if v not in hard_now and v not in known_soft]
            self._soft = (kept + tuple(Pattern.compile(v) for v in new_soft))[-SOFT_SLOTS:]
            stored_soft = [v for v in new_soft if v in {p.raw for p in self._soft}]
            if on_soft is not None and stored_soft:
                on_soft(tuple(stored_soft))
            return len(new_hard) + len(stored_soft)

    def outbound(self, q: bytes) -> None:
        """Deny a query that covers an enrolled value; returns None when clean."""
        if type(q) is not bytes:
            raise Denied("D_QUERY_TYPE")
        with self._lock:
            patterns = self._patterns
        if not patterns:
            return
        if len(q) > MAX_QUERY:
            raise Denied("D_QUERY_SIZE")
        for pattern in patterns:
            if pattern.covered_by(q):
                raise Denied("D_MATCH")

    def matching_slot(self, q: bytes) -> int | None:
        """Index of the first enrolled value ``q`` covers, for audit; never the value."""
        with self._lock:
            patterns = self._patterns
        for i, pattern in enumerate(patterns):
            if len(q) <= MAX_QUERY and pattern.covered_by(q):
                return i
        return None
