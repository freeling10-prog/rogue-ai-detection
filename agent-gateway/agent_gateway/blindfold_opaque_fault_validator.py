"""Predicate B: opaque refusals and near-neighbor perturbation quarantine.

Every refusal teaches the caller something: which rule fired, and, by
trying small variations, where the boundary lies. An agent driven by an
injection can search the policy one perturbation at a time. Zhu et al.
(*Blindfold: Keeping the Audit Coin Secret from LLM Agents*,
arXiv:2610.37055) show the related point for audits: a certificate stays
unbiased only if what the agent observes before committing does not depend on
the defender's secret choice.

B does two things for a session it is attached to:

1. **Opaque faults.** ``seal`` turns a refusal into one constant public
   envelope (``AGENT_ENVELOPE``) for the agent and a private, HMAC-signed
   receipt (rule, level, request fingerprint, sequence) for people.
   ``verify_receipt`` checks a receipt with ``hmac.compare_digest``.
2. **Perturbation quarantine.** ``seal`` also remembers the refused request's
   fingerprint (at most ``MAX_REFUSALS``). ``inspect`` compares each new
   request's exact set of 4-byte grams with those fingerprints. Exact Jaccard
   ``J`` with ``0.25 <= J < 1`` (in integers: ``4 * |A & B| >= |A | B|`` and
   ``|A & B| < |A | B|``) is a near neighbor of a refusal: the branch is
   locked and the call denied (``B_PERTURBATION_LOCK``). An exact repeat
   (``J == 1``) is not a perturbation.

Under this project's standing rules a lock is the one allowed automated
action: it auto-lifts after ``LOCK_SECONDS`` (15 minutes) and is reported as
a lead for human review. When more than ``MAX_LOCKED`` branches are locked,
the root is locked instead, on the same auto-lifting timer. The 64-bit
SimHash in a fingerprint (BLAKE2b, personalization ``AG-v14B``) is telemetry
for the receipt only; enforcement uses the exact gram sets.

Requests are canonical bytes of 4..2048 bytes. A request outside those
bounds cannot be compared: ``inspect`` refuses it while any refusal is held,
and ``seal`` locks its branch. Every refusal raises ``Denied`` with a fixed
reason code; request bytes never appear in reason codes or receipts.

Residual: a perturbation below 25% gram overlap is not caught, and an
attacker who already knows the policy needs no search. False positives are
real: a legitimate retry that differs a little from a refused request locks
its branch for 15 minutes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from threading import RLock

from .common import Denied

MIN_REQUEST = 4
MAX_REQUEST = 2048
MAX_REFUSALS = 32
MAX_LOCKED = 64
LOCK_SECONDS = 900
GRAM = 4
AGENT_ENVELOPE = b'{"code":-32079,"message":"request refused"}'
_PERSON = b"AG-v14B"


@dataclass(frozen=True, slots=True, repr=False)
class Fingerprint:
    grams: frozenset
    digest: str
    simhash: int


@dataclass(frozen=True, slots=True, repr=False)
class SealedFault:
    public_bytes: bytes
    private_receipt: bytes


def gram_set(canonical_request: bytes) -> frozenset:
    """The exact set of 4-byte grams: all that enforcement compares."""
    if type(canonical_request) is not bytes or not MIN_REQUEST <= len(canonical_request) <= MAX_REQUEST:
        raise Denied("B_REQUEST_SIZE")
    b = canonical_request
    return frozenset(b[i:i + GRAM] for i in range(len(b) - GRAM + 1))


def fingerprint(canonical_request: bytes) -> Fingerprint:
    """Grams plus the receipt telemetry (sorted-gram SHA-256 and SimHash)."""
    grams = gram_set(canonical_request)
    ordered = sorted(grams)
    digest = hashlib.sha256(b"".join(ordered)).hexdigest()
    votes = [0] * 64
    for g in ordered:
        h = int.from_bytes(hashlib.blake2b(g, digest_size=8, person=_PERSON).digest(), "big")
        for bit in range(64):
            votes[bit] += 1 if (h >> bit) & 1 else -1
    simhash = sum(1 << bit for bit in range(64) if votes[bit] > 0)
    return Fingerprint(grams, digest, simhash)


def near_neighbor(a: frozenset, b: frozenset) -> bool:
    """Exact Jaccard in [0.25, 1): close to a refusal but not the same request."""
    # |A | B| = |A| + |B| - |A & B|: one set operation, not two.
    if 4 * min(len(a), len(b)) < max(len(a), len(b)):
        return False  # even total overlap stays under 25%
    inter = len(a & b)
    union = len(a) + len(b) - inter
    return 4 * inter >= union and inter < union


def _mac(key: bytes, payload: bytes) -> str:
    return hmac.new(key, b"AG-v14B-receipt|" + payload, hashlib.sha256).hexdigest()


def verify_receipt(receipt: bytes, receipt_key: bytes) -> bool:
    """True only for a receipt this key signed, byte for byte."""
    try:
        doc = json.loads(receipt.decode("utf-8"))
        payload = doc["payload"].encode("utf-8")
        mac = doc["mac"]
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        return False
    if type(mac) is not str:
        return False
    return hmac.compare_digest(_mac(receipt_key, payload), mac)


class BlindfoldSealer:
    """ONE root's refusal memory and branch locks; every change is serialized."""

    def __init__(self, receipt_key: bytes, *, clock=time.monotonic, lock_seconds: int = LOCK_SECONDS):
        if type(receipt_key) is not bytes or len(receipt_key) < 32:
            raise Denied("B_KEY")
        if type(lock_seconds) is not int or not 1 <= lock_seconds <= LOCK_SECONDS:
            raise Denied("B_LOCK_SECONDS")
        self._key = receipt_key
        self._clock = clock
        self.lock_seconds = lock_seconds
        self.refusals: list[Fingerprint] = []
        self.locked: dict[str, float] = {}
        self.root_locked_until = 0.0
        self.sequence = 0
        self._lock = RLock()

    # --- locks (auto-lifting) -------------------------------------------------------

    def _prune(self, now: float) -> None:
        for branch in [b for b, until in self.locked.items() if until <= now]:
            del self.locked[branch]

    @property
    def root_locked(self) -> bool:
        with self._lock:
            return self._clock() < self.root_locked_until

    def is_locked(self, branch_id: str) -> bool:
        with self._lock:
            now = self._clock()
            self._prune(now)
            return now < self.root_locked_until or branch_id in self.locked

    def _lock_branch(self, branch_id: str) -> None:
        now = self._clock()
        self._prune(now)
        if branch_id not in self.locked and len(self.locked) >= MAX_LOCKED:
            self.root_locked_until = now + self.lock_seconds
        else:
            self.locked[branch_id] = now + self.lock_seconds

    # --- checks ---------------------------------------------------------------------

    def inspect(self, branch_id: str, canonical_request: bytes) -> None:
        """Deny a locked branch, or a near neighbor of a refusal (and lock it)."""
        if type(branch_id) is not str or not 1 <= len(branch_id) <= 128:
            raise Denied("B_BRANCH_ID")
        with self._lock:
            if self.is_locked(branch_id):
                raise Denied("B_LOCKED")
            if not self.refusals:
                return
            grams = gram_set(canonical_request)  # B_REQUEST_SIZE: cannot be compared
            for refused in self.refusals:
                if near_neighbor(grams, refused.grams):
                    self._lock_branch(branch_id)
                    raise Denied("B_PERTURBATION_LOCK")

    def seal(self, branch_id: str, canonical_request: bytes, fault: str, *,
             sarif_rule: str = "", sarif_level: str = "error") -> SealedFault:
        """Remember a refusal and return its public envelope and private receipt."""
        for value in (fault, sarif_rule, sarif_level):
            if type(value) is not str or len(value) > 128:
                raise Denied("B_FAULT")
        with self._lock:
            try:
                fp = fingerprint(canonical_request)
            except Denied:
                fp = None
                self._lock_branch(branch_id)  # out of bounds: cannot be remembered
            if fp is not None:
                if len(self.refusals) >= MAX_REFUSALS:
                    self._lock_branch(branch_id)
                elif all(r.digest != fp.digest for r in self.refusals):
                    self.refusals.append(fp)
            self.sequence += 1
            payload = json.dumps({
                "v": 1, "seq": self.sequence, "branch": branch_id, "fault": fault,
                "sarif_rule": sarif_rule, "sarif_level": sarif_level,
                "request_sha256": None if fp is None else fp.digest,
                "simhash": None if fp is None else f"{fp.simhash:016x}",
            }, sort_keys=True, separators=(",", ":"))
            receipt = json.dumps({"payload": payload, "mac": _mac(self._key, payload.encode("utf-8"))},
                                 sort_keys=True, separators=(",", ":")).encode("utf-8")
            return SealedFault(AGENT_ENVELOPE, receipt)
