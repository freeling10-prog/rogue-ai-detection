"""Bounded 16-place Petri net with weighted token conservation.

The marking is 16 unsigned 4-bit places packed into one 64-bit integer. The
manifest is supplied by the authorized workflow compiler, never by a caller.
Places in ``obligation_places_mask`` hold resource cleanup state that must be
settled (zero tokens) before any outbound step fires.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .common import Denied, digest

PLACES = 16
CAPACITY = 15
MARKING_LIMIT = 1 << 64
MAX_TRANSITIONS = 64
MAX_WEIGHT = 1 << 16
# Each place spread into an 8-bit lane: four headroom bits absorb per-lane
# borrows and carries, so lane arithmetic never crosses into a neighbour.
LANE_HIGH = int.from_bytes(b"\x80" * PLACES, "little")
LANE_OVERFLOW = int.from_bytes(b"\xf0" * PLACES, "little")
_SPREAD = tuple((b & 0xF) | ((b >> 4) << 8) for b in range(256))


def _place(place: int) -> None:
    if type(place) is not int or not 0 <= place < PLACES:
        raise Denied("PLACE_INDEX")


def _marking(marking: int) -> None:
    if type(marking) is not int or not 0 <= marking < MARKING_LIMIT:
        raise Denied("MARKING_RANGE")


def get_nibble(marking: int, place: int) -> int:
    _marking(marking)
    _place(place)
    return (marking >> (4 * place)) & 0xF


def set_nibble(marking: int, place: int, value: int) -> int:
    _marking(marking)
    _place(place)
    if type(value) is not int or not 0 <= value <= CAPACITY:
        raise Denied("NIBBLE_VALUE")
    shift = 4 * place
    return (marking & ~(0xF << shift)) | (value << shift)


def pack_vector(vector: tuple[int, ...]) -> int:
    if len(vector) > PLACES:
        raise Denied("VECTOR_LENGTH")
    packed = 0
    for place, value in enumerate(vector):
        packed = set_nibble(packed, place, value)
    return packed


def unpack(marking: int) -> tuple[int, ...]:
    return tuple(get_nibble(marking, i) for i in range(PLACES))


def spread(marking: int) -> int:
    """Map nibble i to byte lane i (a 128-bit integer)."""
    out = 0
    for i, byte in enumerate(marking.to_bytes(8, "little")):
        out |= _SPREAD[byte] << (16 * i)
    return out


def compact(lanes: int) -> int:
    out = 0
    for i, byte in enumerate(lanes.to_bytes(PLACES, "little")):
        out |= (byte & 0xF) << (4 * i)
    return out


@dataclass(frozen=True, slots=True)
class TransitionSpec:
    provider: str
    method: str
    pre_vector: tuple[int, ...]
    post_vector: tuple[int, ...]
    is_external_egress: bool
    is_bootstrap: bool = False


@dataclass(frozen=True, slots=True)
class ObligationManifest:
    initial_marking: int
    obligation_places_mask: int
    transitions: tuple[TransitionSpec, ...]
    weight_vector: tuple[int, ...] = (1,) * PLACES


@dataclass(frozen=True, slots=True)
class CompiledTransition:
    spec: TransitionSpec
    pre_mask: int
    post_mask: int
    pre_lanes: int = field(repr=False)
    post_lanes: int = field(repr=False)


@dataclass(frozen=True, slots=True)
class Firing:
    sequence: int
    provider: str
    method: str
    marking_before: int
    marking_after: int

    @property
    def marking_hex(self) -> str:
        return f"{self.marking_after:016x}"


def weighted_delta(spec: TransitionSpec, weights: tuple[int, ...]) -> int:
    pre = spec.pre_vector + (0,) * (PLACES - len(spec.pre_vector))
    post = spec.post_vector + (0,) * (PLACES - len(spec.post_vector))
    return sum(w * (b - a) for w, a, b in zip(weights, pre, post))


def compile_manifest(manifest: ObligationManifest) -> dict[tuple[str, str], CompiledTransition]:
    """Cold path: bounds, uniqueness and the non-minting conservation rule.

    For every repeatable transition t: sum_i w_i * (Post[t][i] - Pre[t][i]) <= 0,
    so the weighted token count of the marking is non-increasing under any
    firing sequence that excludes the one-shot bootstrap transitions.
    """
    _marking(manifest.initial_marking)
    _marking(manifest.obligation_places_mask)
    mask = manifest.obligation_places_mask
    if any(((mask >> (4 * i)) & 0xF) not in {0, 0xF} for i in range(PLACES)):
        raise Denied("OBLIGATION_MASK")
    weights = tuple(manifest.weight_vector)
    if len(weights) != PLACES or any(
            type(w) is not int or not 1 <= w <= MAX_WEIGHT for w in weights):
        raise Denied("WEIGHT_VECTOR")
    if not 1 <= len(manifest.transitions) <= MAX_TRANSITIONS:
        raise Denied("MANIFEST_LIMIT")
    table = {}
    for spec in manifest.transitions:
        spec = TransitionSpec(spec.provider, spec.method, tuple(spec.pre_vector),
                              tuple(spec.post_vector), bool(spec.is_external_egress),
                              bool(spec.is_bootstrap))
        if not isinstance(spec.provider, str) or not isinstance(spec.method, str):
            raise Denied("TRANSITION_NAME")
        key = (spec.provider, spec.method)
        if key in table:
            raise Denied("DUPLICATE_TRANSITION")
        pre_mask = pack_vector(spec.pre_vector)
        post_mask = pack_vector(spec.post_vector)
        if not spec.is_bootstrap and weighted_delta(spec, weights) > 0:
            raise Denied("CONSERVATION_VIOLATION")
        table[key] = CompiledTransition(spec, pre_mask, post_mask,
                                        spread(pre_mask), spread(post_mask))
    return table


def successor(marking: int, transition: CompiledTransition, obligation_mask: int) -> int:
    """Hot path, O(1): the enabled-and-bounded successor marking, or Denied."""
    lanes = spread(marking)
    # Lane i of (lanes | 0x80..) - pre is >= 0x80 exactly when M[i] >= Pre[i].
    if ((lanes | LANE_HIGH) - transition.pre_lanes) & LANE_HIGH != LANE_HIGH:
        raise Denied("INSUFFICIENT_TOKENS")
    # Each lane now lies in 0..30, so no carry can cross into the next lane.
    after = lanes - transition.pre_lanes + transition.post_lanes
    if after & LANE_OVERFLOW:
        raise Denied("PLACE_CAPACITY")
    if transition.spec.is_external_egress and marking & obligation_mask:
        raise Denied("UNSETTLED_OBLIGATION")
    return compact(after)


class ObligationNet:
    """ONE session's marking; every firing is serialized under the lock."""

    def __init__(self, manifest: ObligationManifest):
        self._transitions = compile_manifest(manifest)
        self.obligation_mask = manifest.obligation_places_mask
        self.weights = tuple(manifest.weight_vector)
        self.commitment = digest("obligation-manifest-v1", {
            "initial": f"{manifest.initial_marking:016x}",
            "obligations": f"{self.obligation_mask:016x}",
            "weights": list(self.weights),
            "transitions": [
                {"provider": t.spec.provider, "method": t.spec.method,
                 "pre": f"{t.pre_mask:016x}", "post": f"{t.post_mask:016x}",
                 "egress": t.spec.is_external_egress,
                 "bootstrap": t.spec.is_bootstrap}
                for _, t in sorted(self._transitions.items())]})
        self.marking = manifest.initial_marking
        self.sequence = 0
        self._spent: set[tuple[str, str]] = set()
        self._lock = RLock()

    @property
    def marking_hex(self) -> str:
        with self._lock:
            return f"{self.marking:016x}"

    def _lookup(self, provider: str, method: str) -> CompiledTransition:
        transition = self._transitions.get((provider, method))
        if transition is None:
            raise Denied("UNKNOWN_TRANSITION")
        if (provider, method) in self._spent:
            raise Denied("BOOTSTRAP_SPENT")
        return transition

    def check(self, provider: str, method: str) -> int:
        """Return the successor marking without committing it."""
        with self._lock:
            return successor(self.marking, self._lookup(provider, method),
                             self.obligation_mask)

    def fire(self, provider: str, method: str,
             *, expected_sequence: int | None = None) -> Firing:
        with self._lock:
            if expected_sequence is not None and expected_sequence != self.sequence:
                raise Denied("STALE_MARKING_SEQUENCE")
            transition = self._lookup(provider, method)
            before = self.marking
            after = successor(before, transition, self.obligation_mask)
            if transition.spec.is_bootstrap:
                self._spent.add((provider, method))
            self.marking = after
            self.sequence += 1
            return Firing(self.sequence, provider, method, before, after)

    def weighted_tokens(self) -> int:
        with self._lock:
            return sum(w * n for w, n in zip(self.weights, unpack(self.marking)))
