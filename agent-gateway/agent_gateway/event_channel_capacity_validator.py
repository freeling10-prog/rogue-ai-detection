"""Predicate E: capacity of the event-selection channel into one sink.

Content filters inspect what a call says. A colluding or injected agent can
also signal through *which* eligible tool it calls and the structural choices
it makes (which of several fields, how many items, which enum value), even
when every argument is clean. Event-driven covert channels in agent dialogue
use exactly this (Huang et al., *Whispering Agents*, arXiv:2508.02188). An
egress reference monitor with a covert-capacity ledger is the closest prior
design (Metere, arXiv:2605.20734); E is a much smaller, selection-only ledger.

E bounds that channel per (root, sink) with Hartley support accounting: an
event drawn from a manifest with ``N`` possible combinations can carry at most
``log2 N`` bits. ``quarter_bits(N) = (N**4 - 1).bit_length()``, the exact
integer ``ceil(4 * log2 N)`` for ``N > 1`` (0 for ``N = 1``), so the budget is
counted in quarter bits with no floating point.

An event is charged only when it could carry a protected bit: the budget is
sticky-tainted, the calling branch is tainted, or live secret pins exist
(Predicates D, Z, I). Untainted calls with nothing to protect charge 0.

Two-phase: ``reserve`` checks and holds the charge, denying with
``E_CAPACITY`` when ``spent + reserved + charge >= max_quarter_bits``;
``commit`` spends it once the call is allowed; ``abort`` releases it when a
later gate denies the call. Event ids are single-use (``E_REPLAY``).

This is support accounting, not KL divergence or a Shannon-rate measurement:
it upper-bounds the bits an adversary can choose to send through selection,
not what an observer learns. Timing, argument content and refusal outcomes
are other channels. Bounds: 1..64 eligible tools, at most 8 structural
dimensions of 1..1024 choices, ``combinations <= 2**20``, at most 32 pending
reservations and 256 committed ids. Every refusal raises ``Denied`` with a
fixed reason code.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from .common import Denied

MAX_CHOICES = 1 << 20
MAX_TOOLS = 64
MAX_DIMENSIONS = 8
MAX_DIMENSION = 1024
MAX_PENDING = 32
MAX_COMMITTED = 256
MAX_ID = 128
DEFAULT_LIMIT = 32  # quarter bits: 8 bits per (root, sink)


def quarter_bits(choice_count: int) -> int:
    """Exact ``ceil(4 * log2(choice_count))`` in integers (0 for one choice)."""
    if type(choice_count) is not int or not 1 <= choice_count <= MAX_CHOICES:
        raise Denied("E_INVALID_CHOICES")
    return (choice_count ** 4 - 1).bit_length()


@dataclass(frozen=True, slots=True)
class EventManifest:
    eligible_tools: tuple[str, ...]
    structural_choice_counts: tuple[int, ...] = ()

    def __post_init__(self):
        tools, dims = self.eligible_tools, self.structural_choice_counts
        if type(tools) is not tuple or not 1 <= len(tools) <= MAX_TOOLS:
            raise Denied("E_MANIFEST")
        if any(type(t) is not str or not 1 <= len(t) <= MAX_ID for t in tools) or len(set(tools)) != len(tools):
            raise Denied("E_MANIFEST")
        if type(dims) is not tuple or len(dims) > MAX_DIMENSIONS:
            raise Denied("E_MANIFEST")
        if any(type(d) is not int or not 1 <= d <= MAX_DIMENSION for d in dims):
            raise Denied("E_MANIFEST")
        if self.combinations > MAX_CHOICES:
            raise Denied("E_MANIFEST")

    @property
    def combinations(self) -> int:
        n = len(self.eligible_tools)
        for d in self.structural_choice_counts:
            n *= d
        return n


class EventChannelBudget:
    """ONE (root, sink) budget; reservations are serialized and single-use."""

    def __init__(self, root_id: str, sink_id: str, max_quarter_bits: int = DEFAULT_LIMIT):
        for value in (root_id, sink_id):
            if type(value) is not str or not 1 <= len(value) <= MAX_ID:
                raise Denied("E_ID")
        if type(max_quarter_bits) is not int or not 1 <= max_quarter_bits <= 4 * 1024:
            raise Denied("E_LIMIT")
        self.root_id, self.sink_id = root_id, sink_id
        self.max_quarter_bits = max_quarter_bits
        self.spent = 0
        self.pending: dict[str, int] = {}
        self.committed: dict[str, None] = {}
        self.sticky_tainted = False
        self._lock = RLock()

    @property
    def reserved(self) -> int:
        with self._lock:
            return sum(self.pending.values())

    def reserve(self, event_id: str, tool: str, manifest: EventManifest, *,
                branch_tainted: bool, live_pins: bool) -> int:
        """Hold this event's charge; returns it. Nothing changes on a denial."""
        if type(event_id) is not str or not 1 <= len(event_id) <= MAX_ID:
            raise Denied("E_ID")
        if type(manifest) is not EventManifest:
            raise Denied("E_MANIFEST")
        if type(branch_tainted) is not bool or type(live_pins) is not bool:
            raise Denied("E_LABEL")
        with self._lock:
            if event_id in self.pending or event_id in self.committed:
                raise Denied("E_REPLAY")
            if tool not in manifest.eligible_tools:
                raise Denied("E_INELIGIBLE")
            if len(self.pending) >= MAX_PENDING:
                raise Denied("E_PENDING")
            if len(self.committed) + len(self.pending) >= MAX_COMMITTED:
                raise Denied("E_REPLAY_CAPACITY")
            sticky = self.sticky_tainted or branch_tainted
            charge = quarter_bits(manifest.combinations) if (sticky or live_pins) else 0
            if self.spent + sum(self.pending.values()) + charge >= self.max_quarter_bits:
                raise Denied("E_CAPACITY")
            self.sticky_tainted = sticky
            self.pending[event_id] = charge
            return charge

    def commit(self, event_id: str) -> int:
        """Spend a held charge (the call was allowed); returns the new total."""
        with self._lock:
            if event_id not in self.pending:
                raise Denied("E_UNKNOWN_EVENT")
            self.spent += self.pending.pop(event_id)
            self.committed[event_id] = None
            return self.spent

    def abort(self, event_id: str) -> None:
        """Release a held charge (a later gate denied the call)."""
        with self._lock:
            if self.pending.pop(event_id, None) is None:
                raise Denied("E_UNKNOWN_EVENT")
