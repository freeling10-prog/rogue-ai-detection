"""Predicate V: one conservation ledger for a root session and its forked branches.

Per-session budgets and Petri-net markings assume one session. When a root
session forks sub-agent branches and later joins them, two gaps open: a
child that receives a fresh, independent quota multiplies the root's denial,
outbound and token budgets, and two branches that dispatch concurrently can
both spend the same balance. V keeps up to ``WIDTH`` lifetime branches under
ONE ledger:

* every branch owns a wallet ``(denial_units, outbound_bytes, *tokens)``; a
  fork moves a grant out of the parent's wallet, a join moves the child's
  wallet back, and nothing else creates budget;
* ``spent`` records consumed denial units and outbound bytes, so for those two
  columns: sum of active wallets + spent == initial, at every step;
* token places move only by weighted-conserving firings, so the weighted
  token total across active branches equals the initial weighted total;
* token amounts are in units of 1/``UNIT`` of a capability: a branch holding a
  fraction below ``UNIT`` cannot take a full-token transition until the
  fraction is joined back;
* every operation is fenced on the branch's own vector-clock component, so a
  result computed from a stale view never commits;
* an outbound step needs every active branch in the ledger to hold zero tokens
  in the obligation places (cleanup state is settled ledger-wide, not per
  branch);
* taint is copied to a child at fork and joined back into the parent.

Slots are never reused: slot 0 is the root, a joined branch is inactive for
good, and at most ``WIDTH`` branches exist over the root's lifetime. ``Root``
is immutable; ``Owner`` holds the current ``Root`` and serializes every
transition under one lock. Denials raise ``Denied`` with a fixed reason code.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from threading import Lock

from .common import Denied

WIDTH = 8
PLACES = 16
UNIT = 256
MAX_EVENTS = 65535
MAX_VALUE = 65535
MAX_SEND = 512
ZERO = (0,) * (2 + PLACES)


def _counts(values, length: int, low: int, reason: str) -> tuple[int, ...]:
    values = tuple(values)
    if len(values) != length or any(type(v) is not int or not low <= v <= MAX_VALUE for v in values):
        raise Denied(reason)
    return values


@dataclass(frozen=True, slots=True, repr=False)
class Branch:
    parent: int
    active: bool
    clock: tuple[int, ...]
    wallet: tuple[int, ...]  # (denial_units, outbound_bytes, *16 token fractions)
    taint: int = 0


@dataclass(frozen=True, slots=True, repr=False)
class Root:
    branches: tuple[Branch, ...]
    initial: tuple[int, ...]
    spent: tuple[int, int] = (0, 0)
    weights: tuple[int, ...] = (1,) * PLACES
    events: int = 0
    obligation_mask: int = 0

    @classmethod
    def make(cls, denials: int = 3, outbound: int = 4096,
             tokens: tuple[int, ...] = (UNIT,) + (0,) * (PLACES - 1),
             obligation_mask: int = 0,
             weights: tuple[int, ...] = (1,) * PLACES) -> Root:
        denials, outbound = _counts((denials, outbound), 2, 0, "BUDGET_RANGE")
        tokens = _counts(tokens, PLACES, 0, "TOKEN_RANGE")
        weights = _counts(weights, PLACES, 1, "WEIGHT_RANGE")
        if type(obligation_mask) is not int or not 0 <= obligation_mask < 1 << PLACES:
            raise Denied("OBLIGATION_MASK")
        initial = (denials, outbound) + tokens
        root = Branch(-1, True, (0,) * WIDTH, initial)
        return cls((root,), initial, weights=weights, obligation_mask=obligation_mask)

    # --- hot path -------------------------------------------------------------------

    def checked(self, slot: int, expected: int) -> Branch:
        if type(slot) is not int or not 0 <= slot < len(self.branches):
            raise Denied("BRANCH_SLOT")
        branch = self.branches[slot]
        if not branch.active:
            raise Denied("BRANCH_INACTIVE")
        if expected != branch.clock[slot]:
            raise Denied("STALE_CLOCK")
        if self.events >= MAX_EVENTS:
            raise Denied("EVENT_BUDGET")
        return branch

    def commit(self, slot: int, b: Branch, *, rows=None, **changes) -> Root:
        clock = list(b.clock)
        if clock[slot] >= MAX_EVENTS:
            raise Denied("CLOCK_BUDGET")
        clock[slot] += 1
        rows = list(self.branches if rows is None else rows)
        rows[slot] = replace(b, clock=tuple(clock))
        return replace(self, branches=tuple(rows), events=self.events + 1, **changes)

    def fork(self, slot: int, expected: int, grant: tuple[int, ...]) -> tuple[Root, int]:
        b = self.checked(slot, expected)
        if len(self.branches) >= WIDTH:
            raise Denied("WIDTH_EXHAUSTED")
        grant = _counts(grant, 2 + PLACES, 0, "GRANT_SHAPE")
        if any(g > w for g, w in zip(grant, b.wallet)):
            raise Denied("GRANT_EXCEEDS_WALLET")
        parent = replace(b, wallet=tuple(w - g for w, g in zip(b.wallet, grant)))
        root = self.commit(slot, parent)
        child_slot = len(root.branches)
        clock = list(root.branches[slot].clock)
        clock[child_slot] = 1  # the fork is the child's first event
        child = Branch(slot, True, tuple(clock), grant, b.taint)
        return replace(root, branches=root.branches + (child,)), child_slot

    def join(self, slot: int, expected: int, child: int) -> Root:
        b = self.checked(slot, expected)
        if type(child) is not int or not 0 < child < len(self.branches):
            raise Denied("BRANCH_SLOT")
        c = self.branches[child]
        if not c.active:
            raise Denied("JOIN_INACTIVE")
        if c.parent != slot:
            raise Denied("JOIN_NOT_CHILD")
        if any(row.active and row.parent == child for row in self.branches):
            raise Denied("JOIN_HAS_CHILDREN")
        merged = replace(b, wallet=tuple(x + y for x, y in zip(b.wallet, c.wallet)),
                         clock=tuple(max(x, y) for x, y in zip(b.clock, c.clock)),
                         taint=max(b.taint, c.taint))
        rows = list(self.branches)
        rows[child] = replace(c, active=False, wallet=ZERO)
        return self.commit(slot, merged, rows=rows)

    def taint(self, slot: int, expected: int) -> Root:
        b = self.checked(slot, expected)
        return self.commit(slot, replace(b, taint=1))

    def deny(self, slot: int, expected: int) -> Root:
        b = self.checked(slot, expected)
        if b.wallet[0] <= 0:
            raise Denied("DENIAL_BUDGET")
        wallet = (b.wallet[0] - 1,) + b.wallet[1:]
        return self.commit(slot, replace(b, wallet=wallet),
                           spent=(self.spent[0] + 1, self.spent[1]))

    def unsettled(self) -> bool:
        """True when any active branch holds tokens in an obligation place."""
        return any(row.wallet[i + 2] and (self.obligation_mask >> i) & 1
                   for row in self.branches if row.active for i in range(PLACES))

    def send(self, slot: int, expected: int, byte_count: int) -> Root:
        b = self.checked(slot, expected)
        if type(byte_count) is not int or not 0 <= byte_count <= MAX_SEND:
            raise Denied("SEND_LIMIT")
        if b.wallet[0] <= 0:
            raise Denied("DENIAL_BUDGET")  # An exhausted branch may not send.
        if byte_count > b.wallet[1]:
            raise Denied("OUTBOUND_BUDGET")
        if self.unsettled():
            raise Denied("UNSETTLED_OBLIGATION")
        wallet = (b.wallet[0], b.wallet[1] - byte_count) + b.wallet[2:]
        return self.commit(slot, replace(b, wallet=wallet),
                           spent=(self.spent[0], self.spent[1] + byte_count))

    def fire(self, slot: int, expected: int, take: tuple[int, ...], put: tuple[int, ...]) -> Root:
        b = self.checked(slot, expected)
        take = _counts(take, PLACES, 0, "FIRE_SHAPE")
        put = _counts(put, PLACES, 0, "FIRE_SHAPE")
        if (sum(x * w for x, w in zip(take, self.weights))
                != sum(x * w for x, w in zip(put, self.weights))):
            raise Denied("FIRE_NOT_CONSERVED")
        if any(x > y for x, y in zip(take, b.wallet[2:])):
            raise Denied("INSUFFICIENT_TOKENS")
        tokens = tuple(y - x + z for x, y, z in zip(take, b.wallet[2:], put))
        return self.commit(slot, replace(b, wallet=b.wallet[:2] + tokens))

    # --- audit ----------------------------------------------------------------------

    def weighted_tokens(self) -> int:
        return sum(w * t for row in self.branches if row.active
                   for w, t in zip(self.weights, row.wallet[2:]))

    def conserved(self) -> bool:
        """The ledger invariants. True after every committed transition."""
        active = [row for row in self.branches if row.active]
        if not 1 <= len(self.branches) <= WIDTH or not self.branches[0].active:
            return False
        if any(not row.active and row.wallet != ZERO for row in self.branches):
            return False
        if any(v < 0 for row in active for v in row.wallet):
            return False
        for column in (0, 1):
            if sum(row.wallet[column] for row in active) + self.spent[column] != self.initial[column]:
                return False
        initial_weighted = sum(w * t for w, t in zip(self.weights, self.initial[2:]))
        if self.weighted_tokens() != initial_weighted:
            return False
        # Each commit ticks one component; each fork also starts the child at 1.
        return sum(row.clock[i] for i, row in enumerate(self.branches)) == \
            self.events + len(self.branches) - 1


# Operations an Owner applies in one fenced batch.
FIRE, SEND, TAINT, FORK, DENY = "fire", "send", "taint", "fork", "deny"


class Owner:
    """The current Root of one ledger; every transition runs under one lock.

    ``transitions`` is the trusted table mapping a method name to the
    ``(take, put)`` token vectors its call fires. Each entry must conserve the
    weighted token count, so no method can mint.
    """

    def __init__(self, root: Root, transitions: dict[str, tuple] | None = None):
        if type(root) is not Root or not root.conserved():
            raise Denied("ROOT_STATE")
        table = {}
        for method, (take, put) in dict(transitions or {}).items():
            if type(method) is not str or not method:
                raise Denied("TRANSITION_NAME")
            take = _counts(take, PLACES, 0, "FIRE_SHAPE")
            put = _counts(put, PLACES, 0, "FIRE_SHAPE")
            if (sum(x * w for x, w in zip(take, root.weights))
                    != sum(x * w for x, w in zip(put, root.weights))):
                raise Denied("FIRE_NOT_CONSERVED")
            table[method] = (take, put)
        self.transitions = table
        self._root = root
        self._lock = Lock()

    @property
    def root(self) -> Root:
        with self._lock:
            return self._root

    def _own_clock(self, slot: int) -> int:
        if type(slot) is not int or not 0 <= slot < len(self._root.branches):
            raise Denied("BRANCH_SLOT")
        return self._root.branches[slot].clock[slot]

    def clock(self, slot: int) -> int:
        with self._lock:
            return self._own_clock(slot)

    @staticmethod
    def _run(root: Root, slot: int, expected: int, ops) -> tuple[Root, tuple]:
        root.checked(slot, expected)  # An empty batch still needs a live, current branch.
        results = []
        for op, *args in ops:
            if op == FORK:
                root, child = root.fork(slot, expected, *args)
                results.append(child)
            elif op in (FIRE, SEND, TAINT, DENY):
                root = getattr(root, op)(slot, expected, *args)
                results.append(None)
            else:
                raise Denied("UNKNOWN_OPERATION")
            expected = root.branches[slot].clock[slot]
        return root, tuple(results)

    def check(self, slot: int, expected: int, ops) -> tuple:
        """Dry run against the current root; nothing changes."""
        with self._lock:
            return self._run(self._root, slot, expected, tuple(ops))[1]

    def apply(self, slot: int, expected: int, ops) -> tuple:
        """Run the batch fenced on ``expected`` and commit it, all or nothing."""
        with self._lock:
            root, results = self._run(self._root, slot, expected, tuple(ops))
            self._root = root
            return results

    def join(self, slot: int, child: int) -> Root:
        with self._lock:
            self._root = self._root.join(slot, self._own_clock(slot), child)
            return self._root

    def charge_denial(self, slot: int) -> bool:
        """Spend one denial unit for a denial issued elsewhere; False when none is left."""
        with self._lock:
            try:
                self._root = self._root.deny(slot, self._own_clock(slot))
            except Denied:
                return False
            return True
