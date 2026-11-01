"""Predicate A: path-qualified capability confinement over a workflow DAG.

Least privilege per *tool* is not enough once a workflow is under way: a
tool that is fine at step 2 can be the wrong next step at step 5, and after
untrusted input some steps should become unreachable altogether. Progent
(Shi et al., arXiv:2504.11703) enforces tool-level privilege policies at
runtime; reachability-based confinement (arXiv:2608.30041) prunes the
capabilities an agent may still exercise to those on a path that can finish
the task.

A ``ReachabilityPolicy`` is a DAG of at most 64 ``Node``s, forward-indexed
(every successor index is larger than its node's), so index order is a
topological order. Node 0 is the start state. A node may discharge
obligation bits (at most 8) and may be ``forbidden_if_tainted``. A node with
no successors must be ``terminal``.

At boot the policy precomputes, in reverse topological order:

* ``forward[i]``: the bitmask of ``i``'s successors;
* ``viable_paths[t][r]``: the bitmask of nodes ``i`` from which, entering
  ``i`` with remaining obligations ``r`` under taint ``t``, some path reaches
  a terminal with every obligation discharged and, when tainted, no
  forbidden node. A node's own discharge is applied first
  (``r' = r & ~discharge_mask``) and its children are looked up under ``r'``,
  so a terminal reachable only *after* an intermediate discharge is never
  pruned early.

* ``live_paths[t][r][i]``: the bitmask of nodes on at least one such
  completion path that starts after ``i`` (with ``r`` already reduced by
  ``i``'s discharge), applying each node's discharge along the path.

The hot path is three ANDs: ``forward[step] & viable_paths[tainted][obligations]
& ~revoked``. Revocation is sticky: whenever the state changes, every node
not in ``live_paths[tainted][obligations][step]`` is added to ``revoked`` and
stays there. A node that only becomes viable after a later discharge on the
way is live, so it is not revoked early. ``contaminate()`` raises taint (taint
never falls); ``transition`` moves to a candidate node or denies
(``A_UNREACHABLE``); ``terminate_or_deny`` denies stopping anywhere but a
terminal with no obligations left (``A_UNFINISHED``).

Boot work is ``O(2**obligation_bits * n * out-degree)``, at most
``256 * 64 * 63`` bit operations; each call is O(1). Every refusal raises
``Denied`` with a fixed reason code.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from .common import Denied

MAX_NODES = 64
MAX_OBLIGATION_BITS = 8
MAX_NAME = 128


@dataclass(frozen=True, slots=True)
class Node:
    name: str
    successors: tuple[int, ...] = ()
    terminal: bool = False
    discharge_mask: int = 0
    forbidden_if_tainted: bool = False


class ReachabilityPolicy:
    """Immutable after construction; every table is computed once."""

    def __init__(self, nodes, obligation_bits: int = 0):
        nodes = tuple(nodes)
        if not 1 <= len(nodes) <= MAX_NODES or any(type(n) is not Node for n in nodes):
            raise Denied("A_NODES")
        if type(obligation_bits) is not int or not 0 <= obligation_bits <= MAX_OBLIGATION_BITS:
            raise Denied("A_OBLIGATIONS")
        n = len(nodes)
        for i, node in enumerate(nodes):
            if type(node.name) is not str or not 1 <= len(node.name) <= MAX_NAME:
                raise Denied("A_NAME")
            succ = node.successors
            if (type(succ) is not tuple or len(set(succ)) != len(succ)
                    or any(type(j) is not int or not i < j < n for j in succ)):
                raise Denied("A_NOT_FORWARD")
            if not succ and not node.terminal:
                raise Denied("A_DEAD_END")
            if type(node.terminal) is not bool or type(node.forbidden_if_tainted) is not bool:
                raise Denied("A_NODE_FLAGS")
            if type(node.discharge_mask) is not int or not 0 <= node.discharge_mask < (1 << obligation_bits):
                raise Denied("A_DISCHARGE")
        self.nodes = nodes
        self.obligation_bits = obligation_bits
        self.all_mask = (1 << n) - 1
        self.forward = tuple(sum(1 << j for j in node.successors) for node in nodes)
        rows = 1 << obligation_bits
        viable = [[0] * rows for _ in range(2)]
        for t in (0, 1):
            for r in range(rows):  # r & ~mask <= r: smaller rows are already done
                mask = 0
                for i in range(n - 1, -1, -1):
                    node = nodes[i]
                    if t and node.forbidden_if_tainted:
                        continue
                    rem = r & ~node.discharge_mask
                    if node.terminal and rem == 0:
                        mask |= 1 << i
                        continue
                    child_row = mask if rem == r else viable[t][rem]
                    if self.forward[i] & child_row:
                        mask |= 1 << i
                viable[t][r] = mask
        self.viable_paths = tuple(tuple(row) for row in viable)
        live = [[[0] * n for _ in range(rows)] for _ in range(2)]
        for t in (0, 1):
            for r in range(rows):
                for i in range(n - 1, -1, -1):
                    acc = 0
                    for j in nodes[i].successors:
                        if (viable[t][r] >> j) & 1:
                            acc |= (1 << j) | live[t][r & ~nodes[j].discharge_mask][j]
                    live[t][r][i] = acc
        self.live_paths = tuple(tuple(tuple(row) for row in by_r) for by_r in live)

    def index_of(self, name: str, candidates: int) -> int:
        """The lowest-index candidate node with this name."""
        for i, node in enumerate(self.nodes):
            if node.name == name and (candidates >> i) & 1:
                return i
        if any(node.name == name for node in self.nodes):
            raise Denied("A_UNREACHABLE")
        raise Denied("A_NOT_IN_POLICY")


class CapabilityPruner:
    """ONE workflow run's position; every transition is serialized."""

    def __init__(self, policy: ReachabilityPolicy, initial_step: int = 0, obligations: int = 0,
                 tainted: bool = False):
        if type(policy) is not ReachabilityPolicy:
            raise Denied("A_POLICY")
        if type(initial_step) is not int or not 0 <= initial_step < len(policy.nodes):
            raise Denied("A_STEP")
        if type(obligations) is not int or not 0 <= obligations < (1 << policy.obligation_bits):
            raise Denied("A_OBLIGATIONS")
        if type(tainted) is not bool:
            raise Denied("A_TAINT")
        self.policy = policy
        self.step = initial_step
        self.obligations = obligations & ~policy.nodes[initial_step].discharge_mask
        self.tainted = tainted
        self.revoked_mask = 0
        self._lock = RLock()
        self._revoke()

    def _revoke(self) -> None:
        p = self.policy
        live = p.live_paths[int(self.tainted)][self.obligations][self.step]
        self.revoked_mask |= p.all_mask & ~live

    def _candidate_mask(self) -> int:
        p = self.policy
        return (p.forward[self.step] & p.viable_paths[int(self.tainted)][self.obligations]
                & (~self.revoked_mask & p.all_mask))

    def candidates(self) -> tuple[str, ...]:
        with self._lock:
            mask = self._candidate_mask()
            return tuple(n.name for i, n in enumerate(self.policy.nodes) if (mask >> i) & 1)

    def contaminate(self) -> None:
        with self._lock:
            self.tainted = True
            self._revoke()

    def check(self, node, incoming_taint: bool = False) -> int:
        """Pure: the node index ``transition`` would move to, or ``Denied``."""
        with self._lock:
            tainted = self.tainted or bool(incoming_taint)
            p = self.policy
            mask = (p.forward[self.step] & p.viable_paths[int(tainted)][self.obligations]
                    & ~self.revoked_mask & p.all_mask)
            if type(node) is int:
                if not 0 <= node < len(p.nodes):
                    raise Denied("A_NOT_IN_POLICY")
                if not (mask >> node) & 1:
                    raise Denied("A_UNREACHABLE")
                return node
            if type(node) is not str:
                raise Denied("A_NOT_IN_POLICY")
            return p.index_of(node, mask)

    def transition(self, node, incoming_taint: bool = False) -> int:
        with self._lock:
            if incoming_taint:
                self.contaminate()
            index = self.check(node)
            self.step = index
            self.obligations &= ~self.policy.nodes[index].discharge_mask
            self._revoke()
            return index

    def terminate_or_deny(self) -> None:
        with self._lock:
            node = self.policy.nodes[self.step]
            if not node.terminal or self.obligations:
                raise Denied("A_UNFINISHED")
