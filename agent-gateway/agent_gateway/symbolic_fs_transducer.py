"""Predicate T: (confidentiality, integrity) labels carried across file effects.

``workspace_path_validator.py`` (Predicate W) denies writes to protected paths
and inodes but deliberately allows reading them: ``cat .mcp.json`` or
``cp .mcp.json out/x`` are legal effects. Two flows stay open after W alone:

* secret laundering - a protected or sensitive file is copied into an ordinary
  workspace file, and the copy is then attached to an outbound call;
* untrusted write-back - content produced while the session is untrusted is
  written into a workspace file, and that file is later consumed by a config
  or execution sink.

This module tracks a two-dimensional label per file object in a copy-on-write
overlay on top of W's immutable ``Snapshot``. It is a MODEL, like W: it
executes nothing and reads no real file. The broker that owns the namespace
publishes new base snapshots with ``FsTransducer.rebase``.

Lattice: ``Confidentiality`` (PUBLIC < SENSITIVE < PROTECTED) times
``Integrity`` (TRUSTED < UNTRUSTED), joined pointwise with ``max``.

For one analyzed call with resolved read sources R and write targets E::

    label_new = (PUBLIC, session_integrity) join (join of label(r) for r in R)
    label(w) := label(w) join label_new          for every w in E

Labels only ever rise. The model cannot see whether a write completed or
replaced the whole file, so lowering a label on overwrite could understate
what the file holds; raising it can only overstate. The whole analyzed
command is one unit: W's effect union does not say which pipeline member
feeds which, so joining across the command over-approximates the flow and
never misses one.

Sinks, checked against R before any state changes:

* ``is_egress`` - deny when any source has confidentiality above PUBLIC;
* ``is_config_or_exec_sink`` - deny when any source has integrity UNTRUSTED;
* ``chmod`` - its target is treated as an execution sink (``Intent`` drops
  the mode bits, so every chmod of an UNTRUSTED file is denied).

Every denial raises ``Denied`` with a fixed reason code; reason codes never
carry paths or file content. A denial from the base W check propagates
unchanged and leaves the overlay untouched.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from threading import RLock
from types import MappingProxyType

from .common import Denied
from .workspace_path_validator import Intent, Resolved, Snapshot, protected

MAX_OVERLAY = 65536
_NO_INODE = (0, 0)


class Confidentiality(IntEnum):
    PUBLIC = 0
    SENSITIVE = 1
    PROTECTED = 2


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1


@dataclass(frozen=True, slots=True)
class FileLabel:
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    integrity: Integrity = Integrity.TRUSTED

    def __post_init__(self):
        if type(self.confidentiality) is not Confidentiality or type(self.integrity) is not Integrity:
            raise Denied("LABEL_TYPE")

    def join(self, other: FileLabel) -> FileLabel:
        return FileLabel(max(self.confidentiality, other.confidentiality),
                         max(self.integrity, other.integrity))

    def flows_to(self, other: FileLabel) -> bool:
        """Lattice order: pointwise <=."""
        return (self.confidentiality <= other.confidentiality
                and self.integrity <= other.integrity)


BOTTOM = FileLabel()
TOP = FileLabel(Confidentiality.PROTECTED, Integrity.UNTRUSTED)
PROTECTED_DEFAULT = FileLabel(Confidentiality.PROTECTED, Integrity.TRUSTED)


class LabelDenied(Denied):
    """A Predicate T denial. ``axis`` is confidentiality, integrity or state."""

    def __init__(self, reason: str, axis: str):
        super().__init__(reason)
        self.axis = axis


@dataclass(frozen=True, slots=True)
class FlowEffect:
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    source_label: FileLabel
    label: FileLabel


def object_key(resolved: Resolved) -> tuple:
    """Inode identity when the model has one, else the canonical path."""
    node = resolved.node
    if node is not None and node.inode != _NO_INODE:
        return ("inode",) + tuple(node.inode)
    return ("path", resolved.path)


def path_intents(reads: tuple[str, ...] = (), writes: tuple[str, ...] = ()) -> tuple[Intent, ...]:
    """Explicit read and write path sets expressed as W intents."""
    return (tuple(Intent("read", p) for p in reads)
            + tuple(Intent("write", p) for p in writes))


def _unique(items: list[Resolved]) -> tuple[Resolved, ...]:
    seen = {}
    for item in items:
        seen.setdefault(item.path, item)
    return tuple(seen.values())


class TransducerSnapshot:
    """Immutable: W's base snapshot plus a label overlay and its generation."""

    __slots__ = ("base", "overlay", "generation")

    def __init__(self, base: Snapshot, overlay=None, generation: int = 0):
        if not isinstance(base, Snapshot):
            raise Denied("BASE_SNAPSHOT")
        overlay = dict(overlay or {})
        if len(overlay) > MAX_OVERLAY:
            raise LabelDenied("LABEL_OVERLAY_LIMIT", "state")
        object.__setattr__(self, "base", base)
        object.__setattr__(self, "overlay", MappingProxyType(overlay))
        object.__setattr__(self, "generation", generation)

    def __setattr__(self, name, value):
        raise AttributeError("TransducerSnapshot is immutable")

    def default_label(self, resolved: Resolved) -> FileLabel:
        base = self.base
        node = resolved.node
        if (resolved.path in base.protected_names or protected(resolved.path, base.root)
                or (node is not None and node.inode != _NO_INODE
                    and node.inode in base.protected_inodes)):
            return PROTECTED_DEFAULT
        return BOTTOM

    def label_of(self, resolved: Resolved) -> FileLabel:
        label = self.default_label(resolved)
        for key in {object_key(resolved), ("path", resolved.path)}:
            entry = self.overlay.get(key)
            if entry is not None:
                label = label.join(entry)
        return label

    def label_at(self, path: str, cwd: str | None = None) -> FileLabel:
        return self.label_of(self.base.check(Intent("read", path), cwd))

    def evaluate(self, intents: tuple[Intent, ...], cwd: str | None = None, *,
                 session_integrity: Integrity = Integrity.TRUSTED,
                 is_egress: bool = False, is_config_or_exec_sink: bool = False,
                 ) -> tuple[FlowEffect, TransducerSnapshot]:
        """Pure: return the effect and the successor snapshot, or raise Denied."""
        intents = tuple(intents)
        targets = self.base.check_all(intents, cwd)  # Predicate W first.
        reads: list[Resolved] = []
        writes: list[Resolved] = []
        exec_targets: list[Resolved] = []
        for intent, target in zip(intents, targets):
            op = intent.operation
            if op == "read":
                reads.append(target)
            elif op in {"copy", "move"}:
                reads.append(self.base.resolve(intent.source, cwd))
                writes.append(target)
            elif op == "write":
                writes.append(target)
            elif op in {"append", "edit"}:
                if target.node is not None:
                    reads.append(target)  # Prior content remains in the file.
                writes.append(target)
            elif op == "chmod":
                exec_targets.append(target)
            # remove / symlink carry no content; labels are kept (never lowered).
        reads_u, writes_u = _unique(reads), _unique(writes)
        read_labels = [self.label_of(r) for r in reads_u]
        if is_egress and any(l.confidentiality > Confidentiality.PUBLIC for l in read_labels):
            raise LabelDenied("CONFIDENTIAL_SOURCE_TO_EGRESS", "confidentiality")
        if is_config_or_exec_sink and any(l.integrity > Integrity.TRUSTED for l in read_labels):
            raise LabelDenied("UNTRUSTED_SOURCE_TO_EXEC_SINK", "integrity")
        if any(self.label_of(t).integrity > Integrity.TRUSTED for t in exec_targets):
            raise LabelDenied("UNTRUSTED_CHMOD_TARGET", "integrity")
        source_label = BOTTOM
        for label in read_labels:
            source_label = source_label.join(label)
        label_new = FileLabel(Confidentiality.PUBLIC, Integrity(session_integrity)).join(source_label)
        effect = FlowEffect(tuple(r.path for r in reads_u), tuple(w.path for w in writes_u),
                            source_label, label_new)
        if not writes_u:
            return effect, self
        overlay = dict(self.overlay)
        for target in writes_u:
            key = object_key(target)
            overlay[key] = overlay.get(key, BOTTOM).join(label_new)
        return effect, TransducerSnapshot(self.base, overlay, self.generation + 1)


@dataclass(frozen=True, slots=True)
class PendingLabels:
    expected_generation: int
    effect: FlowEffect
    successor: TransducerSnapshot


class FsTransducer:
    """ONE session's label state; every transition is serialized under the lock."""

    def __init__(self, snapshot: Snapshot):
        self._state = TransducerSnapshot(snapshot)
        self.session_integrity = Integrity.TRUSTED
        self._lock = RLock()

    @property
    def state(self) -> TransducerSnapshot:
        with self._lock:
            return self._state

    @property
    def generation(self) -> int:
        with self._lock:
            return self._state.generation

    def observe_untrusted(self) -> None:
        """Monotonic: once untrusted, every later write carries UNTRUSTED."""
        with self._lock:
            self.session_integrity = Integrity.UNTRUSTED

    def label_at(self, path: str, cwd: str | None = None) -> FileLabel:
        with self._lock:
            return self._state.label_at(path, cwd)

    def check(self, intents: tuple[Intent, ...], cwd: str | None = None, *,
              is_egress: bool = False, is_config_or_exec_sink: bool = False) -> PendingLabels:
        """Evaluate without committing."""
        with self._lock:
            state = self._state
            effect, successor = state.evaluate(
                intents, cwd, session_integrity=self.session_integrity,
                is_egress=is_egress, is_config_or_exec_sink=is_config_or_exec_sink)
            return PendingLabels(state.generation, effect, successor)

    def commit(self, pending: PendingLabels) -> FlowEffect:
        """Fenced on the generation the pending result was computed from."""
        with self._lock:
            if pending.expected_generation != self._state.generation:
                raise LabelDenied("STALE_LABEL_GENERATION", "state")
            self._state = pending.successor
            return pending.effect

    def apply(self, intents: tuple[Intent, ...], cwd: str | None = None, **sinks) -> FlowEffect:
        with self._lock:
            return self.commit(self.check(intents, cwd, **sinks))

    def rebase(self, snapshot: Snapshot, *, aliases=None, path_moves=None) -> None:
        """Adopt a newer broker-published base; labels carry over and follow identity.

        Three carries, each a join (labels never lower):

        * a ``("path", p)`` label whose path now resolves to a modeled inode is
          copied onto that inode key, so an unborn file keeps its label once it
          is published;
        * ``aliases`` maps an old inode to the inode that replaced it (GNU
          ``sed -i`` and ``mv`` swap inodes): the old inode's label is joined
          onto the new one;
        * ``path_moves`` maps an old canonical path to the path it was renamed
          or materialized at: the old path's full label (defaults included) is
          joined onto the new path and the inode it resolves to.

        ``aliases`` and ``path_moves`` must come from the broker that ran the
        commands, never from the agent. A declared target that is malformed or
        does not resolve to a modeled object in ``snapshot`` fails closed
        (``LABEL_ALIAS_UNRESOLVABLE``) and nothing changes.
        """
        with self._lock:
            state = self._state
            base = state.base
            if not isinstance(snapshot, Snapshot) or snapshot.root != base.root:
                raise LabelDenied("REBASE_ROOT", "state")
            if snapshot.generation <= base.generation:
                raise LabelDenied("STALE_FILESYSTEM_GENERATION", "state")
            aliases = dict(aliases or {})
            path_moves = dict(path_moves or {})
            if len(aliases) + len(path_moves) > MAX_OVERLAY:
                raise LabelDenied("LABEL_OVERLAY_LIMIT", "state")
            old = state.overlay
            overlay = dict(old)

            def carry(key: tuple, label: FileLabel) -> None:
                if label != BOTTOM:
                    overlay[key] = overlay.get(key, BOTTOM).join(label)

            def inode_key(inode) -> tuple:
                if (type(inode) is not tuple or len(inode) != 2
                        or any(type(x) is not int or x < 0 for x in inode) or inode == _NO_INODE):
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state")
                return ("inode",) + inode

            def resolve_new(path) -> Resolved:
                if type(path) is not str or not path.startswith(snapshot.root + "/"):
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state")
                try:
                    resolved = snapshot.resolve(path)
                except Denied:
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state") from None
                if resolved.node is None or resolved.node.kind != "file":
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state")
                return resolved

            # Unborn (or path-keyed) labels follow their path onto its new inode.
            for key, label in old.items():
                if key[0] != "path":
                    continue
                try:
                    resolved = snapshot.resolve(key[1])
                except Denied:
                    continue
                if resolved.node is not None and resolved.node.inode != _NO_INODE:
                    carry(object_key(resolved), label)

            modeled = {n.inode for n in snapshot.nodes.values() if n.inode != _NO_INODE}
            for old_inode, new_inode in aliases.items():
                old_key, new_key = inode_key(old_inode), inode_key(new_inode)
                if new_inode not in modeled:
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state")
                carry(new_key, old.get(old_key, BOTTOM))

            for old_path, new_path in path_moves.items():
                if type(old_path) is not str or not old_path.startswith(base.root + "/"):
                    raise LabelDenied("LABEL_ALIAS_UNRESOLVABLE", "state")
                label = old.get(("path", old_path), BOTTOM)
                try:
                    label = label.join(state.label_of(base.resolve(old_path)))
                except Denied:
                    pass  # Unborn in the old model: its path key is all there is.
                target = resolve_new(new_path)
                carry(("path", target.path), label)
                carry(object_key(target), label)

            # The bump fences any result computed against the old base.
            self._state = TransducerSnapshot(snapshot, overlay, state.generation + 1)
