"""Predicate C: implicit-flow and absence laundering across branches.

Explicit taint tracking follows data. It misses information that moves
through *control*: a branch that reads untrusted text, then creates, deletes
or renames a file, or sets a task status, *depending on* that text, signals
one bit to whoever later checks whether the file exists, lists the directory
or reads the status. Deleting is as informative as creating, so the absence
of a name is a channel too. Persistent-memory and provenance work names the
same failure for agent state (Xu et al., *Memory Provenance Laundering in LLM
Agents*, arXiv:2607.29167; AGATE, arXiv:2609.30830).

C keeps, per root, a set of branches and three sticky label maps:

* ``Branch``: ``tainted`` (it has ingested untrusted data) and a program-
  counter stack ``pc_stack`` of condition labels pushed by a trusted control
  plane around data-dependent decisions; ``pc_tainted = tainted or any(pc_stack)``.
* ``entries`` and ``directories``: path -> tainted, for every namespace object
  a branch created, unlinked, made, removed or renamed. The label is the
  mutating branch's ``pc_tainted`` and only rises. An ``unlink`` / ``rmdir`` /
  ``rename`` keeps its source as a tombstone: the name's absence still
  carries the label.
* ``status_labels``: target id -> tainted, for statuses set by a branch.

An observation joins the label into the observer: ``probe`` (existence or
read of a path) joins the labels of the path and every ancestor directory;
``list_directory`` joins those plus every labeled path at or below the
directory; ``observe_status`` joins the status label. The gateway mirrors a
branch's taint into its session before Predicates A and E authorize the
call, so a laundered bit meets the same post-taint gates as a direct read.

Bounds: ``MAX_BRANCHES`` branches, ``MAX_PATHS`` labeled paths in total (the
capacity is checked before any mutation), pc stacks of ``MAX_DEPTH``, paths
of at most ``MAX_PATH_BYTES`` UTF-8 bytes and ``MAX_DEPTH`` components below
``ROOT``. Every refusal raises ``Denied`` with a fixed reason code; paths and
statuses never appear in reason codes.

Not covered: timing of mutations, file sizes and contents (Predicate T),
paths outside ``ROOT``, and any namespace effect the trusted adapter does not
report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .common import Denied

MAX_BRANCHES = 64
MAX_PATHS = 256
MAX_DEPTH = 16
MAX_PATH_BYTES = 256
MAX_ID = 128
MAX_STATUS = 64
ROOT = "/workspace"
OPERATIONS = frozenset({"create", "unlink", "mkdir", "rmdir", "rename"})


@dataclass(slots=True)
class Branch:
    tainted: bool = False
    pc_stack: list[bool] = field(default_factory=list)
    status: str = "active"

    @property
    def pc_tainted(self) -> bool:
        return self.tainted or any(self.pc_stack)


def canonical_path(path, root: str = ROOT) -> str:
    """The path itself, if it is a canonical absolute path at or below ``root``."""
    if type(path) is not str or "\x00" in path:
        raise Denied("C_PATH")
    try:
        size = len(path.encode("utf-8"))
    except UnicodeError:
        raise Denied("C_PATH") from None
    if size > MAX_PATH_BYTES:
        raise Denied("C_PATH")
    if path == root:
        return path
    if not path.startswith(root + "/"):
        raise Denied("C_PATH")
    parts = path[len(root) + 1:].split("/")
    if len(parts) > MAX_DEPTH or any(p in ("", ".", "..") for p in parts):
        raise Denied("C_PATH")
    return path


def _ancestors(path: str, root: str) -> list[str]:
    """``root`` and every directory strictly above ``path`` below it."""
    out = [root]
    if path == root:
        return []
    parts = path[len(root) + 1:].split("/")
    for i in range(1, len(parts)):
        out.append(root + "/" + "/".join(parts[:i]))
    return out


def _ident(value, reason: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_ID:
        raise Denied(reason)
    return value


class CausalityValidator:
    """ONE root's branches and namespace labels; every change is serialized."""

    def __init__(self, root: str = ROOT):
        if type(root) is not str or not root.startswith("/") or root.endswith("/") or len(root) > 64:
            raise Denied("C_ROOT")
        self.root = root
        self.branches: dict[str, Branch] = {}
        self.entries: dict[str, bool] = {}
        self.directories: dict[str, bool] = {}
        self.status_labels: dict[str, bool] = {}
        self.statuses: dict[str, str] = {}
        self._lock = RLock()

    # --- branches -----------------------------------------------------------------

    def branch(self, branch_id: str) -> Branch:
        """The branch, created on first use (at most ``MAX_BRANCHES``)."""
        branch_id = _ident(branch_id, "C_BRANCH_ID")
        with self._lock:
            b = self.branches.get(branch_id)
            if b is None:
                if len(self.branches) >= MAX_BRANCHES:
                    raise Denied("C_BRANCHES")
                b = self.branches[branch_id] = Branch()
            return b

    def _active(self, branch_id: str) -> Branch:
        b = self.branch(branch_id)
        if b.status != "active":
            raise Denied("C_BRANCH_INACTIVE")
        return b

    def ingest_untrusted(self, branch_id: str) -> None:
        with self._lock:
            self.branch(branch_id).tainted = True

    def push_pc(self, branch_id: str, condition_tainted: bool) -> None:
        """Trusted control plane: entering a decision whose condition has this label."""
        if type(condition_tainted) is not bool:
            raise Denied("C_PC_LABEL")
        with self._lock:
            b = self._active(branch_id)
            if len(b.pc_stack) >= MAX_DEPTH:
                raise Denied("C_PC_DEPTH")
            b.pc_stack.append(condition_tainted)

    def pop_pc(self, branch_id: str) -> None:
        with self._lock:
            b = self._active(branch_id)
            if not b.pc_stack:
                raise Denied("C_PC_UNDERFLOW")
            b.pc_stack.pop()

    def is_tainted(self, branch_id: str) -> bool:
        with self._lock:
            return self.branch(branch_id).tainted

    # --- namespace mutations ------------------------------------------------------

    def check_mutation(self, branch_id: str, operation: str, path: str,
                       dest: str | None = None) -> tuple[tuple[str, str], ...]:
        """Pure: the (map, path) keys a mutation would label, or ``Denied``.

        Capacity is checked here, before anything changes.
        """
        if operation not in OPERATIONS:
            raise Denied("C_OPERATION")
        path = canonical_path(path, self.root)
        if path == self.root:
            raise Denied("C_PATH")
        if operation == "rename":
            if dest is None:
                raise Denied("C_DEST")
            dest = canonical_path(dest, self.root)
            if dest == self.root or dest == path:
                raise Denied("C_DEST")
        elif dest is not None:
            raise Denied("C_DEST")
        with self._lock:
            self._active(branch_id)
            if operation in ("mkdir", "rmdir"):
                keys = (("directories", path),)
            elif operation == "rename":
                kind = "directories" if path in self.directories else "entries"
                # The source stays as a tombstone; the destination is new.
                keys = ((kind, path), (kind, dest))
            else:
                keys = (("entries", path),)
            new = {k for k in keys if k[1] not in getattr(self, k[0])}
            if len(self.entries) + len(self.directories) + len(new) > MAX_PATHS:
                raise Denied("C_CAPACITY")
            return keys

    def record_mutation(self, branch_id: str, operation: str, path: str,
                        dest: str | None = None) -> None:
        """Label the mutated names with the branch's pc label (sticky, never lowered)."""
        with self._lock:
            keys = self.check_mutation(branch_id, operation, path, dest)
            label = self.branches[branch_id].pc_tainted
            for kind, key in keys:
                labels = getattr(self, kind)
                labels[key] = labels.get(key, False) or label
            if operation == "rename" and keys[0][0] == "directories":
                # Children move with a directory; their labels join the new name.
                inherited = any(v for p, v in self.entries.items() if p.startswith(keys[0][1] + "/"))
                self.directories[keys[1][1]] = self.directories[keys[1][1]] or inherited

    # --- observations -------------------------------------------------------------

    def _path_label(self, path: str) -> bool:
        """The path's own label joined with every ancestor name's.

        Any labeled ancestor counts, file or directory: whether ``a`` exists
        decides whether ``a/b`` can (ENOTDIR versus ENOENT).
        """
        if self.entries.get(path) or self.directories.get(path):
            return True
        return any(self.directories.get(a) or self.entries.get(a) for a in _ancestors(path, self.root))

    def probe(self, branch_id: str, path: str) -> bool:
        """Observe one path (existence, metadata or read); returns the label joined."""
        path = canonical_path(path, self.root)
        with self._lock:
            b = self.branch(branch_id)
            label = self._path_label(path)
            if label:
                b.tainted = True
            return label

    def list_directory(self, branch_id: str, directory: str) -> bool:
        """Observe a directory listing: every labeled name at or below it counts."""
        directory = canonical_path(directory, self.root)
        prefix = directory.rstrip("/") + "/"
        with self._lock:
            b = self.branch(branch_id)
            label = self._path_label(directory) or any(
                v for p, v in self.entries.items() if p.startswith(prefix)) or any(
                v for p, v in self.directories.items() if p.startswith(prefix))
            if label:
                b.tainted = True
            return label

    def check_status(self, actor_id: str, target_id: str, status: str) -> None:
        """Pure: ``Denied`` when ``record_status`` would refuse."""
        target_id = _ident(target_id, "C_TARGET_ID")
        if type(status) is not str or not 1 <= len(status) <= MAX_STATUS:
            raise Denied("C_STATUS")
        with self._lock:
            self._active(actor_id)
            if target_id not in self.statuses and len(self.statuses) >= MAX_BRANCHES:
                raise Denied("C_CAPACITY")

    def record_status(self, actor_id: str, target_id: str, status: str) -> None:
        """A branch sets a status others can read; the status carries its pc label."""
        with self._lock:
            self.check_status(actor_id, target_id, status)
            actor = self.branches[actor_id]
            self.statuses[target_id] = status
            self.status_labels[target_id] = self.status_labels.get(target_id, False) or actor.pc_tainted

    def observe_status(self, observer_id: str, target_id: str) -> str | None:
        """Read a status; its label joins the observer. None when never set."""
        target_id = _ident(target_id, "C_TARGET_ID")
        with self._lock:
            observer = self.branch(observer_id)
            if self.status_labels.get(target_id):
                observer.tainted = True
            return self.statuses.get(target_id)
