"""Cross-session file-label sidecar for Predicate T.

Labels committed by ``FsTransducer`` are appended to a hash-chained log and
projected into an index that the next session on the same workspace loads.
The chain is the authority. The index is rewritten with ``os.replace`` under
``flock`` so a reader never observes a torn projection.

A real file, when the broker binds a directory, is addressed by
``dev + inode + size + mtime_ns + SHA-256``. A file whose mtime is at or
after the store epoch and that has no record for that exact identity is
UNTRUSTED. So is a file whose inode was recorded and whose bytes no longer
match. Pre-epoch files with no record keep the model default.

The state directory is trusted storage. ``flock`` is advisory and per host.
See DESIGN.md section 6 for the residual cases this does not close.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import fcntl

from .symbolic_fs_transducer import (
    BOTTOM,
    TOP,
    Confidentiality,
    FileLabel,
    Integrity,
    LabelDenied,
)

SCHEMA = "agent-gateway.fs-label-chain/1"
GENESIS = "0" * 64
MAX_RECORDS = 65536
# Filesystem timestamps can lag time.time_ns() by a fraction of a millisecond.
# Anything not strictly older than the epoch by this margin is treated as
# modified during the gateway's lifetime when it has no content record.
EPOCH_SKEW_NS = 2_000_000_000


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _link(record: dict, seq: int, prev_hash: str) -> dict:
    entry = dict(record)
    entry["seq"] = seq
    entry["prev_hash"] = prev_hash
    entry["entry_hash"] = _entry_hash(entry)
    return entry


def encode_object_key(key: tuple) -> str:
    if key and key[0] == "inode" and len(key) == 3:
        return f"inode:{int(key[1])}:{int(key[2])}"
    if key and key[0] == "path" and len(key) == 2 and isinstance(key[1], str):
        return "path:" + key[1]
    raise LabelDenied("LABEL_KEY", "state")


def decode_object_key(text: str) -> tuple:
    if text.startswith("inode:"):
        parts = text.split(":")
        if len(parts) != 3:
            raise LabelDenied("LABEL_KEY", "state")
        return ("inode", int(parts[1]), int(parts[2]))
    if text.startswith("path:") and len(text) > len("path:"):
        return ("path", text[len("path:"):])
    raise LabelDenied("LABEL_KEY", "state")


@dataclass(frozen=True, slots=True)
class ContentId:
    """Identity of one regular file's bytes at one timestamp."""

    dev: int
    ino: int
    size: int
    mtime_ns: int
    sha256: str

    @property
    def key(self) -> str:
        return f"{self.dev}:{self.ino}:{self.size}:{self.mtime_ns}:{self.sha256}"


class FsLabelStore:
    """Append-only label log for one workspace root."""

    def __init__(self, directory: Path, workspace: str, *, epoch_ns: int | None = None):
        if not isinstance(workspace, str) or not workspace.startswith("/") or workspace.endswith("/"):
            raise LabelDenied("LABEL_STORE_ROOT", "state")
        self.directory = Path(directory)
        self.workspace = workspace
        self.directory.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.directory / "chain.jsonl"
        self.index_path = self.directory / "index.json"
        self.lock_path = self.directory / "lock"
        self.real_root: Path | None = None
        self._thread = threading.RLock()
        self.tampered = False
        self.epoch_ns = int(epoch_ns if epoch_ns is not None else 0)
        self._labels: dict[tuple, FileLabel] = {}
        self._content: dict[str, FileLabel] = {}
        self._inode_content: dict[tuple[int, int], str] = {}
        self._seq = 0
        self._head = GENESIS
        self._chain_size = -1
        if epoch_ns is None:
            import time
            self.epoch_ns = time.time_ns()
        with self._exclusive():
            if self.chain_path.is_file() and self.chain_path.stat().st_size:
                self._reload()
            else:
                self._append({"kind": "epoch", "workspace": self.workspace,
                               "epoch_ns": self.epoch_ns, "schema": SCHEMA})
                self._publish_index()

    def bind_real_root(self, real_root: str | Path) -> None:
        """Observe this directory when deciding labels for model paths.

        The directory is the broker's workspace on disk. Model path ``/ws/a``
        maps to ``real_root/a`` when the store's workspace is ``/ws``.
        """
        root = Path(real_root).resolve()
        if not root.is_dir():
            raise LabelDenied("LABEL_STORE_ROOT", "state")
        self.real_root = root

    def floor_label(self) -> FileLabel | None:
        """Label joined into every model file when the chain cannot be trusted."""
        return TOP if self.tampered else None

    def labels_for(self, workspace: str) -> dict[tuple, FileLabel]:
        if workspace != self.workspace or self.tampered:
            return {}
        with self._exclusive():
            return dict(self._labels)

    def content_identity(self, model_path: str) -> ContentId | None:
        """Hash a regular file under the bound root, or None if it is not there."""
        if self.real_root is None or self.tampered:
            return None
        path = self._real_path(model_path)
        if path is None or not path.is_file():
            return None
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return ContentId(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, digest.hexdigest())

    def content_label(self, model_path: str) -> FileLabel | None:
        """Recorded label, an UNTRUSTED floor, or None when the model default stands.

        None means "no opinion": the file is absent, or it predates the epoch
        and this store has never recorded that inode. A symlink, a path that
        escapes the bound root, a post-epoch file with no record, or an inode
        whose bytes changed under it is UNTRUSTED.
        """
        if self.tampered:
            return TOP
        if self.real_root is None:
            return None
        escaped = self._escapes(model_path)
        if escaped:
            return FileLabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED)
        path = self._real_path(model_path)
        if path is None or not path.exists():
            return None
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return FileLabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED)
        ident = self.content_identity(model_path)
        if ident is None:
            return FileLabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED)
        with self._exclusive():
            recorded = self._content.get(ident.key)
            previous = self._inode_content.get((ident.dev, ident.ino))
            changed = previous is not None and previous != ident.key
            if recorded is not None and not changed:
                return recorded
            if changed or ident.mtime_ns + EPOCH_SKEW_NS >= self.epoch_ns:
                floor = FileLabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED)
                if previous is not None and previous in self._content:
                    floor = self._content[previous].join(floor)
                return floor if recorded is None else recorded.join(floor)
            return recorded

    def record(self, key: tuple, label: FileLabel, content: ContentId | None = None) -> None:
        """Append ``label`` if it rises. Labels never lower."""
        if type(label) is not FileLabel:
            raise LabelDenied("LABEL_TYPE", "state")
        encoded = encode_object_key(key)
        with self._exclusive():
            if self.tampered:
                raise LabelDenied("LABEL_STORE_TAMPER", "state")
            if self._seq >= MAX_RECORDS:
                raise LabelDenied("LABEL_STORE_LIMIT", "state")
            current = self._labels.get(key, BOTTOM)
            # flows_to is pointwise <=. Equal labels do not rise. A new content
            # identity is still recorded so a later byte change is visible.
            risen = not label.flows_to(current)
            content_new = False
            if content is not None:
                existing = self._content.get(content.key)
                content_new = existing is None or not label.flows_to(existing)
            if not risen and not content_new:
                return
            body = {
                "kind": "label",
                "workspace": self.workspace,
                "schema": SCHEMA,
                "object_key": encoded,
                "confidentiality": int(label.confidentiality),
                "integrity": int(label.integrity),
            }
            if content is not None:
                body["content_key"] = content.key
                body["inode"] = [content.dev, content.ino]
            self._append(body)
            self._publish_index()

    def verify(self) -> bool:
        with self._exclusive():
            return not self.tampered

    # --- internals -----------------------------------------------------------------

    @contextmanager
    def _exclusive(self):
        with self._thread:
            self.lock_path.touch(exist_ok=True)
            fd = os.open(self.lock_path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._reload_if_stale()
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _reload_if_stale(self) -> None:
        size = self.chain_path.stat().st_size if self.chain_path.is_file() else 0
        if size != self._chain_size:
            self._reload()

    def _reload(self) -> None:
        self.tampered = False
        self._labels = {}
        self._content = {}
        self._inode_content = {}
        self._seq = 0
        self._head = GENESIS
        if not self.chain_path.is_file():
            self._chain_size = 0
            return
        try:
            text = self.chain_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            self._tamper()
            return
        self._chain_size = len(text.encode("utf-8"))
        if not text:
            self._chain_size = 0
            return
        if not text.endswith("\n"):
            self._tamper()
            return
        prev = GENESIS
        epoch = None
        seq = 0
        for line in text.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                self._tamper()
                return
            if (not isinstance(entry, dict) or entry.get("seq") != seq
                    or entry.get("prev_hash") != prev
                    or entry.get("entry_hash") != _entry_hash(entry)
                    or entry.get("workspace") != self.workspace
                    or entry.get("schema") != SCHEMA):
                self._tamper()
                return
            kind = entry.get("kind")
            if kind == "epoch":
                if epoch is not None or not isinstance(entry.get("epoch_ns"), int):
                    self._tamper()
                    return
                epoch = entry["epoch_ns"]
            elif kind == "label":
                try:
                    label = FileLabel(Confidentiality(entry["confidentiality"]),
                                      Integrity(entry["integrity"]))
                    obj = decode_object_key(entry["object_key"])
                except (KeyError, ValueError, LabelDenied):
                    self._tamper()
                    return
                self._labels[obj] = self._labels.get(obj, BOTTOM).join(label)
                content_key = entry.get("content_key")
                if isinstance(content_key, str):
                    self._content[content_key] = self._content.get(content_key, BOTTOM).join(label)
                    inode = entry.get("inode")
                    if isinstance(inode, list) and len(inode) == 2:
                        self._inode_content[(int(inode[0]), int(inode[1]))] = content_key
            else:
                self._tamper()
                return
            prev = entry["entry_hash"]
            seq += 1
        if epoch is None:
            self._tamper()
            return
        self.epoch_ns = epoch
        self._seq = seq
        self._head = prev

    def _tamper(self) -> None:
        self.tampered = True
        self._labels = {}
        self._content = {}
        self._inode_content = {}
        try:
            self._publish_index()
        except OSError:
            pass

    def _append(self, record: dict) -> None:
        entry = _link(record, self._seq, self._head)
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self.chain_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._seq += 1
        self._head = entry["entry_hash"]
        self._chain_size = self.chain_path.stat().st_size
        if record["kind"] == "label":
            label = FileLabel(Confidentiality(record["confidentiality"]),
                              Integrity(record["integrity"]))
            key = decode_object_key(record["object_key"])
            self._labels[key] = self._labels.get(key, BOTTOM).join(label)
            content_key = record.get("content_key")
            if isinstance(content_key, str):
                self._content[content_key] = self._content.get(content_key, BOTTOM).join(label)
                inode = record.get("inode")
                if isinstance(inode, list) and len(inode) == 2:
                    self._inode_content[(int(inode[0]), int(inode[1]))] = content_key

    def _publish_index(self) -> None:
        projection = {
            "schema": SCHEMA,
            "workspace": self.workspace,
            "epoch_ns": self.epoch_ns,
            "head": self._head,
            "records": self._seq,
            "tampered": self.tampered,
            "labels": {encode_object_key(k): [int(v.confidentiality), int(v.integrity)]
                       for k, v in sorted(self._labels.items(), key=lambda item: encode_object_key(item[0]))},
        }
        blob = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        tmp = self.index_path.with_suffix(".json.tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, self.index_path)

    def _real_path(self, model_path: str) -> Path | None:
        if self.real_root is None or self._escapes(model_path):
            return None
        root = self.workspace
        if model_path == root:
            rel = ""
        elif model_path.startswith(root + "/"):
            rel = model_path[len(root) + 1:]
        else:
            return None
        return self.real_root / rel if rel else self.real_root

    def _escapes(self, model_path: str) -> bool:
        if self.real_root is None:
            return False
        root = self.workspace
        if model_path == root:
            rel = ""
        elif isinstance(model_path, str) and model_path.startswith(root + "/"):
            rel = model_path[len(root) + 1:]
        else:
            return False
        if not rel:
            return False
        if rel.startswith("/") or any(part == ".." for part in rel.split("/")):
            return True
        candidate = (self.real_root / rel).resolve()
        try:
            candidate.relative_to(self.real_root)
        except ValueError:
            return True
        return False
