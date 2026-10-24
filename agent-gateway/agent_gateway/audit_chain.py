"""Tamper-evident hash-chained decision log and audit manifest.

Every PEP decision-log line (``alerts.jsonl``) carries:

- ``seq``: 0-based position in the chain
- ``prev_hash``: ``entry_hash`` of the previous line (``"0" * 64`` for seq 0)
- ``entry_hash``: SHA-256 over the canonical JSON of the line without
  ``entry_hash`` (sorted keys, no whitespace)

Editing, dropping, reordering, or inserting a line breaks the chain. Dropping
lines from the tail is caught by the manifest, which records the head hash
and entry count.

``audit_manifest.json`` lists SHA-256 digests of every file in an audit
output directory plus the decision-log head, and an HMAC-SHA256 over the
manifest body with the gateway root key (``AGENT_GATEWAY_HMAC_KEY``).
``verify_audit_dir`` recomputes all of it. A passing verify says the files
match the manifest and the chain is continuous. It is not a certification and
not a penetration test.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .capability import hmac_key

GENESIS = "0" * 64
MANIFEST_NAME = "audit_manifest.json"
MANIFEST_SCHEMA = "agent-gateway.audit-manifest/1"
DECISION_LOG_NAME = "decision-log.jsonl"
CHAIN_FIELDS = ("seq", "prev_hash", "entry_hash")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def link(record: dict, seq: int, prev_hash: str) -> dict:
    """Return ``record`` with chain fields set. Existing chain fields are replaced."""
    entry = {k: v for k, v in record.items() if k not in CHAIN_FIELDS}
    entry["seq"] = int(seq)
    entry["prev_hash"] = prev_hash
    entry["entry_hash"] = entry_hash(entry)
    return entry


class ChainWriter:
    """Append-only JSONL writer that links each line to the previous one.

    Resumes from the last chained line already in the file, so a restarted
    gateway keeps extending the same chain.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.seq, self.head = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.path.is_file():
            return 0, GENESIS
        last: Optional[dict] = None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and isinstance(obj.get("entry_hash"), str) and isinstance(obj.get("seq"), int):
                    last = obj
        if last is None:
            return 0, GENESIS
        return int(last["seq"]) + 1, str(last["entry_hash"])

    def append(self, record: dict) -> dict:
        with self._lock:
            entry = link(record, self.seq, self.head)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
            self.seq += 1
            self.head = entry["entry_hash"]
            return entry


@dataclass
class ChainReport:
    ok: bool
    entries: int = 0
    head_hash: str = GENESIS
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries, "head_hash": self.head_hash, "errors": self.errors[:50]}


def verify_chain_lines(lines: list[str]) -> ChainReport:
    """Check seq continuity, prev_hash links, and each entry_hash."""
    errors: list[str] = []
    prev = GENESIS
    seq = 0
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            errors.append(f"line {lineno}: not JSON")
            continue
        if not isinstance(entry, dict) or not all(k in entry for k in CHAIN_FIELDS):
            errors.append(f"line {lineno}: missing seq/prev_hash/entry_hash")
            continue
        if entry["seq"] != seq:
            errors.append(f"line {lineno}: seq {entry['seq']!r}, expected {seq}")
        if entry["prev_hash"] != prev:
            errors.append(f"line {lineno}: prev_hash does not match the previous entry")
        if entry_hash(entry) != entry["entry_hash"]:
            errors.append(f"line {lineno}: entry_hash mismatch (content changed)")
        prev = str(entry["entry_hash"])
        seq += 1
    return ChainReport(ok=not errors, entries=seq, head_hash=prev, errors=errors)


def verify_chain_file(path: Path) -> ChainReport:
    return verify_chain_lines(Path(path).read_text(encoding="utf-8").splitlines())


def _manifest_mac(body: dict, key: Optional[bytes] = None) -> str:
    return hmac.new(hmac_key() if key is None else key, canonical(body), hashlib.sha256).hexdigest()


def build_manifest(out_dir: Path, *, decision_log: Optional[Path] = None, key: Optional[bytes] = None) -> dict:
    """Digest every regular file in ``out_dir`` (except the manifest itself)."""
    out_dir = Path(out_dir)
    files = {}
    for path in sorted(out_dir.iterdir()):
        if not path.is_file() or path.name == MANIFEST_NAME:
            continue
        files[path.name] = {"sha256": sha256_file(path), "bytes": path.stat().st_size}
    chain: Optional[dict] = None
    if decision_log is not None and Path(decision_log).is_file():
        rep = verify_chain_file(decision_log)
        chain = {"file": Path(decision_log).name, **rep.as_dict()}
    body = {
        "schema": MANIFEST_SCHEMA,
        "hash": "sha256",
        "files": files,
        "decision_log": chain,
        "note": "Tamper-evidence for these files only. Not a certification and not a penetration test.",
    }
    return {**body, "hmac_sha256": _manifest_mac(body, key)}


def write_manifest(out_dir: Path, *, decision_log: Optional[Path] = None, key: Optional[bytes] = None) -> dict:
    manifest = build_manifest(out_dir, decision_log=decision_log, key=key)
    (Path(out_dir) / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_audit_dir(audit_dir: Path, *, key: Optional[bytes] = None) -> dict:
    """Recompute file digests, the decision-log chain, and the manifest HMAC."""
    audit_dir = Path(audit_dir)
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    mpath = audit_dir / MANIFEST_NAME
    if not mpath.is_file():
        check("manifest", False, f"{MANIFEST_NAME} not found")
        return {"ok": False, "audit_dir": str(audit_dir), "checks": checks}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        check("manifest", False, f"not JSON: {exc.msg}")
        return {"ok": False, "audit_dir": str(audit_dir), "checks": checks}
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        check("manifest", False, "unknown schema")
        return {"ok": False, "audit_dir": str(audit_dir), "checks": checks}

    body = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    mac = str(manifest.get("hmac_sha256") or "")
    expect = _manifest_mac(body, key)
    check("manifest_hmac", len(mac) == len(expect) and hmac.compare_digest(mac, expect),
          "HMAC-SHA256 with the gateway root key")

    files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    for name, meta in sorted(files.items()):
        path = audit_dir / name
        if "/" in name or "\\" in name or name.startswith(".."):
            check(f"file:{name}", False, "unsafe path in manifest")
            continue
        if not path.is_file():
            check(f"file:{name}", False, "missing")
            continue
        got = sha256_file(path)
        check(f"file:{name}", got == (meta or {}).get("sha256"), "sha256 matches" if got == (meta or {}).get("sha256") else "sha256 differs")
    for path in sorted(audit_dir.iterdir()):
        if path.is_file() and path.name != MANIFEST_NAME and path.name not in files:
            check(f"file:{path.name}", False, "not listed in manifest")

    chain = manifest.get("decision_log")
    if isinstance(chain, dict):
        log_path = audit_dir / str(chain.get("file") or DECISION_LOG_NAME)
        if not log_path.is_file():
            check("decision_log_chain", False, "decision log missing")
        else:
            rep = verify_chain_file(log_path)
            check("decision_log_chain", rep.ok, "; ".join(rep.errors[:5]) or f"{rep.entries} entries linked")
            check("decision_log_head", rep.entries == chain.get("entries") and rep.head_hash == chain.get("head_hash"),
                  "entry count and head hash match the manifest")
    else:
        check("decision_log_chain", True, "no decision log in this audit")

    return {"ok": all(c["ok"] for c in checks), "audit_dir": str(audit_dir), "checks": checks}
