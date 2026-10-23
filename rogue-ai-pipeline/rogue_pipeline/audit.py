"""Hash-chained, append-only audit log (JSON Lines) with a verifier.

Record = {seq, ts, kind, payload, prev, hash}, hash = SHA-256 over the canonical JSON of the other fields, and
``prev`` = the previous record's hash (genesis = 64 zeros). Editing, deleting, inserting or reordering any
record breaks the chain at that point and ``verify`` reports where.

Limit (stated plainly): a hash chain alone cannot detect TRUNCATION of the tail or a wholesale re-computation of
the chain by someone who can rewrite the file. Two mitigations are built in: a sidecar ``<log>.head`` holding the
latest (seq, hash), and an optional ``--anchor <hash>`` you store somewhere else (ticket, other host, printed
page). Verification against an external anchor is the real guarantee.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")


def _hash(rec: Dict[str, Any]) -> str:
    body = {k: rec[k] for k in ("seq", "ts", "kind", "payload", "prev")}
    return hashlib.sha256(_canon(body)).hexdigest()


class AuditLog:
    """Append-only writer. Re-opening an existing log continues its chain (after verifying it)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.head_path = self.path.with_suffix(self.path.suffix + ".head")
        self._seq = 0
        self._prev = GENESIS
        if self.path.exists() and self.path.stat().st_size > 0:
            res = verify_log(self.path)
            if not res.ok:
                raise ValueError(f"refusing to append to a log that fails verification: {res.message}")
            self._seq, self._prev = res.records, res.head or GENESIS

    @property
    def head(self) -> str:
        return self._prev

    def append(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        rec: Dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kind": kind,
            "payload": json.loads(_canon(payload)),   # normalise through JSON so verification round-trips
            "prev": self._prev,
        }
        rec["hash"] = _hash(rec)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self._seq += 1
        self._prev = rec["hash"]
        self.head_path.write_text(json.dumps({"seq": self._seq, "head": self._prev}) + "\n", encoding="utf-8")
        return rec


@dataclass
class VerifyResult:
    ok: bool
    records: int
    message: str
    head: Optional[str] = None
    problems: List[str] = field(default_factory=list)


def verify_log(path: str | Path, anchor: Optional[str] = None) -> VerifyResult:
    """Verify the chain. ``anchor`` (optional) is an externally stored head hash the log must end with."""
    p = Path(path)
    if not p.exists():
        return VerifyResult(False, 0, f"log not found: {p}")
    prev, n = GENESIS, 0
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        try:
            rec = json.loads(line)
            seq, stored, rprev = rec["seq"], rec["hash"], rec["prev"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return VerifyResult(False, n, f"line {lineno}: unreadable or malformed record", None, [f"line {lineno}"])
        if seq != n:
            return VerifyResult(False, n, f"line {lineno}: sequence gap/reorder (expected {n}, found {seq})", None, [f"line {lineno}"])
        if rprev != prev:
            return VerifyResult(False, n, f"line {lineno}: previous-hash link broken (record removed, inserted or reordered)", None, [f"line {lineno}"])
        try:
            expect = _hash(rec)
        except KeyError:
            return VerifyResult(False, n, f"line {lineno}: missing fields", None, [f"line {lineno}"])
        if expect != stored:
            return VerifyResult(False, n, f"line {lineno}: record content does not match its hash (modified)", None, [f"line {lineno}"])
        prev, n = stored, n + 1
    head_file = p.with_suffix(p.suffix + ".head")
    if head_file.exists():
        try:
            h = json.loads(head_file.read_text(encoding="utf-8"))
            if h.get("seq") != n or h.get("head") != prev:
                return VerifyResult(False, n, f"chain is internally consistent but ends at record {n}, while the head file "
                                    f"records {h.get('seq')} (tail truncated or head file stale)", prev, ["head mismatch"])
        except json.JSONDecodeError:
            return VerifyResult(False, n, "head file is unreadable", prev, ["head file"])
    if anchor is not None and anchor != prev:
        return VerifyResult(False, n, "final hash does not match the supplied external anchor", prev, ["anchor mismatch"])
    return VerifyResult(True, n, f"OK: {n} records, chain intact", prev)
