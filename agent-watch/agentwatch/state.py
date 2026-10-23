"""Small bounded cross-process state store (stdlib sqlite3).

Gunicorn runs several worker processes, so in-memory dicts cannot hold the coordination-board
session state (handoff tokens, single-use nonces, step counters) or the "which decoys has this client
touched" memory.  This store keeps only:

* board sessions (LRU-capped at ``max_sessions``): our own generated decoy token, issuer session id +
  IP, step counter, and *hashes* of the outstanding nonces;
* a capped set of (client key, decoy kind) pairs.

It never stores visitor-supplied text (no captured prompts, no bodies) - those go only to the scrubbed
JSONL.  The file is created mode 0600.  All values written are server-generated or already validated.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

MAX_HIT_ROWS = 20000


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


class StateStore:
    def __init__(self, path: str | Path, max_sessions: int = 2000) -> None:
        self.path = str(path)
        self.max_sessions = max(1, int(max_sessions))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.path):
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, sid TEXT NOT NULL, ip TEXT NOT NULL, created REAL, last REAL,
                registered INTEGER DEFAULT 0, steps INTEGER DEFAULT 0, over_cap_logged INTEGER DEFAULT 0,
                claim_nonce TEXT, board_nonce TEXT)""")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS sessions_sid ON sessions(sid)")
            db.execute("CREATE TABLE IF NOT EXISTS hits (key TEXT, kind TEXT, PRIMARY KEY (key, kind))")
            db.execute("CREATE TABLE IF NOT EXISTS rejects (sid TEXT PRIMARY KEY, n INTEGER)")

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            db.close()

    # ---- board sessions ---------------------------------------------------------------------
    def issue_token(self, sid: str, ip: str, new_token: str) -> tuple[str, bool]:
        """Return (token, reissued).  One token per session id; evicts oldest sessions beyond the cap."""
        now = time.time()
        with self._tx() as db:
            row = db.execute("SELECT token FROM sessions WHERE sid=?", (sid,)).fetchone()
            if row:
                db.execute("UPDATE sessions SET last=? WHERE sid=?", (now, sid))
                return row["token"], True
            db.execute("INSERT INTO sessions(token,sid,ip,created,last) VALUES (?,?,?,?,?)", (new_token, sid, ip, now, now))
            db.execute("DELETE FROM sessions WHERE token IN (SELECT token FROM sessions ORDER BY last ASC "
                       "LIMIT max(0, (SELECT COUNT(*) FROM sessions) - ?))", (self.max_sessions,))
            return new_token, False

    def lookup(self, token: str) -> Optional[dict[str, Any]]:
        if not token or len(token) > 200:
            return None
        with self._tx() as db:
            row = db.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
            return dict(row) if row else None

    def update(self, token: str, **cols: Any) -> None:
        allowed = {"registered", "steps", "over_cap_logged", "claim_nonce", "board_nonce", "last"}
        assert set(cols) <= allowed
        sets = ", ".join(f"{k}=?" for k in cols)
        with self._tx() as db:
            db.execute(f"UPDATE sessions SET {sets} WHERE token=?", (*cols.values(), token))  # noqa: S608 - fixed column names

    def set_nonce(self, token: str, which: str, nonce: Optional[str]) -> None:
        assert which in ("claim_nonce", "board_nonce")
        self.update(token, **{which: _h(nonce) if nonce else None})

    def consume_nonce(self, token: str, which: str, presented: str) -> bool:
        """True (and clears it) iff *presented* equals the outstanding single-use nonce."""
        assert which in ("claim_nonce", "board_nonce")
        with self._tx() as db:
            row = db.execute(f"SELECT {which} AS n FROM sessions WHERE token=?", (token,)).fetchone()  # noqa: S608
            if not row or not row["n"] or row["n"] != _h(presented):
                return False
            db.execute(f"UPDATE sessions SET {which}=NULL WHERE token=?", (token,))  # noqa: S608
            return True

    def count_sessions(self) -> int:
        with self._tx() as db:
            return int(db.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"])

    def note_reject(self, sid: str) -> int:
        """Count of rejected board/claim attempts by this presenter (bounds how many we log)."""
        with self._tx() as db:
            db.execute("INSERT INTO rejects(sid,n) VALUES (?,1) ON CONFLICT(sid) DO UPDATE SET n=n+1", (sid,))
            db.execute("DELETE FROM rejects WHERE sid IN (SELECT sid FROM rejects ORDER BY rowid ASC "
                       "LIMIT max(0, (SELECT COUNT(*) FROM rejects) - 5000))")
            return int(db.execute("SELECT n FROM rejects WHERE sid=?", (sid,)).fetchone()["n"])

    # ---- decoy kinds touched per client ---------------------------------------------------------------
    def add_hit(self, keys: list[str], kind: str) -> None:
        with self._tx() as db:
            for k in keys:
                db.execute("INSERT OR IGNORE INTO hits(key,kind) VALUES (?,?)", (k, kind))
            db.execute("DELETE FROM hits WHERE rowid IN (SELECT rowid FROM hits ORDER BY rowid ASC "
                       "LIMIT max(0, (SELECT COUNT(*) FROM hits) - ?))", (MAX_HIT_ROWS,))

    def hit_kinds(self, keys: list[str]) -> set[str]:
        with self._tx() as db:
            q = ",".join("?" * len(keys))
            return {r["kind"] for r in db.execute(f"SELECT kind FROM hits WHERE key IN ({q})", keys)}  # noqa: S608
