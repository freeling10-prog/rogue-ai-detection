"""Honeypot lead records: schema, sanitisation, capped JSONL writer, reader.

A *lead* is one JSON object per line.  Schema ``agentwatch.lead/1``::

    {
      "schema": "agentwatch.lead/1",
      "event_type": "honeytoken_hit",        # or "decoy_context" (informational)
      "event_id": "<uuid hex>",
      "timestamp": "2026-10-22T20:55:01.123456Z",   # UTC
      "source_ip": "127.0.0.1",
      "priority": "high",  "severity": "high",  "lead": true,
      "token_id": "ht-1a2b3c4d5e6f",         # unique per decoy
      "decoy": {"name": ..., "kind": ..., "token_id": ...},
      "request": {"method","path","raw_query","query","headers",
                  "user_agent","referer","body_preview","body_bytes_read",
                  "body_truncated","content_length","response_status","response_bytes"},
      "matches": {"credential_token_ids": [...], "canary_ids": [...]},
      "detail": {...flat scalars: step/of/chain_valid, origin, tool, ...},
      "timing": {"since_prev_response_s","prev_response_bytes","approx_prev_tokens"},
      "tags": [...], "tarpit_delay_s": 0.0, "decoy_content_synthetic": true,
      # flat aliases for simple downstream consumers:
      "user_agent","method","path","decoy_kind"
    }

The scoring engine ingests these through agentwatch.parser (they become
Requests tagged with the decoy).  Everything attacker-controlled is
sanitised: control characters (incl. ESC/CR/LF) are neutralised and every
field is length-capped, so neither the log file nor a terminal can be abused.
"""
from __future__ import annotations

import json
import os
import re
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .scrubber import Scrubber, get_default_scrubber

SCHEMA = "agentwatch.lead/1"

MAX_BODY_BYTES = 4096          # request body bytes read & logged, at most
MAX_HEADERS = 40
MAX_HEADER_VALUE = 300
MAX_PATH = 512
MAX_QUERY_KEYS = 20
MAX_QUERY_VALUE = 200
DEFAULT_MAX_LOG_BYTES = 50 * 1024 * 1024
REDACTED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key"})

_ESCAPES = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}
# C0/C1 controls, DEL, line/paragraph separators, and bidi override characters.  They are DELETED
# (not replaced) so a secret cannot be split into scrubber-proof fragments by inserting them.
_BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def sanitize_text(value: Any, limit: int = 256) -> str:
    """Make attacker-controlled text safe to log and to print.

    CR/LF/TAB become the visible escapes ``\\r \\n \\t`` (so a payload cannot
    forge extra log lines), other control/format characters (ESC, zero-width...) are deleted,
    and the result is truncated to *limit* characters with a marker.
    """
    text = value if isinstance(value, str) else str(value)
    for ch, rep in _ESCAPES.items():
        text = text.replace(ch, rep)
    text = _BAD_CHARS.sub("", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")   # zero-width, BOM, soft hyphen...
    if len(text) > limit:
        text = text[:limit] + f"...[truncated {len(text) - limit} chars]"
    return text


def sanitize_detail(detail: Mapping[str, Any]) -> dict[str, Any]:
    """Flat dict of scalars only: strings sanitised/capped, at most 12 keys."""
    out: dict[str, Any] = {}
    for i, (k, v) in enumerate(detail.items()):
        if i >= 12:
            break
        key = sanitize_text(k, 40)
        out[key] = v if isinstance(v, (bool, int, float)) or v is None else sanitize_text(v, 200)
    return out


def utc_iso(dt: datetime) -> str:
    """ISO-8601 UTC with trailing Z."""
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sanitize_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Cap, sanitise and redact credential-bearing headers.

    Credentials are never stored: only their length is kept (plus, for recognised token shapes, the salted
    hash from the scrubber), so a real secret that is mistakenly sent to the honeypot does not land in the log.
    """
    out: dict[str, str] = {}
    for i, (k, v) in enumerate(headers):
        if i >= MAX_HEADERS:
            out["x-agentwatch-note"] = "header list truncated"
            break
        name = sanitize_text(k, 64).lower()
        if name in REDACTED_HEADERS:
            # credential header: keep only a salted hash of any recognised token (correlation without the secret)
            shown = get_default_scrubber().scrub_text(sanitize_text(v, MAX_HEADER_VALUE))
            out[name] = f"[redacted len={len(v)}] {shown}" if "[REDACTED_" in shown else f"[redacted len={len(v)}]"
        else:
            out[name] = sanitize_text(v, MAX_HEADER_VALUE)
    return out


def sanitize_query(args: Mapping[str, list[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i, (k, vals) in enumerate(args.items()):
        if i >= MAX_QUERY_KEYS:
            out["_truncated"] = ["more query keys omitted"]
            break
        out[sanitize_text(k, 64)] = [sanitize_text(v, MAX_QUERY_VALUE) for v in vals[:5]]
    return out


class LeadWriter:
    """Thread-safe, size-capped, append-only JSONL writer (file mode 0600)."""

    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_LOG_BYTES,
                 scrubber: Optional[Scrubber] = None) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.scrubber = scrubber or get_default_scrubber()
        self.dropped = 0
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict[str, Any]) -> bool:
        """Scrub, then append one record; returns False if dropped (size cap or scrub failure).

        The scrubber runs HERE, immediately before serialisation, so no code path can write a raw
        secret/PII value.  On any scrub error the record is dropped (never written raw) and the
        exception message is not propagated (it could contain the value)."""
        try:
            safe = self.scrubber.scrub(record)
        except Exception:                                    # noqa: BLE001 - deliberately opaque
            self.dropped += 1
            return False
        # json.dumps escapes newlines, so one record is always exactly one line.
        line = json.dumps(safe, ensure_ascii=True, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size + len(line) > self.max_bytes:
                self.dropped += 1
                return False
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
        return True


def make_lead(
    *, now: datetime, source_ip: str, decoy_name: str, kind: str, token_id: str,
    request: dict[str, Any], event_type: str = "honeytoken_hit", priority: str = "high",
    matches: Optional[dict[str, list[str]]] = None, tags: Optional[list[str]] = None,
    tarpit_delay_s: float = 0.0, detail: Optional[dict[str, Any]] = None,
    timing: Optional[dict[str, Any]] = None, extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Assemble a lead record (see module docstring for the schema)."""
    lead = priority == "high"
    record = {
        "schema": SCHEMA,
        "event_type": event_type,
        "event_id": uuid.uuid4().hex,
        "timestamp": utc_iso(now),
        "source_ip": sanitize_text(source_ip, 64),
        "priority": priority,
        "severity": priority if priority in ("high", "critical") else "info",
        "lead": lead,
        "token_id": token_id,
        "decoy": {"name": decoy_name, "kind": kind, "token_id": token_id},
        "request": request,
        "matches": matches or {"credential_token_ids": [], "canary_ids": []},
        "tags": tags or [],
        "detail": sanitize_detail(detail or {}),
        "timing": timing or {},
        "tarpit_delay_s": round(tarpit_delay_s, 3),
        "decoy_content_synthetic": True,   # the *served content* is synthetic; traffic may be real
        # flat aliases
        "user_agent": request.get("user_agent", ""),
        "method": request.get("method", ""),
        "path": request.get("path", ""),
        "decoy_kind": kind,
    }
    if extra:
        record.update(extra)      # e.g. "coordination", "cognitive_capture" (built from sanitised values)
    return record


def read_leads(path: str | Path) -> list[dict[str, Any]]:
    """Read lead records back (skips malformed lines)."""
    out: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("schema") == SCHEMA:
                out.append(obj)
    return out
