"""Out-of-band human approval tokens bound to canonical tool args (LLM cannot mint these).

Token = HMAC over (session_id, step_index, tool_name, sha256(canonical_args), taint_source_id).
One-time use; argument swap and replay are rejected (ATLAS AML.T0051 / AML.T0053 policy gate).

Separate from the session capability macaroon in ``capability.py``. OOB is the
one-time, hash-bound exception that authorizes a single gated call. The
capability chain is what attenuation uses to deny egress without a shared
session table.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from .capability import hmac_key as _hmac_key


def state_dir() -> Path:
    raw = os.environ.get("AGENT_GATEWAY_STATE_DIR")
    if raw:
        p = Path(raw)
    else:
        p = Path.home() / ".local" / "state" / "agent-gateway"
    (p / "approvals").mkdir(parents=True, exist_ok=True)
    return p


def canonical_args_hash(arguments: Any) -> str:
    """Stable sha256 over canonical JSON (sorted keys, no whitespace variance)."""
    payload = json.dumps(arguments if arguments is not None else {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def binding_message(
    session_id: str,
    step_index: int,
    tool_name: str,
    args_hash: str,
    taint_source_id: str,
) -> bytes:
    return f"{session_id}|{step_index}|{tool_name}|{args_hash}|{taint_source_id}".encode()


def mint(
    session_id: str,
    step_index: int,
    tool_name: str,
    arguments: Any,
    taint_source_id: str = "",
    ttl_s: float = 600.0,
) -> dict:
    """Create a one-time approval token bound to exact tool call parameters."""
    args_hash = canonical_args_hash(arguments)
    exp = time.time() + ttl_s
    msg = binding_message(session_id, step_index, tool_name, args_hash, taint_source_id or "")
    token = hmac.new(_hmac_key(), msg + f"|{exp:.0f}".encode(), hashlib.sha256).hexdigest()
    rec = {
        "session_id": session_id,
        "step_index": int(step_index),
        "tool_name": tool_name,
        "args_hash": args_hash,
        "taint_source_id": taint_source_id or "",
        "token": token,
        "expires_at": exp,
        "used": False,
    }
    # Store under session+step so multiple pending approvals can coexist
    path = state_dir() / "approvals" / f"{session_id}__{step_index}.json"
    path.write_text(json.dumps(rec), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return rec


def verify_and_consume(
    session_id: str,
    step_index: int,
    tool_name: str,
    arguments: Any,
    token: str,
    taint_source_id: str = "",
    now: Optional[float] = None,
) -> bool:
    """Validate bound HMAC and consume (one-time). Rejects arg-swap and replay."""
    path = state_dir() / "approvals" / f"{session_id}__{step_index}.json"
    if not path.is_file():
        return False
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return False
    n = now or time.time()
    if rec.get("used"):
        return False
    if rec.get("session_id") != session_id:
        return False
    if int(rec.get("step_index", -1)) != int(step_index):
        return False
    if rec.get("tool_name") != tool_name:
        return False
    if rec.get("token") != token:
        return False
    if float(rec.get("expires_at") or 0) < n:
        return False
    args_hash = canonical_args_hash(arguments)
    if not hmac.compare_digest(rec.get("args_hash") or "", args_hash):
        return False  # argument swap
    expect_tsource = rec.get("taint_source_id") or ""
    if expect_tsource != (taint_source_id or ""):
        return False
    msg = binding_message(session_id, step_index, tool_name, args_hash, expect_tsource)
    expect = hmac.new(_hmac_key(), msg + f"|{float(rec['expires_at']):.0f}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, token):
        return False
    rec["used"] = True
    path.write_text(json.dumps(rec), encoding="utf-8")
    return True
