"""Interactive OOB approval payload for a tainted tool call held for a human.

Formatter only. Building a payload does not open a socket. HTTP delivery runs
only when the PEP is constructed with ``webhook_deliver=True`` (default off)
and a ``webhook_url``.

The payload is safe to drop into Slack Block Kit (``text`` + ``blocks``) and
is also a generic webhook document. Tool arguments are passed through the
gateway scrubber before they are copied into the document. Callback buttons
are one-time and hash-bound to the session, step, tool, canonical args, and
taint source. ``Approve Once`` does not clear taint. ``Deny & Freeze Key 15m``
freezes only a key that is already in the lab registry, for the existing
15-minute (900s) window.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .approve import canonical_args_hash, state_dir
from .capability import hmac_key, parse as parse_capability
from .registry import Registry
from .scrub import scrub_obj, scrub_text

log = logging.getLogger("agent_gateway.approval_webhook")

SCHEMA = "agent-gateway.approval_webhook/1"
ACTION_APPROVE_ONCE = "approve_once"
ACTION_DENY_FREEZE = "deny_freeze_15m"
LABEL_APPROVE_ONCE = "Approve Once"
LABEL_DENY_FREEZE = "Deny & Freeze Key 15m"
FREEZE_SECONDS = 900
CALLBACK_TTL_S = 600
ATLAS_T0051 = "AML.T0051"
ATLAS_T0080 = "AML.T0080"
ATLAS_T0086 = "AML.T0086"

WebhookSender = Callable[[str, dict], None]


@dataclass(frozen=True)
class CallbackVerdict:
    ok: bool
    reason: str = ""
    action: str = ""
    agent_key: str = ""
    freeze_seconds: int = 0


def atlas_for(*, taint_source_id: str, taint_reasons: Optional[list[str]], gate_atlas: str) -> str:
    """Map the triggering taint to AML.T0051, AML.T0080, or AML.T0086."""
    source = (taint_source_id or "").lower()
    if "scratchpad" in source:
        return ATLAS_T0080
    if "tools.list" in source or "tools/list" in source or "untrusted_tools_list" in source:
        return ATLAS_T0051
    reasons = " ".join(taint_reasons or []).lower()
    if "scratchpad" in reasons and not source:
        return ATLAS_T0080
    if gate_atlas in (ATLAS_T0051, ATLAS_T0080, ATLAS_T0086):
        return gate_atlas
    if "untrusted_tools_list" in reasons:
        return ATLAS_T0051
    if gate_atlas == ATLAS_T0086:
        return ATLAS_T0086
    return ATLAS_T0051


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _canon(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _canon(obj[k]) for k in sorted(obj, key=lambda x: str(x))}
    if isinstance(obj, list):
        return [_canon(x) for x in obj]
    return obj


def _mac(fields: dict) -> str:
    body = {k: fields[k] for k in fields if k != "mac"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hmac.new(hmac_key(), b"agw-cb|v1|" + raw, hashlib.sha256).hexdigest()


def _nonce(session_id: str, step: int, tool_name: str, args_hash: str, taint_source_id: str, principal_key: str) -> str:
    material = "|".join([session_id, str(int(step)), tool_name, args_hash, taint_source_id, principal_key])
    return hmac.new(hmac_key(), b"agw-cb-nonce|" + material.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _callback_root():
    root = state_dir() / "approval_callbacks"
    root.mkdir(parents=True, exist_ok=True)
    (root / "macs").mkdir(parents=True, exist_ok=True)
    return root


def _pending_path(nonce: str):
    return _callback_root() / f"{nonce}.json"


def _mac_path(mac: str):
    return _callback_root() / "macs" / mac


def _load_pending(nonce: str) -> Optional[dict]:
    path = _pending_path(nonce)
    if not path.is_file():
        return None
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) else None


def _write_json(path, obj: Any) -> None:
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _capability_state(token: str, allow_egress: bool) -> dict:
    parsed = parse_capability(token) if token else None
    safe_token = token if isinstance(token, str) and token.startswith("agw1.") else ""
    return {
        "prefix": "agw1.",
        "token": safe_token,
        "allow_egress": bool(allow_egress if parsed is None else parsed.allows_egress),
        "caveats": list(parsed.caveats) if parsed else [],
        "taint_source": parsed.taint_source if parsed else "",
    }


def _signed_callback(
    *,
    action: str,
    label: str,
    session_id: str,
    session_sha: str,
    step_index: int,
    tool_display: str,
    tool_sha: str,
    args_hash: str,
    taint_display: str,
    taint_sha: str,
    principal_display: str,
    principal_sha: str,
    nonce: str,
    expires_at: int,
    freeze_seconds: Optional[int] = None,
) -> dict:
    fields: dict[str, Any] = {
        "v": 1,
        "action": action,
        "label": label,
        "session_id": session_id,
        "session_sha256": session_sha,
        "step_index": int(step_index),
        "tool_name": tool_display,
        "tool_sha256": tool_sha,
        "args_hash": args_hash,
        "taint_source_id": taint_display,
        "taint_sha256": taint_sha,
        "principal": principal_display,
        "principal_sha256": principal_sha,
        "nonce": nonce,
        "expires_at": int(expires_at),
    }
    if freeze_seconds is not None:
        fields["freeze_seconds"] = int(freeze_seconds)
    fields["mac"] = _mac(fields)
    return fields


def _blocks(summary: dict, approve_cb: dict, deny_cb: dict) -> list[dict]:
    cap = summary["capability_state"]["token"] or "agw1.(none)"
    principal = summary["principal"]["principal_key"] or summary["principal"]["agent_id"] or "unknown"
    args_text = json.dumps(summary["canonical_args"], sort_keys=True, separators=(",", ":"), default=str)
    if len(args_text) > 1500:
        args_text = args_text[:1500] + "…"
    fields = [
        ("Principal", principal),
        ("Session", summary["session_id"]),
        ("Capability", cap),
        ("Taint source", summary["taint_source_id"] or "(none)"),
        ("ATLAS", summary["atlas_id"]),
        ("Tool", summary["tool_name"]),
    ]
    approve_value = json.dumps(approve_cb, sort_keys=True, separators=(",", ":"), default=str)
    deny_value = json.dumps(deny_cb, sort_keys=True, separators=(",", ":"), default=str)
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Tainted tool call awaiting approval", "emoji": False},
        },
        {
            "type": "section",
            "fields": [
                {"type": "plain_text", "text": f"{label}: {value}"[:2000], "emoji": False}
                for label, value in fields
            ],
        },
        {
            "type": "section",
            "text": {"type": "plain_text", "text": f"Canonical args: {args_text}"[:3000], "emoji": False},
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "action_id": ACTION_APPROVE_ONCE,
                    "style": "primary",
                    "text": {"type": "plain_text", "text": LABEL_APPROVE_ONCE, "emoji": False},
                    "value": approve_value,
                },
                {
                    "type": "button",
                    "action_id": ACTION_DENY_FREEZE,
                    "style": "danger",
                    "text": {"type": "plain_text", "text": LABEL_DENY_FREEZE, "emoji": False},
                    "value": deny_value,
                },
            ],
        },
    ]


def build_approval_payload(
    *,
    principal_key: str,
    agent_id: str,
    agent_key: str,
    session_id: str,
    capability_token: str,
    allow_egress: bool,
    taint_source_id: str,
    taint_reasons: Optional[list[str]],
    gate_atlas: str,
    tool_name: str,
    arguments: Any,
    step_index: int,
    now: float,
    freeze_seconds: float = FREEZE_SECONDS,
) -> dict:
    """Build (and persist) a deterministic approval payload. No network I/O."""
    args_hash = canonical_args_hash(arguments if isinstance(arguments, dict) else {})
    nonce = _nonce(session_id, int(step_index), tool_name, args_hash, taint_source_id or "", principal_key or "")
    existing = _load_pending(nonce)
    if existing and existing.get("used") and isinstance(existing.get("payload"), dict):
        return json.loads(json.dumps(existing["payload"]))

    freeze_s = int(freeze_seconds if freeze_seconds else FREEZE_SECONDS)
    expires_at = int(now) + CALLBACK_TTL_S
    atlas_id = atlas_for(
        taint_source_id=taint_source_id or "",
        taint_reasons=list(taint_reasons or []),
        gate_atlas=gate_atlas or "",
    )
    tool_display = scrub_text(tool_name or "")
    taint_display = scrub_text(taint_source_id or "")
    principal_display = scrub_text(principal_key or "")
    session_display = scrub_text(session_id or "")
    agent_display = scrub_text(agent_id or "")
    scrubbed_args = scrub_obj(_canon(arguments if isinstance(arguments, dict) else {}))
    session_sha = _sha256(session_id or "")
    tool_sha = _sha256(tool_name or "")
    taint_sha = _sha256(taint_source_id or "")
    principal_sha = _sha256(principal_key or "")
    common = dict(
        session_id=session_display,
        session_sha=session_sha,
        step_index=int(step_index),
        tool_display=tool_display,
        tool_sha=tool_sha,
        args_hash=args_hash,
        taint_display=taint_display,
        taint_sha=taint_sha,
        principal_display=principal_display,
        principal_sha=principal_sha,
        nonce=nonce,
        expires_at=expires_at,
    )
    approve_cb = _signed_callback(action=ACTION_APPROVE_ONCE, label=LABEL_APPROVE_ONCE, **common)
    deny_label = LABEL_DENY_FREEZE if freeze_s == FREEZE_SECONDS else f"Deny & Freeze Key {freeze_s}s"
    deny_cb = _signed_callback(
        action=ACTION_DENY_FREEZE, label=deny_label, freeze_seconds=freeze_s, **common,
    )
    capability_state = _capability_state(capability_token or "", allow_egress)
    principal = {
        "agent_id": agent_display,
        "principal_key": principal_display,
        "role": "root_parent_principal",
    }
    summary = {
        "schema": SCHEMA,
        "text": "Policy gate: tainted tool call awaiting human approval",
        "delivered": False,
        "principal": principal,
        "session_id": session_display,
        "capability_state": capability_state,
        "taint_source_id": taint_display,
        "atlas_id": atlas_id,
        "gate_atlas": gate_atlas or "",
        "tool_name": tool_display,
        "canonical_args": scrubbed_args,
        "step_index": int(step_index),
        "callbacks": {
            ACTION_APPROVE_ONCE: approve_cb,
            ACTION_DENY_FREEZE: deny_cb,
        },
    }
    summary["blocks"] = _blocks(summary, approve_cb, deny_cb)
    summary["webhook"] = {
        "event": "agent_gateway.approval_required",
        "schema": SCHEMA,
        "principal": principal,
        "session_id": session_display,
        "capability_state": capability_state,
        "taint_source_id": taint_display,
        "atlas_id": atlas_id,
        "tool_name": tool_display,
        "canonical_args": scrubbed_args,
        "step_index": int(step_index),
        "callbacks": {
            ACTION_APPROVE_ONCE: approve_cb,
            ACTION_DENY_FREEZE: deny_cb,
        },
    }
    record = {
        "nonce": nonce,
        "used": False,
        "session_id": session_id or "",
        "step_index": int(step_index),
        "tool_name": tool_name or "",
        "tool_sha256": tool_sha,
        "args_hash": args_hash,
        "taint_source_id": taint_source_id or "",
        "taint_sha256": taint_sha,
        "principal_key": principal_key or "",
        "principal_sha256": principal_sha,
        "session_sha256": session_sha,
        "agent_key": agent_key or "",
        "approve_mac": approve_cb["mac"],
        "deny_mac": deny_cb["mac"],
        "expires_at": expires_at,
        "freeze_seconds": freeze_s,
        "payload": summary,
    }
    _write_json(_pending_path(nonce), record)
    _write_json(_mac_path(approve_cb["mac"]), {"nonce": nonce, "action": ACTION_APPROVE_ONCE})
    _write_json(_mac_path(deny_cb["mac"]), {"nonce": nonce, "action": ACTION_DENY_FREEZE})
    return json.loads(json.dumps(summary))


def _eq(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str) or len(a) != len(b) or not a:
        return False
    return hmac.compare_digest(a, b)


def verify_callback(
    callback: dict,
    *,
    session_id: str,
    step_index: int,
    tool_name: str,
    arguments: Any,
    taint_source_id: str,
    now: float,
) -> CallbackVerdict:
    """Reject a callback whose signed fields or presented parameters were changed.

    Success consumes the nonce. A second presentation is a replay.
    """
    if not isinstance(callback, dict):
        return CallbackVerdict(False, "malformed_callback")
    action = callback.get("action")
    if action not in (ACTION_APPROVE_ONCE, ACTION_DENY_FREEZE):
        return CallbackVerdict(False, "action_rejected")
    mac = callback.get("mac")
    nonce = callback.get("nonce")
    if not isinstance(mac, str) or not isinstance(nonce, str):
        return CallbackVerdict(False, "malformed_callback")
    if not _eq(_mac(callback), mac):
        return CallbackVerdict(False, "mac_mismatch")
    pending = _load_pending(nonce)
    if not pending:
        return CallbackVerdict(False, "unknown_callback")
    if pending.get("used"):
        return CallbackVerdict(False, "replay")
    try:
        expires_at = int(callback.get("expires_at"))
    except (TypeError, ValueError):
        return CallbackVerdict(False, "malformed_callback")
    if int(now) >= expires_at or int(pending.get("expires_at") or 0) != expires_at:
        return CallbackVerdict(False, "expired")
    expected_mac = pending.get("approve_mac") if action == ACTION_APPROVE_ONCE else pending.get("deny_mac")
    if not _eq(str(expected_mac or ""), mac):
        return CallbackVerdict(False, "mac_mismatch")
    if int(pending.get("step_index", -1)) != int(step_index) or int(callback.get("step_index", -2)) != int(step_index):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(session_id or ""), str(callback.get("session_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(session_id or ""), str(pending.get("session_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(tool_name or ""), str(callback.get("tool_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(tool_name or ""), str(pending.get("tool_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if (pending.get("tool_name") or "") != (tool_name or ""):
        return CallbackVerdict(False, "parameter_mismatch")
    presented_hash = canonical_args_hash(arguments if isinstance(arguments, dict) else {})
    if not _eq(presented_hash, str(callback.get("args_hash") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(presented_hash, str(pending.get("args_hash") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(taint_source_id or ""), str(callback.get("taint_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if not _eq(_sha256(taint_source_id or ""), str(pending.get("taint_sha256") or "")):
        return CallbackVerdict(False, "parameter_mismatch")
    if (pending.get("taint_source_id") or "") != (taint_source_id or ""):
        return CallbackVerdict(False, "parameter_mismatch")
    freeze_s = int(pending.get("freeze_seconds") or 0)
    if action == ACTION_DENY_FREEZE:
        try:
            claimed = int(callback.get("freeze_seconds"))
        except (TypeError, ValueError):
            return CallbackVerdict(False, "parameter_mismatch")
        if claimed != freeze_s:
            return CallbackVerdict(False, "parameter_mismatch")
    pending["used"] = True
    _write_json(_pending_path(nonce), pending)
    return CallbackVerdict(
        True,
        action=action,
        agent_key=str(pending.get("agent_key") or ""),
        freeze_seconds=freeze_s,
    )


def apply_callback(
    registry: Registry,
    callback: dict,
    *,
    session_id: str,
    step_index: int,
    tool_name: str,
    arguments: Any,
    taint_source_id: str,
    now: float,
) -> dict:
    """Apply a verified button. Freeze touches registered keys only."""
    verdict = verify_callback(
        callback,
        session_id=session_id,
        step_index=step_index,
        tool_name=tool_name,
        arguments=arguments,
        taint_source_id=taint_source_id,
        now=now,
    )
    if not verdict.ok:
        return {"ok": False, "error": verdict.reason, "frozen_agent_ids": []}
    if verdict.action == ACTION_APPROVE_ONCE:
        return {"ok": True, "action": verdict.action, "frozen_agent_ids": []}
    if not registry.get(verdict.agent_key):
        return {
            "ok": False,
            "error": "unregistered_key",
            "action": verdict.action,
            "frozen_agent_ids": [],
        }
    seconds = verdict.freeze_seconds or FREEZE_SECONDS
    ids = registry.freeze_root(verdict.agent_key, seconds=float(seconds), now=now)
    return {
        "ok": True,
        "action": verdict.action,
        "frozen_agent_ids": ids,
        "freeze_seconds": seconds,
    }


def consume_approve_once(
    token: str,
    *,
    session_id: str,
    step_index: int,
    tool_name: str,
    arguments: Any,
    taint_source_id: str,
    now: float,
) -> bool:
    """Treat an Approve Once callback mac as a one-time approval token."""
    if not isinstance(token, str) or len(token) != 64:
        return False
    path = _mac_path(token)
    if not path.is_file():
        return False
    try:
        idx = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(idx, dict) or idx.get("action") != ACTION_APPROVE_ONCE:
        return False
    pending = _load_pending(str(idx.get("nonce") or ""))
    if not pending or pending.get("used"):
        return False
    if not _eq(str(pending.get("approve_mac") or ""), token):
        return False
    payload = pending.get("payload") if isinstance(pending.get("payload"), dict) else {}
    callbacks = payload.get("callbacks") if isinstance(payload.get("callbacks"), dict) else {}
    callback = callbacks.get(ACTION_APPROVE_ONCE)
    if not isinstance(callback, dict):
        return False
    verdict = verify_callback(
        callback,
        session_id=session_id,
        step_index=step_index,
        tool_name=tool_name,
        arguments=arguments,
        taint_source_id=taint_source_id,
        now=now,
    )
    return bool(verdict.ok and verdict.action == ACTION_APPROVE_ONCE)


def deliver_webhook(url: str, payload: dict, timeout: float = 5.0) -> None:
    """POST ``payload`` as JSON. Callers must opt in; the formatter never calls this."""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "agent-gateway-approval-webhook"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit opt-in only
            resp.read(1024)
    except urllib.error.URLError:
        raise
