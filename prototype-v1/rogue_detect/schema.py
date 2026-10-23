"""Common event schema shared by every collector and detector."""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Dict

KINDS = ("post", "message", "read", "tool_call", "access")
STATUSES = ("ok", "denied")
EPOCH0 = 1_767_225_600.0  # 2026-01-01T00:00:00Z, base time for synthetic data


@dataclass(frozen=True)
class Event:
    """One observed action by one agent.

    kind     : post | message | read | tool_call | access
    target   : channel (post), recipient agent id (message), url/resource (read),
               tool name (tool_call), resource path (access)
    """

    ts: float
    agent_id: str
    kind: str
    target: str = ""
    text: str = ""
    status: str = "ok"
    in_scope: bool = True          # was the target inside the agent's granted scope?
    ingest_external: bool = False  # did this action pull in untrusted external content?
    dest_external: bool = False    # did this action send data to an external destination?
    payload_bytes: int = 0
    synthetic: bool = True
    source: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Event":
        return validate_event_dict(d)


_REQUIRED = ("ts", "agent_id", "kind")
_FIELDS = set(Event.__dataclass_fields__)


def validate_event_dict(d: Dict[str, Any]) -> Event:
    """Validate a raw dict and return an Event. Raises ValueError on bad input.

    Unknown fields are rejected on purpose: community contributions must not smuggle
    extra (possibly personal) attributes into the pipeline.
    """
    if not isinstance(d, dict):
        raise ValueError("event must be an object")
    for k in _REQUIRED:
        if k not in d:
            raise ValueError(f"missing required field: {k}")
    extra = set(d) - _FIELDS
    if extra:
        raise ValueError(f"unknown fields not allowed: {sorted(extra)}")
    try:
        ts = float(d["ts"])
    except (TypeError, ValueError):
        raise ValueError("ts must be a number (unix seconds)")
    if not math.isfinite(ts) or ts < 0:
        raise ValueError("ts out of range")
    agent_id = d["agent_id"]
    if not isinstance(agent_id, str) or not (0 < len(agent_id) <= 64):
        raise ValueError("agent_id must be a non-empty string up to 64 chars")
    if d["kind"] not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    status = d.get("status", "ok")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    for bkey in ("in_scope", "ingest_external", "dest_external", "synthetic"):
        if bkey in d and not isinstance(d[bkey], bool):
            raise ValueError(f"{bkey} must be a boolean")
    pb = d.get("payload_bytes", 0)
    if not isinstance(pb, int) or isinstance(pb, bool) or pb < 0:
        raise ValueError("payload_bytes must be a non-negative integer")
    for skey in ("target", "text", "source"):
        if skey in d and not isinstance(d[skey], str):
            raise ValueError(f"{skey} must be a string")
    text = d.get("text", "")
    if len(text) > 2000:
        raise ValueError("text longer than 2000 characters")
    kwargs = {k: d[k] for k in d if k in _FIELDS}
    kwargs["ts"] = ts
    return Event(**kwargs)
