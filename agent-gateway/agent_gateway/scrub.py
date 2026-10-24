"""Deterministic scrubbing of tool arguments before they hit disk."""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any

_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "API_KEY"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "GITHUB_TOKEN"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS_KEY"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{16,}"), "BEARER"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "EMAIL"),
]


def _salt() -> bytes:
    env = os.environ.get("AGENT_GATEWAY_SCRUB_SALT", "agent-gateway-lab-salt-change-me")
    return env.encode() if isinstance(env, str) else env


def scrub_text(text: str) -> str:
    out = text
    for rx, kind in _PATTERNS:
        def repl(m, kind=kind):
            h = hashlib.sha256(_salt() + m.group(0).encode()).hexdigest()[:10]
            return f"[REDACTED_{kind}_SHA256:{h}]"
        out = rx.sub(repl, out)
    return out


def scrub_obj(obj: Any, depth: int = 0) -> Any:
    if depth > 12:
        return "[max-depth]"
    if isinstance(obj, str):
        return scrub_text(obj)[:4000]
    if isinstance(obj, dict):
        return {scrub_text(str(k))[:200]: scrub_obj(v, depth + 1) for k, v in list(obj.items())[:40]}
    if isinstance(obj, list):
        return [scrub_obj(x, depth + 1) for x in obj[:40]]
    return obj
