"""Safelog scrubber for offline analysis: 2-round percent-decode + secret/dict-key redaction.

Deterministic salted hashes. Scrub BEFORE any write to disk.
Does not import Flask or the honeypot runtime.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

SALT_ENV = "AGENTWATCH_ANALYZER_SALT"
DEFAULT_SALT = "analyzer-lab-salt-change-me!!"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OPENAI_ANTHROPIC_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{16,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[a-zA-Z0-9]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]*")),
    ("BEARER", re.compile(r"(?i:bearer)(?:\s|\+)+[a-zA-Z0-9._\-]+")),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")),
]

# Dict keys whose values are always redacted (even if pattern-miss)
SENSITIVE_KEYS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "api_key", "apikey",
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "private_key", "client_secret",
})

_QUERY = re.compile(r"\?[^\s\"']*")
_LONG_SEG = re.compile(r"(?<=/)(?:[0-9a-fA-F]{10,}|[A-Za-z0-9_\-]{20,})(?=[/\s\"'?]|$)")


def _salt() -> bytes:
    return os.environ.get(SALT_ENV, DEFAULT_SALT).encode()


def _hash_token(kind: str, value: str) -> str:
    h = hashlib.sha256(_salt() + value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"[REDACTED_{kind}_SHA256:{h}]"


def _two_round_decode(text: str) -> str:
    """Percent-decode up to two rounds, then NFKC-normalize."""
    out = text
    for _ in range(2):
        try:
            nxt = unquote(out)
        except Exception:
            break
        if nxt == out:
            break
        out = nxt
    return unicodedata.normalize("NFKC", out)


def scrub_text(text: str, *, drop_query: bool = True) -> str:
    if not isinstance(text, str):
        text = str(text)
    out = _two_round_decode(text)
    for kind, rx in PATTERNS:
        def repl(m: re.Match[str], kind: str = kind) -> str:
            return _hash_token(kind, m.group(0))
        out = rx.sub(repl, out)
    if drop_query:
        out = _QUERY.sub("?[query-redacted]", out)
    out = _LONG_SEG.sub("[id]", out)
    return out


def scrub_obj(obj: Any, depth: int = 0) -> Any:
    if depth > 16:
        return "[max-depth]"
    if isinstance(obj, str):
        return scrub_text(obj, drop_query=False)[:8000]
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:80]:
            sk = scrub_text(str(k), drop_query=False)[:200]
            if str(k).lower().replace("-", "_") in SENSITIVE_KEYS or str(k).lower() in SENSITIVE_KEYS:
                out[sk] = _hash_token("DICT_KEY", str(v))
            else:
                out[sk] = scrub_obj(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [scrub_obj(x, depth + 1) for x in obj[:80]]
    return obj


def scrub_json_line(obj: dict) -> str:
    return json.dumps(scrub_obj(obj), ensure_ascii=False, default=str)
