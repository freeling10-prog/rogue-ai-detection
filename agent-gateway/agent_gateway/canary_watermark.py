"""Forensic canary watermarking and credential-pattern tracker (approximate AML.T0086).

Two deterministic, zero-compute mechanisms over ``SENSITIVE_READ`` output:

1. **Zero-width watermark.** A short HMAC tag bound to ``(session_id, step,
   tool)`` is encoded into zero-width characters (``U+200B`` = 0, ``U+200C`` =
   1, framed by ``U+2060``) and woven into the returned text. It is invisible
   to the model and the UI. If that watermark later surfaces in an outbound
   tool call, the exact sensitive read it came from is known: the registry
   records ``origin_step_index`` and ``origin_tool_name``.

2. **Credential tracker.** Standard secret formats in the output (AWS
   ``AKIA`` / ``ASIA``, GitHub ``ghp_`` / ``gho_`` / ``github_pat_``,
   OpenAI / Anthropic ``sk-`` / ``sk-ant-``, Google ``AIza``, Slack
   ``xox[baprs]-``, JWTs, and PEM private-key blocks) are recorded by salted
   digest with the same provenance.

``scan_outbound`` decodes any zero-width run in an outbound argument back to a
tag, and also hashes the argument's own credential matches, and reports the
first match with full provenance. The PEP denies the call and freezes the
registered lab key for 15 minutes. The registry stores digests and the
emitted watermark tags, never the raw secret.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from .capability import hmac_key

ATLAS_EXFIL = "AML.T0086"
ZW_ZERO = "​"
ZW_ONE = "‌"
ZW_FRAME = "⁠"
_ZW_CHARS = frozenset({ZW_ZERO, ZW_ONE, ZW_FRAME})
TAG_BYTES = 6
MAX_SECRETS_PER_SESSION = 512
_MAX_SCAN = 200_000

CREDENTIAL_PATTERNS = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[posru]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("pem_private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
)


def _encode_tag(tag: bytes) -> str:
    bits = "".join(f"{byte:08b}" for byte in tag)
    body = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
    return ZW_FRAME + body + ZW_FRAME


def _decode_runs(text: str) -> list[bytes]:
    """Every maximal zero-width run decoded to bytes (ignoring frame markers)."""
    out: list[bytes] = []
    run: list[str] = []

    def flush() -> None:
        bits = "".join("1" if c == ZW_ONE else "0" for c in run if c in (ZW_ZERO, ZW_ONE))
        n = len(bits) - (len(bits) % 8)
        if n >= 8:
            out.append(bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8)))

    for ch in text:
        if ch in _ZW_CHARS:
            run.append(ch)
        elif run:
            flush()
            run = []
    if run:
        flush()
    return out


def canary_tag(session_id: str, step: int, tool: str, *, key: Optional[bytes] = None) -> bytes:
    root = hmac_key() if key is None else key
    msg = f"canary|{session_id}|{int(step)}|{tool}".encode("utf-8")
    return hmac.new(root, msg, hashlib.sha256).digest()[:TAG_BYTES]


def find_credentials(text: str) -> list[tuple[str, str]]:
    """(kind, matched value) for each credential pattern in ``text``."""
    out: list[tuple[str, str]] = []
    for kind, rx in CREDENTIAL_PATTERNS:
        for m in rx.finditer(text[:_MAX_SCAN]):
            out.append((kind, m.group(0)))
    return out


@dataclass
class CanaryProvenance:
    origin_step_index: int
    origin_tool_name: str
    kind: str  # watermark | credential:<type>

    def as_dict(self) -> dict[str, Any]:
        return {"origin_step_index": self.origin_step_index, "origin_tool_name": self.origin_tool_name,
                "match_kind": self.kind, "atlas": ATLAS_EXFIL, "atlas_approximate": True}


@dataclass
class _SessionCanaries:
    tags: dict[bytes, CanaryProvenance] = field(default_factory=dict)
    cred_digests: dict[str, CanaryProvenance] = field(default_factory=dict)


class CanaryRegistry:
    """Per-session watermark tags and credential digests with provenance."""

    def __init__(self, salt: Optional[bytes] = None, *, key: Optional[bytes] = None):
        import os

        self._salt = salt if salt is not None else os.urandom(16)
        self._key = key
        self._sessions: dict[str, _SessionCanaries] = {}

    def _sess(self, session_id: str) -> _SessionCanaries:
        s = self._sessions.get(session_id)
        if s is None:
            s = self._sessions[session_id] = _SessionCanaries()
        return s

    def _digest(self, value: str) -> str:
        return hashlib.sha256(self._salt + value.encode("utf-8")).hexdigest()

    def watermark_output(self, session_id: str, step: int, tool: str, text: str) -> str:
        """Record a canary for this read and return ``text`` with the watermark woven in."""
        s = self._sess(session_id)
        tag = canary_tag(session_id, step, tool, key=self._key)
        s.tags[tag] = CanaryProvenance(step, tool, "watermark")
        self.register_credentials(session_id, step, tool, text)
        mark = _encode_tag(tag)
        if not isinstance(text, str) or not text:
            return mark
        # Weave after the first whitespace so it rides along if a prefix is copied.
        idx = text.find(" ")
        return text[: idx + 1] + mark + text[idx + 1:] if idx != -1 else text + mark

    def register_credentials(self, session_id: str, step: int, tool: str, text: Any) -> int:
        """Record credential patterns found in a (possibly structured) sensitive output."""
        s = self._sess(session_id)
        n = 0
        for chunk in _iter_strings(text):
            for kind, value in find_credentials(chunk):
                if len(s.cred_digests) >= MAX_SECRETS_PER_SESSION:
                    return n
                digest = self._digest(value)
                if digest not in s.cred_digests:
                    s.cred_digests[digest] = CanaryProvenance(step, tool, f"credential:{kind}")
                    n += 1
        return n

    def has_canaries(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        return bool(s and (s.tags or s.cred_digests))

    def scan_outbound(self, session_id: str, arguments: Any) -> Optional[CanaryProvenance]:
        """Watermark tag or recorded credential surfacing in an outbound call, or ``None``."""
        s = self._sessions.get(session_id)
        if s is None or (not s.tags and not s.cred_digests):
            return None
        for chunk in _iter_strings(arguments):
            if s.tags:
                for decoded in _decode_runs(chunk):
                    for tag, prov in s.tags.items():
                        if tag in decoded:
                            return prov
            if s.cred_digests:
                for _kind, value in find_credentials(chunk):
                    prov = s.cred_digests.get(self._digest(value))
                    if prov is not None:
                        return prov
        return None

    def watermark_count(self, session_id: str) -> int:
        s = self._sessions.get(session_id)
        return 0 if s is None else len(s.tags) + len(s.cred_digests)


def _iter_strings(obj: Any, depth: int = 0) -> Iterator[str]:
    if depth > 12:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _iter_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v, depth + 1)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        yield str(obj)
