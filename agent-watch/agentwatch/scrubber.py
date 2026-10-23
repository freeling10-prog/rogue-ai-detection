"""Deterministic secret/PII scrubber, applied before ANY write to disk.

Each match is replaced with ``[REDACTED_<TYPE>_SHA256:<first 10 hex of salted sha256>]``.
Identical secrets give identical tokens (so reviewers can correlate reuse) while
the secret itself is never stored.  The salt is *never hard-coded*:

1. ``AGENT_WATCH_SCRUB_SALT`` env var (>= 16 chars), else
2. the salt file named by ``AGENT_WATCH_SALT_FILE`` (default
   ``~/.local/state/agent-watch/scrub.salt``); if missing it is created with a random
   256-bit salt and mode 0600 (O_EXCL, so concurrent workers cannot clobber it).

Defence against evasion: before matching, text is NFKC-normalised (full-width and
compatibility forms become ASCII) and zero-width / format / control characters are
*deleted* (not replaced), so ``sk-abc<ZWSP>def...`` or ``AKIA<ESC>...`` still match.  The same
deletion is done by ``leads.sanitize_text``, so "sanitise then scrub" and "scrub then sanitise"
both leave no raw secret.

Nothing here puts a raw value in an exception or log message.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
import unicodedata
from pathlib import Path
from typing import Any, Optional

SALT_ENV = "AGENT_WATCH_SCRUB_SALT"
SALT_FILE_ENV = "AGENT_WATCH_SALT_FILE"
DEFAULT_SALT_FILE = "~/.local/state/agent-watch/scrub.salt"
MIN_SALT_CHARS = 16
MAX_DEPTH = 24

# Order matters: specific token shapes first, generic "Bearer <token>" last.
# No leading word-boundary on purpose: over-redacting "task-xxxxxxxxxxxxxxxx" is safer than missing a key
# glued to other text.
PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("OPENAI_ANTHROPIC_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{16,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[a-zA-Z0-9]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]*")),
    ("BEARER", re.compile(r"(?i:bearer)\s+[a-zA-Z0-9._\-]+")),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")),
]

_STRIP = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")   # C0/C1 controls except \t \n \r


def _strip_invisible(text: str) -> str:
    """Delete control + Unicode 'format' (Cf: zero-width, bidi, BOM, soft hyphen) characters."""
    text = _STRIP.sub("", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


class Scrubber:
    """Salted, deterministic redactor for strings and nested JSON-like structures."""

    def __init__(self, salt: str | bytes) -> None:
        raw = salt.encode("utf-8") if isinstance(salt, str) else salt
        if len(raw) < MIN_SALT_CHARS:
            raise ValueError("scrub salt too short")           # never echo the value
        self._salt = raw
        self.redactions = 0
        self._lock = threading.Lock()

    # ---- construction ------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "Scrubber":
        """Salt from env, else from (and if absent, created in) the per-install salt file."""
        env = os.environ.get(SALT_ENV)
        if env:
            return cls(env)
        path = Path(os.path.expanduser(os.environ.get(SALT_FILE_ENV, DEFAULT_SALT_FILE)))
        return cls(load_or_create_salt(path))

    # ---- core ----------------------------------------------------------------------------
    def _digest(self, value: str) -> str:
        return hashlib.sha256(self._salt + b"\x00" + value.encode("utf-8", "replace")).hexdigest()[:10]

    def scrub_text(self, text: str) -> str:
        """Redact secrets/PII in one string (after normalisation and invisible-char deletion)."""
        if not text:
            return text
        text = _strip_invisible(unicodedata.normalize("NFKC", text))
        for name, rx in PATTERNS:
            def repl(m: "re.Match[str]", name: str = name) -> str:
                value = m.group(0)
                if name == "BEARER":
                    value = value.split(None, 1)[1]           # hash the token itself
                elif name == "EMAIL":
                    value = value.lower()                      # same mailbox -> same hash
                with self._lock:
                    self.redactions += 1
                return f"[REDACTED_{name}_SHA256:{self._digest(value)}]"
            text = rx.sub(repl, text)
        return text

    def scrub(self, obj: Any, _depth: int = 0) -> Any:
        """Recursively scrub strings in dicts (keys too), lists and tuples; other scalars pass through."""
        if _depth > MAX_DEPTH:
            return "[TRUNCATED_DEPTH]"
        if isinstance(obj, str):
            return self.scrub_text(obj)
        if isinstance(obj, dict):
            return {self.scrub_text(str(k)) if isinstance(k, str) else k: self.scrub(v, _depth + 1) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v, _depth + 1) for v in obj]
        return obj


def load_or_create_salt(path: Path) -> str:
    """Read the salt file, creating it (0600, random 256-bit) if it does not exist."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(secrets.token_hex(32))
    try:
        os.chmod(path, 0o600)                                  # tighten if someone loosened it
    except OSError:
        pass
    salt = path.read_text(encoding="utf-8").strip()
    if len(salt) < MIN_SALT_CHARS:
        raise ValueError(f"salt file {path} is empty or too short")
    return salt


_default: Optional[Scrubber] = None
_default_lock = threading.Lock()


def get_default_scrubber() -> Scrubber:
    """Process-wide scrubber (lazy; honours the env vars at first use)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Scrubber.from_env()
        return _default


def reset_default_scrubber() -> None:
    """Forget the cached scrubber (tests)."""
    global _default
    with _default_lock:
        _default = None
