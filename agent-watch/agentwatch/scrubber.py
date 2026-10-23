"""Deterministic secret/PII scrubber, applied before ANY write to disk.

Each match is replaced with ``[REDACTED_<TYPE>_SHA256:<first 10 hex of salted sha256>]``.
Identical secrets give identical tokens (so reviewers can correlate reuse) while
the secret itself is never stored.  The salt is *never hard-coded*:

1. ``AGENT_WATCH_SCRUB_SALT`` env var (>= 16 chars), else
2. the salt file named by ``AGENT_WATCH_SALT_FILE`` (default
   ``~/.local/state/agent-watch/scrub.salt``); if missing it is created with a random
   256-bit salt and mode 0600 (O_EXCL, so concurrent workers cannot clobber it).

Defence against evasion: before matching, text is NFKC-normalised (full-width and
compatibility forms become ASCII) and zero-width / format characters are deleted.
CR/LF/TAB are kept in the stored text (``sanitize_text`` shows them as ``\\n`` / ``\\r`` /
``\\t`` so a payload cannot forge log lines) but are ignored *while matching*, as are
percent-decodes (``%40``, ``%20``, ``%0A``, including one extra encoding round) and
JSON ``\\uXXXX`` escapes.  A secret split or encoded that way is still one match, so
"sanitise then scrub" and "scrub then sanitise" both leave no raw secret.

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
    ("BEARER", re.compile(r"(?i:bearer)(?:\s|\+)+[a-zA-Z0-9._\-]+")),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")),
]

_STRIP = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")   # C0/C1 controls except \t \n \r
_HEX = frozenset("0123456789abcdefABCDEF")
_GAP_CATS = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _strip_invisible(text: str) -> str:
    """Delete control + Unicode 'format' (Cf: zero-width, bidi, BOM, soft hyphen) characters."""
    text = _STRIP.sub("", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _pieces(text: str) -> list[tuple[str, int, int]]:
    return [(ch, i, i + 1) for i, ch in enumerate(text)]


def _pct_byte(pieces: list[tuple[str, int, int]], i: int) -> Optional[tuple[int, tuple[int, int], int]]:
    if i + 2 < len(pieces) and pieces[i][0] == "%" and pieces[i + 1][0] in _HEX and pieces[i + 2][0] in _HEX:
        return int(pieces[i + 1][0] + pieces[i + 2][0], 16), (pieces[i][1], pieces[i + 2][2]), i + 3
    return None


def _utf8_len(lead: int) -> int:
    if lead < 0x80:
        return 1
    if 0xC2 <= lead <= 0xDF:
        return 2
    if 0xE0 <= lead <= 0xEF:
        return 3
    if 0xF0 <= lead <= 0xF4:
        return 4
    return 1


def _percent_decode_once(pieces: list[tuple[str, int, int]]) -> tuple[list[tuple[str, int, int]], bool]:
    """Decode ``%XX`` (UTF-8) once.  Invalid sequences stay as source characters."""
    out: list[tuple[str, int, int]] = []
    i = 0
    changed = False
    while i < len(pieces):
        nxt = _pct_byte(pieces, i)
        if nxt is None:
            out.append(pieces[i])
            i += 1
            continue
        b0, span0, j = nxt
        n = _utf8_len(b0)
        buf = [(b0, span0)]
        k = j
        ok = n > 1
        if n == 1:
            out.append((chr(b0), span0[0], span0[1]))
            changed = True
            i = j
            continue
        for _ in range(n - 1):
            cont = _pct_byte(pieces, k)
            if cont is None or not 0x80 <= cont[0] <= 0xBF:
                ok = False
                break
            buf.append((cont[0], cont[1]))
            k = cont[2]
        if not ok:
            out.append(pieces[i])
            i += 1
            continue
        try:
            text = bytes(b for b, _ in buf).decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if len(text) != 1:
            out.append(pieces[i])
            i += 1
            continue
        out.append((text, buf[0][1][0], buf[-1][1][1]))
        changed = True
        i = k
    return out, changed


def _unicode_escape_once(pieces: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Decode one JSON-style ``\\uXXXX`` escape (the raw six characters) into its code point."""
    out: list[tuple[str, int, int]] = []
    i = 0
    while i < len(pieces):
        if (i + 5 < len(pieces) and pieces[i][0] == "\\" and pieces[i + 1][0] == "u"
                and all(p[0] in _HEX for p in pieces[i + 2:i + 6])):
            cp = int("".join(p[0] for p in pieces[i + 2:i + 6]), 16)
            if cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF:
                out.append((chr(cp), pieces[i][1], pieces[i + 5][2]))
                i += 6
                continue
        out.append(pieces[i])
        i += 1
    return out


def _match_view(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Text as the matcher sees it, plus each kept character's span in *text*.

    Percent-encoding (two rounds) and ``\\uXXXX`` are decoded.  Controls, format
    characters, and the ``\\\\n`` / ``\\\\r`` / ``\\\\t`` escapes written by
    ``sanitize_text`` are gaps: they do not break a token, and a match that
    straddles them still covers them in *text*.
    """
    pieces = _pieces(text)
    for _ in range(2):
        pieces, changed = _percent_decode_once(pieces)
        pieces = _unicode_escape_once(pieces)
        if not changed:
            break
    kept: list[tuple[str, int, int]] = []
    i = 0
    while i < len(pieces):
        ch, start, end = pieces[i]
        if i + 1 < len(pieces) and ch == "\\" and pieces[i + 1][0] in "nrt":
            i += 2
            continue
        if unicodedata.category(ch) in _GAP_CATS:
            i += 1
            continue
        kept.append((ch, start, end))
        i += 1
    return "".join(p[0] for p in kept), [(p[1], p[2]) for p in kept]


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

    def _redact_value(self, name: str, value: str) -> str:
        if name == "BEARER":
            value = re.split(r"(?:\s|\+)+", value, maxsplit=1)[1]   # hash the token itself
        elif name == "EMAIL":
            value = value.lower()                                    # same mailbox -> same hash
        with self._lock:
            self.redactions += 1
        return f"[REDACTED_{name}_SHA256:{self._digest(value)}]"

    def scrub_text(self, text: str) -> str:
        """Redact secrets/PII in one string (after normalisation and invisible-char deletion)."""
        if not text:
            return text
        text = _strip_invisible(unicodedata.normalize("NFKC", text))
        for name, rx in PATTERNS:
            view, spans = _match_view(text)
            matches = list(rx.finditer(view))
            if not matches:
                continue
            for m in reversed(matches):
                if m.end() <= m.start():
                    continue
                start = spans[m.start()][0]
                end = spans[m.end() - 1][1]
                text = text[:start] + self._redact_value(name, m.group(0)) + text[end:]
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
