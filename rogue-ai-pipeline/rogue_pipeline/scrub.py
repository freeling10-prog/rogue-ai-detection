"""Encoded-secret scrubber for raw telemetry fields (v4 parity port of agent-watch's scrubber normalisation).

Collectors (agent-watch) scrub secrets before export, but a pipeline fed by OTHER collectors or ordinary logs cannot assume that.
This module re-applies, at ingest and before ANY hashing/feature extraction, the same matching rules:

  * text is NFKC-normalised (full-width and compatibility forms become ASCII) and zero-width / format characters are deleted;
  * percent-encoding (``%40``, ``%20``, ``%0A``, including one extra round such as ``%2540``) and JSON ``\\uXXXX`` escapes are decoded
    FOR MATCHING;
  * CR / LF / TAB, their ``\\n`` ``\\r`` ``\\t`` escape forms and format characters are GAPS: they do not break a token, so a secret
    split by a newline or a tab is still one match, and the whole span is replaced.

Each match becomes ``[REDACTED_<TYPE>_SHA256:<10 hex>]`` - the exact shape ``schema.REDACTION_RE`` already treats as an opaque,
correlatable marker.  The 10 hex characters come from the pipeline's keyed HMAC (domain "scrub"), NOT a salt file: the same secret
gives the same marker within a key, the secret itself is never stored, and without the key a marker cannot be brute-forced.
Nothing here puts a raw value in an exception or log message.
"""
from __future__ import annotations

import re
import threading
import unicodedata
from typing import Any, Callable, List, Optional, Tuple

MAX_DEPTH = 24

# Order matters: specific token shapes first, generic "Bearer <token>" last.  No leading word boundary on purpose.
PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
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


def _pieces(text: str) -> List[Tuple[str, int, int]]:
    return [(ch, i, i + 1) for i, ch in enumerate(text)]


def _pct_byte(pieces: List[Tuple[str, int, int]], i: int) -> Optional[Tuple[int, Tuple[int, int], int]]:
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


def _percent_decode_once(pieces: List[Tuple[str, int, int]]) -> tuple[List[Tuple[str, int, int]], bool]:
    """Decode ``%XX`` (UTF-8) once.  Invalid sequences stay as source characters."""
    out: List[Tuple[str, int, int]] = []
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


def _unicode_escape_once(pieces: List[Tuple[str, int, int]]) -> Tuple[List[Tuple[str, int, int]], bool]:
    """Decode one JSON-style ``\\uXXXX`` escape (the raw six characters) into its code point.  Returns (pieces, changed)."""
    out: List[Tuple[str, int, int]] = []
    changed = False
    i = 0
    while i < len(pieces):
        if (i + 5 < len(pieces) and pieces[i][0] == "\\" and pieces[i + 1][0] == "u"
                and all(p[0] in _HEX for p in pieces[i + 2:i + 6])):
            cp = int("".join(p[0] for p in pieces[i + 2:i + 6]), 16)
            if cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF:
                out.append((chr(cp), pieces[i][1], pieces[i + 5][2]))
                changed = True
                i += 6
                continue
        out.append(pieces[i])
        i += 1
    return out, changed


def _match_view(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Text as the matcher sees it, plus each kept character's span in *text*.

    Percent-encoding (two rounds) and ``\\uXXXX`` are decoded.  Controls, format
    characters, and the ``\\\\n`` / ``\\\\r`` / ``\\\\t`` escapes written by
    ``sanitize_text`` are gaps: they do not break a token, and a match that
    straddles them still covers them in *text*.
    """
    pieces = _pieces(text)
    for _ in range(2):
        pieces, pct_changed = _percent_decode_once(pieces)
        pieces, uni_changed = _unicode_escape_once(pieces)
        # PR #4 review (synced from GitHub main): continue when EITHER pass changed the text.  ``bob\u002540example.com`` needs the
        # unicode pass first (-> ``bob%40example.com``) and a second percent pass (-> ``bob@example.com``).  Still capped at 2 rounds.
        if not (pct_changed or uni_changed):
            break
    kept: List[Tuple[str, int, int]] = []
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
    """Keyed, deterministic redactor for strings and nested JSON-like structures.  ``digest(value)`` must return a hex string
    (>= 10 chars) from a KEYED hash (the pipeline passes ``Pseudonymizer.token("scrub", value, "")``)."""

    def __init__(self, digest: Callable[[str], str]) -> None:
        self._digest_fn = digest
        self.redactions = 0
        self._lock = threading.Lock()

    def _redact_value(self, name: str, value: str) -> str:
        if name == "BEARER":
            value = re.split(r"(?:\s|\+)+", value, maxsplit=1)[1]   # hash the token itself
        elif name == "EMAIL":
            value = value.lower()                                    # same mailbox -> same marker
        with self._lock:
            self.redactions += 1
        return f"[REDACTED_{name}_SHA256:{self._digest_fn(value)[:10]}]"

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
        """Recursively scrub strings in dicts (string KEYS too - PR #4 review, parity with agent-watch), lists and tuples; other scalars
        pass through.  A secret used as a dict key (``{"sk-...": 1}``) is replaced by its marker; two keys that scrub to the same marker
        collapse to one entry (last value wins), which is acceptable because the key itself was a secret, not data."""
        if _depth > MAX_DEPTH:
            return "[TRUNCATED_DEPTH]"
        if isinstance(obj, str):
            return self.scrub_text(obj)
        if isinstance(obj, dict):
            return {(self.scrub_text(k) if isinstance(k, str) else k): self.scrub(v, _depth + 1) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v, _depth + 1) for v in obj]
        return obj
