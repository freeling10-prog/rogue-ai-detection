"""Sanitization of UNTRUSTED, attacker-controlled text (honeypot captures) at ingest.

Captured agent metadata (system-prompt summary, declared tools, objective, message) is written by whoever is on
the other end of a decoy endpoint. Treat it as hostile data, never as instructions:
  * control, format (zero-width, bidi override), surrogate, private-use and line/paragraph-separator characters
    are removed, so it cannot forge log lines, spoof terminal output or visually reorder text;
  * whitespace is collapsed; text is NFC-normalised;
  * URL schemes are defanged (http -> hxxp) so a report or STIX consumer never renders a live link;
  * every field is truncated to a soft limit (with a visible marker and a flag); absurdly large inputs are
    rejected outright (hard limit) and end up in quarantine;
  * the result is only ever stored and displayed - it is never fed to the detectors' scoring, never evaluated.
Sanitizing reduces risk; it does not make the text safe to obey. Do not paste it into an LLM prompt.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Tuple

TRUNC_MARK = "...[truncated]"
_BAD_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
_URL = re.compile(r"(?i)\b(https?|ftp)://")
_WS = re.compile(r"\s+")
_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def sanitize_untrusted(text: str, max_len: int) -> Tuple[str, bool, int]:
    """Return ``(clean_text, was_truncated, n_chars_removed)``."""
    text = unicodedata.normalize("NFC", text)
    kept = []
    removed = 0
    for ch in text:
        if ch in "\n\r\t\v\f":
            kept.append(" ")
        elif unicodedata.category(ch) in _BAD_CATEGORIES:
            removed += 1
        else:
            kept.append(ch)
    t = _WS.sub(" ", "".join(kept)).strip()
    t = _URL.sub(lambda m: _DEFANG[m.group(1).lower()] + "://", t)
    truncated = len(t) > max_len
    if truncated:
        t = t[: max(max_len - len(TRUNC_MARK), 0)] + TRUNC_MARK
    return t, truncated, removed
