"""Cross-step smuggling and encoding de-obfuscation (approximate AML.T0086).

When a sensitive read returns data, or a canary secret is registered, the
guard keeps only salted SHA-256 digests of the secret's n-grams. It never
keeps the secret itself. Each secret is fingerprinted in five forms:

- raw
- Base64 (standard and URL-safe alphabets, padding stripped)
- hex (lowercase)
- URL-encoded
- whitespace-stripped

Outbound tool arguments that actually leave the gateway are appended to a
per-session sliding window, both as one global stream and as one stream per
argument key. Each chunk is also decoded on its own (Base64, hex, URL,
whitespace-stripped) into parallel decoded windows. A leak is any n-gram of
``min_leak_chars`` characters from any secret form that shows up in any
window. This catches:

- split-chunk exfiltration (4-6 characters per call across several calls)
- encode-then-split (Base64 or hex of the whole secret, sent in pieces)
- split-then-encode (each piece encoded on its own)
- whitespace or URL-escape padding

The check is deterministic and zero-compute: string slicing and SHA-256.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional

ATLAS_EXFIL = "AML.T0086"
DEFAULT_NGRAM = 8
MIN_SECRET_CHARS = 6
WINDOW_CHARS = 4096
MAX_CHUNK_CHARS = 4096
MAX_SECRETS = 256

FORM_RAW = "raw"
FORM_B64 = "base64"
FORM_HEX = "hex"
FORM_URL = "url"
FORM_WS = "ws_stripped"

_WS_RE = re.compile(r"\s+")
_TOKEN_SPLIT_RE = re.compile(r"[\s,;\"'`()<>\[\]{}]+|(?<=[:=])")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX_RUN_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){4,}")


def _strip_ws(text: str) -> str:
    return _WS_RE.sub("", text)


def secret_forms(secret: str) -> dict[str, list[str]]:
    """The normalizations a secret is fingerprinted under."""
    raw = secret.encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii").rstrip("=")
    b64u = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    forms = {
        FORM_RAW: [secret],
        FORM_B64: sorted({b64, b64u}),
        FORM_HEX: [raw.hex()],
        FORM_URL: sorted({urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)}),
        FORM_WS: [_strip_ws(secret)],
    }
    return forms


def _printable(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
        return None
    return text


def _b64_decode(token: str) -> Optional[str]:
    body = token.rstrip("=")
    if len(body) % 4 == 1:
        return None
    pad = "=" * ((4 - len(body) % 4) % 4)
    alt = body.replace("-", "+").replace("_", "/")
    try:
        return _printable(base64.b64decode(alt + pad, validate=True))
    except (binascii.Error, ValueError):
        return None


def _hex_decode(token: str) -> Optional[str]:
    if len(token) % 2:
        return None
    try:
        return _printable(bytes.fromhex(token))
    except ValueError:
        return None


def decoded_variants(chunk: str) -> dict[str, str]:
    """Decode one outbound chunk on its own. Keys name the decoder."""
    out: dict[str, str] = {}
    stripped = _strip_ws(chunk)
    if stripped != chunk:
        out[FORM_WS] = stripped
    url = urllib.parse.unquote_plus(chunk)
    if url != chunk:
        out[FORM_URL] = url
    for key, rx, dec in (("b64", _B64_RUN_RE, _b64_decode), ("hex", _HEX_RUN_RE, _hex_decode)):
        parts = []
        source = stripped
        whole = dec(source) if source else None
        if whole is not None:
            parts.append(whole)
        else:
            for m in rx.finditer(source):
                got = dec(m.group(0))
                if got is not None:
                    parts.append(got)
        if parts:
            out[key] = "".join(parts)
    return out


def iter_strings(obj: Any, depth: int = 0) -> Iterator[tuple[str, str]]:
    """(key path, string value) for every string leaf. Keys count too."""
    if depth > 12:
        return
    if isinstance(obj, str):
        yield "", obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            if isinstance(v, str):
                yield key, v
            else:
                for sub, s in iter_strings(v, depth + 1):
                    yield (f"{key}.{sub}" if sub else key), s
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from iter_strings(item, depth + 1)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        yield "", str(obj)


def secret_candidates(value: str, depth: int = 0) -> list[str]:
    """Secret-like values inside one result string.

    A short string with no whitespace is one value. Free text ("your key is
    sk-...") is split into tokens, and only tokens of ``DEFAULT_NGRAM`` or more
    characters count, so ordinary words in a result do not become fingerprints.
    JSON text is parsed into its leaves first.
    """
    value = value.strip()
    if not value:
        return []
    if depth < 2 and value[:1] in "{[":
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            return [c for _k, v in iter_strings(parsed) for c in secret_candidates(v, depth + 1)]
    if not _WS_RE.search(value) and len(value) <= 512:
        return [value]
    return [t for t in _TOKEN_SPLIT_RE.split(value) if len(t) >= DEFAULT_NGRAM]


@dataclass
class _Fingerprint:
    label: str
    n: int
    digests: dict[str, frozenset[str]]  # form -> n-gram digests


@dataclass
class LeakMatch:
    label: str
    form: str
    window: str
    ngram_chars: int

    def as_dict(self) -> dict[str, Any]:
        return {"secret_label": self.label, "form": self.form, "window": self.window,
                "ngram_chars": self.ngram_chars, "atlas": ATLAS_EXFIL, "atlas_approximate": True}


@dataclass
class _Window:
    limit: int
    text: str = ""


@dataclass
class SessionWindows:
    limit: int = WINDOW_CHARS
    streams: dict[str, _Window] = field(default_factory=dict)


class DeobfuscationGuard:
    """Registered secret fingerprints plus per-session outbound windows."""

    def __init__(self, n: int = DEFAULT_NGRAM, window_chars: int = WINDOW_CHARS, salt: Optional[bytes] = None):
        self.n = int(n)
        self.window_chars = int(window_chars)
        # Random per-process salt: digests are useless outside this process.
        self._salt = salt if salt is not None else os.urandom(16)
        self._global: dict[str, _Fingerprint] = {}
        self._session: dict[str, dict[str, _Fingerprint]] = {}
        self._windows: dict[str, SessionWindows] = {}

    def _digest(self, gram: str) -> str:
        return hashlib.sha256(self._salt + gram.encode("utf-8")).hexdigest()

    def _grams(self, text: str, n: int) -> Iterable[str]:
        if len(text) < n:
            return ()
        return (text[i:i + n] for i in range(len(text) - n + 1))

    def _fingerprint(self, secret: str, label: str) -> Optional[_Fingerprint]:
        if not isinstance(secret, str):
            return None
        secret = secret.strip()
        if len(secret) < MIN_SECRET_CHARS:
            return None
        n = min(self.n, len(secret))
        digests: dict[str, frozenset[str]] = {}
        for form, values in secret_forms(secret).items():
            grams: set[str] = set()
            for value in values:
                value = value.lower() if form == FORM_HEX else value
                grams.update(self._digest(g) for g in self._grams(value, n))
            if grams:
                digests[form] = frozenset(grams)
        return _Fingerprint(label=label, n=n, digests=digests)

    def register(self, secret: str, label: str = "sensitive_read", session_id: Optional[str] = None) -> bool:
        """Fingerprint a secret. ``session_id=None`` registers a global canary."""
        fp = self._fingerprint(secret, label)
        if fp is None:
            return False
        key = self._digest("secret|" + secret.strip())
        table = self._global if session_id is None else self._session.setdefault(session_id, {})
        if key not in table and len(table) >= MAX_SECRETS:
            table.pop(next(iter(table)))
        table[key] = fp
        return True

    def register_output(self, obj: Any, label: str, session_id: Optional[str] = None) -> int:
        """Register the secret-like values in a sensitive tool result."""
        count = 0
        for _key, value in iter_strings(obj):
            for candidate in secret_candidates(value):
                if self.register(candidate, label=label, session_id=session_id):
                    count += 1
        return count

    def has_secrets(self, session_id: str) -> bool:
        return bool(self._global or self._session.get(session_id))

    def secret_count(self, session_id: Optional[str] = None) -> int:
        n = len(self._global)
        if session_id is not None:
            n += len(self._session.get(session_id, {}))
        return n

    def _fingerprints(self, session_id: str) -> list[_Fingerprint]:
        return [*self._global.values(), *self._session.get(session_id, {}).values()]

    def _staged(self, session_id: str, tool_name: str, arguments: Any) -> dict[str, str]:
        """Window texts if this call were appended. Nothing is committed."""
        current = self._windows.get(session_id) or SessionWindows(self.window_chars)
        additions: dict[str, list[str]] = {}
        for key, value in iter_strings(arguments):
            chunk = value[:MAX_CHUNK_CHARS]
            if not chunk:
                continue
            leaf = key.rsplit(".", 1)[-1] or "_"
            for stream in ("all", f"key:{leaf}"):
                additions.setdefault(f"{stream}|raw", []).append(chunk)
                for dec_name, dec_text in decoded_variants(chunk).items():
                    additions.setdefault(f"{stream}|{dec_name}", []).append(dec_text)
        staged: dict[str, str] = {}
        for name, chunks in additions.items():
            prior = current.streams.get(name)
            staged[name] = ((prior.text if prior else "") + "".join(chunks))[-self.window_chars:]
        return staged

    def scan(self, session_id: str, tool_name: str, arguments: Any) -> Optional[LeakMatch]:
        """Would sending ``arguments`` complete a leak? Read-only."""
        fps = self._fingerprints(session_id)
        if not fps:
            return None
        staged = self._staged(session_id, tool_name, arguments)
        if not staged:
            return None
        cache: dict[tuple[str, int, bool], set[str]] = {}
        for name, text in staged.items():
            for fp in fps:
                for form, digests in fp.digests.items():
                    lower = form == FORM_HEX
                    ck = (name, fp.n, lower)
                    grams = cache.get(ck)
                    if grams is None:
                        src = text.lower() if lower else text
                        grams = cache[ck] = {self._digest(g) for g in self._grams(src, fp.n)}
                    if grams & digests:
                        return LeakMatch(label=fp.label, form=form, window=name, ngram_chars=fp.n)
        return None

    def commit(self, session_id: str, tool_name: str, arguments: Any) -> None:
        """Append an allowed call's arguments to the session windows."""
        staged = self._staged(session_id, tool_name, arguments)
        win = self._windows.setdefault(session_id, SessionWindows(self.window_chars))
        for name, text in staged.items():
            w = win.streams.get(name)
            if w is None:
                w = win.streams[name] = _Window(self.window_chars)
            w.text = text
