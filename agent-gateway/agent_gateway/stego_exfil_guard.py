"""Living-off-the-land and shingle exfiltration guard.

Catches a secret that leaves through an ordinary developer side effect after
being reshaped: split into a git branch or tag name, a package to install, a
DNS label or URL path segment, or a commit title. Raw-string canaries and
entropy checks miss these because the pieces are short, separated, and
low-entropy.

Registration (``register_secret``) normalizes a value (NFKC, case-folded,
everything but letters and digits removed) and its hex, base32, and
URL-safe base64 spellings, then keeps salted SHA-256 digests of their
character k-grams (``k=6`` by default). For the ordered-subsequence check it
also keeps the normalized forms in memory; nothing about a secret is ever
written to the log except a digest prefix of its label.

``inspect_outbound`` extracts side-effect identifiers from tool arguments
and shell commands (``git checkout -b`` / ``branch`` / ``tag`` / ``push`` /
``commit -m``, ``npm`` / ``pip`` / ``yarn`` / ``pnpm`` / ``gem`` / ``cargo`` /
``go`` install targets, ``dig`` / ``nslookup`` / ``host`` / ``ping`` names,
URL host labels, path segments, and query values) plus every string
argument (with ``identifiers_only=True``, only identifier-style keys such
as ``name``, ``branch``, ``tag``, ``ref``, ``package``, ``host``, ``title``,
``url`` and the URL parts found in any argument; ``PolicyEngine`` uses this
mode and leaves free-text bodies to ``deobfuscate.py``), and reports:

- ``STEGO_SECRET_SHINGLE_LEAK``: an identifier or argument shares at least
  ``min_shingles`` distinct k-gram shingles with one registered secret.
- ``STEGO_SUBSEQUENCE_EXFIL``: an identifier (at most ``max_identifier``
  normalized characters) contains a registered secret as an ordered
  subsequence covering at least ``lcs_ratio`` of the secret, densely
  (the aligned characters are at least ``min_density`` of the identifier),
  for secrets of at least ``min_lcs_secret`` characters. The longest common
  subsequence uses a bit-parallel algorithm, so a check is linear in the
  identifier length.

Denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). Lexical and statistical checks: a secret that
is paraphrased, encrypted, or leaked a character per call over many
identifiers is not caught here.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets as _secrets
import shlex
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

SHINGLE_LEAK = "STEGO_SECRET_SHINGLE_LEAK"
SUBSEQUENCE = "STEGO_SUBSEQUENCE_EXFIL"
RULE_CODES = (SHINGLE_LEAK, SUBSEQUENCE)
MIN_SECRET_CHARS = 8
MAX_SCAN_CHARS = 65_536

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s'\"<>`]+")
_PKG_TOOLS = {"npm": ("install", "i", "add"), "pnpm": ("add", "install", "i"), "yarn": ("add",),
              "pip": ("install",), "pip3": ("install",), "uv": ("add", "pip"), "poetry": ("add",),
              "gem": ("install",), "cargo": ("install", "add"), "go": ("install", "get"),
              "composer": ("require",), "apt": ("install",), "apt-get": ("install",), "brew": ("install",)}
_DNS_TOOLS = frozenset({"dig", "nslookup", "host", "ping", "ping6", "drill", "getent"})
COMMAND_KEYS = frozenset({"command", "cmd", "script"})
IDENTIFIER_KEYS = frozenset({"name", "branch", "branch_name", "tag", "tag_name", "ref", "package", "packages",
                             "package_name", "module", "host", "hostname", "domain", "subdomain", "title", "slug",
                             "label", "url", "uri", "link", "endpoint", "repo", "repository", "bucket", "key"})


def normalize(text: str) -> str:
    """NFKC, case-folded, letters and digits only."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", str(text)).casefold() if ch.isalnum())


def lcs_length(pattern: str, text: str) -> int:
    """Longest common subsequence length, bit-parallel (Hyyrö 2004). Linear in ``len(text)``."""
    m = len(pattern)
    if m == 0 or not text:
        return 0
    masks: dict[str, int] = {}
    for i, ch in enumerate(pattern):
        masks[ch] = masks.get(ch, 0) | (1 << i)
    full = (1 << m) - 1
    v = full
    for ch in text:
        u = v & masks.get(ch, 0)
        v = ((v + u) | (v - u)) & full
    return m - bin(v).count("1")


@dataclass
class _Secret:
    label_sha256: str
    forms: tuple[str, ...]  # normalized spellings, held in memory for the subsequence check
    shingles: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class StegoDecision:
    allowed: bool
    rule_code: str
    channel: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "channel": self.channel, "detail": self.detail}


CLEAN = StegoDecision(True, "STEGO_CLEAN")


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _url_parts(url: str) -> list[tuple[str, str]]:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return [("url", url)]
    out = [("url_host_label", label) for label in (u.hostname or "").split(".") if label]
    out += [("url_path_segment", urllib.parse.unquote(s)) for s in u.path.split("/") if s]
    for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
        out += [("url_query", k), ("url_query", v)]
    if u.fragment:
        out.append(("url_fragment", urllib.parse.unquote(u.fragment)))
    return out


def split_segments(command: str) -> list[str]:
    """Split on unquoted ``;``, ``&``, ``|`` and newlines, keeping quoted text (multi-line messages) intact."""
    segments, buf, quote, i = [], [], "", 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                buf.append(command[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in ";&|\n":
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [seg for seg in segments if seg.strip()]


def side_effect_identifiers(command: str) -> list[tuple[str, str]]:
    """``(channel, identifier)`` pairs a shell command would publish."""
    out: list[tuple[str, str]] = []
    for seg in split_segments(command):
        words = _words(seg)
        while words and (words[0] in ("sudo", "env") or re.match(r"^[A-Za-z_]\w*=", words[0])):
            words = words[1:]
        if not words:
            continue
        cmd = words[0].rsplit("/", 1)[-1]
        args = words[1:]
        plain = [a for a in args if not a.startswith("-")]
        if cmd == "git" and args:
            sub = args[0]
            rest = args[1:]
            if sub in ("checkout", "switch") and any(a in ("-b", "-B", "-c", "-C", "--orphan") for a in rest):
                names = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a in ("-b", "-B", "-c", "-C", "--orphan")]
                out += [("git_branch", n) for n in names]
            elif sub in ("branch", "tag"):
                out += [(f"git_{sub}", a) for a in rest if not a.startswith("-")][:2]
            elif sub == "push":
                out += [("git_ref", r.split(":")[-1].lstrip("+")) for r in rest if not r.startswith("-")][1:]
            elif sub == "commit":
                msgs = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a in ("-m", "--message")]
                msgs += [a.split("=", 1)[1] for a in rest if a.startswith("--message=")]
                out += [("commit_title", m.splitlines()[0] if m else m) for m in msgs]
        elif cmd in _PKG_TOOLS and plain and plain[0] in _PKG_TOOLS[cmd]:
            out += [("package_install", p) for p in plain[1:]]
        elif cmd in _DNS_TOOLS:
            for p in plain:
                out += [("dns_label", label) for label in p.split(".") if label]
    for m in _URL_RE.finditer(command):
        out += _url_parts(m.group(0))
    return out


def _arg_strings(obj: Any, key: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(obj, str):
        yield key, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _arg_strings(v, str(k))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _arg_strings(v, key)


class StegoExfilGuard:
    """Registered secrets as salted k-gram shingles; outbound identifiers checked for collisions and subsequences."""

    def __init__(self, *, k: int = 6, min_shingles: int = 2, lcs_ratio: float = 0.8, min_density: float = 0.5,
                 min_lcs_secret: int = 12, max_identifier: int = 256, audit_log: Optional[Path] = None) -> None:
        if k < 3:
            raise ValueError("k must be at least 3")
        self.k = k
        self.min_shingles = max(1, min_shingles)
        self.lcs_ratio = lcs_ratio
        self.min_density = min_density
        self.min_lcs_secret = min_lcs_secret
        self.max_identifier = max_identifier
        self._salt = _secrets.token_bytes(16)
        self._secrets: dict[Optional[str], list[_Secret]] = {}
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None

    def _digest(self, gram: str) -> str:
        return hashlib.sha256(self._salt + gram.encode("utf-8")).hexdigest()[:32]

    def _shingles(self, text: str) -> set[str]:
        return {self._digest(text[i:i + self.k]) for i in range(len(text) - self.k + 1)}

    @staticmethod
    def variants(value: str) -> tuple[str, ...]:
        raw = str(value).encode("utf-8")
        forms = [normalize(value), normalize(binascii.hexlify(raw).decode("ascii")),
                 normalize(base64.b32encode(raw).decode("ascii")),
                 normalize(base64.urlsafe_b64encode(raw).decode("ascii"))]
        return tuple(dict.fromkeys(f for f in forms if len(f) >= MIN_SECRET_CHARS))

    def register_secret(self, value: str, *, label: str = "secret", session_id: Optional[str] = None) -> bool:
        """Protect ``value`` in every session, or only in ``session_id``. Returns False when it is too short."""
        if not isinstance(value, str) or len(normalize(value)) < MIN_SECRET_CHARS:
            return False
        forms = self.variants(value)
        shingles = frozenset().union(*(self._shingles(f) for f in forms))
        entry = _Secret(hashlib.sha256(label.encode("utf-8")).hexdigest()[:16], forms, shingles)
        bucket = self._secrets.setdefault(session_id, [])
        if any(s.forms == forms for s in bucket):
            return False
        bucket.append(entry)
        return True

    def secret_count(self, session_id: Optional[str] = None) -> int:
        return len(self._secrets.get(None, [])) + (len(self._secrets.get(session_id, [])) if session_id else 0)

    def _applicable(self, session_id: Optional[str]) -> list[_Secret]:
        return [*self._secrets.get(None, []), *(self._secrets.get(session_id, []) if session_id else [])]

    def check_identifier(self, channel: str, identifier: str, secrets: list[_Secret]) -> Optional[StegoDecision]:
        text = normalize(identifier[:MAX_SCAN_CHARS])
        if len(text) < self.k:
            return None
        grams = self._shingles(text)
        for s in secrets:
            hits = len(grams & s.shingles)
            if hits >= self.min_shingles:
                return StegoDecision(False, SHINGLE_LEAK, channel, f"{hits} shingles of secret {s.label_sha256}")
        if len(text) > self.max_identifier:
            return None
        for s in secrets:
            for form in s.forms:
                if len(form) < self.min_lcs_secret:
                    continue
                lcs = lcs_length(form, text)
                if lcs >= self.lcs_ratio * len(form) and lcs >= self.min_density * len(text):
                    return StegoDecision(False, SUBSEQUENCE, channel,
                                         f"subsequence covers {lcs}/{len(form)} of secret {s.label_sha256}")
        return None

    def inspect_outbound(self, tool_name: str, args: Any, *, session_id: Optional[str] = None,
                         identifiers_only: bool = False) -> StegoDecision:
        secrets = self._applicable(session_id)
        if not secrets:
            return CLEAN
        candidates: list[tuple[str, str]] = []
        for key, text in _arg_strings(args):
            k = key.casefold()
            if not identifiers_only or k in IDENTIFIER_KEYS:
                candidates.append((f"arg:{key}" if key else "arg", text))
            if k in COMMAND_KEYS:
                candidates += side_effect_identifiers(text)
            else:
                for m in _URL_RE.finditer(text):
                    candidates += _url_parts(m.group(0))
        for channel, ident in candidates:
            d = self.check_identifier(channel, ident, secrets)
            if d is not None:
                if self.chain is not None:
                    self.chain.append({"ts": round(time.time(), 6), "kind": d.rule_code, "verdict": "DENY",
                                       "rule_code": d.rule_code, "tool": tool_name, "channel": channel,
                                       "session_id": session_id or "", "detail": d.detail})
                return d
        return CLEAN
