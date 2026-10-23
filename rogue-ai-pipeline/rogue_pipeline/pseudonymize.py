"""Keyed pseudonymization (HMAC-SHA256) with domain separation.

* The key comes from an environment variable (name set in config) - never from source code or config files.
* Each identifier class (agent, ip, user, resource, content shingle) uses its own domain prefix, so the same
  string in two roles yields unrelated pseudonyms and cannot be joined across classes.
* Pseudonyms are stable for a given key, which is what makes behavioural profiling possible; whoever holds the
  key can re-link them, so the key is the secret that protects people. Rotate it to unlink historical data.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import os
import re
import secrets
from collections import Counter
from typing import Mapping, Optional, Tuple

PRODUCTION_SECRET_ENV = "PIPELINE_HMAC_SECRET"
PIPELINE_ENV = "PIPELINE_ENV"


class KeyConfigError(Exception):
    """Raised when the HMAC key is missing or too short."""


class MissingKeyError(KeyConfigError):
    pass


class ProductionKeyError(KeyConfigError):
    """Production mode was requested but the HMAC secret is missing, weak, a known default, or ephemeral.
    There is deliberately no fallback."""


class Pseudonymizer:
    """HMAC-SHA256 pseudonymizer. The key is held privately and never printed."""

    def __init__(self, key: bytes, digest_hex_len: int = 16, min_key_bytes: int = 16,
                 production_validated: bool = False) -> None:
        if len(key) < min_key_bytes:
            raise KeyConfigError(f"HMAC key must be at least {min_key_bytes} bytes")
        self.__key = bytes(key)
        self._n = digest_hex_len
        self.production_validated = production_validated    # True only if built via ``resolve_key(production=True)``

    def __repr__(self) -> str:  # never leak the key through logging or tracebacks
        return "Pseudonymizer(key=<hidden>)"

    def _digest(self, domain: str, value: str) -> bytes:
        return hmac.new(self.__key, f"{domain}\x1f{value}".encode("utf-8"), hashlib.sha256).digest()

    def token(self, domain: str, value: str, prefix: str) -> str:
        return prefix + self._digest(domain, value).hex()[: self._n]

    def agent(self, v: str) -> str:
        return self.token("agent", v, "ag_")

    def ip(self, v: str) -> str:
        return self.token("ip", v, "ip_")

    def user(self, v: str) -> str:
        return self.token("user", v, "us_")

    def resource(self, v: str) -> str:
        return self.token("resource", v, "rs_")

    def shingle(self, v: str) -> int:
        """Keyed 64-bit hash of a content shingle (raw text is discarded after shingling)."""
        return int.from_bytes(self._digest("shingle", v)[:8], "big")


def load_key(env_name: str, min_bytes: int = 16, allow_ephemeral: bool = False) -> tuple[bytes, bool]:
    """Read the key from ``$env_name``. Returns ``(key, is_ephemeral)``.

    With ``allow_ephemeral`` a random in-memory key is generated when the variable is unset (suitable for
    demos and evaluation only: pseudonyms then differ between runs). Otherwise a missing key is an error.
    """
    raw: Optional[str] = os.environ.get(env_name)
    if raw:
        key = raw.encode("utf-8")
        if len(key) < min_bytes:
            raise KeyConfigError(f"${env_name} is too short: need at least {min_bytes} bytes")
        return key, False
    if allow_ephemeral:
        return secrets.token_bytes(32), True
    raise MissingKeyError(
        f"HMAC key not set. Export a random secret, e.g.  export {env_name}=$(python -c "
        "'import secrets;print(secrets.token_hex(32))')   (or pass --ephemeral-key for demos)"
    )


# ---- production key enforcement ---------------------------------------------------------------------------
MIN_PROD_BYTES = 32
_WEAK_WORDS = ("test", "changeme", "change-me", "change_me", "password", "passw0rd", "secret", "default", "demo", "example",
               "ephemeral", "selftest", "unit-test", "hunter2", "qwerty", "letmein", "admin", "todo", "placeholder",
               "yourkey", "your-key", "your_key")
_WEAK_TEXT_ONLY = ("xxxx", "0000", "1234")      # too likely to occur by chance in a random hex/base64 string
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _shannon(data: bytes) -> float:
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _patterned(data: bytes) -> bool:
    """Obvious structure: a short block repeated, or an arithmetic run (abcdef..., 123456...)."""
    n = len(data)
    for period in range(1, 9):
        if n >= period * 4 and all(data[i] == data[i % period] for i in range(n)):
            return True
    steps = [(data[i + 1] - data[i]) % 256 for i in range(n - 1)]
    return bool(steps) and max(Counter(steps).values()) / len(steps) >= 0.8


def decode_secret(raw: str) -> Tuple[bytes, str]:
    """Interpret a secret string: hex (>=64 chars) -> bytes, base64 (>=44 chars, strict) -> bytes, else the UTF-8 text."""
    v = raw.strip()
    if len(v) >= 64 and len(v) % 2 == 0 and _HEX.match(v):
        return bytes.fromhex(v), "hex"
    if len(v) >= 44:
        try:
            return base64.b64decode(v, altchars=b"-_" if ("-" in v or "_" in v) else None, validate=True), "base64"
        except (binascii.Error, ValueError):
            pass
    return v.encode("utf-8"), "text"


def check_production_secret(raw: Optional[str], other_dev_key: Optional[str] = None) -> bytes:
    """Validate ``PIPELINE_HMAC_SECRET``. Raises ``ProductionKeyError`` (never echoing the secret) or returns key bytes.

    Checks: present; >= 32 bytes after hex/base64 decoding, or >= 32 characters of text; not a known weak or demo
    value (substring match on common defaults); basic entropy (Shannon bits per byte and distinct-byte count); no
    obvious pattern (repeated block, arithmetic run); different from the dev key ``ROGUE_PIPELINE_HMAC_KEY``.
    These are sanity checks against careless values - not a proof the secret is random. Generate it with a CSPRNG:
    ``python -c 'import secrets;print(secrets.token_hex(32))'``."""
    if raw is None or not raw.strip():
        raise ProductionKeyError(f"production mode requires {PRODUCTION_SECRET_ENV}; it is not set. There is no fallback "
                                 f"(ROGUE_PIPELINE_HMAC_KEY and --ephemeral-key are not accepted in production).")
    key, form = decode_secret(raw)
    low = raw.lower()
    hit = next((w for w in _WEAK_WORDS + (_WEAK_TEXT_ONLY if form == "text" else ()) if w in low), None)
    if hit:
        raise ProductionKeyError(f"{PRODUCTION_SECRET_ENV} looks like a default or demo value (contains {hit!r}); refusing.")
    if len(key) < MIN_PROD_BYTES:
        raise ProductionKeyError(f"{PRODUCTION_SECRET_ENV} is too short: {len(key)} bytes after {form} decoding "
                                 f"(need >= {MIN_PROD_BYTES}).")
    if len(set(key)) < 12 or _shannon(key) < 3.3:
        raise ProductionKeyError(f"{PRODUCTION_SECRET_ENV} has too little entropy ({len(set(key))} distinct bytes, "
                                 f"{_shannon(key):.1f} bits/byte); use a random secret.")
    if _patterned(key):
        raise ProductionKeyError(f"{PRODUCTION_SECRET_ENV} has an obvious pattern (repeated block or sequence); refusing.")
    if other_dev_key and other_dev_key.strip() == raw.strip():
        raise ProductionKeyError(f"{PRODUCTION_SECRET_ENV} equals the development key ROGUE_PIPELINE_HMAC_KEY; "
                                 f"production must use its own secret.")
    return key


def production_requested(flag: bool = False, env: Optional[Mapping[str, str]] = None) -> bool:
    """Production mode if ``--production`` was given or ``PIPELINE_ENV=production`` (case-insensitive)."""
    env = os.environ if env is None else env
    return bool(flag) or env.get(PIPELINE_ENV, "").strip().lower() == "production"


def resolve_key(dev_env_name: str, min_bytes: int = 16, *, production: bool = False, allow_ephemeral: bool = False,
                env: Optional[Mapping[str, str]] = None) -> Tuple[bytes, bool, str]:
    """Pick the pseudonymization key. Returns ``(key, is_ephemeral, mode)`` with mode ``"production"`` or ``"dev"``.

    production:  ONLY ``PIPELINE_HMAC_SECRET`` is used and it must pass ``check_production_secret``. If
                 ``ROGUE_PIPELINE_HMAC_KEY`` is also set it is IGNORED (and rejected if identical to the secret);
                 ``allow_ephemeral`` is an error. No fallback of any kind.
    dev:         ``ROGUE_PIPELINE_HMAC_KEY`` wins if set; otherwise ``PIPELINE_HMAC_SECRET`` is accepted as a
                 convenience (length check only); otherwise a missing key is an error unless ``allow_ephemeral``.
    """
    env = os.environ if env is None else env
    if production:
        if allow_ephemeral:
            raise ProductionKeyError("--ephemeral-key is not allowed in production mode.")
        return check_production_secret(env.get(PRODUCTION_SECRET_ENV), env.get(dev_env_name)), False, "production"
    raw = env.get(dev_env_name) or env.get(PRODUCTION_SECRET_ENV)
    if raw:
        key = raw.encode("utf-8")
        if len(key) < min_bytes:
            raise KeyConfigError(f"the HMAC key is too short: need at least {min_bytes} bytes")
        return key, False, "dev"
    if allow_ephemeral:
        return secrets.token_bytes(32), True, "dev"
    raise MissingKeyError(
        f"HMAC key not set. Export a random secret, e.g.  export {dev_env_name}=$(python -c "
        "'import secrets;print(secrets.token_hex(32))')   (or pass --ephemeral-key for demos)")
