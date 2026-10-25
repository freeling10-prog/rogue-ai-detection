"""Chained HMAC capability tokens (macaroon-style caveats).

A session capability is a hash chain any gateway worker can check with the
shared HMAC secret (``AGENT_GATEWAY_HMAC_KEY``). The holder of a token can
append a caveat by using the current tag as the next HMAC key (attenuate).
Dropping, reordering, or rewriting a caveat breaks the chain. Egress is
monotonic: once ``allow_egress=false`` appears, a later ``allow_egress=true``
does not restore it.

Token
-----
``agw1.<base64url(json)>.<hex>``

.. code-block:: text

    json = {"v": 1, "id": "<session_id>", "caveats": ["...", ...]}
    sig0 = HMAC-SHA256(root_key, "agw1|" + session_id)
    sig_i = HMAC-SHA256(sig_{i-1}, caveat_i)   # caveat string, UTF-8
    published signature = lowercase hex of sig_n

Initial caveats, minted by a worker that holds the root key:

1. ``bind:session=<sha256("session|" + session_id)[:32]>``
2. ``bind:agent=<sha256("agent|" + agent_key)[:32]>``
3. ``allow_egress=true``

A session that may answer server-initiated MCP ``sampling/createMessage``
requests carries ``grant:sampling=<HMAC(root_key, "sampling|" + session_id)[:32]>``
right after ``allow_egress=true``. Only a worker that holds the root key can
compute that tag, so a holder cannot grant sampling by attenuation.
``allow_sampling=false`` revokes it for the rest of the chain.

On untrusted ingest the PEP appends ``allow_egress=false`` and
``taint_source=<sanitized id>``. Verification recomputes the chain from the
root key only — no shared session table.

The HMAC secret is the trust root: a worker that holds it can mint a fresh
allowing token for a session it has never seen. A holder who does not have
the root key cannot turn an attenuated chain back into one that allows egress.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

TOKEN_PREFIX = "agw1"
CAVEAT_ALLOW_EGRESS = "allow_egress=true"
CAVEAT_DENY_EGRESS = "allow_egress=false"
CAVEAT_DENY_SAMPLING = "allow_sampling=false"
GRANT_SAMPLING_PREFIX = "grant:sampling="
MAX_CAVEATS = 32
_CAVEAT_RE = re.compile(r"^[A-Za-z0-9_.:@=+/-]{1,512}$")
_SIG_RE = re.compile(r"^[0-9a-f]{64}$")


def hmac_key(*, allow_default: bool = False) -> bytes:
    """Shared lab root key. Workers that verify capabilities need only this.

    Fails closed if ``AGENT_GATEWAY_HMAC_KEY`` is unset. Pass
    ``allow_default=True`` only for pure local lab scripts that never leave
    the machine.
    """
    env = os.environ.get("AGENT_GATEWAY_HMAC_KEY")
    if env:
        if len(env.encode()) < 32:
            raise RuntimeError(
                "AGENT_GATEWAY_HMAC_KEY must be at least 32 bytes. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        return env.encode()
    if allow_default:
        # Explicit opt-in only. Never use this in any networked or shared process.
        return b"agent-gateway-lab-hmac-key-32b!!"
    raise RuntimeError(
        "AGENT_GATEWAY_HMAC_KEY is not set. "
        "Refusing to start. Set a strong random key in the environment "
        "or pass allow_default=True only for isolated local tests."
    )


def _eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def _bind_hash(label: str, value: str) -> str:
    return hashlib.sha256(f"{label}|{value}".encode("utf-8")).hexdigest()[:32]


def session_binding(session_id: str) -> str:
    return _bind_hash("session", session_id)


def agent_binding(agent_key: str) -> str:
    return _bind_hash("agent", agent_key)


def sanitize_source(source: str) -> str:
    """Caveat-safe taint source id (no raw secrets; charset is authenticated)."""
    safe = re.sub(r"[^A-Za-z0-9_.:@=+/-]", "_", source)[:160]
    return safe or "unknown"


def sampling_grant(session_id: str, *, key: Optional[bytes] = None) -> str:
    """Root-keyed grant caveat. A holder without the root key cannot forge it."""
    root = hmac_key() if key is None else key
    tag = hmac.new(root, f"sampling|{session_id}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"{GRANT_SAMPLING_PREFIX}{tag}"


def allows_sampling(cap: "Capability", *, key: Optional[bytes] = None) -> bool:
    """Explicit root-keyed sampling grant, egress still open, and no revocation."""
    if not cap.allows_egress or CAVEAT_DENY_SAMPLING in cap.caveats:
        return False
    expect = sampling_grant(cap.session_id, key=key)
    return any(len(c) == len(expect) and hmac.compare_digest(c, expect) for c in cap.caveats)


def taint_source_caveat(source: str) -> str:
    return f"taint_source={sanitize_source(source)}"


def _sig0(key: bytes, session_id: str) -> bytes:
    return hmac.new(key, f"agw1|{session_id}".encode("utf-8"), hashlib.sha256).digest()


def _fold(sig: bytes, caveat: str) -> bytes:
    return hmac.new(sig, caveat.encode("utf-8"), hashlib.sha256).digest()


def _chain(key: bytes, session_id: str, caveats: tuple[str, ...]) -> bytes:
    sig = _sig0(key, session_id)
    for caveat in caveats:
        sig = _fold(sig, caveat)
    return sig


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


@dataclass(frozen=True)
class Capability:
    session_id: str
    caveats: tuple[str, ...]
    signature: str  # lowercase hex of the final chain tag

    @property
    def allows_egress(self) -> bool:
        """Monotonic: any deny caveat wins over a later allow caveat."""
        return CAVEAT_DENY_EGRESS not in self.caveats

    @property
    def taint_source(self) -> str:
        prefix = "taint_source="
        for caveat in self.caveats:
            if caveat.startswith(prefix):
                return caveat[len(prefix):]
        return ""

    @property
    def agent_bind(self) -> str:
        prefix = "bind:agent="
        for caveat in self.caveats:
            if caveat.startswith(prefix):
                return caveat[len(prefix):]
        return ""


def serialize(cap: Capability) -> str:
    payload = {"v": 1, "id": cap.session_id, "caveats": list(cap.caveats)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{TOKEN_PREFIX}.{_b64e(raw)}.{cap.signature}"


def parse(token: str) -> Optional[Capability]:
    """Structural parse. Does not check the HMAC (holders can do this)."""
    if not isinstance(token, str) or not token or len(token) > 8000:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None
    if _SIG_RE.fullmatch(parts[2]) is None:
        return None
    try:
        payload = json.loads(_b64d(parts[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return None
    session_id = payload.get("id")
    caveats = payload.get("caveats")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 512:
        return None
    if not isinstance(caveats, list) or not (1 <= len(caveats) <= MAX_CAVEATS):
        return None
    if not all(isinstance(c, str) and _CAVEAT_RE.fullmatch(c) for c in caveats):
        return None
    return Capability(session_id=session_id, caveats=tuple(caveats), signature=parts[2])


def verify(token: str, *, key: Optional[bytes] = None) -> Optional[Capability]:
    """Recompute the chain from the root HMAC key. Stateless."""
    cap = parse(token)
    if cap is None:
        return None
    if cap.caveats[0] != f"bind:session={session_binding(cap.session_id)}":
        return None
    root = hmac_key() if key is None else key
    expect = _chain(root, cap.session_id, cap.caveats)
    try:
        got = bytes.fromhex(cap.signature)
    except ValueError:
        return None
    if not _eq(expect, got):
        return None
    return cap


def agent_matches(cap: Capability, agent_key: str) -> bool:
    binding = cap.agent_bind
    expect = agent_binding(agent_key)
    if not binding or len(binding) != len(expect):
        return False
    return hmac.compare_digest(binding, expect)


def extends(prefix: tuple[str, ...], longer: tuple[str, ...]) -> bool:
    """True when ``longer`` is ``prefix`` plus zero or more appended caveats."""
    return len(longer) >= len(prefix) and longer[: len(prefix)] == prefix


def mint(
    session_id: str, agent_key: str, *, key: Optional[bytes] = None, sampling: bool = False,
) -> Capability:
    """Mint an allowing capability. Requires the root key.

    ``sampling=True`` adds the root-keyed MCP sampling grant.
    """
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id required")
    if not isinstance(agent_key, str) or not agent_key:
        raise ValueError("agent_key required")
    caveats = (
        f"bind:session={session_binding(session_id)}",
        f"bind:agent={agent_binding(agent_key)}",
        CAVEAT_ALLOW_EGRESS,
    )
    if sampling:
        caveats += (sampling_grant(session_id, key=key),)
    root = hmac_key() if key is None else key
    sig = _chain(root, session_id, caveats).hex()
    return Capability(session_id=session_id, caveats=caveats, signature=sig)


def attenuate(cap: Capability, caveat: str) -> Capability:
    """Append one caveat. Uses only the current tag — not the root key."""
    if not isinstance(caveat, str) or _CAVEAT_RE.fullmatch(caveat) is None:
        raise ValueError("caveat rejected")
    if len(cap.caveats) >= MAX_CAVEATS:
        raise ValueError("caveat limit")
    sig = _fold(bytes.fromhex(cap.signature), caveat).hex()
    return Capability(cap.session_id, cap.caveats + (caveat,), sig)


def attenuate_token(token: str, caveat: str) -> str:
    """Holder-side attenuation. Does not require the root key."""
    cap = parse(token)
    if cap is None:
        raise ValueError("malformed capability")
    return serialize(attenuate(cap, caveat))
