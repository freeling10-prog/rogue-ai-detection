"""Module 2 scaffold: ``agw2`` capability tokens with typed, attenuating caveats.

An ``agw1`` token (``capability.py``) carries two deny bits. An ``agw2``
token states what its holder may do: which tools, which destinations, which
argument values, until when, how many times, and how many quarter bits of
the P3 leakage budget. Standard library only (``hmac``, ``hashlib``,
``json``).

Token
-----
``agw2.<base64url(body)>.<hex>``

.. code-block:: text

    body  = canonical JSON {"v": 2, "tid": <32 hex>, "scope": {...}, "caveats": [...]}
    sig0  = HMAC-SHA256(root_key, "agw2|" + canonical({"v", "tid", "scope"}))
    sig_i = HMAC-SHA256(sig_{i-1}, canonical(caveat_i))
    published signature = lowercase hex of sig_n

``scope`` is fixed at mint by a holder of the root key:
``{"kind": "session", "id": H(session)}`` or ``{"kind": "coalition",
"id": H(anchor session)}``. A coalition token is usable by any session that
is in the anchor's P3 coalition at the time of the call.

Caveats (closed vocabulary)
---------------------------
``tools`` and ``dest`` (allow sets), ``arg`` (one predicate on one argument
path: ``eq``, ``in``, ``prefix``, ``max_len``, ``range``, ``absent``),
``session`` (narrow a coalition token to one member), ``exp`` (not after a
millisecond time), ``calls`` (at most n admitted events), ``budget_qb`` (at
most n quarter bits of P3 charge) and ``once`` (single use, named by a
nonce). A token with a caveat outside this vocabulary, a malformed caveat,
or a body that is not in canonical form does not verify. There is no
caveat that grants anything.

Attenuation
-----------
A request is admitted only when every caveat on the chain admits it, so
appending a caveat can only remove requests. ``attenuate`` needs the
current tag, not the root key; dropping, reordering or editing a caveat
breaks the chain. The counter behind a ``calls``, ``budget_qb`` or ``once``
caveat is keyed by the chain tag at that caveat's position, and every token
derived from that prefix shares it: a sub-token cannot spend more than the
caveat it inherited allows, and siblings draw on the same counter.

Within the bounds in ``tests/test_capability_token.py``, "an extension
admits a subset of what its prefix admits" and "admitted spend under a tag
never exceeds that caveat's limit" are checked by bounded enumeration.
Nothing outside those bounds is claimed, and neither is proven.

Not in this scaffold
--------------------
Counters live in one process, like the P3 ledger. Tokens are attached to a
session by the control plane; presenting one on the wire, and binding it to
a holder key so a copied token is useless, are the next steps
(``docs/MODULE2_CAPABILITY_TOKENS.md``). ``exp`` is a validity window, not
a timing-channel control.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional

from .capability import hmac_key
from .common import Denied

TOKEN_PREFIX = "agw2"
VERSION = 2
MAX_TOKEN_CHARS = 16_384
MAX_CAVEATS = 32
MAX_SET = 64
MAX_NAME = 128
MAX_PATH_DEPTH = 4
MAX_VALUE_CHARS = 512
MAX_COUNT = 1 << 40
MAX_COUNTERS = 4096
MAX_REVOKED = 4096
MAX_LOG = 4096
SCOPE_KINDS = ("session", "coalition")
ARG_OPS = ("eq", "in", "prefix", "max_len", "range", "absent")
ANY_TOOL = "*"

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CAVEAT_KEYS = {
    "tools": {"t", "allow"},
    "dest": {"t", "allow"},
    "arg": {"t", "tool", "path", "op", "value"},
    "session": {"t", "id"},
    "exp": {"t", "not_after_ms"},
    "calls": {"t", "max"},
    "budget_qb": {"t", "max"},
    "once": {"t", "nonce"},
}
STATEFUL = ("calls", "budget_qb", "once")


def canonical(obj: Any) -> bytes:
    """Sorted keys, no whitespace, ASCII. The bytes the chain is computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def scope_hash(session_id: str) -> str:
    """Scope id for a session. The raw session id is not written into a token."""
    if type(session_id) is not str or not 1 <= len(session_id) <= 512:
        raise Denied("CAP_SCOPE")
    return hashlib.sha256(b"agw2-scope|" + session_id.encode("utf-8")).hexdigest()[:32]


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("alphabet")
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_name(value: Any) -> bool:
    return type(value) is str and 1 <= len(value) <= MAX_NAME


def _is_scalar(value: Any) -> bool:
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return -MAX_COUNT <= value <= MAX_COUNT
    return type(value) is str and len(value) <= MAX_VALUE_CHARS


def _same(a: Any, b: Any) -> bool:
    """Equality that does not let ``True`` stand in for ``1``."""
    return type(a) is type(b) and a == b


def _name_set(value: Any, *, allow_empty_name: bool = False) -> bool:
    if type(value) is not list or not 1 <= len(value) <= MAX_SET:
        return False
    for item in value:
        if type(item) is not str or len(item) > MAX_NAME or (not item and not allow_empty_name):
            return False
    return value == sorted(set(value))


def check_caveat(caveat: Any) -> dict:
    """Return ``caveat`` if it is in the vocabulary and well formed. Else ``Denied``."""
    if type(caveat) is not dict:
        raise Denied("CAP_CAVEAT")
    kind = caveat.get("t")
    keys = _CAVEAT_KEYS.get(kind) if type(kind) is str else None
    if keys is None:
        raise Denied("CAP_CAVEAT_UNKNOWN")
    optional = {"value"} if kind == "arg" and caveat.get("op") == "absent" else set()
    if not (keys - optional) <= set(caveat) <= keys:
        raise Denied("CAP_CAVEAT")
    ok = False
    if kind == "tools":
        ok = _name_set(caveat["allow"])
    elif kind == "dest":
        ok = _name_set(caveat["allow"], allow_empty_name=True)
    elif kind == "session":
        ok = type(caveat["id"]) is str and _HEX32.fullmatch(caveat["id"]) is not None
    elif kind == "exp":
        ok = _is_int(caveat["not_after_ms"]) and 0 <= caveat["not_after_ms"] <= 2 ** 62
    elif kind in ("calls", "budget_qb"):
        ok = _is_int(caveat["max"]) and 0 <= caveat["max"] <= MAX_COUNT
    elif kind == "once":
        ok = type(caveat["nonce"]) is str and _HEX32.fullmatch(caveat["nonce"]) is not None
    elif kind == "arg":
        ok = _check_arg(caveat)
    if not ok:
        raise Denied("CAP_CAVEAT")
    return caveat


def _check_arg(caveat: dict) -> bool:
    path, op = caveat["path"], caveat["op"]
    if not _is_name(caveat["tool"]) or op not in ARG_OPS:
        return False
    if type(path) is not list or not 1 <= len(path) <= MAX_PATH_DEPTH or not all(_is_name(p) for p in path):
        return False
    if op == "absent":
        return "value" not in caveat
    value = caveat["value"]
    if op == "eq":
        return _is_scalar(value)
    if op == "in":
        return type(value) is list and 1 <= len(value) <= MAX_SET and all(_is_scalar(v) for v in value)
    if op == "prefix":
        return type(value) is str and 1 <= len(value) <= MAX_VALUE_CHARS
    if op == "max_len":
        return _is_int(value) and 0 <= value <= MAX_COUNT
    return (type(value) is list and len(value) == 2 and all(_is_int(v) for v in value)
            and -MAX_COUNT <= value[0] <= value[1] <= MAX_COUNT)


# --- caveat constructors (holder side) --------------------------------------

def tools(*names: str) -> dict:
    return check_caveat({"t": "tools", "allow": sorted(set(names))})


def destinations(*names: str) -> dict:
    return check_caveat({"t": "dest", "allow": sorted(set(names))})


def arg(tool: str, path: str | list, op: str, value: Any = None) -> dict:
    """One predicate on ``arguments[path...]`` for ``tool`` (``"*"`` for any tool)."""
    caveat = {"t": "arg", "tool": tool, "path": [path] if type(path) is str else list(path), "op": op}
    if op != "absent":
        caveat["value"] = value
    return check_caveat(caveat)


def only_session(session_id: str) -> dict:
    return check_caveat({"t": "session", "id": scope_hash(session_id)})


def expires(not_after_ms: int) -> dict:
    return check_caveat({"t": "exp", "not_after_ms": not_after_ms})


def max_calls(n: int) -> dict:
    return check_caveat({"t": "calls", "max": n})


def max_budget_qb(n: int) -> dict:
    return check_caveat({"t": "budget_qb", "max": n})


def once(nonce: Optional[str] = None) -> dict:
    """Single use. Every token derived from this caveat shares the one use."""
    return check_caveat({"t": "once", "nonce": secrets.token_hex(16) if nonce is None else nonce})


# --- token -------------------------------------------------------------------

@dataclass(frozen=True)
class Token:
    tid: str
    scope_kind: str
    scope_id: str
    caveats: tuple
    signature: str

    def head(self) -> dict:
        return {"v": VERSION, "tid": self.tid, "scope": {"kind": self.scope_kind, "id": self.scope_id}}


@dataclass(frozen=True)
class Verified:
    """A token whose chain checked out, with the tag after each caveat."""

    token: Token
    root_tag: str
    tags: tuple


@dataclass(frozen=True)
class Request:
    """One outbound event, as the engine's shared outbound check sees it."""

    session_id: str
    tool: str
    destination: str
    arguments: dict
    now_ms: int
    # Sessions in the caller's P3 coalition. Just the caller when P3 is not attached.
    coalition: frozenset = frozenset()
    charge_qb: int = 0


def _sig0(key: bytes, head: dict) -> bytes:
    return hmac.new(key, b"agw2|" + canonical(head), hashlib.sha256).digest()


def _fold(tag: bytes, caveat: dict) -> bytes:
    return hmac.new(tag, canonical(caveat), hashlib.sha256).digest()


def serialize(token: Token) -> str:
    body = {**token.head(), "caveats": list(token.caveats)}
    return f"{TOKEN_PREFIX}.{_b64e(canonical(body))}.{token.signature}"


def _pairs(items: list) -> dict:
    out: dict = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def parse(text: Any) -> Token:
    """Structural parse. Raises ``Denied``; does not check the chain."""
    if type(text) is not str or not text or len(text) > MAX_TOKEN_CHARS:
        raise Denied("CAP_FORMAT")
    parts = text.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or _HEX64.fullmatch(parts[2]) is None:
        raise Denied("CAP_FORMAT")
    try:
        raw = _b64d(parts[1])
        body = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_float=_no_float,
                          parse_constant=_no_float)
    except (ValueError, UnicodeError):
        raise Denied("CAP_FORMAT") from None
    if type(body) is not dict or set(body) != {"v", "tid", "scope", "caveats"}:
        raise Denied("CAP_FORMAT")
    scope, caveats = body["scope"], body["caveats"]
    if not _same(body["v"], VERSION) or type(body["tid"]) is not str or _HEX32.fullmatch(body["tid"]) is None:
        raise Denied("CAP_FORMAT")
    if (type(scope) is not dict or set(scope) != {"kind", "id"} or scope["kind"] not in SCOPE_KINDS
            or type(scope["id"]) is not str or _HEX32.fullmatch(scope["id"]) is None):
        raise Denied("CAP_FORMAT")
    if type(caveats) is not list or len(caveats) > MAX_CAVEATS:
        raise Denied("CAP_FORMAT")
    for caveat in caveats:
        check_caveat(caveat)
    if canonical(body) != raw:
        raise Denied("CAP_NOT_CANONICAL")
    return Token(tid=body["tid"], scope_kind=scope["kind"], scope_id=scope["id"],
                 caveats=tuple(caveats), signature=parts[2])


def _no_float(_text: str):
    raise ValueError("no floats in a token")


def mint(scope_kind: str, session_id: str, caveats: tuple | list = (), *,
         key: Optional[bytes] = None, tid: Optional[str] = None) -> str:
    """Mint a token. Needs the root key. ``session_id`` is the session, or the coalition anchor."""
    if scope_kind not in SCOPE_KINDS:
        raise Denied("CAP_SCOPE")
    tid = secrets.token_hex(16) if tid is None else tid
    if type(tid) is not str or _HEX32.fullmatch(tid) is None:
        raise Denied("CAP_FORMAT")
    if len(caveats) > MAX_CAVEATS:
        raise Denied("CAP_LIMIT")
    token = Token(tid=tid, scope_kind=scope_kind, scope_id=scope_hash(session_id),
                  caveats=tuple(check_caveat(c) for c in caveats), signature="")
    tag = _sig0(hmac_key() if key is None else key, token.head())
    for caveat in token.caveats:
        tag = _fold(tag, caveat)
    return serialize(Token(token.tid, token.scope_kind, token.scope_id, token.caveats, tag.hex()))


def attenuate(text: str, *caveats: dict) -> str:
    """Append caveats. Uses only the current tag, so any holder can do it."""
    token = parse(text)
    if len(token.caveats) + len(caveats) > MAX_CAVEATS:
        raise Denied("CAP_LIMIT")
    tag = bytes.fromhex(token.signature)
    added = []
    for caveat in caveats:
        tag = _fold(tag, check_caveat(caveat))
        added.append(caveat)
    return serialize(Token(token.tid, token.scope_kind, token.scope_id,
                           token.caveats + tuple(added), tag.hex()))


def verify(text: Any, *, key: Optional[bytes] = None) -> Verified:
    """Recompute the chain from the root key. Raises ``Denied``."""
    token = parse(text)
    tag = _sig0(hmac_key() if key is None else key, token.head())
    root_tag = tag.hex()
    tags = []
    for caveat in token.caveats:
        tag = _fold(tag, caveat)
        tags.append(tag.hex())
    if not hmac.compare_digest(tag, bytes.fromhex(token.signature)):
        raise Denied("CAP_SIGNATURE")
    return Verified(token=token, root_tag=root_tag, tags=tuple(tags))


def extends(parent: Token, child: Token) -> bool:
    """True when ``child`` is ``parent`` plus zero or more appended caveats."""
    return (parent.head() == child.head() and len(child.caveats) >= len(parent.caveats)
            and child.caveats[:len(parent.caveats)] == parent.caveats)


# --- stateless admission -----------------------------------------------------

_MISSING = object()


def _lookup(arguments: Any, path: list) -> Any:
    node = arguments
    for part in path:
        if type(node) is not dict or part not in node:
            return _MISSING
        node = node[part]
    return node


def _arg_holds(caveat: dict, request: Request) -> bool:
    if caveat["tool"] not in (ANY_TOOL, request.tool):
        return True
    got = _lookup(request.arguments, caveat["path"])
    op = caveat["op"]
    if op == "absent":
        return got is _MISSING
    if got is _MISSING:
        return False
    value = caveat["value"]
    if op == "eq":
        return _same(got, value)
    if op == "in":
        return any(_same(got, v) for v in value)
    if op == "prefix":
        return type(got) is str and got.startswith(value)
    if op == "max_len":
        if type(got) is str:
            return len(got.encode("utf-8", "surrogatepass")) <= value
        return type(got) is list and len(got) <= value
    return type(got) is int and value[0] <= got <= value[1]


def refusal(token: Token, request: Request) -> Optional[str]:
    """The first reason the scope or a stateless caveat refuses ``request``, or None."""
    caller = scope_hash(request.session_id)
    if token.scope_kind == "session":
        if not hmac.compare_digest(token.scope_id, caller):
            return "CAP_SCOPE"
    else:
        members = {scope_hash(m) for m in request.coalition} | {caller}
        if token.scope_id not in members:
            return "CAP_SCOPE"
    for caveat in token.caveats:
        kind = caveat["t"]
        if kind == "tools" and request.tool not in caveat["allow"]:
            return "CAP_TOOL"
        if kind == "dest" and request.destination not in caveat["allow"]:
            return "CAP_DESTINATION"
        if kind == "session" and not hmac.compare_digest(caveat["id"], caller):
            return "CAP_SCOPE"
        if kind == "exp" and request.now_ms > caveat["not_after_ms"]:
            return "CAP_EXPIRED"
        if kind == "arg" and not _arg_holds(caveat, request):
            return "CAP_ARGUMENT"
    return None


# --- counters ----------------------------------------------------------------

@dataclass
class _Counter:
    limit: int
    used: int = 0
    reserved: int = 0


@dataclass(frozen=True)
class Reservation:
    reservation_id: int
    tid: str
    holds: tuple  # (tag, amount)


@dataclass
class TokenLedger:
    """Counters and revocations for every ``agw2`` token of one engine process.

    Reserve, then commit or abort, the same shape as the P3 ledger. A
    reservation counts against its limits until it is settled, so two
    in-flight events cannot both take the last use.
    """

    key: Optional[bytes] = None
    counters: dict = field(default_factory=dict)
    revoked: set = field(default_factory=set)
    open: dict = field(default_factory=dict)
    # The most recent MAX_LOG decisions. No arguments and no session ids.
    decision_log: deque = field(default_factory=lambda: deque(maxlen=MAX_LOG))
    _next: int = 0
    _lock: RLock = field(default_factory=RLock)

    def verify(self, text: Any) -> Verified:
        verified = verify(text, key=self.key)
        with self._lock:
            if verified.root_tag in self.revoked or any(tag in self.revoked for tag in verified.tags):
                raise Denied("CAP_REVOKED")
        return verified

    def revoke(self, tag: str) -> None:
        """Kill every token whose chain passes through ``tag`` (a root or caveat tag)."""
        if type(tag) is not str or _HEX64.fullmatch(tag) is None:
            raise Denied("CAP_FORMAT")
        with self._lock:
            if len(self.revoked) >= MAX_REVOKED and tag not in self.revoked:
                raise Denied("CAP_LIMIT")
            self.revoked.add(tag)
            self.decision_log.append({"kind": "CAP_REVOKE", "tag": tag[:16]})

    def reserve(self, text: Any, request: Request) -> Reservation:
        """Admit ``request`` under the token, or raise ``Denied`` with the reason.

        Nothing is consumed on a refusal. On success the stateful caveats
        hold their share until ``commit`` or ``abort``.
        """
        if type(request.charge_qb) is not int or request.charge_qb < 0 or type(request.now_ms) is not int:
            raise Denied("CAP_REQUEST")
        verified = self.verify(text)
        token = verified.token
        reason = refusal(token, request)
        if reason is not None:
            self._log("CAP_DENY", token, request, reason=reason)
            raise Denied(reason)
        needs = []
        for caveat, tag in zip(token.caveats, verified.tags):
            kind = caveat["t"]
            if kind == "calls":
                needs.append((tag, caveat["max"], 1, "CAP_CALLS_EXHAUSTED"))
            elif kind == "once":
                needs.append((tag, 1, 1, "CAP_USED"))
            elif kind == "budget_qb":
                needs.append((tag, caveat["max"], request.charge_qb, "CAP_BUDGET_EXHAUSTED"))
        with self._lock:
            fresh = sum(1 for tag, *_rest in needs if tag not in self.counters)
            if len(self.counters) + fresh > MAX_COUNTERS:
                self._log("CAP_DENY", token, request, reason="CAP_LIMIT")
                raise Denied("CAP_LIMIT")
            for tag, limit, amount, code in needs:
                counter = self.counters.get(tag)
                taken = 0 if counter is None else counter.used + counter.reserved
                if taken + amount > limit:
                    self._log("CAP_DENY", token, request, reason=code)
                    raise Denied(code)
            holds = []
            for tag, limit, amount, _code in needs:
                counter = self.counters.setdefault(tag, _Counter(limit=limit))
                counter.reserved += amount
                holds.append((tag, amount))
            self._next += 1
            reservation = Reservation(self._next, token.tid, tuple(holds))
            self.open[reservation.reservation_id] = reservation
            return reservation

    def _settle(self, reservation: Reservation, spend: bool) -> None:
        with self._lock:
            if self.open.pop(reservation.reservation_id, None) is None:
                raise Denied("CAP_UNKNOWN_RESERVATION")
            for tag, amount in reservation.holds:
                counter = self.counters[tag]
                counter.reserved -= amount
                if spend:
                    counter.used += amount
            self.decision_log.append({"kind": "CAP_COMMIT" if spend else "CAP_ABORT",
                                      "tid": reservation.tid[:16], "counters": len(reservation.holds)})

    def commit(self, reservation: Reservation) -> None:
        self._settle(reservation, True)

    def abort(self, reservation: Reservation) -> None:
        self._settle(reservation, False)

    def used(self, tag: str) -> int:
        with self._lock:
            counter = self.counters.get(tag)
            return 0 if counter is None else counter.used

    def _log(self, kind: str, token: Token, request: Request, **extra) -> None:
        # No arguments and no session id: the tool name and a token id prefix only.
        self.decision_log.append({"kind": kind, "tid": token.tid[:16], "tool": request.tool[:MAX_NAME], **extra})
