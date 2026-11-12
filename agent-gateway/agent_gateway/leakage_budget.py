"""P3: one leakage budget, in quarter bits, for a coalition of sessions.

An external observer of a coalition sees which outbound event leaves, the
bytes that were forwarded, and the slot it was released in. Each event is
charged the length of a prefix code for that triple (continuation, Elias
gamma of the slot gap, member choice, manifest selection, typed fields or a
raw DEFLATE length). The coalition is admitted while committed unapproved
cost plus the new charge is within budget, compared with ``<=``.

Costs are integers in quarter bits (1 bit = 4 qb). There is no floating
point in this module. A coalition lives in one process; several gateway
processes are out of scope. Person-approved events are recorded on a
separate overdraft and are outside the transcript bound.

The transcript bound is checked by bounded enumeration within the E2 bounds.
Nothing outside those bounds is claimed.

``mode="log_only"`` still computes and logs every charge and every would-be
budget hold, and never holds or denies for a budget reason. Other reasons
(size, replay, a busy coalition) are unchanged. ``scope="coalition_sink"``
is a weaker budget: an observer who can split sinks gets one budget each.
The slot clock stays one per coalition either way.
"""
from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass, field
from threading import RLock

from .common import Denied

QB_PER_BIT = 4
MAX_COALITIONS = 1024
MAX_MEMBERS = 64
MAX_PENDING = 1
MAX_EVENT_BYTES = 65_536
MAX_ZDICT = 32_768
MAX_BUDGET_QB = 4 * 4096
MAX_COMMITTED_IDS = 256
MAX_MANIFEST = 256
MAX_ID = 128
MAX_FIELD_CHOICES = 1 << 20
MAX_SCHEMA_FIELDS = 16
MAX_FIELD_DEPTH = 4

# Fixed DEFLATE parameters. Not knobs. Raw DEFLATE drops the zlib header
# and the Adler-32 trailer, which carry no adversary choice.
_DEFLATE = dict(level=9, method=zlib.DEFLATED, wbits=-15, memLevel=9,
                strategy=zlib.Z_DEFAULT_STRATEGY)

ZLIB_RUNTIME_VERSION = getattr(zlib, "ZLIB_RUNTIME_VERSION", "unknown")

# Monkeypatched by the E2 mutants. Production values are the spec's code.
CONTINUATION_QB = 4


def gamma_bits(x: int) -> int:
    """Elias gamma code length for ``x >= 1``: ``2 * floor(log2 x) + 1``."""
    if type(x) is not int or x < 1:
        raise Denied("P3_GAP")
    return 2 * x.bit_length() - 1


def length_header_bits(length: int) -> int:
    """Prefix-free length header ``gamma(L + 1)``. Mutant M2 drops it."""
    if type(length) is not int or length < 0:
        raise Denied("P3_LENGTH")
    return gamma_bits(length + 1)


def qb_choice(n: int) -> int:
    """``ceil(4 * log2 n)`` for ``n >= 1``, exact. ``qb_choice(1) == 0``."""
    if type(n) is not int or not 1 <= n <= MAX_FIELD_CHOICES:
        raise Denied("P3_CHOICES")
    return (n ** 4 - 1).bit_length()


def qb_gamma(x: int) -> int:
    return 4 * gamma_bits(x)


def deflate_len(payload: bytes, zdict: bytes) -> int:
    """Raw DEFLATE length. ``zdict`` must already be fixed for the coalition."""
    if zdict:
        comp = zlib.compressobj(**_DEFLATE, zdict=zdict)
    else:
        comp = zlib.compressobj(**_DEFLATE)
    return len(comp.compress(payload) + comp.flush())


def content_code_bits(compressed_len: int) -> int:
    """``8L + gamma(L + 1)``, the bit length charged for one payload."""
    return 8 * compressed_len + length_header_bits(compressed_len)


def zlib_content_qb(payload: bytes, zdict: bytes) -> int:
    return 4 * content_code_bits(deflate_len(payload, zdict))


LINK_SOURCES = frozenset({
    "root_principal",
    "delegation",
    "spawn",
    "fork_join",
    "internal_bus",
    "scratchpad",
    "provenance",
    "collusion",
    "causality",
    "control_plane",
})


def _member_hash(member: str) -> str:
    return hashlib.sha256(member.encode("utf-8")).hexdigest()


def fold_observable(destination: str, tool: str, payload: bytes) -> bytes:
    """Injective encoding of destination, tool and forwarded bytes.

    Used when no selection manifest covers the pair, so both names are part
    of the content the raw coder charges.
    """
    dest = destination.encode("utf-8")
    name = tool.encode("utf-8")
    return (len(dest).to_bytes(4, "big") + dest
            + len(name).to_bytes(4, "big") + name
            + payload)


def fold_destination(destination: str, payload: bytes) -> bytes:
    """Destination plus bytes that already carry the tool name."""
    dest = destination.encode("utf-8")
    return len(dest).to_bytes(4, "big") + dest + payload


class Hold(Exception):
    """A person must approve this one event. Not a :class:`Denied`.

    Budget holds, an oversized payload and a full replay store use this.
    The detail is for the decision log and the approval finding. It never
    includes the payload.
    """

    def __init__(self, reason: str, **detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = {"reason": reason, **detail}


# --- Typed field coder -------------------------------------------------------

def _reject_bool(value: object, what: str) -> int:
    if type(value) is not int:
        raise Denied(what)
    return value


@dataclass(frozen=True, slots=True)
class Constant:
    """A field the sender cannot vary. Cost 0."""


@dataclass(frozen=True, slots=True)
class Enum:
    """One of ``n`` values, coded as an index ``0 .. n-1``."""

    n: int

    def __post_init__(self) -> None:
        _reject_bool(self.n, "P3_FIELD")
        if not 1 <= self.n <= MAX_FIELD_CHOICES:
            raise Denied("P3_FIELD")


@dataclass(frozen=True, slots=True)
class IntRange:
    """Inclusive integer interval. Cost is ``qb_choice(hi - lo + 1)``."""

    lo: int
    hi: int

    def __post_init__(self) -> None:
        _reject_bool(self.lo, "P3_FIELD")
        _reject_bool(self.hi, "P3_FIELD")
        span = self.hi - self.lo + 1
        if span < 1 or span > MAX_FIELD_CHOICES:
            raise Denied("P3_FIELD")


@dataclass(frozen=True, slots=True)
class Bool:
    """One bit, charged as 4 quarter bits."""


@dataclass(frozen=True, slots=True)
class Optional:
    """Presence bit plus the inner value when present."""

    inner: object

    def __post_init__(self) -> None:
        _check_field(self.inner, 1)


@dataclass(frozen=True, slots=True)
class Bytes:
    """Free bytes, charged with the raw DEFLATE length code."""


@dataclass(frozen=True, slots=True)
class Str:
    """Free text, charged as UTF-8 through the raw DEFLATE length code."""


@dataclass(frozen=True, slots=True)
class List:
    """Length in ``0 .. max_len`` plus each element. Order is the sender's."""

    inner: object
    max_len: int

    def __post_init__(self) -> None:
        _reject_bool(self.max_len, "P3_FIELD")
        if not 0 <= self.max_len <= 32:
            raise Denied("P3_FIELD")
        _check_field(self.inner, 1)


_FIELD_TYPES = (Constant, Enum, IntRange, Bool, Optional, Bytes, Str, List)


def _check_field(ft: object, depth: int) -> None:
    if depth > MAX_FIELD_DEPTH or type(ft) not in _FIELD_TYPES:
        raise Denied("P3_FIELD")
    if type(ft) is Optional:
        _check_field(ft.inner, depth + 1)
    elif type(ft) is List:
        _check_field(ft.inner, depth + 1)


def field_cost(ft: object, value: object, zdict: bytes) -> int | None:
    """Quarter bits for one value, or None when the value is not in the type.

    ``None`` means this event is not covered by the typed coder.
    """
    if type(ft) is Constant:
        return 0
    if type(ft) is Enum:
        if type(value) is not int or not 0 <= value < ft.n:
            return None
        return qb_choice(ft.n)
    if type(ft) is IntRange:
        if type(value) is not int or not ft.lo <= value <= ft.hi:
            return None
        return qb_choice(ft.hi - ft.lo + 1)
    if type(ft) is Bool:
        if type(value) is not bool:
            return None
        return 4
    if type(ft) is Optional:
        if value is None:
            return 4
        inner = field_cost(ft.inner, value, zdict)
        if inner is None:
            return None
        return 4 + inner
    if type(ft) is Str:
        if type(value) is not str:
            return None
        return zlib_content_qb(value.encode("utf-8"), zdict)
    if type(ft) is Bytes:
        if type(value) is not bytes:
            return None
        return zlib_content_qb(value, zdict)
    if type(ft) is List:
        if type(value) not in (list, tuple) or len(value) > ft.max_len:
            return None
        total = qb_choice(ft.max_len + 1)
        for item in value:
            part = field_cost(ft.inner, item, zdict)
            if part is None:
                return None
            total += part
        return total
    return None


def typed_cost(schema: FieldSchema, arguments: dict, zdict: bytes) -> int | None:
    """Cost of ``arguments`` under ``schema``, or None if a field is uncovered."""
    if type(arguments) is not dict:
        return None
    known = []
    total = 0
    for name, ft in schema.fields:
        known.append(name)
        present = name in arguments
        if not present:
            if type(ft) is Optional:
                total += 4
                continue
            if type(ft) is Constant:
                continue
            return None
        part = field_cost(ft, arguments[name], zdict)
        if part is None:
            return None
        total += part
    for key in arguments:
        if key not in known:
            return None
    return total


@dataclass(frozen=True, slots=True)
class FieldSchema:
    """Typed coder input for one tool, fields in canonical key order."""

    tool: str
    fields: tuple

    def __post_init__(self) -> None:
        if type(self.tool) is not str or not 1 <= len(self.tool) <= MAX_ID:
            raise Denied("P3_SCHEMA")
        fields = self.fields
        if type(fields) is not tuple or not 1 <= len(fields) <= MAX_SCHEMA_FIELDS:
            raise Denied("P3_SCHEMA")
        names = []
        for item in fields:
            if type(item) is not tuple or len(item) != 2:
                raise Denied("P3_SCHEMA")
            name, ft = item
            if type(name) is not str or not 1 <= len(name) <= MAX_ID:
                raise Denied("P3_SCHEMA")
            _check_field(ft, 0)
            names.append(name)
        if len(set(names)) != len(names):
            raise Denied("P3_SCHEMA")


@dataclass(frozen=True, slots=True)
class SelectionManifest:
    """Eligible ``(destination, tool)`` pairs. Selection cost is ``qb_choice(T)``."""

    eligible: tuple

    def __post_init__(self) -> None:
        rows = self.eligible
        if type(rows) is not tuple or not 1 <= len(rows) <= MAX_MANIFEST:
            raise Denied("P3_MANIFEST")
        seen = []
        for row in rows:
            if type(row) is not tuple or len(row) != 2:
                raise Denied("P3_MANIFEST")
            dest, tool = row
            if type(dest) is not str or type(tool) is not str:
                raise Denied("P3_MANIFEST")
            if not len(dest) <= MAX_ID or not 1 <= len(tool) <= MAX_ID:
                raise Denied("P3_MANIFEST")
            seen.append((dest, tool))
        if len(set(seen)) != len(seen):
            raise Denied("P3_MANIFEST")


def _default_links() -> frozenset:
    return LINK_SOURCES


@dataclass(frozen=True, slots=True)
class P3Config:
    """Control-plane attachment. Defaults are the 12 Nov decisions."""

    budget_qb: int = 128
    slot_ms: int = 1000
    epoch_ms: int = 0
    scope: str = "coalition"
    charge_member_choice: bool = True
    max_event_bytes: int = MAX_EVENT_BYTES
    link_sources: frozenset = field(default_factory=_default_links)
    zlib_version_pin: str | None = None
    mode: str = "enforce"

    def __post_init__(self) -> None:
        _reject_bool(self.budget_qb, "P3_CONFIG")
        _reject_bool(self.slot_ms, "P3_CONFIG")
        _reject_bool(self.epoch_ms, "P3_CONFIG")
        _reject_bool(self.max_event_bytes, "P3_CONFIG")
        if not 0 <= self.budget_qb <= MAX_BUDGET_QB:
            raise Denied("P3_CONFIG")
        if not 1 <= self.slot_ms <= 86_400_000:
            raise Denied("P3_CONFIG")
        if not 0 <= self.epoch_ms <= 2 ** 62:
            raise Denied("P3_CONFIG")
        if self.scope not in ("coalition", "coalition_sink"):
            raise Denied("P3_CONFIG")
        if self.mode not in ("enforce", "log_only"):
            raise Denied("P3_CONFIG")
        if not 1 <= self.max_event_bytes <= MAX_EVENT_BYTES:
            raise Denied("P3_CONFIG")
        if type(self.charge_member_choice) is not bool:
            raise Denied("P3_CONFIG")
        if type(self.link_sources) is not frozenset or not set(self.link_sources) <= set(LINK_SOURCES):
            raise Denied("P3_CONFIG")
        if self.zlib_version_pin is not None and type(self.zlib_version_pin) is not str:
            raise Denied("P3_CONFIG")


@dataclass(slots=True)
class Pending:
    event_id: str
    member: str
    charge_qb: int
    gap_qb: int
    gap: int
    member_qb: int
    selection_qb: int
    content_qb: int
    release_slot: int | None
    approved: bool
    destination: str
    sink_key: str


@dataclass(slots=True)
class _Bucket:
    budget_qb: int
    spent_qb: int = 0
    overdraft_qb: int = 0


@dataclass(slots=True)
class Coalition:
    cid: str
    members: set
    budget_qb: int
    spent_qb: int = 0
    overdraft_qb: int = 0
    charging: bool = False
    charge_start_slot: int | None = None
    last_slot: int | None = None
    pending: Pending | None = None
    zdict: bytes = b""
    manifest: SelectionManifest | None = None
    schemas: dict = field(default_factory=dict)
    committed_ids: dict = field(default_factory=dict)
    scope: str = "coalition"
    mode: str = "enforce"
    slot_ms: int = 1000
    epoch_ms: int = 0
    charge_member_choice: bool = True
    max_event_bytes: int = MAX_EVENT_BYTES
    link_sources: frozenset = field(default_factory=_default_links)
    sinks: dict = field(default_factory=dict)
    # Anchor used only by mutant M7. Production gap math ignores it.
    shadow_slot: int | None = None
    lock: RLock = field(default_factory=RLock)


def _schemas_equal(a: dict, b: dict) -> bool:
    if a.keys() != b.keys():
        return False
    return all(a[k] == b[k] for k in a)


class LeakageLedger:
    """All coalitions of one PolicyEngine. Union-find on session ids.

    Coalitions only merge. A session that is not attached and then links to
    one that is joins that coalition with no prior spend.
    """

    # Overridden by E2 mutants inside the test module.
    merge_blocks_on_pending = True
    link_merges = True
    recompute_on_commit = True
    commit_adds = True
    clear_charging_on_commit = False
    same_slot_ok = False

    def __init__(self) -> None:
        self._lock = RLock()
        self.parent: dict[str, str] = {}
        self.coalitions: dict[str, Coalition] = {}
        self.decision_log: list[dict] = []
        self._header_written = False

    # --- log -----------------------------------------------------------------

    def _record(self, kind: str, **fields) -> dict:
        rec = {"kind": kind, "zlib_runtime_version": ZLIB_RUNTIME_VERSION, **fields}
        self.decision_log.append(rec)
        return rec

    def log_header(self) -> None:
        if self._header_written:
            return
        self._header_written = True
        self._record("P3_HEADER", zlib_runtime_version=ZLIB_RUNTIME_VERSION)

    # --- union-find ----------------------------------------------------------

    def _find(self, session_id: str) -> str | None:
        parent = self.parent.get(session_id)
        if parent is None:
            return None
        while self.parent[parent] != parent:
            self.parent[parent] = self.parent[self.parent[parent]]
            parent = self.parent[parent]
        self.parent[session_id] = parent
        return parent

    def contains(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self.parent

    def coalition(self, session_id: str) -> Coalition:
        with self._lock:
            root = self._find(session_id)
            if root is None:
                raise Denied("P3_UNKNOWN_SESSION")
            return self.coalitions[root]

    def _cid_of(self, session_id: str) -> str:
        root = self._find(session_id)
        if root is None:
            raise Denied("P3_UNKNOWN_SESSION")
        return root

    # --- attach / link / grant ----------------------------------------------

    def attach(self, session_id: str, cfg: P3Config, *, zdict: bytes = b"",
               manifest: SelectionManifest | None = None, schemas: dict | None = None) -> Coalition:
        """Create a singleton coalition, or refuse if ``session_id`` is already in one."""
        if type(session_id) is not str or not 1 <= len(session_id) <= MAX_ID:
            raise Denied("P3_ID")
        if type(cfg) is not P3Config:
            raise Denied("P3_CONFIG")
        if type(zdict) is not bytes or len(zdict) > MAX_ZDICT:
            raise Denied("P3_ZDICT")
        if manifest is not None and type(manifest) is not SelectionManifest:
            raise Denied("P3_MANIFEST")
        schemas = dict(schemas or {})
        for tool, schema in schemas.items():
            if type(schema) is not FieldSchema or schema.tool != tool:
                raise Denied("P3_SCHEMA")
        if cfg.zlib_version_pin is not None and cfg.zlib_version_pin != ZLIB_RUNTIME_VERSION:
            raise Denied("P3_ZLIB_VERSION")
        with self._lock:
            self.log_header()
            if session_id in self.parent:
                raise Denied("P3_ATTACHED")
            if len(self.coalitions) >= MAX_COALITIONS:
                raise Denied("P3_LIMIT")
            coalition = Coalition(
                cid=session_id,
                members={session_id},
                budget_qb=cfg.budget_qb,
                spent_qb=0,
                overdraft_qb=0,
                zdict=zdict,
                manifest=manifest,
                schemas=schemas,
                scope=cfg.scope,
                mode=cfg.mode,
                slot_ms=cfg.slot_ms,
                epoch_ms=cfg.epoch_ms,
                charge_member_choice=cfg.charge_member_choice,
                max_event_bytes=cfg.max_event_bytes,
                link_sources=cfg.link_sources,
            )
            self.parent[session_id] = session_id
            self.coalitions[session_id] = coalition
            self._record(
                "P3_ATTACH", cid=session_id, budget_qb=cfg.budget_qb, mode=cfg.mode,
                scope=cfg.scope, zlib_runtime_version=ZLIB_RUNTIME_VERSION,
                slot_ms=cfg.slot_ms, epoch_ms=cfg.epoch_ms,
            )
            return coalition

    def _sources_allow(self, coalition: Coalition, source: str) -> bool:
        return source in coalition.link_sources

    def link(self, a: str, b: str, source: str) -> str | None:
        """Merge ``a`` and ``b`` when ``source`` is enabled. Returns the cid.

        A missing side is pulled into the attached coalition with zero spend.
        Returns None when neither side is attached or the source is off.
        Raises ``P3_BUSY`` when a reservation is in progress, unless mutant
        M11 has turned that guard off.
        """
        if type(source) is not str or source not in LINK_SOURCES:
            raise Denied("P3_SOURCE")
        for sid in (a, b):
            if type(sid) is not str or not 1 <= len(sid) <= MAX_ID:
                raise Denied("P3_ID")
        with self._lock:
            self.log_header()
            ra, rb = self._find(a), self._find(b)
            if ra is None and rb is None:
                return None
            if ra is not None and not self._sources_allow(self.coalitions[ra], source):
                return ra if rb is None or ra == rb else self._cid_of(a)
            if rb is not None and not self._sources_allow(self.coalitions[rb], source):
                return self._cid_of(b) if ra is None else self._cid_of(a)
            if ra is None:
                cid = self._adopt(a, rb)
                self._record("P3_MERGE", cid=cid, other=a, source=source, adopted=True)
                return cid
            if rb is None:
                cid = self._adopt(b, ra)
                self._record("P3_MERGE", cid=cid, other=b, source=source, adopted=True)
                return cid
            if ra == rb:
                return ra
            if not self.link_merges:
                # Mutant M5: sessions keep separate budgets.
                self._record("P3_MERGE", cid=ra, other=rb, source=source, merged=False)
                return ra
            ca, cb = self.coalitions[ra], self.coalitions[rb]
            if self.merge_blocks_on_pending and (ca.pending is not None or cb.pending is not None):
                raise Denied("P3_BUSY")
            cid = self._merge(ca, cb, source)
            return cid

    def _adopt(self, session_id: str, root: str) -> str:
        coalition = self.coalitions[root]
        if len(coalition.members) >= MAX_MEMBERS:
            raise Denied("P3_LIMIT")
        self.parent[session_id] = root
        coalition.members.add(session_id)
        # cid stays the smallest member id.
        if session_id < coalition.cid:
            self._reseat(coalition, session_id)
        return coalition.cid

    def _reseat(self, coalition: Coalition, new_cid: str) -> None:
        old = coalition.cid
        coalition.cid = new_cid
        if old != new_cid:
            self.coalitions.pop(old, None)
        self.coalitions[new_cid] = coalition
        for member in coalition.members:
            self.parent[member] = new_cid
        self.parent[new_cid] = new_cid

    def _merge(self, a: Coalition, b: Coalition, source: str) -> str:
        if len(a.members | b.members) > MAX_MEMBERS:
            raise Denied("P3_LIMIT")
        downgrade = False
        if a.zdict != b.zdict:
            a.zdict = b""
            downgrade = True
        if a.manifest != b.manifest:
            a.manifest = None
            downgrade = True
        if not _schemas_equal(a.schemas, b.schemas):
            a.schemas = {}
            downgrade = True
        if a.scope != b.scope or a.mode != b.mode or a.slot_ms != b.slot_ms or a.epoch_ms != b.epoch_ms:
            downgrade = True
        # Stricter clock: keep the already-attached side's slot grid if they differ.
        if a.slot_ms != b.slot_ms or a.epoch_ms != b.epoch_ms:
            pass
        if a.mode != b.mode:
            a.mode = "enforce" if "enforce" in (a.mode, b.mode) else "log_only"
        if a.scope != b.scope:
            # One shared budget is the stricter scope.
            self._flatten_to_coalition(a)
            self._flatten_to_coalition(b)
            a.scope = "coalition"
        a.charge_member_choice = a.charge_member_choice or b.charge_member_choice
        a.max_event_bytes = min(a.max_event_bytes, b.max_event_bytes)
        a.link_sources = a.link_sources & b.link_sources
        start = _earliest(
            a.charge_start_slot if a.charging else None,
            b.charge_start_slot if b.charging else None,
        )
        if a.scope == "coalition_sink":
            self._merge_sinks(a, b)
            a.spent_qb = self._combine_spent(a.spent_qb, b.spent_qb)
            a.overdraft_qb = a.overdraft_qb + b.overdraft_qb
        else:
            a.spent_qb = self._combine_spent(a.spent_qb, b.spent_qb)
            a.overdraft_qb = a.overdraft_qb + b.overdraft_qb
            a.budget_qb = min(a.budget_qb, b.budget_qb)
        a.charging = a.charging or b.charging
        a.charge_start_slot = start
        a.last_slot = _later(a.last_slot, b.last_slot)
        a.shadow_slot = _later(a.shadow_slot, b.shadow_slot)
        if len(a.committed_ids) + len(b.committed_ids) <= MAX_COMMITTED_IDS * 2:
            a.committed_ids.update(b.committed_ids)
        else:
            a.committed_ids.update(b.committed_ids)
        # Pending is refused above when the guard is on. M11 can arrive here
        # with one pending; keep a single pending if only one side has one.
        if a.pending is None:
            a.pending = b.pending
        elif b.pending is not None and a.pending is not None:
            # Two pendings cannot both survive MAX_PENDING. Drop neither
            # silently: record the downgrade and keep the lexicographic id
            # so the result is deterministic. The E2 race check expects the
            # guard to have refused this path.
            keep = a.pending if a.pending.event_id <= b.pending.event_id else b.pending
            a.pending = keep
            downgrade = True
        for member in b.members:
            a.members.add(member)
        new_cid = min(a.members)
        old_b = b.cid
        self.coalitions.pop(old_b, None)
        self._reseat(a, new_cid)
        if downgrade:
            self._record("P3_CONFIG_DOWNGRADE", cid=a.cid, other=old_b, source=source)
        self._record(
            "P3_MERGE", cid=a.cid, other=old_b, source=source, merged=True,
            spent_qb=a.spent_qb, budget_qb=a.budget_qb, members=len(a.members),
        )
        return a.cid

    def _combine_spent(self, left: int, right: int) -> int:
        """Sum, unless mutant M6 keeps only the larger spend."""
        return left + right

    def _flatten_to_coalition(self, c: Coalition) -> None:
        if c.scope != "coalition_sink":
            return
        spent = over = 0
        budgets = [c.budget_qb]
        for bucket in c.sinks.values():
            spent += bucket.spent_qb
            over += bucket.overdraft_qb
            budgets.append(bucket.budget_qb)
        c.spent_qb = spent
        c.overdraft_qb = over
        c.budget_qb = min(budgets)
        c.sinks = {}
        c.scope = "coalition"

    def _merge_sinks(self, a: Coalition, b: Coalition) -> None:
        keys = set(a.sinks) | set(b.sinks)
        for key in keys:
            left = a.sinks.get(key)
            right = b.sinks.get(key)
            if left is None:
                a.sinks[key] = right
                continue
            if right is None:
                continue
            left.spent_qb = self._combine_spent(left.spent_qb, right.spent_qb)
            left.overdraft_qb += right.overdraft_qb
            left.budget_qb = min(left.budget_qb, right.budget_qb)
        a.budget_qb = min(a.budget_qb, b.budget_qb)

    def mark_charging(self, session_id: str, slot: int) -> None:
        """Charging is sticky. Unknown sessions are ignored."""
        if type(slot) is not int:
            raise Denied("P3_CLOCK")
        with self._lock:
            root = self._find(session_id)
            if root is None:
                return
            coalition = self.coalitions[root]
            if not coalition.charging:
                coalition.charging = True
                coalition.charge_start_slot = slot
                self._record("P3_CHARGING", cid=coalition.cid, charge_start_slot=slot)

    def grant(self, cid: str, add_qb: int, approver_id: str) -> int:
        """Control plane only. Raises the budget. Never called automatically."""
        _reject_bool(add_qb, "P3_GRANT")
        if type(approver_id) is not str or not 1 <= len(approver_id) <= MAX_ID:
            raise Denied("P3_GRANT")
        if add_qb < 1:
            raise Denied("P3_GRANT")
        with self._lock:
            coalition = self.coalitions.get(cid)
            if coalition is None:
                root = self._find(cid)
                coalition = self.coalitions.get(root) if root else None
            if coalition is None:
                raise Denied("P3_UNKNOWN_SESSION")
            if coalition.budget_qb + add_qb > MAX_BUDGET_QB:
                raise Denied("P3_GRANT")
            coalition.budget_qb += add_qb
            for bucket in coalition.sinks.values():
                if bucket.budget_qb + add_qb <= MAX_BUDGET_QB:
                    bucket.budget_qb += add_qb
            self._record("P3_GRANT", cid=coalition.cid, add_qb=add_qb, approver_id=approver_id,
                         budget_qb=coalition.budget_qb)
            return coalition.budget_qb

    # --- reserve / commit / abort --------------------------------------------

    def _bucket(self, coalition: Coalition, destination: str) -> tuple[str, _Bucket | None]:
        """Return the spend bucket. None means the coalition-level counters."""
        if coalition.scope != "coalition_sink":
            return "", None
        bucket = coalition.sinks.get(destination)
        if bucket is None:
            bucket = _Bucket(budget_qb=coalition.budget_qb)
            coalition.sinks[destination] = bucket
        return destination, bucket

    def _spent_of(self, coalition: Coalition, bucket: _Bucket | None) -> tuple[int, int]:
        if bucket is None:
            return coalition.spent_qb, coalition.budget_qb
        return bucket.spent_qb, bucket.budget_qb

    def _gap_base(self, coalition: Coalition) -> int:
        """Slot the next gap is measured from. Production uses committed state.

        Mutant M7 points this at the last reserved slot, including one that
        was aborted.
        """
        if coalition.shadow_slot is not None and not self.recompute_on_commit:
            return coalition.shadow_slot
        if coalition.last_slot is not None:
            return coalition.last_slot
        return coalition.charge_start_slot - 1

    def reserve(self, session_id: str, event_id: str, destination: str, tool: str,
                payload: bytes, now_ms: int, approved: bool, *,
                arguments: dict | None = None, schema: FieldSchema | None = None,
                fold_names: bool = True) -> Pending:
        """Hold this event's charge. ``Hold`` leaves no pending reservation.

        In ``log_only``, a charge that would exceed the budget is logged and
        the event is still reserved. It is not held and it is not denied.
        """
        if type(event_id) is not str or not 1 <= len(event_id) <= MAX_ID:
            raise Denied("P3_ID")
        if type(destination) is not str or len(destination) > MAX_ID:
            raise Denied("P3_ID")
        if type(tool) is not str or not 1 <= len(tool) <= MAX_ID:
            raise Denied("P3_ID")
        if type(payload) is not bytes:
            raise Denied("P3_PAYLOAD")
        if type(now_ms) is not int or type(approved) is not bool:
            raise Denied("P3_CLOCK")
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                return self._reserve_locked(
                    coalition, session_id, event_id, destination, tool, payload,
                    now_ms, approved, arguments, schema, fold_names,
                )

    def _reserve_locked(self, coalition, session_id, event_id, destination, tool,
                        payload, now_ms, approved, arguments, schema, fold_names) -> Pending:
        if event_id in coalition.committed_ids or (
                coalition.pending is not None and coalition.pending.event_id == event_id):
            raise Denied("P3_REPLAY")
        if coalition.pending is not None:
            raise Denied("P3_BUSY")
        if len(coalition.committed_ids) >= MAX_COMMITTED_IDS:
            self._hold(coalition, "P3_REPLAY_CAPACITY", session_id, event_id,
                       charge_qb=0, spent_qb=coalition.spent_qb, budget_qb=coalition.budget_qb)
        if len(payload) > coalition.max_event_bytes:
            self._hold(coalition, "P3_EVENT_TOO_LARGE", session_id, event_id,
                       charge_qb=0, spent_qb=coalition.spent_qb, budget_qb=coalition.budget_qb,
                       payload_len=len(payload))
        if now_ms < coalition.epoch_ms:
            raise Denied("P3_CLOCK")
        cur = (now_ms - coalition.epoch_ms) // coalition.slot_ms
        sink_key, bucket = self._bucket(coalition, destination)
        if not coalition.charging:
            pending = Pending(
                event_id=event_id, member=session_id, charge_qb=0, gap_qb=0, gap=0,
                member_qb=0, selection_qb=0, content_qb=0, release_slot=None,
                approved=approved, destination=destination, sink_key=sink_key,
            )
            coalition.pending = pending
            self._record("P3_CHARGE", cid=coalition.cid, event_id=event_id, charge_qb=0,
                         charging=False, approved=approved, mode=coalition.mode)
            return pending
        base = self._gap_base(coalition)
        release = cur if self.same_slot_ok else max(cur, base + 1)
        if not self.same_slot_ok and release < base + 1:
            release = base + 1
        gap = release - base
        if gap < 1:
            # Same-slot mutant. Keep the integer positive so gamma is defined;
            # the slot-order check is what E2-L I4 observes at commit.
            gap = 1 if release > base else 0
        if gap < 1:
            gap_qb = 0
        else:
            gap_qb = qb_gamma(gap)
        member_qb = 0
        k = len(coalition.members)
        if coalition.charge_member_choice and k > 1:
            member_qb = qb_choice(k)
        manifest_hit = False
        selection_qb = 0
        if coalition.manifest is not None and (destination, tool) in coalition.manifest.eligible:
            manifest_hit = True
            selection_qb = qb_choice(len(coalition.manifest.eligible))
        chosen = schema if schema is not None else coalition.schemas.get(tool)
        content_qb = None
        if manifest_hit and chosen is not None and arguments is not None:
            content_qb = typed_cost(chosen, arguments, coalition.zdict)
        if content_qb is None:
            if manifest_hit:
                raw = payload
            elif fold_names:
                raw = fold_observable(destination, tool, payload)
            else:
                # Payload already carries the tool name (re-serialised params).
                raw = fold_destination(destination, payload)
            content_qb = zlib_content_qb(raw, coalition.zdict)
            if not manifest_hit:
                selection_qb = 0
        charge = CONTINUATION_QB + gap_qb + member_qb + selection_qb + content_qb
        spent, budget = self._spent_of(coalition, bucket)
        components = dict(
            cid=coalition.cid, event_id=event_id, charge_qb=charge, continuation_qb=CONTINUATION_QB,
            gap_qb=gap_qb, gap=gap, member_qb=member_qb, selection_qb=selection_qb,
            content_qb=content_qb, spent_qb=spent, budget_qb=budget, approved=approved,
            release_slot=release, mode=coalition.mode,
        )
        would_hold = (not approved) and spent + charge > budget
        self._record("P3_CHARGE", **components, would_hold=would_hold)
        if would_hold and coalition.mode == "enforce":
            self._hold(coalition, "P3_BUDGET_EXHAUSTED", session_id, event_id, **{
                "charge_qb": charge, "spent_qb": spent, "budget_qb": budget,
                "continuation_qb": CONTINUATION_QB, "gap_qb": gap_qb,
                "member_qb": member_qb, "selection_qb": selection_qb, "content_qb": content_qb,
            })
        if would_hold and coalition.mode == "log_only":
            self._record("P3_BUDGET_EXHAUSTED", would_hold=True, held=False, **{
                k_: components[k_] for k_ in (
                    "cid", "event_id", "charge_qb", "spent_qb", "budget_qb",
                    "continuation_qb", "gap_qb", "member_qb", "selection_qb", "content_qb",
                )
            })
        pending = Pending(
            event_id=event_id, member=session_id, charge_qb=charge, gap_qb=gap_qb, gap=gap,
            member_qb=member_qb, selection_qb=selection_qb, content_qb=content_qb,
            release_slot=release, approved=approved, destination=destination, sink_key=sink_key,
        )
        coalition.pending = pending
        coalition.shadow_slot = release
        return pending

    def _hold(self, coalition: Coalition, reason: str, session_id: str, event_id: str, **detail) -> None:
        self._record(reason, cid=coalition.cid, event_id=event_id, member_hash=_member_hash(session_id),
                     held=True, **detail)
        raise Hold(reason, cid=coalition.cid, **detail)

    def commit(self, session_id: str, event_id: str) -> dict:
        """Spend a held charge. Returns the audit record. Never includes the payload."""
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                pending = coalition.pending
                if pending is None or pending.event_id != event_id:
                    raise Denied("P3_UNKNOWN_EVENT")
                release = pending.release_slot
                charge = pending.charge_qb
                gap = pending.gap
                gap_qb = pending.gap_qb
                if release is not None and coalition.charging:
                    base = coalition.last_slot if coalition.last_slot is not None else (
                        coalition.charge_start_slot - 1)
                    if self.recompute_on_commit:
                        if release <= base and not self.same_slot_ok:
                            coalition.pending = None
                            raise Denied("P3_SLOT_ORDER")
                        if self.same_slot_ok and release < base:
                            coalition.pending = None
                            raise Denied("P3_SLOT_ORDER")
                        new_gap = release - base
                        if new_gap < 1:
                            new_gap = 0 if self.same_slot_ok else 1
                        new_gap_qb = 0 if new_gap < 1 else qb_gamma(new_gap)
                        charge = pending.charge_qb - pending.gap_qb + new_gap_qb
                        gap = new_gap
                        gap_qb = new_gap_qb
                    bucket = coalition.sinks.get(pending.sink_key) if coalition.scope == "coalition_sink" else None
                    spent, budget = self._spent_of(coalition, bucket)
                    if (not pending.approved) and spent + charge > budget and coalition.mode == "enforce":
                        coalition.pending = None
                        raise Denied("P3_COMMIT_EXHAUSTED")
                    if (not pending.approved) and spent + charge > budget and coalition.mode == "log_only":
                        self._record(
                            "P3_COMMIT_EXHAUSTED", would_hold=True, held=False, cid=coalition.cid,
                            event_id=event_id, charge_qb=charge, spent_qb=spent, budget_qb=budget,
                        )
                    if self.commit_adds:
                        self._add_spend(coalition, bucket, charge, pending.approved)
                    if self.clear_charging_on_commit:
                        coalition.charging = False
                    coalition.last_slot = release
                    coalition.shadow_slot = None
                if len(coalition.committed_ids) >= MAX_COMMITTED_IDS:
                    coalition.pending = None
                    self._hold(coalition, "P3_REPLAY_CAPACITY", session_id, event_id,
                               charge_qb=charge, spent_qb=coalition.spent_qb, budget_qb=coalition.budget_qb)
                coalition.committed_ids[event_id] = None
                coalition.pending = None
                release_at = None
                if release is not None:
                    release_at = coalition.epoch_ms + release * coalition.slot_ms
                record = self._record(
                    "P3_COMMIT", cid=coalition.cid, event_id=event_id,
                    member_hash=_member_hash(pending.member), release_slot=release, gap=gap,
                    continuation_qb=CONTINUATION_QB if coalition.charging or charge else 0,
                    gap_qb=gap_qb, member_qb=pending.member_qb, selection_qb=pending.selection_qb,
                    content_qb=pending.content_qb, charge_qb=charge,
                    spent_qb=coalition.spent_qb, overdraft_qb=coalition.overdraft_qb,
                    approved=pending.approved, release_at_ms=release_at,
                )
                return record

    def _add_spend(self, coalition: Coalition, bucket: _Bucket | None, charge: int, approved: bool) -> None:
        if approved:
            self._approval_effect(coalition, bucket, charge)
            return
        if bucket is None:
            coalition.spent_qb += charge
        else:
            bucket.spent_qb += charge
            coalition.spent_qb += charge

    def _approval_effect(self, coalition: Coalition, bucket: _Bucket | None, charge: int) -> None:
        """Approved cost goes to the overdraft. It does not change spent or budget.

        Mutant M9 replaces this with a reset of spent or a budget increase.
        """
        coalition.overdraft_qb += charge
        if bucket is not None:
            bucket.overdraft_qb += charge

    def abort(self, session_id: str, event_id: str) -> None:
        """Drop a reservation. No spend, no slot, no committed id.

        Mutant M4 refunds into spent from here. Mutant M7 keeps the reserved
        slot as the next gap anchor (see ``shadow_slot``).
        """
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                pending = coalition.pending
                if pending is None or pending.event_id != event_id:
                    raise Denied("P3_UNKNOWN_EVENT")
                self._abort_effect(coalition, pending)
                if not self.recompute_on_commit:
                    coalition.shadow_slot = pending.release_slot
                else:
                    coalition.shadow_slot = None
                coalition.pending = None
                self._record("P3_ABORT", cid=coalition.cid, event_id=event_id, spent_qb=coalition.spent_qb)

    def _abort_effect(self, coalition: Coalition, pending: Pending) -> None:
        """Production abort changes nothing but the pending slot."""

    def state(self, session_id: str) -> dict:
        """spent, overdraft, budget, members, last_slot. No payload."""
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                return {
                    "cid": coalition.cid,
                    "spent_qb": coalition.spent_qb,
                    "overdraft_qb": coalition.overdraft_qb,
                    "budget_qb": coalition.budget_qb,
                    "members": tuple(sorted(coalition.members)),
                    "last_slot": coalition.last_slot,
                    "charging": coalition.charging,
                    "charge_start_slot": coalition.charge_start_slot,
                    "pending": None if coalition.pending is None else coalition.pending.event_id,
                    "mode": coalition.mode,
                    "scope": coalition.scope,
                    "committed": len(coalition.committed_ids),
                    "zlib_runtime_version": ZLIB_RUNTIME_VERSION,
                }

    def snapshot(self, session_id: str) -> dict:
        """Integer checkpoint for a search that backtracks. Test support."""
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                return {
                    "spent_qb": coalition.spent_qb,
                    "overdraft_qb": coalition.overdraft_qb,
                    "budget_qb": coalition.budget_qb,
                    "last_slot": coalition.last_slot,
                    "charging": coalition.charging,
                    "charge_start_slot": coalition.charge_start_slot,
                    "committed": tuple(coalition.committed_ids),
                    "pending": None if coalition.pending is None else coalition.pending.event_id,
                    "shadow_slot": coalition.shadow_slot,
                    "sinks": tuple(
                        (key, b.spent_qb, b.overdraft_qb, b.budget_qb)
                        for key, b in sorted(coalition.sinks.items())
                    ),
                }

    def restore(self, session_id: str, shot: dict) -> None:
        with self._lock:
            coalition = self.coalition(session_id)
            with coalition.lock:
                coalition.spent_qb = shot["spent_qb"]
                coalition.overdraft_qb = shot["overdraft_qb"]
                coalition.budget_qb = shot["budget_qb"]
                coalition.last_slot = shot["last_slot"]
                coalition.charging = shot["charging"]
                coalition.charge_start_slot = shot["charge_start_slot"]
                coalition.committed_ids = {eid: None for eid in shot["committed"]}
                coalition.pending = None
                coalition.shadow_slot = shot["shadow_slot"]
                coalition.sinks = {
                    key: _Bucket(budget_qb=budget, spent_qb=spent, overdraft_qb=over)
                    for key, spent, over, budget in shot["sinks"]
                }


def _later(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


def _earliest(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a <= b else b
