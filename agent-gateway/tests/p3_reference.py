"""Reference ledger: plain dicts and ints, no locks.

Costs come from ``p3_oracle``. State transitions follow the P3 spec. The
real ``LeakageLedger`` is compared with this after every enumerated action.
"""
from __future__ import annotations

from agent_gateway.leakage_budget import (
    LINK_SOURCES, MAX_BUDGET_QB, MAX_COMMITTED_IDS, MAX_EVENT_BYTES, Denied, Hold,
)
from tests.p3_oracle import content_qb, event_qb, fold_destination, fold_observable


class Model:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.co: dict[str, dict] = {}

    def _root(self, sid: str) -> str | None:
        seen = sid
        if sid not in self.parent:
            return None
        while self.parent[seen] != seen:
            seen = self.parent[seen]
        return seen

    def _c(self, sid: str) -> dict:
        root = self._root(sid)
        if root is None:
            raise Denied("P3_UNKNOWN_SESSION")
        return self.co[root]

    def attach(self, sid: str, budget: int, *, slot_ms: int = 1000, epoch: int = 0,
               manifest: tuple | None = None, schema: object | None = None,
               mode: str = "enforce", links: frozenset | None = None,
               member_choice: bool = True, max_bytes: int = MAX_EVENT_BYTES,
               zdict: bytes = b"") -> None:
        if sid in self.parent:
            raise Denied("P3_ATTACHED")
        self.parent[sid] = sid
        self.co[sid] = {
            "cid": sid, "members": {sid}, "budget": budget, "spent": 0, "over": 0,
            "charging": False, "start": None, "last": None, "pending": None,
            "committed": set(), "manifest": manifest, "schema": schema,
            "mode": mode, "links": links, "member_choice": member_choice,
            "max_bytes": max_bytes, "slot_ms": slot_ms, "epoch": epoch,
            "zdict": zdict, "shadow": None,
        }
        if self.co[sid]["links"] is None:
            self.co[sid]["links"] = LINK_SOURCES

    def mark(self, sid: str, slot: int) -> None:
        if self._root(sid) is None:
            return
        c = self._c(sid)
        if not c["charging"]:
            c["charging"] = True
            c["start"] = slot

    def link(self, a: str, b: str, source: str) -> str | None:
        ra, rb = self._root(a), self._root(b)
        if ra is None and rb is None:
            return None
        if ra is not None and source not in (self.co[ra]["links"] or set()):
            return ra
        if rb is not None and source not in (self.co[rb]["links"] or set()):
            return rb
        if ra is None:
            return self._adopt(a, rb)
        if rb is None:
            return self._adopt(b, ra)
        if ra == rb:
            return ra
        ca, cb = self.co[ra], self.co[rb]
        if ca["pending"] or cb["pending"]:
            raise Denied("P3_BUSY")
        return self._merge(ca, cb)

    def _adopt(self, sid: str, root: str) -> str:
        c = self.co[root]
        self.parent[sid] = root
        c["members"].add(sid)
        if sid < c["cid"]:
            self._reseat(c, sid)
        return c["cid"]

    def _reseat(self, c: dict, new: str) -> None:
        old = c["cid"]
        c["cid"] = new
        if old != new:
            self.co.pop(old, None)
        self.co[new] = c
        for member in c["members"]:
            self.parent[member] = new

    def _merge(self, a: dict, b: dict) -> str:
        if a["zdict"] != b["zdict"]:
            a["zdict"] = b""
        if a["manifest"] != b["manifest"]:
            a["manifest"] = None
        if a["schema"] != b["schema"]:
            a["schema"] = None
        if a["mode"] != b["mode"]:
            a["mode"] = "enforce"
        start = None
        for flag, slot in ((a["charging"], a["start"]), (b["charging"], b["start"])):
            if flag and slot is not None:
                start = slot if start is None else min(start, slot)
        a["spent"] = a["spent"] + b["spent"]
        a["over"] = a["over"] + b["over"]
        a["budget"] = min(a["budget"], b["budget"])
        a["charging"] = a["charging"] or b["charging"]
        a["start"] = start
        if a["last"] is None:
            a["last"] = b["last"]
        elif b["last"] is not None:
            a["last"] = max(a["last"], b["last"])
        a["member_choice"] = a["member_choice"] or b["member_choice"]
        a["max_bytes"] = min(a["max_bytes"], b["max_bytes"])
        if a["links"] is not None and b["links"] is not None:
            a["links"] = frozenset(a["links"]) & frozenset(b["links"])
        a["committed"] |= b["committed"]
        a["members"] |= b["members"]
        old_b = b["cid"]
        self.co.pop(old_b, None)
        self._reseat(a, min(a["members"]))
        return a["cid"]

    def _content(self, c: dict, destination: str, tool: str, payload: bytes,
                 arguments, fold_names: bool) -> tuple[int, int]:
        manifest = c["manifest"]
        hit = manifest is not None and (destination, tool) in manifest
        selection = 0
        if hit:
            from tests.p3_oracle import qb_choice
            selection = qb_choice(len(manifest))
            if c["schema"] is not None and arguments is not None:
                typed = _typed(c["schema"], arguments, c["zdict"])
                if typed is not None:
                    return selection, typed
            return selection, content_qb(payload, c["zdict"])
        raw = fold_observable(destination, tool, payload) if fold_names else fold_destination(destination, payload)
        return 0, content_qb(raw, c["zdict"])

    def reserve(self, sid: str, eid: str, destination: str, tool: str, payload: bytes,
                now_ms: int, approved: bool, *, arguments=None, fold_names: bool = True):
        c = self._c(sid)
        if eid in c["committed"] or (c["pending"] and c["pending"]["eid"] == eid):
            raise Denied("P3_REPLAY")
        if c["pending"] is not None:
            raise Denied("P3_BUSY")
        if len(c["committed"]) >= MAX_COMMITTED_IDS:
            raise Hold("P3_REPLAY_CAPACITY")
        if len(payload) > c["max_bytes"]:
            raise Hold("P3_EVENT_TOO_LARGE")
        if now_ms < c["epoch"]:
            raise Denied("P3_CLOCK")
        if not c["charging"]:
            c["pending"] = {"eid": eid, "charge": 0, "gap_qb": 0, "gap": 0, "release": None,
                            "approved": approved, "member": sid}
            return c["pending"]
        cur = (now_ms - c["epoch"]) // c["slot_ms"]
        base = c["last"] if c["last"] is not None else c["start"] - 1
        release = max(cur, base + 1)
        gap = release - base
        selection, content = self._content(c, destination, tool, payload, arguments, fold_names)
        parts = event_qb(
            gap=gap, members=len(c["members"]),
            manifest_n=len(c["manifest"]) if (c["manifest"] and (destination, tool) in c["manifest"]) else 0,
            content_qb_value=content, charge_member=c["member_choice"],
        )
        # selection inside event_qb uses manifest_n; content already excludes a second selection.
        # event_qb adds selection again. Pass content only and manifest_n.
        charge = parts["charge_qb"]
        # parts included selection from manifest_n AND we also computed selection. event_qb's
        # selection equals `selection` when manifest hits. Good, don't add twice.
        if (not approved) and c["spent"] + charge > c["budget"] and c["mode"] == "enforce":
            raise Hold("P3_BUDGET_EXHAUSTED")
        c["pending"] = {
            "eid": eid, "charge": charge, "gap_qb": parts["gap_qb"], "gap": gap,
            "release": release, "approved": approved, "member": sid,
            "member_qb": parts["member_qb"], "selection_qb": parts["selection_qb"],
            "content_qb": parts["content_qb"],
        }
        return c["pending"]

    def commit(self, sid: str, eid: str) -> dict:
        c = self._c(sid)
        p = c["pending"]
        if p is None or p["eid"] != eid:
            raise Denied("P3_UNKNOWN_EVENT")
        release = p["release"]
        charge = p["charge"]
        if release is not None and c["charging"]:
            base = c["last"] if c["last"] is not None else c["start"] - 1
            if release <= base:
                c["pending"] = None
                raise Denied("P3_SLOT_ORDER")
            new_gap = release - base
            from tests.p3_oracle import qb_gamma
            new_gap_qb = qb_gamma(new_gap)
            charge = p["charge"] - p["gap_qb"] + new_gap_qb
            if (not p["approved"]) and c["spent"] + charge > c["budget"] and c["mode"] == "enforce":
                c["pending"] = None
                raise Denied("P3_COMMIT_EXHAUSTED")
            if p["approved"]:
                c["over"] += charge
            else:
                c["spent"] += charge
            c["last"] = release
        if len(c["committed"]) >= MAX_COMMITTED_IDS:
            c["pending"] = None
            raise Hold("P3_REPLAY_CAPACITY")
        c["committed"].add(eid)
        c["pending"] = None
        return {"charge_qb": charge, "release_slot": release, "approved": p["approved"]}

    def abort(self, sid: str, eid: str) -> None:
        c = self._c(sid)
        p = c["pending"]
        if p is None or p["eid"] != eid:
            raise Denied("P3_UNKNOWN_EVENT")
        c["pending"] = None

    def grant(self, cid: str, add: int, approver: str) -> int:
        c = self.co.get(cid)
        if c is None:
            raise Denied("P3_UNKNOWN_SESSION")
        if add < 1 or c["budget"] + add > MAX_BUDGET_QB:
            raise Denied("P3_GRANT")
        c["budget"] += add
        return c["budget"]

    def view(self, sid: str) -> dict:
        c = self._c(sid)
        return {
            "cid": c["cid"],
            "spent_qb": c["spent"],
            "overdraft_qb": c["over"],
            "budget_qb": c["budget"],
            "members": tuple(sorted(c["members"])),
            "last_slot": c["last"],
            "charging": c["charging"],
            "charge_start_slot": c["start"],
            "pending": None if c["pending"] is None else c["pending"]["eid"],
            "committed": len(c["committed"]),
        }


def _typed(schema, arguments, zdict: bytes):
    from agent_gateway.leakage_budget import Bool, Bytes, Constant, Enum, IntRange, List, Optional, Str
    from tests.p3_oracle import qb_choice

    if type(arguments) is not dict:
        return None
    total = 0
    names = []
    for name, ft in schema.fields:
        names.append(name)
        if name not in arguments:
            if type(ft) is Optional:
                total += 4
                continue
            if type(ft) is Constant:
                continue
            return None
        part = _one(ft, arguments[name], zdict, qb_choice)
        if part is None:
            return None
        total += part
    for key in arguments:
        if key not in names:
            return None
    return total


def _one(ft, value, zdict, qb_choice):
    from agent_gateway.leakage_budget import Bool, Bytes, Constant, Enum, IntRange, List, Optional, Str
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
        inner = _one(ft.inner, value, zdict, qb_choice)
        return None if inner is None else 4 + inner
    if type(ft) is Str:
        if type(value) is not str:
            return None
        return content_qb(value.encode("utf-8"), zdict)
    if type(ft) is Bytes:
        if type(value) is not bytes:
            return None
        return content_qb(value, zdict)
    if type(ft) is List:
        if type(value) not in (list, tuple) or len(value) > ft.max_len:
            return None
        total = qb_choice(ft.max_len + 1)
        for item in value:
            part = _one(ft.inner, item, zdict, qb_choice)
            if part is None:
                return None
            total += part
        return total
    return None
