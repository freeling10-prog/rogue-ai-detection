"""P3 log-only calibration: replay a benign JSONL trace and size the budget.

``python -m agent_gateway p3-calibrate trace.jsonl`` replays recorded tool
calls through a fresh ``LeakageLedger`` with ``mode="log_only"`` and prints
how many quarter bits each session and each coalition would have spent, how
that spend splits over the five cost components, and a budget that covers
the trace with a margin. Nothing is held or denied for a budget reason, and
no call is forwarded: this reads a file and does arithmetic. Standard
library only. All quantities are integers in quarter bits (1 bit = 4 qb).

Trace rows, one JSON object per line
------------------------------------
A call::

    {"ts_ms": 1700000000000, "session": "s1", "tool": "send_email",
     "destination": "mcp:mail", "arguments": {"to": "a@b.c", "body": "hi"}}

or the MCP wire shape (``tools/call``, ``resources/read``, ``prompts/get``;
other methods are counted as skipped)::

    {"ts_ms": 1700000000000, "session": "s1", "server": "mail",
     "message": {"jsonrpc": "2.0", "method": "tools/call",
                 "params": {"name": "send_email", "arguments": {...}}}}

Optional keys on a call: ``coalition`` (sessions with the same value are
linked), ``charging`` (true marks the session as tainted from this row on),
``outbound`` (overrides the outbound test). ``ts`` in seconds is accepted
in place of ``ts_ms``; a row with neither reuses the previous row's time.
A link::

    {"link": ["s1", "s2"], "source": "delegation"}

What the replay matches and what it does not
--------------------------------------------
- Outbound classification is ``pep.is_outbound_event``, the engine's own
  test. Charged bytes are the canonical argument body with destination and
  tool folded in, as for an in-process ``evaluate_call``. A deployment that
  goes through the MCP proxy forwards re-serialised ``params`` instead, so
  its content charge differs by a few bytes per event.
- ``charge="always"`` (the default) charges every outbound event from a
  session's first row. That is an upper estimate. ``charge="trace"`` starts
  charging at a row marked ``charging``, an external read, or a credential
  read, which is the engine's taint and sensitive-read rule on the built-in
  tool table. A tool the table does not know never starts it.
- Typed field codes apply only where a manifest and schema are supplied
  (``--manifest``), exactly as on the live ledger. Everything else uses the
  raw DEFLATE length.
- The ledger refuses new events once a coalition has 256 committed event
  ids. The replay clears that store when it fills so spend keeps being
  measured, and reports where a live coalition would have hit the limit.
- The budget is one total per coalition for its lifetime. It does not
  refill, so the recommendation is tied to how long the traced sessions ran.
- The gap component is P3's slot code. It does not see timing inside a
  slot. For the side-channel guard's own timing rule: Regular-rhythm timing
  beacons are flagged; irregular timing channels are not yet bounded.

The recommendation is arithmetic on this trace. It is not a statement about
traffic the trace does not contain.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .common import Denied
from .leakage_budget import (
    LINK_SOURCES, MAX_BUDGET_QB, MAX_ZDICT, Bool, Constant, Enum, FieldSchema, Hold, IntRange,
    LeakageLedger, List, Optional as OptionalField, P3Config, SelectionManifest, Str,
)
from .taint import (
    CORE_MCP_SERVERS, EGRESS_CREDS, EGRESS_EXTERNAL_READ, SENSITIVE_READ_TOOLS,
    UNTRUSTED_INGEST_TOOLS, egress_class,
)

SCHEMA = "agent-gateway.p3-calibration/1"
COMPONENTS = ("continuation_qb", "gap_qb", "member_qb", "selection_qb",
              "content_typed_qb", "content_raw_qb")
COMPONENT_LABELS = {
    "continuation_qb": "continuation bit",
    "gap_qb": "Elias-gamma timing gap",
    "member_qb": "member choice",
    "selection_qb": "tool selection",
    "content_typed_qb": "content: typed field codes",
    "content_raw_qb": "content: raw DEFLATE length",
}
MAX_LISTED_ERRORS = 20
MAX_LISTED_ROWS = 10
MAX_LINE_BYTES = 1_048_576
_MCP_PSEUDO = {"resources/read": "mcp.resources/read", "prompts/get": "mcp.prompts/get"}


class TraceError(ValueError):
    """One trace row, or the manifest file, could not be used."""


@dataclass(frozen=True)
class CalibrationConfig:
    """Replay settings. ``budget_qb`` is the candidate budget rows are compared with."""

    budget_qb: int = 128
    slot_ms: int = 1000
    margin_pct: int = 25
    basis: str = "peak"
    charge: str = "always"
    core_servers: frozenset = field(default_factory=lambda: frozenset(c.lower() for c in CORE_MCP_SERVERS))
    show_ids: bool = False

    def __post_init__(self) -> None:
        for name in ("budget_qb", "slot_ms", "margin_pct"):
            if type(getattr(self, name)) is not int:
                raise TraceError(f"{name} must be an integer")
        if not 0 <= self.budget_qb <= MAX_BUDGET_QB:
            raise TraceError(f"budget_qb must be 0..{MAX_BUDGET_QB}")
        if not 1 <= self.slot_ms <= 86_400_000:
            raise TraceError("slot_ms must be 1..86400000")
        if not 0 <= self.margin_pct <= 1000:
            raise TraceError("margin_pct must be 0..1000")
        if self.basis not in ("peak", "p95"):
            raise TraceError("basis must be 'peak' or 'p95'")
        if self.charge not in ("always", "trace"):
            raise TraceError("charge must be 'always' or 'trace'")


@dataclass(frozen=True)
class Attachment:
    """What the control plane would attach: dictionary, manifest and schemas."""

    zdict: bytes = b""
    manifest: Optional[SelectionManifest] = None
    schemas: dict = field(default_factory=dict)


# --- integer statistics ------------------------------------------------------

def nearest_rank(values: Iterable[int], percent: int) -> int:
    """Nearest-rank percentile of integers. ``0`` for an empty input."""
    ordered = sorted(values)
    if not ordered:
        return 0
    rank = (percent * len(ordered) + 99) // 100
    return ordered[max(rank, 1) - 1]


def with_margin(basis_qb: int, margin_pct: int) -> int:
    """``ceil(basis * (100 + margin) / 100)`` in integers."""
    return (basis_qb * (100 + margin_pct) + 99) // 100


def qb_as_bits(qb: int) -> str:
    """Quarter bits as a decimal bit string, exact (``130`` -> ``"32.5"``)."""
    return f"{qb // 4}{('', '.25', '.5', '.75')[qb % 4]}"


def _share(part: int, total: int) -> str:
    """Percent with one decimal, computed in integers."""
    if total <= 0:
        return "0.0"
    tenths = (part * 1000 + total // 2) // total
    return f"{tenths // 10}.{tenths % 10}"


def _spread(values: list[int]) -> dict:
    return {
        "n": len(values),
        "peak_qb": max(values) if values else 0,
        "p95_qb": nearest_rank(values, 95),
        "p50_qb": nearest_rank(values, 50),
        "total_qb": sum(values),
    }


# --- manifest file -----------------------------------------------------------

def _field(spec: Any, depth: int = 0) -> object:
    if depth > 3:
        raise TraceError("schema field nested too deep")
    if spec == "str":
        return Str()
    if spec == "bool":
        return Bool()
    if spec == "constant":
        return Constant()
    if isinstance(spec, dict) and len(spec) >= 1:
        if "enum" in spec and type(spec["enum"]) is int:
            return Enum(spec["enum"])
        if "int" in spec and isinstance(spec["int"], list) and len(spec["int"]) == 2:
            return IntRange(spec["int"][0], spec["int"][1])
        if "optional" in spec:
            return OptionalField(_field(spec["optional"], depth + 1))
        if "list" in spec and type(spec.get("max_len")) is int:
            return List(_field(spec["list"], depth + 1), spec["max_len"])
    raise TraceError(f"unknown schema field {spec!r}")


def load_attachment(doc: Any) -> Attachment:
    """Build the attachment from a manifest document.

    ``{"zdict_hex": "...", "eligible": [[destination, tool], ...],
    "schemas": {tool: {field: spec}}}``. A spec is ``"str"``, ``"bool"``,
    ``"constant"``, ``{"enum": n}``, ``{"int": [lo, hi]}``,
    ``{"optional": spec}`` or ``{"list": spec, "max_len": n}``. Enum and int
    arguments must already be integers in the trace, as on the live ledger.
    """
    if not isinstance(doc, dict):
        raise TraceError("manifest must be a JSON object")
    try:
        zdict = bytes.fromhex(doc.get("zdict_hex") or "")
    except (TypeError, ValueError):
        raise TraceError("zdict_hex is not hex") from None
    if len(zdict) > MAX_ZDICT:
        raise TraceError(f"zdict is longer than {MAX_ZDICT} bytes")
    try:
        manifest = None
        rows = doc.get("eligible")
        if rows:
            manifest = SelectionManifest(tuple((str(d), str(t)) for d, t in rows))
        schemas = {}
        for tool, fields in (doc.get("schemas") or {}).items():
            if not isinstance(fields, dict) or not fields:
                raise TraceError(f"schema for {tool!r} must be a non-empty object")
            ordered = sorted(fields.items(), key=lambda item: item[0].encode("utf-8"))
            schemas[tool] = FieldSchema(tool, tuple((name, _field(spec)) for name, spec in ordered))
    except Denied as exc:
        raise TraceError(f"manifest refused by the ledger: {exc}") from None
    except (TypeError, ValueError) as exc:
        if isinstance(exc, TraceError):
            raise
        raise TraceError(f"manifest is malformed: {exc}") from None
    return Attachment(zdict=zdict, manifest=manifest, schemas=schemas)


# --- trace rows --------------------------------------------------------------

@dataclass(frozen=True)
class Call:
    session: str
    tool: str
    destination: str
    arguments: dict
    ts_ms: Optional[int]
    coalition: Optional[str] = None
    charging: bool = False
    outbound: Optional[bool] = None


@dataclass(frozen=True)
class Link:
    a: str
    b: str
    source: str


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise TraceError(f"{what} must be a string of 1..128 characters")
    return value


def _time_ms(row: dict) -> Optional[int]:
    if "ts_ms" in row:
        value = row["ts_ms"]
        if type(value) is not int or value < 0:
            raise TraceError("ts_ms must be a non-negative integer")
        return value
    if "ts" in row:
        value = row["ts"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise TraceError("ts must be a non-negative number of seconds")
        return int(value * 1000)
    return None


def parse_row(row: Any) -> Call | Link | None:
    """One trace object. ``None`` for an MCP method that is not a gated call."""
    if not isinstance(row, dict):
        raise TraceError("row is not a JSON object")
    if "link" in row:
        pair = row["link"]
        if not isinstance(pair, list) or len(pair) != 2:
            raise TraceError("link must be a list of two session ids")
        source = row.get("source", "control_plane")
        if source not in LINK_SOURCES:
            raise TraceError(f"unknown link source {source!r}")
        return Link(_text(pair[0], "link session"), _text(pair[1], "link session"), source)
    session = _text(row.get("session", row.get("session_id")), "session")
    destination = row.get("destination")
    if destination is None and row.get("server") is not None:
        destination = "mcp:" + _text(row["server"], "server")
    message = row.get("message") if isinstance(row.get("message"), dict) else row
    method = message.get("method")
    if method is not None:
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if method == "tools/call":
            tool = params.get("name")
            arguments = params.get("arguments")
        elif method == "resources/read":
            tool = _MCP_PSEUDO[method]
            arguments = {"uri": str(params.get("uri") or "")}
        elif method == "prompts/get":
            tool = _MCP_PSEUDO[method]
            arguments = {"name": str(params.get("name") or "")}
            if isinstance(params.get("arguments"), dict):
                arguments["arguments"] = params["arguments"]
        else:
            return None
    else:
        tool = row.get("tool", row.get("name"))
        arguments = row.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise TraceError("arguments must be an object")
    if destination is not None and (not isinstance(destination, str) or len(destination) > 128):
        raise TraceError("destination must be a string of at most 128 characters")
    coalition = row.get("coalition")
    if coalition is not None:
        coalition = _text(coalition, "coalition")
    outbound = row.get("outbound")
    if outbound is not None and type(outbound) is not bool:
        raise TraceError("outbound must be true or false")
    return Call(
        session=session, tool=_text(tool, "tool"), destination=destination or "",
        arguments=arguments, ts_ms=_time_ms(row), coalition=coalition,
        charging=row.get("charging") is True, outbound=outbound,
    )


def read_trace(lines: Iterable[str | bytes]) -> tuple[list[tuple[int, Call | Link]], list[dict], int]:
    """Parse JSONL. Returns ``(rows, rejected, skipped_methods)``.

    A rejected line does not stop the read. It is listed with its line number
    and reason, never with its content.
    """
    rows: list[tuple[int, Call | Link]] = []
    rejected: list[dict] = []
    skipped = 0
    for lineno, raw in enumerate(lines, start=1):
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                rejected.append({"line": lineno, "reason": "not UTF-8"})
                continue
        text = raw.strip()
        if not text:
            continue
        if len(text) > MAX_LINE_BYTES:
            rejected.append({"line": lineno, "reason": "line too long"})
            continue
        try:
            parsed = parse_row(json.loads(text))
        except json.JSONDecodeError:
            rejected.append({"line": lineno, "reason": "not JSON"})
            continue
        except TraceError as exc:
            rejected.append({"line": lineno, "reason": str(exc)})
            continue
        if parsed is None:
            skipped += 1
            continue
        rows.append((lineno, parsed))
    return rows, rejected, skipped


# --- replay ------------------------------------------------------------------

def _body(arguments: dict) -> bytes:
    """The canonical argument body ``PolicyEngine._p3_body`` charges."""
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8", "surrogatepass")


def _starts_charging(call: Call) -> bool:
    eclass = egress_class(call.tool)
    return (call.charging or eclass in (EGRESS_EXTERNAL_READ, EGRESS_CREDS)
            or call.tool in UNTRUSTED_INGEST_TOOLS or call.tool in SENSITIVE_READ_TOOLS)


def _blank() -> dict:
    return {name: 0 for name in COMPONENTS}


def calibrate(rows: Iterable[tuple[int, Call | Link]], cfg: Optional[CalibrationConfig] = None,
              attachment: Optional[Attachment] = None) -> dict:
    """Replay parsed rows in log-only mode and return the calibration summary."""
    from .pep import is_outbound_event  # the engine's outbound test, imported late

    cfg = cfg or CalibrationConfig()
    attachment = attachment or Attachment()
    ledger = LeakageLedger()
    p3cfg = P3Config(budget_qb=cfg.budget_qb, slot_ms=cfg.slot_ms, mode="log_only")
    session_qb: dict[str, int] = {}
    session_events: dict[str, int] = {}
    coalition_key_owner: dict[str, str] = {}
    totals = _blank()
    event_charges: list[int] = []
    over_budget_events = 0
    counts = {"calls": 0, "outbound": 0, "charged": 0, "local": 0, "uncharged_outbound": 0,
              "oversize": 0, "links": 0}
    rejected: list[dict] = []
    replay_capacity: dict[str, int] = {}
    per_event: list[tuple[str, int, int]] = []  # (session, spent_before, charge)
    clock = 0
    serial = 0

    def attach(session: str) -> None:
        if not ledger.contains(session):
            ledger.attach(session, p3cfg, zdict=attachment.zdict, manifest=attachment.manifest,
                          schemas=attachment.schemas)
        session_qb.setdefault(session, 0)
        session_events.setdefault(session, 0)

    for lineno, row in rows:
        try:
            if type(row) is Link:
                attach(row.a)
                attach(row.b)
                ledger.link(row.a, row.b, row.source)
                counts["links"] += 1
                continue
            counts["calls"] += 1
            if row.ts_ms is not None:
                clock = row.ts_ms
            attach(row.session)
            if row.coalition is not None:
                owner = coalition_key_owner.setdefault(row.coalition, row.session)
                if owner != row.session:
                    ledger.link(owner, row.session, "control_plane")
            slot = clock // cfg.slot_ms
            if cfg.charge == "always" or _starts_charging(row):
                ledger.mark_charging(row.session, slot)
            outbound = row.outbound
            if outbound is None:
                outbound = is_outbound_event(row.tool, egress_class(row.tool), row.arguments,
                                             row.destination or None, cfg.core_servers)
            if not outbound:
                counts["local"] += 1
                continue
            counts["outbound"] += 1
            serial += 1
            event_id = f"cal{serial}"
            before = ledger.state(row.session)
            body = _body(row.arguments)
            try:
                ledger.reserve(row.session, event_id, row.destination, row.tool, body, clock, False,
                               arguments=row.arguments)
            except Hold as hold:
                if hold.reason == "P3_EVENT_TOO_LARGE":
                    counts["oversize"] += 1
                    continue
                if hold.reason != "P3_REPLAY_CAPACITY":
                    raise
                # A live coalition holds every later event here. Calibration
                # ids are never replayed, so drop the store and keep measuring.
                replay_capacity.setdefault(before["cid"], counts["outbound"])
                ledger.coalition(row.session).committed_ids.clear()
                ledger.reserve(row.session, event_id, row.destination, row.tool, body, clock, False,
                               arguments=row.arguments)
            record = ledger.commit(row.session, event_id)
        except (Denied, TraceError) as exc:
            rejected.append({"line": lineno, "reason": f"ledger refused the row: {exc}"})
            continue
        charge = record["charge_qb"]
        if not before["charging"] or record["release_slot"] is None:
            counts["uncharged_outbound"] += 1
            continue
        counts["charged"] += 1
        totals["continuation_qb"] += record["continuation_qb"]
        totals["gap_qb"] += record["gap_qb"]
        totals["member_qb"] += record["member_qb"]
        totals["selection_qb"] += record["selection_qb"]
        coder = "content_typed_qb" if record["content_coder"] == "typed" else "content_raw_qb"
        totals[coder] += record["content_qb"]
        session_qb[row.session] += charge
        session_events[row.session] += 1
        event_charges.append(charge)
        per_event.append((row.session, before["spent_qb"], charge))
        if before["spent_qb"] + charge > cfg.budget_qb:
            over_budget_events += 1

    # Coalitions as they stand at the end of the trace. They only merge.
    groups: dict[str, list[str]] = {}
    for session in session_qb:
        groups.setdefault(ledger.state(session)["cid"], []).append(session)
    coalition_qb = {cid: ledger.state(cid)["spent_qb"] for cid in groups}
    for cid, members in groups.items():
        if coalition_qb[cid] != sum(session_qb[m] for m in members):
            raise AssertionError("coalition spend does not equal its members' spend")

    def shown(identifier: str) -> str:
        if cfg.show_ids:
            return identifier
        return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]

    sessions = _spread(list(session_qb.values()))
    coalitions = _spread(list(coalition_qb.values()))
    basis_qb = coalitions["peak_qb"] if cfg.basis == "peak" else coalitions["p95_qb"]
    recommended = with_margin(basis_qb, cfg.margin_pct)
    grand = sum(totals.values())
    components = [
        {"component": name, "label": COMPONENT_LABELS[name], "qb": totals[name],
         "share_pct": _share(totals[name], grand)}
        for name in COMPONENTS
    ]
    content_qb = totals["content_typed_qb"] + totals["content_raw_qb"]
    top_coalitions = sorted(coalition_qb.items(), key=lambda item: (-item[1], item[0]))[:MAX_LISTED_ROWS]
    top_sessions = sorted(session_qb.items(), key=lambda item: (-item[1], item[0]))[:MAX_LISTED_ROWS]
    return {
        "schema": SCHEMA,
        "mode": "log_only",
        "config": {"budget_qb": cfg.budget_qb, "slot_ms": cfg.slot_ms, "margin_pct": cfg.margin_pct,
                   "basis": cfg.basis, "charge": cfg.charge,
                   "typed_schemas": sorted(attachment.schemas),
                   "manifest_rows": 0 if attachment.manifest is None else len(attachment.manifest.eligible),
                   "zdict_bytes": len(attachment.zdict)},
        "rows": {**counts, "rejected": len(rejected)},
        "rejected": rejected[:MAX_LISTED_ERRORS],
        "per_session": {**sessions, "over_budget": sum(1 for v in session_qb.values() if v > cfg.budget_qb)},
        "per_coalition": {**coalitions,
                          "over_budget": sum(1 for v in coalition_qb.values() if v > cfg.budget_qb)},
        "per_event": {"n": len(event_charges), "peak_qb": max(event_charges) if event_charges else 0,
                      "p95_qb": nearest_rank(event_charges, 95), "p50_qb": nearest_rank(event_charges, 50),
                      "over_budget_at_candidate": over_budget_events},
        "components": components,
        "content": {"qb": content_qb, "share_pct": _share(content_qb, grand),
                    "typed_qb": totals["content_typed_qb"], "raw_qb": totals["content_raw_qb"]},
        "total_qb": grand,
        "top_coalitions": [
            {"coalition": shown(cid), "members": len(groups[cid]), "qb": qb,
             "events": sum(session_events[m] for m in groups[cid])}
            for cid, qb in top_coalitions
        ],
        "top_sessions": [
            {"session": shown(sid), "qb": qb, "events": session_events[sid]} for sid, qb in top_sessions
        ],
        "replay_capacity": [
            {"coalition": shown(cid), "at_outbound_event": index}
            for cid, index in sorted(replay_capacity.items(), key=lambda item: item[1])
        ],
        "recommendation": {
            "basis": cfg.basis, "basis_qb": basis_qb, "margin_pct": cfg.margin_pct,
            "budget_qb": recommended, "budget_bits": qb_as_bits(recommended),
            "within_ledger_limit": recommended <= MAX_BUDGET_QB,
            "coalitions_over": sum(1 for v in coalition_qb.values() if v > recommended),
            "events_over": sum(1 for _s, spent, charge in per_event if spent + charge > recommended),
            "note": ("Counts use log-only accounting: an event over the line still adds its spend. "
                     "Covers this trace only."),
        },
    }


def calibrate_file(trace: Path, cfg: Optional[CalibrationConfig] = None,
                   manifest: Optional[Path] = None) -> dict:
    """Read ``trace`` (and an optional manifest file) and calibrate."""
    attachment = Attachment()
    if manifest is not None:
        try:
            attachment = load_attachment(json.loads(Path(manifest).read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise TraceError(f"manifest is not JSON: {exc.msg}") from None
    with Path(trace).open("rb") as handle:
        rows, rejected, skipped = read_trace(handle)
    out = calibrate(rows, cfg, attachment)
    out["rejected"] = (rejected + out["rejected"])[:MAX_LISTED_ERRORS]
    out["rows"]["rejected"] += len(rejected)
    out["rows"]["skipped_methods"] = skipped
    return out


def render_text(doc: dict) -> str:
    """Plain-text summary of a calibration document."""
    rows, cfg, rec = doc["rows"], doc["config"], doc["recommendation"]
    lines = [
        "P3 calibration (log-only, nothing held)",
        f"  candidate budget {cfg['budget_qb']} qb ({qb_as_bits(cfg['budget_qb'])} bits), "
        f"slot {cfg['slot_ms']} ms, charge={cfg['charge']}",
        f"  rows: {rows['calls']} calls, {rows['outbound']} outbound, {rows['charged']} charged, "
        f"{rows['local']} local, {rows['links']} links, {rows['rejected']} rejected",
        "",
        "Quarter bits spent        n      peak       p95       p50   over budget",
    ]
    for label, key in (("per session", "per_session"), ("per coalition", "per_coalition")):
        s = doc[key]
        lines.append(f"  {label:<16}{s['n']:>8}{s['peak_qb']:>10}{s['p95_qb']:>10}{s['p50_qb']:>10}"
                     f"{s['over_budget']:>14}")
    e = doc["per_event"]
    lines.append(f"  {'per event':<16}{e['n']:>8}{e['peak_qb']:>10}{e['p95_qb']:>10}{e['p50_qb']:>10}"
                 f"{e['over_budget_at_candidate']:>14}")
    lines += ["", "Spend by cost component          qb    share"]
    for item in doc["components"]:
        lines.append(f"  {item['label']:<28}{item['qb']:>8}{item['share_pct']:>8}%")
    lines.append(f"  {'content, both coders':<28}{doc['content']['qb']:>8}{doc['content']['share_pct']:>8}%")
    lines.append(f"  {'total':<28}{doc['total_qb']:>8}")
    lines += [
        "",
        f"Recommended budget: {rec['budget_qb']} qb ({rec['budget_bits']} bits) = "
        f"{rec['basis']} per coalition {rec['basis_qb']} qb + {rec['margin_pct']}% margin",
        f"  at that budget: {rec['coalitions_over']} coalition(s) and {rec['events_over']} event(s) over",
    ]
    if not rec["within_ledger_limit"]:
        lines.append(f"  this is above the ledger's limit of {MAX_BUDGET_QB} qb and cannot be configured")
    for item in doc["replay_capacity"]:
        lines.append(f"  coalition {item['coalition']} filled the 256-id replay store at outbound event "
                     f"{item['at_outbound_event']}; a live ledger holds every later event")
    if rows.get("skipped_methods"):
        lines.append(f"  {rows['skipped_methods']} row(s) with other MCP methods were skipped")
    for item in doc["rejected"]:
        lines.append(f"  line {item['line']} rejected: {item['reason']}")
    return "\n".join(lines) + "\n"
