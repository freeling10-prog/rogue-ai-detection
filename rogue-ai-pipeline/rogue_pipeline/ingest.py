"""Ingest adapter for the agent-watch coordination export (schema ``agentwatch.coordination-event/1``).

agent-watch's honeypot (``export-leads --coordination-out``) writes one record per token/nonce issuance-or-use event
(issuer vs presenter session and IP) plus one ``cognitive_capture`` record. Raw token values are never exported;
records carry stable reference ids (``hf-...`` handoff tokens, ``nn-...`` nonces). This module converts them into
strict ``RawEvent`` dicts so the pipeline's deterministic ``cross_ip_token_handoff`` edge and rules R6/R7 apply.

Mapping (documented so the exporter can keep matching it)::

    record.type        *_issued / *_reissued            -> action=read,  response_tokens=[ref]
                       *_presented                      -> action=write, request_token=ref
                       cognitive_capture                -> action=message, honeypot=cognitive_capture, capture={...}
    record.ref         hf-... -> token_class=handoff_token ; nn-... -> token_class=verification_nonce
    record.presenter   {session_id, ip} -> agent_id="sess:<session_id>", ip
    record.issuer      used ONLY to synthesize the issuing event when the file has no issuance record for that ref
                       (event_id "<id>:iss", agent = issuer session, ip = issuer ip, 1 ms earlier)

Not trusted: every ``cognitive_capture`` field is attacker-controlled; ``CapturedAgentMeta`` sanitizes and truncates
it again at ingest, and records that fail validation are quarantined by the normalizer like any other event.
Records that are not valid JSON, have another schema, or lack timestamps are skipped and counted - never guessed at.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

COORD_SCHEMA = "agentwatch.coordination-event/1"
BOARD = "/api/v1/coordination-board"
_BAD = re.compile(r"[^A-Za-z0-9._:@-]")
_CLASS = {"hf": "handoff_token", "nn": "verification_nonce"}


def _agent(session_id: Any) -> str:
    return ("sess:" + _BAD.sub("_", str(session_id)))[:64]


def _iso_minus(ts: str, seconds: float) -> str:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return datetime.fromtimestamp(dt.timestamp() - seconds, tz=dt.tzinfo).isoformat().replace("+00:00", "Z")


def coordination_to_raw(lines: Iterable[str], *, synthetic: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Convert coordination-event JSONL lines. Returns (RawEvent dicts, counts)."""
    counts = {"records": 0, "events": 0, "synthesized_issuers": 0, "skipped_not_json": 0, "skipped_other_schema": 0, "skipped_invalid": 0}
    recs: List[Dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            counts["skipped_not_json"] += 1
            continue
        if not isinstance(r, dict) or r.get("schema") != COORD_SCHEMA:
            counts["skipped_other_schema"] += 1
            continue
        counts["records"] += 1
        recs.append(r)
    issued_refs = {(r.get("ref")) for r in recs if str(r.get("type", "")).endswith(("_issued", "_reissued"))}
    out: List[Dict[str, Any]] = []
    seen_ids = set()
    synth_done = set()
    for r in recs:
        typ, ts, eid = str(r.get("type", "")), r.get("ts"), str(r.get("event_id", ""))[:64]
        _p = r.get("presenter")
        pres: Dict[str, Any] = _p if isinstance(_p, dict) else {}
        if not typ or not isinstance(ts, str) or not eid or eid in seen_ids or not pres.get("session_id"):
            counts["skipped_invalid"] += 1
            continue
        seen_ids.add(eid)
        base: Dict[str, Any] = {"source": "web_server", "agent_id": _agent(pres["session_id"]), "synthetic": bool(synthetic)}
        if pres.get("ip"):
            base["ip"] = str(pres["ip"])
        if typ == "cognitive_capture":
            _c = r.get("cognitive_capture")
            cap: Dict[str, Any] = _c if isinstance(_c, dict) else {}
            allowed = {k: cap[k] for k in ("system_prompt_summary", "declared_tools", "current_objective", "message") if k in cap}
            out.append({**base, "event_id": eid, "ts": ts, "action": "message", "resource": BOARD, "honeypot": "cognitive_capture",
                        "capture": allowed})
            counts["events"] += 1
            continue
        ref = str(r.get("ref", ""))
        cls = _CLASS.get(ref.split("-", 1)[0])
        if not ref or cls is None:
            counts["skipped_invalid"] += 1
            continue
        if typ.endswith("_presented"):
            iss = r.get("issuer") if isinstance(r.get("issuer"), dict) else None
            if iss and iss.get("session_id") and iss.get("session_id") != pres["session_id"] \
                    and ref not in issued_refs and ref not in synth_done:
                synth_done.add(ref)
                ib: Dict[str, Any] = {"source": "web_server", "agent_id": _agent(iss["session_id"]), "synthetic": bool(synthetic)}
                if iss.get("ip"):
                    ib["ip"] = str(iss["ip"])
                out.append({**ib, "event_id": (eid[:59] + ":iss"), "ts": _iso_minus(ts, 0.001), "action": "read", "resource": BOARD,
                            "honeypot": "coordination_board", "response_tokens": [ref], "token_class": cls})
                counts["events"] += 1
                counts["synthesized_issuers"] += 1
            out.append({**base, "event_id": eid, "ts": ts, "action": "write", "resource": BOARD, "honeypot": "coordination_board",
                        "request_token": ref, "token_class": cls})
        elif typ.endswith(("_issued", "_reissued")):
            out.append({**base, "event_id": eid, "ts": ts, "action": "read", "resource": BOARD, "honeypot": "coordination_board",
                        "response_tokens": [ref], "token_class": cls})
        else:
            counts["skipped_invalid"] += 1
            continue
        counts["events"] += 1
    return out, counts
