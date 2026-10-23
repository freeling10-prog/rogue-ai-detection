"""Export honeypot leads as strict ``RawEvent`` JSONL for the sibling
``rogue-ai-pipeline`` project (``rogue_pipeline.schema.RawEvent``).

That schema forbids unknown fields, so this is a separate, lossy view of the
lead (the full-fidelity lead stays in the honeypot JSONL).  Mapping::

    event_id          <- lead.event_id
    ts                <- lead.timestamp            (ISO-8601 UTC, 'Z')
    source            <- "web_server"
    agent_id          <- "client:<source_ip>"      (sanitised to [A-Za-z0-9._:@-]{1,64})
    action            <- "access"
    status            <- "denied" if response_status >= 400 else "allowed"
    resource          <- request path              (decoy path touched)
    ip                <- source_ip (if a valid address)
    untrusted_content <- True for canary_follow / canary_phrase_echo (the agent
                         acted on text it retrieved)
    payload_bytes     <- bytes of request body read
    text              <- "honeypot lead decoy=<kind> token=<id> ..."
    synthetic         <- only if the caller says the traffic is synthetic

Only high-priority ``honeytoken_hit`` leads are exported; informational
context events are skipped.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .leads import sanitize_text
from .scrubber import get_default_scrubber

UNTRUSTED_KINDS = {"canary_follow", "canary_phrase_echo", "error_hint_follow",
                   "coordination_register", "coordination_claim_step"}
COORD_SCHEMA = "agentwatch.coordination-event/1"
_ID_BAD = re.compile(r"[^A-Za-z0-9._:@-]")


def lead_to_raw_event(lead: dict[str, Any], *, synthetic: bool = False) -> Optional[dict[str, Any]]:
    """Convert one lead to a RawEvent-shaped dict (None if not an exportable hit)."""
    if lead.get("event_type") != "honeytoken_hit":
        return None
    req = lead.get("request") or {}
    decoy = lead.get("decoy") or {}
    ip = str(lead.get("source_ip", ""))
    try:
        ipaddress.ip_address(ip)
        valid_ip: Optional[str] = ip
    except ValueError:
        valid_ip = None
    status = int(req.get("response_status") or 200)
    kind = str(decoy.get("kind", "unknown"))
    text = sanitize_text(
        f"honeypot lead decoy={kind} token={lead.get('token_id')} priority={lead.get('priority')} "
        f"tags={','.join(lead.get('tags') or [])}", 1000)
    return {
        "event_id": str(lead["event_id"])[:64],
        "ts": lead["timestamp"],
        "source": "web_server",
        "agent_id": _ID_BAD.sub("_", f"client:{ip}")[:64] or "client:unknown",
        "action": "access",
        "status": "denied" if status >= 400 else "allowed",
        "resource": sanitize_text(req.get("path", ""), 512).replace("...[truncated", "[truncated")[:512],
        "ip": valid_ip,
        "untrusted_content": kind in UNTRUSTED_KINDS,
        "payload_bytes": int(req.get("body_bytes_read") or 0),
        "text": text,
        "synthetic": bool(synthetic),
    }


def lead_to_coordination_events(lead: dict[str, Any]) -> list[dict[str, Any]]:
    """Second, richer export (schema ``agentwatch.coordination-event/1``, documented in the README).

    One record per handoff_token / verification_nonce issuance-or-use event (issuer vs presenter session
    and IP) plus one ``cognitive_capture`` record when the visitor volunteered text.  Token/nonce values are
    never exported - only stable reference ids (``hf-...``/``nn-...``).  ``cognitive_capture`` fields are
    attacker-controlled data (``untrusted: true``)."""
    if lead.get("event_type") != "honeytoken_hit":
        return []
    coord = lead.get("coordination") if isinstance(lead.get("coordination"), dict) else {}
    cap = lead.get("cognitive_capture") if isinstance(lead.get("cognitive_capture"), dict) else None
    if not coord and not cap:
        return []
    base = {"schema": COORD_SCHEMA, "ts": lead.get("timestamp"), "lead_event_id": str(lead.get("event_id", ""))[:64],
            "decoy_kind": (lead.get("decoy") or {}).get("kind"), "lead_token_id": lead.get("token_id"),
            "response_status": (lead.get("request") or {}).get("response_status"),
            "step": (lead.get("detail") or {}).get("step")}
    out: list[dict[str, Any]] = []
    for i, ev in enumerate(coord.get("events") or []):
        if not isinstance(ev, dict):
            continue
        out.append({**base, "event_id": f"{base['lead_event_id']}:e{i}", "type": ev.get("type"), "ref": ev.get("ref"),
                    "issuer": ev.get("issuer"), "presenter": ev.get("presenter"),
                    "cross_session": bool(ev.get("cross_session")), "cross_ip": bool(ev.get("cross_ip")),
                    "valid": ev.get("valid")})
    if cap:
        out.append({**base, "event_id": f"{base['lead_event_id']}:cap", "type": "cognitive_capture",
                    "presenter": {"session_id": (lead.get("detail") or {}).get("presenter_session"),
                                  "ip": lead.get("source_ip")},
                    "cognitive_capture": cap, "untrusted": True})
    return out


def export_coordination_file(src: str | Path, dst: str | Path) -> int:
    """Write coordination-event JSONL (scrubbed); returns the number of records."""
    scrub = get_default_scrubber()
    n = 0
    with open(src, "r", encoding="utf-8", errors="replace") as fin, open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            try:
                lead = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(lead, dict):
                continue
            for ev in lead_to_coordination_events(lead):
                fout.write(json.dumps(scrub.scrub(ev), separators=(",", ":")) + "\n")
                n += 1
    return n


def export_raw_events(lead_lines: Iterable[str], *, synthetic: bool = False) -> Iterator[dict[str, Any]]:
    for line in lead_lines:
        try:
            lead = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(lead, dict):
            ev = lead_to_raw_event(lead, synthetic=synthetic)
            if ev is not None:
                yield ev


def export_file(src: str | Path, dst: str | Path, *, synthetic: bool = False) -> int:
    """Write RawEvent JSONL; returns the number of events written."""
    n = 0
    scrub = get_default_scrubber()
    with open(src, "r", encoding="utf-8", errors="replace") as fin, open(dst, "w", encoding="utf-8") as fout:
        for ev in export_raw_events(fin, synthetic=synthetic):
            fout.write(json.dumps(scrub.scrub(ev), separators=(",", ":")) + "\n")
            n += 1
    return n
