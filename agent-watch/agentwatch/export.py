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


# ---- v3: mirrored access stream -> RawEvents with a ``web`` block --------------------------------------------------------
_STRONG = {"hidden_link": "hidden_link", "schema_param_use": "schema_param", "session_canary_param": "session_canary",
           "error_hint_follow": "error_hint_follow", "fake_credential_use": "fake_credential_use",
           "mcp_decoy_tool_call": "mcp_tools_call"}
_MCP = {"mcp_initialize": "initialize", "mcp_tools_list": "tools_list", "mcp_decoy_tool_call": "tools_call"}


def export_web_events(paths: Iterable[str | Path], cfg: Optional[dict[str, Any]] = None, *, synthetic: bool = False) -> Iterator[dict[str, Any]]:
    """Convert logs + leads + the mirrored access stream into pipeline ``RawEvent`` dicts WITH a ``web`` block.

    One event per request (honeypot leads and their mirror records are merged first).  The ``web`` block carries only derived
    facts: content kind, whether the move was linked from the previous page / had a valid Referer / was offered earlier,
    Sec-Fetch mismatch, the strongest decoy signal, the MCP method.  The User-Agent is passed through (the pipeline reduces
    it to flags and discards it).  Needs the link graph recorded by the honeypot mirror; without it the link fields are
    simply omitted and the pipeline rules abstain."""
    from .config import load_config
    from .parser import merge_results, parse_file
    from .pipeline import merge_mirror
    from .sessions import build_sessions
    from .webdetectors import _is_asset, is_html_page, transitions
    cfg = cfg or load_config()
    parsed = merge_results([parse_file(p) for p in paths])
    reqs, _ = merge_mirror(parsed.requests)
    scrub = get_default_scrubber()
    n = 0
    for sess in build_sessions(reqs, cfg):
        trans = {id(r): (st, ok) for r, _, st, ok in transitions(sess, cfg)}
        for r in sess.requests:
            n += 1
            ip = r.ip
            try:
                ipaddress.ip_address(ip)
                valid_ip: Optional[str] = ip
            except ValueError:
                valid_ip = None
            kind = "asset" if _is_asset(r, cfg) else "html" if is_html_page(r, cfg) else "api" if r.content_type.startswith("application/") or "/api/" in r.path else "other"
            web: dict[str, Any] = {"content_kind": kind}
            if r.ua:
                web["user_agent"] = r.ua[:300]
            st = trans.get(id(r))
            if st is not None and st[0] not in ("entry", "unknown"):
                web["linked_from_prev"] = st[0] == "linked"
                web["referer_valid"] = st[1]
                web["offered_earlier"] = st[0] == "offered_earlier"
            if kind == "html" and r.headers_logged:
                mode, dest = r.headers.get("sec-fetch-mode", ""), r.headers.get("sec-fetch-dest", "")
                web["sec_fetch_mismatch"] = not mode or dest not in ("document", "iframe", "frame")
            dk = r.decoy_kind or ""
            sig = _STRONG.get(dk) or ("schema_param" if "schema_param_use" in r.tags else "session_canary" if "session_canary_param" in r.tags else None)
            if "mcp_list_then_call" in r.tags:
                sig = "mcp_list_then_call"
            if sig is None and r.source == "honeypot" and r.detail is not None and dk and not dk.startswith(("mcp_", "robots", "discovery", "canary_page")) \
                    and dk not in ("request_too_large",):
                sig = "decoy_hit"
            if sig:
                web["strong_signal"] = sig
            if dk and re.fullmatch(r"[a-z0-9_]{1,40}", dk):
                web["decoy_kind"] = dk
            if dk in _MCP:
                web["mcp"] = _MCP[dk]
            if r.ja4:
                web["ja4"] = r.ja4
            ev = {
                "event_id": (r.event_id or f"w{n:08d}")[:64], "ts": r.ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "source": "web_server",
                "agent_id": _ID_BAD.sub("_", f"client:{ip}")[:64] or "client:unknown", "action": "access",
                "status": "denied" if r.status >= 400 else "allowed", "resource": sanitize_text(r.path, 512).replace("...[truncated", "[truncated")[:512],
                "ip": valid_ip, "payload_bytes": max(0, int(r.size or 0)), "synthetic": bool(synthetic), "web": web}
            yield ev


def export_web_file(paths: Iterable[str | Path], dst: str | Path, cfg: Optional[dict[str, Any]] = None, *, synthetic: bool = False) -> int:
    n = 0
    scrub = get_default_scrubber()
    with open(dst, "w", encoding="utf-8") as fout:
        for ev in export_web_events(paths, cfg, synthetic=synthetic):
            ua = ev["web"].pop("user_agent", None)
            ev = scrub.scrub(ev)
            if ua is not None:
                ev["web"]["user_agent"] = scrub.scrub(ua) if isinstance(ua, str) else ua
            fout.write(json.dumps(ev, separators=(",", ":")) + "\n")
            n += 1
    return n
