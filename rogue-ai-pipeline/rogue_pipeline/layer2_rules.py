"""Layer 2: deterministic rule gates with ATLAS tags and evidence events.

Rules (all deterministic, no learning):

  R1  untrusted_then_tool_shift      AML.T0051  after reading untrusted content, a tool the agent neither used in
                                                its baseline period nor declared is invoked within ``untrusted_window_s``
  R2  tool_outside_declared_purpose  AML.T0053  tool call not in the agent's declared tool list (Policy)
  R3  write_to_new_external_dest     AML.T0086  write-capable tool sends >= ``min_exfil_bytes`` to an external
                                                host never contacted before
  R4  untrusted_then_external_call   AML.T0051  outbound call to a new external host within
                                                ``immediate_window_s`` of reading untrusted content
  R5  access_probing                 AML.T0075  many denied requests concentrated on sensitive resources
                                                (extra rule: R1-R4 cannot see pure access probing)
  R6  honeypot_board_interaction     AML.T0051  agent engaged the decoy coordination-board / claim-shard protocol
                                     (+T0053/T0086 when the interaction invoked a tool / sent data out)
  R7  honeypot_cognitive_capture     AML.T0051  agent disclosed its system-prompt summary / declared tools /
                                     +T0086     objective / message to a decoy (+T0053 when it listed tools)

  R8  asset_starvation               (web) a client whose User-Agent claims a browser loaded >= N HTML pages and never one
                                     CSS/JS/image/favicon (stronger when Sec-Fetch-* is also wrong)
  R9  unlinked_jump                  (web) >= N per-transition moves to a URL that no page ever offered this client, without a
                                     valid Referer (breadth-first queue moves that were offered earlier do not count)
  R10 strong_signal_floor            (web) a SINGLE high-signal event (decoy contact, session canary, schema parameter,
                                     error-hint follow, MCP tools/call) - sets a score FLOOR in fusion that benign padding
                                     cannot dilute.  A lone hidden-link/decoy contact gets the lower "weak" floor.

Baseline: rules R1/R3/R4 compare behaviour with the agent's own baseline period (its first
``baseline_min_seconds``). If the agent has fewer than ``baseline_min_events`` events in it, those rules ABSTAIN
rather than guess. Every flag carries evidence events and the "ATLAS mapping approximate" note.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set

from .atlas import ATLAS_MAPPING_NOTE, ATLAS_TECHNIQUES, atlas_ref
from .config import Layer2Cfg, ResolvedPolicy, ToolsCfg, WebCfg
from .schema import NormalizedEvent


@dataclass
class EvidenceEvent:
    event_id: str
    ts: float
    summary: str                 # derived text only - never raw identifiers or free text


@dataclass
class RuleFlag:
    rule_id: str
    title: str
    agent: str
    atlas: List[Dict[str, str]]
    strength: float              # 0..1, deterministic from the evidence
    explanation: str
    evidence: List[EvidenceEvent]
    mapping_note: str = ATLAS_MAPPING_NOTE
    extra: Dict[str, object] = field(default_factory=dict)


def _ev(e: NormalizedEvent) -> EvidenceEvent:
    bits = [e.action, f"status={e.status}"]
    if e.tool:
        bits.append(f"tool={e.tool}")
    if e.dest_host:
        bits.append(f"dest={e.dest_host}{' (external)' if e.dest_external else ''}")
    if e.untrusted:
        bits.append("untrusted-content")
    if e.sensitive:
        bits.append("sensitive-resource")
    if e.honeypot:
        bits.append(f"honeypot={e.honeypot}")
    if e.payload_bytes:
        bits.append(f"bytes={e.payload_bytes}")
    return EvidenceEvent(e.event_id, e.ts, " ".join(bits))


def _strength(base: float, n: int) -> float:
    return round(min(1.0, base + 0.05 * max(0, n - 1)), 3)


class RuleEngine:
    def __init__(self, cfg: Layer2Cfg, tools: ToolsCfg, policy: ResolvedPolicy, web: Optional[WebCfg] = None) -> None:
        self.cfg = cfg
        self.web = web or WebCfg()
        self.write_tools: FrozenSet[str] = frozenset(tools.write_tools)
        self.policy = policy
        self.exempted: Counter = Counter()      # rule id -> events that WOULD have been evidence but were allowlisted

    def _exempt(self, e: NormalizedEvent, rule: str) -> bool:
        """Per-event allowlist (verified identity / IP / ASN), decided during normalization. Only the single event
        is exempt; its neighbours and the agent's other events are scored as usual."""
        if self.cfg.apply_allowlist and rule in e.exempt_rules:
            self.exempted[rule] += 1
            return True
        return False

    def _learns(self, e: NormalizedEvent) -> bool:
        """May this event teach 'known destinations'? An allow-listed event must not: otherwise one verified post would
        make the host 'known' and let an unverified event from the same agent id to that host pass unnoticed."""
        return not (self.cfg.apply_allowlist and e.exempt_rules & {"R3", "R4"})

    def _baseline(self, evs: Sequence[NormalizedEvent]) -> Optional[List[NormalizedEvent]]:
        """Events in the first ``baseline_min_seconds``; None if too few to be a baseline."""
        t0 = evs[0].ts
        base = [e for e in evs if e.ts < t0 + self.cfg.baseline_min_seconds]
        return base if len(base) >= self.cfg.baseline_min_events else None

    def evaluate_agent(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        evs = sorted(evs, key=lambda e: e.ts)
        if not evs:
            return []
        flags: List[RuleFlag] = []
        base = self._baseline(evs)
        base_end = evs[0].ts + self.cfg.baseline_min_seconds
        if base is not None:
            tool_counts = Counter(e.tool for e in base if e.action == "tool_call")
            base_tools: Set[str] = {t for t in tool_counts if t}
            base_hosts: Set[str] = {e.dest_host for e in base if e.dest_external and e.dest_host}
            flags += self._r1(agent, evs, base_tools, base_end)
            flags += self._r3(agent, evs, base_hosts, base_end)
            flags += self._r4(agent, evs, base_hosts, base_end)
        flags += self._r2(agent, evs)
        flags += self._r5(agent, evs)
        flags += self._r6(agent, evs)
        flags += self._r7(agent, evs)
        if self.web.enabled:
            flags += self._r8(agent, evs)
            flags += self._r9(agent, evs)
            flags += self._r10(agent, evs)
        return flags

    def evaluate(self, by_agent: Dict[str, List[NormalizedEvent]]) -> List[RuleFlag]:
        out: List[RuleFlag] = []
        self.exempted.clear()
        for a in sorted(by_agent):
            out += self.evaluate_agent(a, by_agent[a])
        return out

    # -- R1 ------------------------------------------------------------------------------------------
    def _r1(self, agent: str, evs: Sequence[NormalizedEvent], base_tools: Set[str], base_end: float) -> List[RuleFlag]:
        c = self.cfg
        declared = self.policy.declared_tools.get(agent, frozenset())
        known = base_tools | set(declared)      # declared tools are part of the agent's expected behaviour
        hits: Dict[str, List[NormalizedEvent]] = {}
        last_untrusted: Optional[NormalizedEvent] = None
        for e in evs:
            if e.ts < base_end:
                continue
            if e.untrusted:
                last_untrusted = e
                continue
            if (last_untrusted is not None and e.action == "tool_call" and e.tool not in known
                    and e.ts - last_untrusted.ts <= c.untrusted_window_s and not self._exempt(e, "R1")):
                hits.setdefault(last_untrusted.event_id, [last_untrusted]).append(e)
        if not hits:
            return []
        evidence: List[NormalizedEvent] = [x for v in hits.values() for x in v]
        tools = sorted({e.tool for v in hits.values() for e in v[1:] if e.tool})
        return [RuleFlag(
            "R1", "Untrusted content followed by a sudden shift in tool usage", agent, [atlas_ref("AML.T0051")],
            _strength(0.75, len(hits)),
            f"After reading untrusted content, the agent invoked tool(s) {tools} that it neither used in its baseline "
            f"period nor declared, within {c.untrusted_window_s:.0f}s. Consistent with injected instructions steering the agent.",
            [_ev(e) for e in evidence[: c.max_evidence]], extra={"new_tools": tools, "episodes": len(hits)})]

    # -- R2 ------------------------------------------------------------------------------------------
    def _r2(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        declared = self.policy.declared_tools.get(agent)
        if declared is None:
            return []
        bad = [e for e in evs if e.action == "tool_call" and e.tool not in declared and not self._exempt(e, "R2")]
        if not bad:
            return []
        tools = sorted({e.tool for e in bad if e.tool})
        return [RuleFlag(
            "R2", "Tool calls outside the agent's declared purpose", agent, [atlas_ref("AML.T0053")],
            _strength(0.7, len(bad)),
            f"{len(bad)} call(s) to tool(s) {tools} that are not in the agent's declared tool list "
            f"({sorted(declared)}).",
            [_ev(e) for e in bad[: self.cfg.max_evidence]], extra={"tools": tools, "count": len(bad)})]

    # -- R3 ------------------------------------------------------------------------------------------
    def _r3(self, agent: str, evs: Sequence[NormalizedEvent], base_hosts: Set[str], base_end: float) -> List[RuleFlag]:
        seen = set(base_hosts)
        hits: List[NormalizedEvent] = []
        for e in evs:
            if e.ts < base_end:
                continue
            if e.dest_external and e.dest_host:
                if (e.tool in self.write_tools or (e.action == "write" and e.tool is None)) \
                        and e.dest_host not in seen and e.payload_bytes >= self.cfg.min_exfil_bytes and not e.denied \
                        and not self._exempt(e, "R3"):
                    hits.append(e)
                if self._learns(e):
                    seen.add(e.dest_host)
        if not hits:
            return []
        hosts = sorted({e.dest_host for e in hits if e.dest_host})
        total = sum(e.payload_bytes for e in hits)
        return [RuleFlag(
            "R3", "Write-capable tool sending data to a new external destination", agent, [atlas_ref("AML.T0086")],
            _strength(0.8, len(hits)),
            f"{len(hits)} write/send call(s) moved {total} bytes to {len(hosts)} external host(s) never contacted "
            f"before ({hosts}). Consistent with data leaving via an agent tool.",
            [_ev(e) for e in hits[: self.cfg.max_evidence]], extra={"new_hosts": hosts, "bytes": total})]

    # -- R4 ------------------------------------------------------------------------------------------
    def _r4(self, agent: str, evs: Sequence[NormalizedEvent], base_hosts: Set[str], base_end: float) -> List[RuleFlag]:
        c = self.cfg
        pairs: List[NormalizedEvent] = []
        last_u: Optional[NormalizedEvent] = None
        seen = set(base_hosts)
        for e in evs:
            if e.untrusted:
                last_u = e
            elif (e.ts >= base_end and last_u is not None and e.outbound and not e.denied and e.dest_host
                  and e.dest_host not in seen and e.ts - last_u.ts <= c.immediate_window_s
                  and not self._exempt(e, "R4")):
                pairs += [last_u, e]
            if e.dest_external and e.dest_host and self._learns(e):
                seen.add(e.dest_host)
        if not pairs:
            return []
        return [RuleFlag(
            "R4", "Immediate call to a new external destination after reading untrusted text", agent,
            [atlas_ref("AML.T0051")], _strength(0.7, len(pairs) // 2),
            f"{len(pairs) // 2} outbound call(s) to previously unseen external hosts within "
            f"{c.immediate_window_s:.0f}s of reading untrusted content. Consistent with injected instructions.",
            [_ev(e) for e in pairs[: c.max_evidence]], extra={"episodes": len(pairs) // 2})]

    # -- R5 ------------------------------------------------------------------------------------------
    def _r5(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        c = self.cfg
        denied = [e for e in evs if e.denied and not self._exempt(e, "R5")]
        sens_denied = [e for e in denied if e.sensitive]
        if (len(denied) >= c.access_min_denied and len(denied) / len(evs) >= c.access_min_denied_ratio
                and len(sens_denied) >= c.access_min_sensitive):
            distinct = len({e.resource_key for e in sens_denied})
            return [RuleFlag(
                "R5", "Access probing: many denied requests on sensitive resources", agent, [atlas_ref("AML.T0075")],
                _strength(0.7, distinct // 3),
                f"{len(denied)} of {len(evs)} requests were denied ({len(sens_denied)} on sensitive resources, "
                f"{distinct} distinct). Consistent with an agent enumerating resources it is not authorised to use.",
                [_ev(e) for e in sens_denied[: c.max_evidence]],
                extra={"denied": len(denied), "sensitive_denied": len(sens_denied), "distinct_resources": distinct})]
        return []


    # -- R6 / R7: honeypot interactions (no baseline needed: legitimate agents are never sent to decoys) -----------------
    def _r6(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        board = [e for e in evs if e.honeypot in ("coordination_board", "claim_shard")]
        if not board:
            return []
        atlas = [atlas_ref("AML.T0051")]
        if any(e.action == "tool_call" or e.tool for e in board):
            atlas.append(atlas_ref("AML.T0053"))
        if any(e.action in ("write", "message") and e.payload_bytes > 0 for e in board):
            atlas.append(atlas_ref("AML.T0086"))
        issued = sum(len(e.issued) for e in board)
        shown = sum(e.presented is not None for e in board)
        return [RuleFlag(
            "R6", "Engaged the decoy coordination-board protocol", agent, atlas, _strength(0.7, 1 + (shown > 0) * 2),
            f"The agent made {len(board)} request(s) to honeypot coordination-board endpoints that no legitimate workflow "
            f"points to ({issued} token(s) issued to it, {shown} token presentation(s)). Consistent with an agent acting on "
            f"instructions it found in untrusted content.",
            [_ev(e) for e in board[: self.cfg.max_evidence]], extra={"board_events": len(board), "tokens_issued": issued, "tokens_presented": shown})]

    def _r7(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        caps = [e for e in evs if e.honeypot == "cognitive_capture"]
        if not caps:
            return []
        atlas = [atlas_ref("AML.T0051")]
        meta = next((e.capture for e in caps if e.capture is not None), None)
        if meta is not None and meta.declared_tools:
            atlas.append(atlas_ref("AML.T0053"))
        atlas.append(atlas_ref("AML.T0086"))
        extra: Dict[str, object] = {"capture_events": len(caps)}
        if meta is not None:
            extra["capture"] = meta.to_untrusted_dict()
        return [RuleFlag(
            "R7", "Disclosed its own context to a decoy (cognitive capture)", agent, atlas, _strength(0.85, len(caps)),
            f"The agent sent its own configuration (system-prompt summary / tools / objective / message) to a decoy in "
            f"{len(caps)} request(s). The captured text is attacker-controlled and shown only as sanitized, truncated data.",
            [_ev(e) for e in caps[: self.cfg.max_evidence]], extra=extra)]

    # -- R8 / R9 / R10: web-collector evidence (single facts, not session averages) -----------------------------------
    def _r8(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        w = self.web
        web = [e for e in evs if e.web is not None]
        if not web or any(e.web is not None and e.web.content_kind == "asset" for e in web):
            return []
        if not any(e.web is not None and e.web.ua_class == "browser" for e in web):
            return []                          # a client that declares itself a script/bot is not pretending to be a browser
        pages = [e for e in web if e.web is not None and e.web.content_kind == "html" and e.status == "allowed"]
        if len(pages) < w.asset_starvation_min_pages:
            return []
        checked = [e for e in pages if e.web is not None and e.web.sec_fetch_mismatch is not None]
        mism = [e for e in checked if e.web is not None and e.web.sec_fetch_mismatch]
        sec = bool(checked) and len(mism) / len(checked) >= 0.5
        return [RuleFlag(
            "R8", "Browser-like client that never fetches page assets", agent, [atlas_ref("AML.T0075")],
            w.strength_asset_starvation_sec_fetch if sec else w.strength_asset_starvation,
            f"{len(pages)} HTML pages requested with a browser-like User-Agent and zero CSS/JS/image/favicon fetches"
            + (f"; {len(mism)}/{len(checked)} page loads also lack the Sec-Fetch-* headers a browser sends" if checked else
               "; Sec-Fetch-* headers were not supplied by the collector (not checked)")
            + ". Contact/behaviour evidence only: text-mode browsers, reader modes and ad-blockers look the same.",
            [_ev(e) for e in pages[: self.cfg.max_evidence]], extra={"pages": len(pages), "sec_fetch_mismatch": len(mism), "sec_fetch_checked": len(checked)})]

    def _r9(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        w = self.web
        jumps = [e for e in evs if e.web is not None and e.web.linked_from_prev is False and not e.web.referer_valid]
        never = [e for e in jumps if e.web is not None and not e.web.offered_earlier]
        earlier = len(jumps) - len(never)
        if len(never) < w.unlinked_min_never_offered:
            return []
        s = min(w.strength_unlinked_jump_cap, w.strength_unlinked_jump + 0.05 * (len(never) - w.unlinked_min_never_offered))
        return [RuleFlag(
            "R9", "Moves to URLs that no page offered this client", agent, [atlas_ref("AML.T0075")], round(s, 3),
            f"{len(never)} transition(s) went to a URL that no page served to this client had linked, with no valid Referer "
            f"({earlier} further queue-style move(s) to URLs offered earlier were not counted). Consistent with guessed or "
            f"remembered URLs; a person who types addresses does the same.",
            [_ev(e) for e in never[: self.cfg.max_evidence]], extra={"never_offered": len(never), "offered_earlier": earlier})]

    def _r10(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        w = self.web
        sig = [e for e in evs if e.web is not None and (e.web.strong_signal or e.web.mcp == "tools_call")]
        if not sig:
            return []
        kinds = sorted({(e.web.strong_signal or "mcp_tools_call") for e in sig if e.web is not None})
        decoys = {e.web.decoy_kind for e in sig if e.web is not None and e.web.decoy_kind}
        weak = {"hidden_link", "decoy_hit"}
        adaptive = [k for k in kinds if k not in weak]
        strong = bool(adaptive) or len(decoys) >= w.strong_distinct_decoys
        floor = w.floor_strong if strong else w.floor_weak
        tier = "strong" if strong else "weak"
        return [RuleFlag(
            "R10", "Single high-signal event (score floor)", agent, [atlas_ref("AML.T0075")], round(floor, 3),
            f"{len(sig)} high-signal event(s): {kinds}"
            + (f" across {len(decoys)} decoy kind(s)" if decoys else "")
            + (". Used something a decoy offered (a parsed schema, a tool call, a canary): adaptive behaviour." if strong else
               ". A single decoy contact: an accidental scraper follows hidden links too. Contact, not intent.")
            + " Sets a floor that unrelated benign events cannot dilute.",
            [_ev(e) for e in sig[: self.cfg.max_evidence]],
            extra={"floor": round(floor, 3) if w.floors_enabled else None, "tier": tier, "signals": kinds, "distinct_decoys": len(decoys)})]


# Stable registry used by docs/tests: every rule id and the techniques it may emit.
RULE_ATLAS: Dict[str, List[str]] = {
    "R1": ["AML.T0051"], "R2": ["AML.T0053"], "R3": ["AML.T0086"], "R4": ["AML.T0051"], "R5": ["AML.T0075"],
    # R6/R7 emit a subset of these depending on the evidence (T0051 is always present)
    "R6": ["AML.T0051", "AML.T0053", "AML.T0086"], "R7": ["AML.T0051", "AML.T0053", "AML.T0086"],
    "R8": ["AML.T0075"], "R9": ["AML.T0075"], "R10": ["AML.T0075"],
}
assert all(t in ATLAS_TECHNIQUES for ts in RULE_ATLAS.values() for t in ts)
