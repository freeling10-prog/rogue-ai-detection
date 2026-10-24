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
  R11 browser_agent_inconsistency    (web, v4) a client that fetches HTML + scripts/styles like a browser but reports webdriver /
                                     automation properties through the interaction beacon, hits the ARIA canary, or clicks through
                                     several pages on a beacon-offering site without ever sending the beacon (weak, corroborate!)
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
from typing import Dict, FrozenSet, List, Mapping, Optional, Sequence, Set

from .atlas import ATLAS_MAPPING_NOTE, ATLAS_TECHNIQUES, atlas_ref
from .config import Layer2Cfg, ProbingCfg, ResolvedPolicy, ToolsCfg, WebCfg
from .probing import stats as probing_stats
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


@dataclass
class _Episode:
    """R12: one post-ingestion window that showed a changepoint."""
    ids: List[str]
    jump: bool = False
    chain: bool = False
    ratio: float = 0.0


def _strength(base: float, n: int) -> float:
    return round(min(1.0, base + 0.05 * max(0, n - 1)), 3)


class LinkGraph:
    """Empirical link graph (v4) learned from Referer transitions in the benign reference population when the collector recorded no
    offered links.  Everything is pseudonymous resource keys.  Leave-one-out: when judging client A, A's own transitions never
    support A's moves (support must come from >= ``link_min_support`` OTHER clients), so a client cannot validate itself."""

    def __init__(self) -> None:
        self.edges: Dict[tuple, Set[str]] = {}       # (referer_key, resource_key) -> clients that took it
        self.direct: Dict[str, Set[str]] = {}        # resource_key -> clients that requested it with no referer
        self.agents: Set[str] = set()

    @classmethod
    def learn(cls, by_agent: Mapping[str, Sequence[NormalizedEvent]]) -> "LinkGraph":
        g = cls()
        for a, evs in by_agent.items():
            for e in evs:
                w = e.web
                if w is None or w.content_kind != "html" or e.status != "allowed" or w.linked_from_prev is not None:
                    continue
                g.agents.add(a)
                if w.referer_key:
                    g.edges.setdefault((w.referer_key, w.path_key or e.resource_key), set()).add(a)
                else:
                    g.direct.setdefault(w.path_key or e.resource_key, set()).add(a)
        return g

    def merged(self, other: "LinkGraph") -> "LinkGraph":
        g = LinkGraph()
        for src in (self, other):
            for k, v in src.edges.items():
                g.edges.setdefault(k, set()).update(v)
            for k2, v2 in src.direct.items():
                g.direct.setdefault(k2, set()).update(v2)
            g.agents |= src.agents
        return g

    def usable(self, w: WebCfg) -> bool:
        return len(self.agents) >= 2 * w.link_min_support

    def allowed(self, agent: str, e: NormalizedEvent, w: WebCfg) -> bool:
        wf = e.web
        if wf is None or wf.is_entry:
            return True
        if wf.referer_key:
            return len(self.edges.get((wf.referer_key, wf.path_key or e.resource_key), set()) - {agent}) >= w.link_min_support
        return len(self.direct.get(wf.path_key or e.resource_key, set()) - {agent}) >= w.link_min_support


class RuleEngine:
    def __init__(self, cfg: Layer2Cfg, tools: ToolsCfg, policy: ResolvedPolicy, web: Optional[WebCfg] = None,
                 probing: Optional[ProbingCfg] = None) -> None:
        self.cfg = cfg
        self.web = web or WebCfg()
        self.probing = probing or ProbingCfg()
        self.write_tools: FrozenSet[str] = frozenset(tools.write_tools)
        self.policy = policy
        self.exempted: Counter = Counter()      # rule id -> events that WOULD have been evidence but were allowlisted
        self.link_graph: Optional["LinkGraph"] = None   # v4: empirical link graph for the R9 fallback (set by the pipeline)

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
        if self.cfg.r12_enabled:
            flags += self._r12(agent, evs, base_end if base is not None else None)
        if self.probing.enabled:
            flags += self._r13(agent, evs)
        if self.web.enabled:
            flags += self._r8(agent, evs)
            r9 = self._r9(agent, evs)
            r9 = r9 or self._r9_fallback(agent, evs)
            flags += self._r9_missing_cursor(agent, evs, r9)
            flags += self._r10(agent, evs)
            flags += self._r11(agent, evs)
            if self.web.r14_enabled:
                flags += self._r14(agent, evs)
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
    def _core(self, e: NormalizedEvent) -> bool:
        """Is this a CSS/JS (core rendering) asset fetch?  Legacy events without an asset kind count as core."""
        w = e.web
        return w is not None and w.content_kind == "asset" and (w.asset_kind is None or w.asset_kind in self.web.core_asset_kinds)

    def _r8(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """v4: selective blocking is NOT starvation.  A browser-claiming client that loaded core CSS/JS, or whose Sec-Fetch-* headers
        are valid and coherent, is not flagged merely for skipping images (image-blocking humans, data-saver modes, reader modes).
        R8 is reserved for >= N HTML pages with no core asset AND missing/incoherent Sec-Fetch-*, or contradictory Sec-Fetch-* headers."""
        w = self.web
        web = [e for e in evs if e.web is not None]
        if not web or not any(e.web is not None and e.web.ua_class == "browser" for e in web):
            return []                          # a client that declares itself a script/bot is not pretending to be a browser
        pages = [e for e in web if e.web is not None and e.web.content_kind == "html" and e.status == "allowed"]
        if len(pages) < w.asset_starvation_min_pages:
            return []
        checked = [e for e in pages if e.web is not None and e.web.sec_fetch_mismatch is not None]
        mism = [e for e in checked if e.web is not None and e.web.sec_fetch_mismatch]
        contra = [e for e in pages if e.web is not None and e.web.sec_fetch_state == "contradictory"]
        coherent = [e for e in pages if e.web is not None and e.web.sec_fetch_state == "coherent"]
        n_core = sum(1 for e in web if self._core(e))
        extra: Dict[str, object] = {"pages": len(pages), "sec_fetch_mismatch": len(mism), "sec_fetch_checked": len(checked),
                 "contradictory": len(contra), "core_assets": n_core}
        note = (" Contact/behaviour evidence only: text-mode browsers, reader modes and ad-blockers look the same.")
        if len(contra) >= 3 and len(contra) / len(pages) >= 0.5:
            return [RuleFlag(
                "R8", "Browser-like client with contradictory Sec-Fetch headers", agent, [atlas_ref("AML.T0075")],
                w.strength_asset_starvation_sec_fetch,
                f"{len(contra)}/{len(pages)} page loads carry Sec-Fetch-* headers that contradict a top-level navigation "
                f"(e.g. Dest/Mode of an embedded sub-resource on a document request), with a browser-like User-Agent." + note,
                [_ev(e) for e in contra[: self.cfg.max_evidence]], extra=extra)]
        if n_core:
            return []                          # it rendered the page: only images (or nothing else) were skipped
        if coherent and len(coherent) / len(pages) >= 0.8:
            return []                          # valid, coherent Sec-Fetch-Dest: document / Mode: navigate on (nearly) every page load
        sec = bool(checked) and len(mism) / len(checked) >= 0.5
        return [RuleFlag(
            "R8", "Browser-like client that never fetches CSS/JS", agent, [atlas_ref("AML.T0075")],
            w.strength_asset_starvation_sec_fetch if sec else w.strength_asset_starvation,
            f"{len(pages)} HTML pages requested with a browser-like User-Agent and zero CSS/JS fetches"
            + (f"; {len(mism)}/{len(checked)} page loads also lack the Sec-Fetch-* headers a browser sends" if checked else
               "; Sec-Fetch-* headers were not supplied by the collector (not checked)") + "." + note,
            [_ev(e) for e in pages[: self.cfg.max_evidence]], extra=extra)]

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

    def _r9_fallback(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """v4: R9 when the collector recorded no offered links (ordinary nginx/Apache logs).  The allowed link graph is inferred
        from Referer transitions other clients took in the benign reference (``LinkGraph``); an HTML move that is not an entry
        point, is not a transition >= ``link_min_support`` other clients took, and is not a popular direct-landing page counts
        as a jump.  Noisier than the exact graph (hence higher count, lower strength): it only knows what the log population shows."""
        w, g = self.web, self.link_graph
        if not w.link_graph_fallback or g is None or not g.usable(w):
            return []
        pages = [e for e in evs if e.web is not None and e.web.content_kind == "html" and e.status == "allowed"
                 and e.web.linked_from_prev is None and e.web.offered_earlier is None]
        if len(pages) < w.link_fallback_min_jumps:
            return []
        jumps = [e for e in pages if e.web is not None and not g.allowed(agent, e, w)]
        if len(jumps) < w.link_fallback_min_jumps:
            return []
        return [RuleFlag(
            "R9", "Moves to URLs that no observed navigation path leads to (inferred link graph)", agent, [atlas_ref("AML.T0075")],
            w.link_fallback_strength,
            f"{len(jumps)} of {len(pages)} page moves went to a URL that other clients reach only by direct landing or by a different "
            f"referring page, and that this client did not reach through a known Referer transition. The link graph here is INFERRED from "
            f"benign Referer transitions (no offered-links record exists in this log), so a person with bookmarks looks the same.",
            [_ev(e) for e in jumps[: self.cfg.max_evidence]], extra={"fallback": True, "jumps": len(jumps), "pages": len(pages)})]

    def _r11(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """Browser-backed client behaving like automation (v4, revised in v6).

        STRONG (floor ``floor_strong``): the beacon reports webdriver / automation globals; ARIA canary hit by a rendering client;
        ``beacon_forged`` (a beacon whose per-page challenge proof did not verify: canned / replayed JSON); ``vlm_quantized_interaction``
        (valid proof, i.e. our JS ran, but >= ``vlm_min_beacons`` beacons with pointer movement, NO inertial scroll and a zero-dwell /
        collinear click, or one such beacon plus the DOM-visual inversion link); ``dom_order_synthetic_click`` (the inversion link
        that is first in DOM order but rendered last, plus a zero-dwell click with no pointer movement or a forged beacon).
        WEAK with floor ``floor_weak``: ``script_fetched_but_unexecuted`` - fetched our .js, clicked through, never posted a valid
        beacon - ONLY when the navigation headers are NOT coherent or a decoy was touched.
        CORROBORATE (no floor, strength ``strength_corroborate``; needs another family): the inversion link alone (screen-reader and
        keyboard users traverse DOM order too) or repeated zero-dwell clicks without pointer movement.
        v6 REMOVES the v4 'no_render_no_beacon' reason and the missing-beacon reason for clients with js_assets_fetched == 0 or coherent
        headers: those were the beacon-blocking / NoScript / text-mode human false positives."""
        w = self.web
        web = [e for e in evs if e.web is not None]
        if not web or not any(e.web is not None and e.web.ua_class == "browser" for e in web):
            return []
        pages = [e for e in web if e.web is not None and e.web.content_kind == "html" and e.status == "allowed"]
        beacons = [e for e in web if e.web is not None and e.web.content_kind == "beacon" and e.web.beacon is not None]
        js_counts = [e.web.js_assets_fetched for e in web if e.web is not None and e.web.js_assets_fetched is not None]
        js_fetched = max(js_counts) if js_counts else sum(
            1 for e in web if e.web is not None and e.web.content_kind == "asset" and e.web.asset_kind == "js" and e.status == "allowed")
        loaded_core = any(self._core(e) for e in web)
        sigs = set().union(*[e.web.signals for e in web if e.web is not None])
        reasons: List[str] = []
        weak_reasons: List[str] = []
        ev: List[NormalizedEvent] = []
        strong = False

        def bx(e: NormalizedEvent) -> tuple:
            return e.web.beacon_ext if e.web is not None and e.web.beacon_ext is not None else (None, None, None)

        forged = [e for e in beacons if bx(e)[0] is False] + [
            e for e in web if e.web is not None and ("beacon_forged" in e.web.signals or e.web.decoy_kind == "beacon_forged")]
        forged_ids = {e.event_id for e in forged}
        valid = [e for e in beacons if e.event_id not in forged_ids]          # legacy beacons without a proof field count as valid (v4 compat)
        for e in valid:
            b = e.web.beacon if e.web is not None else None
            if b is None:
                continue
            if b[0]:                           # (webdriver_present, pointer_trail_seen, dom_automation_props)
                reasons.append("webdriver_present"); ev.append(e); strong = True
            if b[2]:
                reasons.append("dom_automation_props"); ev.append(e); strong = True
        aria = [e for e in web if e.web is not None and e.web.strong_signal == "aria_fastpath"]
        if aria and (loaded_core or len(pages) >= 2):
            reasons.append("aria_canary_hit"); ev += aria; strong = True
        if forged:
            reasons.append("beacon_forged"); ev += forged; strong = True
        inversion = [e for e in web if e.web is not None and ("dom_visual_inversion_hit" in e.web.signals
                                                              or e.web.decoy_kind == "dom_visual_inversion_hit")]
        vlm = [e for e in valid if e.web is not None and e.web.beacon is not None and bx(e)[0] is True and bx(e)[2] is False
               and e.web.beacon[1] and (bx(e)[1] is False or inversion)]
        if len(vlm) >= w.vlm_min_beacons or (vlm and inversion):
            reasons.append("vlm_quantized_interaction"); ev += vlm + inversion[:1]; strong = True
        elif "vlm_quantized_interaction" in sigs:
            weak_reasons.append("collector_vlm_signal_not_corroborated_by_beacon_booleans")
        synth = [e for e in valid if e.web is not None and e.web.beacon is not None and bx(e)[1] is False and not e.web.beacon[1]]
        if inversion and js_fetched > 0 and (synth or forged):     # contract: strong only for a script-fetching client without kinematics
            reasons.append("dom_order_synthetic_click"); ev += inversion + synth[:2]; strong = True
        elif inversion:
            weak_reasons.append("dom_visual_inversion_hit"); ev += inversion
        elif len(synth) >= w.synthetic_click_min_beacons:
            weak_reasons.append("synthetic_click_no_pointer"); ev += synth
        tier = "strong" if strong else ""
        ignored: List[str] = []
        if not strong:
            navs = [e for e in pages if e.web is not None and e.web.referer_present]
            offered = any(e.web is not None and e.web.beacon_offered for e in pages)
            coherent = bool(pages) and sum(1 for e in pages if e.web is not None and e.web.sec_fetch_state == "coherent") / len(pages) >= w.nav_coherent_share
            # the inversion link is context-only (crawlers and keyboard users reach it): it is not a "decoy touched" here
            decoy = any(e.web is not None and (e.web.strong_signal or (e.web.decoy_kind and e.web.decoy_kind != "dom_visual_inversion_hit"))
                        for e in web)
            missing = offered and not valid and len(navs) >= w.beacon_min_navs
            if missing and js_fetched > 0 and (not coherent or decoy):
                reasons.append("script_fetched_but_unexecuted"); ev += navs; tier = "weak"
            elif "script_fetched_but_unexecuted" in sigs or missing:
                # the collector's signal (or the v4 missing-beacon fact) is NOT accepted alone for NoScript/blocked-beacon look-alikes
                ignored.append("missing_beacon_exempt:" + ("no_js_fetched" if js_fetched == 0 else "coherent_navigation_headers"))
        if not reasons and not weak_reasons:
            return []
        if not reasons:
            tier = "corroborate"
        uniq = sorted(set(reasons)) + sorted(set(weak_reasons))
        floor = w.floor_strong if tier == "strong" else w.floor_weak if tier == "weak" else None
        strength = max(w.strength_browser_inconsistency, w.floor_strong) if tier == "strong" else \
            w.strength_browser_inconsistency if tier == "weak" else w.strength_corroborate
        title = {"strong": "Browser-backed client behaving like automation",
                 "weak": "Browser-like client that fetched our script but never ran it",
                 "corroborate": "Browser-backed client with one weak automation hint (needs corroboration)"}[tier]
        expl = {"strong": "The client reported automation properties, forged the beacon's challenge proof, interacted in quantized OS-level "
                          "jumps with zero-dwell clicks, or clicked a link in DOM order that is rendered last. A person does not normally do "
                          "these (a screen-reader user can reach the DOM-order link; the decoys are read-only, synthetic).",
                "weak": "Fetched our .js and clicked through pages but never posted a valid beacon, with navigation headers that are not those "
                        "of a coherent browser (or a decoy was touched). Blocked beacons do this too: weak evidence, queue-only.",
                "corroborate": "Followed the DOM-first/visually-last link, or produced repeated zero-dwell clicks without pointer movement. "
                               "Keyboard and screen-reader users can do both, so this never creates a lead on its own."}[tier]
        extra: Dict[str, object] = {"floor": round(floor, 3) if (floor is not None and w.floors_enabled) else None, "tier": tier,
                                    "reasons": uniq, "js_assets_fetched": js_fetched}
        if ignored:
            extra["ignored"] = ignored
        return [RuleFlag("R11", title, agent, [atlas_ref("AML.T0075")], round(strength, 3),
                         f"Signals: {uniq}. " + expl + " Contact/behaviour evidence only, not intent.",
                         [_ev(e) for e in ev[: self.cfg.max_evidence]], extra=extra)]

    def _r10(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """v3 floors, plus v6: ``schema_provenance_cursor`` (a cursor that was only ever served inside /openapi.json, /llms.txt or POST /mcp,
        presented by a session that also browses HTML: it parsed the schema - adaptive, strong; a pure API client gets the weak tier) and
        ``llmjacking_probe`` (the decoy OpenAI-compatible endpoint, ATLAS AML.T0051 + AML.T0053: strong when the request carried tool
        definitions or an autonomous-loop directive, weak for a bare "is this endpoint open?" probe).  Decoys that belong to R11
        (``dom_visual_inversion_hit``, ``beacon_forged``) never set an R10 floor: a screen-reader user can reach the inversion link."""
        w = self.web
        r11_only = {"dom_visual_inversion_hit", "beacon_forged"}
        sig = [e for e in evs if e.web is not None and (e.web.strong_signal or e.web.mcp == "tools_call")
               and e.web.decoy_kind not in r11_only]
        browsing = any(e.web is not None and e.web.content_kind == "html" for e in evs)
        prov = [e for e in evs if e.web is not None and (e.web.cursor_prov == "schema" or "schema_provenance_cursor" in e.web.signals)]
        jack = [e for e in evs if e.web is not None and ("llmjacking_probe" in e.web.signals or e.web.decoy_kind == "llmjacking_probe"
                                                        or e.web.llmjacking is not None)]
        if not sig and not prov and not jack:
            return []
        kinds = sorted({(e.web.strong_signal or "mcp_tools_call") for e in sig if e.web is not None
                        if not (e.web.decoy_kind == "llmjacking_probe" and e.web.strong_signal == "decoy_hit")})
        decoys = {e.web.decoy_kind for e in sig if e.web is not None and e.web.decoy_kind}
        weak = {"hidden_link", "decoy_hit"}
        adaptive = [k for k in kinds if k not in weak]
        if prov:
            kinds.append("schema_provenance_cursor")
            if browsing:
                adaptive.append("schema_provenance_cursor")
        jack_strong = any(e.web is not None and e.web.llmjacking is not None and (e.web.llmjacking[0] > 0 or e.web.llmjacking[2]) for e in jack)
        if jack:
            kinds.append("llmjacking_probe")
            if jack_strong:
                adaptive.append("llmjacking_probe")
        kinds = sorted(set(kinds))
        sig = sig + [e for e in prov + jack if e not in sig]
        strong = bool(adaptive) or len(decoys) >= w.strong_distinct_decoys
        floor = w.floor_strong if strong else w.floor_weak
        tier = "strong" if strong else "weak"
        atlas = [atlas_ref("AML.T0075")] + ([atlas_ref("AML.T0051"), atlas_ref("AML.T0053")] if jack else [])
        extra_jack: Dict[str, object] = {}
        if jack:
            d = next((e.web.llmjacking for e in jack if e.web is not None and e.web.llmjacking is not None), None)
            extra_jack = {"llmjacking": {"requests": len(jack), "tool_count": d[0] if d else None,
                                         "system_prompt_len_bucket": d[1] if d else None, "autonomous_loop_directive": d[2] if d else None}}
        return [RuleFlag(
            "R10", "Single high-signal event (score floor)", agent, atlas, round(floor, 3),
            f"{len(sig)} high-signal event(s): {kinds}"
            + (f" across {len(decoys)} decoy kind(s)" if decoys else "")
            + (". Used something a decoy offered (a parsed schema, a tool call, a canary): adaptive behaviour." if strong else
               ". A single decoy contact: an accidental scraper follows hidden links too. Contact, not intent.")
            + " Sets a floor that unrelated benign events cannot dilute.",
            [_ev(e) for e in sig[: self.cfg.max_evidence]],
            extra={"floor": round(floor, 3) if w.floors_enabled else None, "tier": tier, "signals": kinds, "distinct_decoys": len(decoys),
                   **extra_jack})]

    # -- R9 (v6): stripped load-bearing cursors -------------------------------------------------------------------------------------
    def _r9_missing_cursor(self, agent: str, evs: Sequence[NormalizedEvent], r9: List[RuleFlag]) -> List[RuleFlag]:
        """v6: /kb/ pagination/detail and API routes require a ``cursor`` / ``page_ref`` that pages hand out; without it the collector
        answers 400 Missing Required Cursor.  Per the final agent-watch contract a BARE missing cursor is ADVISORY (a person who edits
        a URL by hand, a stale bookmark): it never creates a flag on its own.  It only strengthens an R9 flag that already exists
        (unlinked jumps / never-offered URLs): >= ``missing_cursor_min`` such requests raise that flag to at least
        ``strength_missing_cursor`` + 0.05 (capped) and are recorded in ``extra``."""
        w = self.web
        miss = [e for e in evs if e.web is not None and "missing_required_cursor" in e.web.signals]
        if len(miss) < w.missing_cursor_min or not r9:
            return r9
        f = r9[0]
        f.extra["missing_required_cursor"] = len(miss)
        f.strength = round(min(w.strength_unlinked_jump_cap, max(f.strength, w.strength_missing_cursor) + 0.05), 3)
        return r9

    # -- R12 (v6): routine-tool hijack after untrusted ingestion --------------------------------------------------------------------
    def _authorized(self, agent: str, evs: Sequence[NormalizedEvent], post_ids: Set[str]) -> Set[str]:
        declared = set(self.policy.declared_tools.get(agent, frozenset()))
        clean = Counter(e.tool for e in evs if e.action == "tool_call" and e.tool and e.event_id not in post_ids and not e.denied)
        return declared | {t for t, n in clean.items() if t is not None and n >= self.cfg.r12_min_clean_calls}

    def _r12(self, agent: str, evs: Sequence[NormalizedEvent], base_end: Optional[float]) -> List[RuleFlag]:
        """Partition the timeline at every untrusted read; an already-authorized routine EGRESS tool (declared, or used >= N times outside
        post-ingestion windows) then shows (a) a >= ``r12_jump_ratio`` jump in outbound argument size x entropy (bytes alone when the
        collector did not measure entropy) over that tool's clean median, within ``r12_post_steps`` events / ``r12_post_window_s``
        seconds after the read, and/or (b) the chain untrusted_read -> sensitive_internal_read -> routine_outbound_send within
        ``r12_chain_steps`` steps.  The destination may be a host the agent always uses: R3/R4 cannot see that case."""
        c = self.cfg
        evs = [e for e in evs if not self._exempt(e, "R12")]
        reads = [i for i, e in enumerate(evs) if e.untrusted and e.action == "read"]
        if not reads:
            return []
        post: Dict[str, int] = {}                           # event id -> index of the untrusted read it follows
        for r in reads:
            for k in range(r + 1, min(len(evs), r + 1 + c.r12_post_steps)):
                if evs[k].untrusted:
                    break
                if evs[k].ts - evs[r].ts <= c.r12_post_window_s:
                    post.setdefault(evs[k].event_id, r)
        auth = self._authorized(agent, evs, set(post))
        egress = lambda e: (e.action == "tool_call" and e.tool in auth and e.tool in self.write_tools and not e.denied
                            and e.payload_bytes > 0)

        def info(e: NormalizedEvent) -> float:
            return float(e.payload_bytes) * (e.arg_entropy / 4.0 if e.arg_entropy is not None else 1.0)

        # the routine baseline is per (tool, destination): "the webhook this agent always posts to", not every use of http_post
        clean_by_tool: Dict[tuple, List[float]] = {}
        clean_bytes: Dict[tuple, List[float]] = {}
        for e in evs:
            if egress(e) and e.event_id not in post and e.tool:
                clean_by_tool.setdefault((e.tool, e.dest_host), []).append(info(e))
                clean_bytes.setdefault((e.tool, e.dest_host), []).append(float(e.payload_bytes))
        episodes: Dict[int, _Episode] = {}
        for i, e in enumerate(evs):
            if not egress(e) or e.event_id not in post or not e.tool:
                continue
            ref = clean_by_tool.get((e.tool, e.dest_host), [])
            if len(ref) < c.r12_min_clean_calls:
                continue                                 # a destination this tool never routinely used: R3/R4 territory, not R12
            med = float(sorted(ref)[len(ref) // 2])
            refb = clean_bytes[(e.tool, e.dest_host)]
            medb = float(sorted(refb)[len(refb) // 2])
            r = post[e.event_id]
            beyond = info(e) >= c.r12_over_clean_max * max(ref) or e.payload_bytes >= c.r12_over_clean_max * max(refb)
            jump = (e.payload_bytes >= c.r12_min_post_bytes and med > 0 and beyond
                    and (info(e) / med >= c.r12_jump_ratio or (medb > 0 and e.payload_bytes / medb >= c.r12_jump_ratio)))
            chain = i - r <= c.r12_chain_steps and any(
                x.sensitive and x.action in ("read", "access") and not x.dest_external and not x.denied for x in evs[r + 1:i])
            if jump or chain:
                ep = episodes.setdefault(r, _Episode(ids=[evs[r].event_id]))
                ep.jump = ep.jump or jump
                ep.chain = ep.chain or chain
                ep.ratio = max(ep.ratio, round(info(e) / med, 2) if med > 0 else 0.0)
                ep.ids += [x.event_id for x in evs[r + 1:i + 1] if x.sensitive] + [e.event_id]
        if not episodes:
            return []
        both = any(ep.jump and ep.chain for ep in episodes.values())
        chain_any = any(ep.chain for ep in episodes.values())
        base = c.r12_strength_both if both else c.r12_strength_chain if chain_any else c.r12_strength_jump
        strength = round(min(c.r12_strength_cap, base + 0.05 * (len(episodes) - 1)), 3)
        ids = [x for ep in episodes.values() for x in ep.ids]
        by_id = {e.event_id: e for e in evs}
        kinds = sorted({"argument_jump" for ep in episodes.values() if ep.jump} | {"read_sensitive_send_chain" for ep in episodes.values() if ep.chain})
        return [RuleFlag(
            "R12", "Routine tool hijacked after reading untrusted content", agent, [atlas_ref("AML.T0080"), atlas_ref("AML.T0086")], strength,
            f"{len(episodes)} episode(s) after an untrusted read in which an already-authorized routine send tool changed behaviour: {kinds}. "
            f"Largest argument jump {max(ep.ratio for ep in episodes.values()):.1f}x the tool's own median outside such windows "
            f"(size x measured entropy). Consistent with planted context steering a trusted tool; a user who forwards a long document "
            f"does the same.",
            [_ev(by_id[x]) for x in dict.fromkeys(ids) if x in by_id][: self.cfg.max_evidence],
            extra={"episodes": len(episodes), "kinds": kinds, "authorized_tools": sorted(auth & self.write_tools)})]

    # -- R13 (v6): slow or shielded probing -----------------------------------------------------------------------------------------
    def _r13(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """CUSUM log-likelihood over boundary-probing actions (refused sensitive / access-check / non-existent URL requests), plus
        multi-horizon densities (any 3 and any 7 consecutive actions, and the full session) and ``subwindow_variance_collapse``.
        Thresholds come from ``ProbingCfg`` and were calibrated on benign reference sessions only (see ``probing.calibrate``).
        Families for the corroboration gate: CUSUM / densities = ``probing``; the timing collapse = ``timing`` (a second, independent
        fact about WHEN, not WHAT).  The collapse alone never fires R13: it only corroborates probing evidence."""
        pc = self.probing
        st = probing_stats(evs, pc)
        if st.n_events < pc.min_events or st.n_probes < pc.min_probes:
            return []
        reasons: List[str] = []
        if st.cusum_max >= pc.cusum_h:
            reasons.append("cusum")
        elif st.cusum_low >= pc.cusum_h_low:
            reasons.append("cusum_low_shift")
        if st.w3_max >= pc.w3_min:
            reasons.append("micro_window_w3")
        if st.w7_max >= pc.w7_min:
            reasons.append("micro_window_w7")
        if st.session_density >= pc.session_density_min:
            reasons.append("session_density")
        if not reasons and st.collapse and st.session_density >= pc.paced_rate_min:
            reasons.append("paced_probe_rate")       # probes above the benign tail rate, issued by a pacing controller
        if not reasons:
            return []
        fams = ["probing"]
        if st.collapse:
            reasons.append("subwindow_variance_collapse")
            fams.append("timing")
        n_prob = len([r for r in reasons if r != "subwindow_variance_collapse"])
        strength = pc.strength_strong if st.cusum_max >= pc.cusum_h * pc.cusum_h_strong else pc.strength_two if n_prob >= 2 else pc.strength_one
        by_id = {e.event_id: e for e in evs}
        return [RuleFlag(
            "R13", "Slow or shielded probing (sequential evidence)", agent, [atlas_ref("AML.T0075")], round(strength, 3),
            f"{st.n_probes} boundary-probing action(s) in {st.n_events}; reasons {reasons}. CUSUM peak {st.cusum_max:.1f} "
            f"(alarm at {pc.cusum_h:.1f}; small-shift CUSUM {st.cusum_low:.1f} vs {pc.cusum_h_low:.1f}; calibrated on benign sessions), densest 3-window {st.w3_max}/3, 7-window {st.w7_max}/7, "
            f"session share {st.session_density:.2f}"
            + (f"; timing is unnaturally regular in every sub-window yet not a clock ({st.collapse_detail})" if st.collapse else "")
            + ". Consistent with probing paced to keep session averages normal; a misconfigured client retrying refused URLs looks similar.",
            [_ev(by_id[x]) for x in st.probe_ids[: self.cfg.max_evidence] if x in by_id],
            extra={"reasons": reasons, "cusum_max": st.cusum_max, "cusum_h": pc.cusum_h, "cusum_low": st.cusum_low, "w3_max": st.w3_max, "w7_max": st.w7_max,
                   "probes": st.n_probes, "events": st.n_events, "collapse": st.collapse_detail, "families": fams})]

    # -- R14 (v6): parasitic session fork -------------------------------------------------------------------------------------------
    def _r14(self, agent: str, evs: Sequence[NormalizedEvent]) -> List[RuleFlag]:
        """Per-session Referer tree (parent = the latest earlier request whose path is this request's Referer).  A FORK is a suspicious
        request - unlinked without a valid Referer, or presenting a schema-provenance cursor - within ``r14_window_s`` of a human-branch
        page load (linked / valid Referer, HTML) on a DIFFERENT path that is neither its ancestor nor its descendant.  A stealth agent
        riding inside a real person's browser shares IP, UA, cookies and valid beacons, but its background sub-tree runs concurrently
        with the person's clicks.  >= ``r14_min_forks`` forks (or the collector's ``parasitic_session_fork`` signal) fire."""
        w = self.web
        nav = sorted([e for e in evs if e.web is not None and e.web.content_kind in ("html", "api", "other")], key=lambda e: e.ts)
        collector = [e for e in evs if e.web is not None and "parasitic_session_fork" in e.web.signals]
        if len(nav) < 4 and not collector:
            return []
        last_at: Dict[str, NormalizedEvent] = {}
        parent: Dict[str, Optional[str]] = {}
        for e in nav:
            wf = e.web
            assert wf is not None
            par = last_at.get(wf.referer_key) if wf.referer_key else None
            parent[e.event_id] = par.event_id if par is not None else None
            if wf.path_key:
                last_at[wf.path_key] = e

        def lineage(x: str) -> Set[str]:
            out: Set[str] = set()
            cur: Optional[str] = x
            while cur is not None and cur not in out and len(out) < 500:
                out.add(cur)
                cur = parent.get(cur)
            return out

        def suspicious(e: NormalizedEvent) -> bool:
            wf = e.web
            return wf is not None and (wf.cursor_prov == "schema" or "schema_provenance_cursor" in wf.signals
                                       or (wf.linked_from_prev is False and not wf.referer_valid))

        def human(e: NormalizedEvent) -> bool:
            wf = e.web
            return wf is not None and wf.content_kind == "html" and e.status == "allowed" and bool(wf.referer_valid or wf.linked_from_prev)

        forks: List[NormalizedEvent] = []
        partners: List[NormalizedEvent] = []
        sus = [e for e in nav if suspicious(e)]
        hum = [e for e in nav if human(e) and not suspicious(e)]
        for x in sus:
            lx = lineage(x.event_id)
            for y in hum:
                if abs(y.ts - x.ts) > w.r14_window_s or y.web is None or x.web is None or y.web.path_key == x.web.path_key:
                    continue
                if y.event_id in lx or x.event_id in lineage(y.event_id):
                    continue
                forks.append(x); partners.append(y)
                break
        n = len(forks) + len(collector)
        if n < w.r14_min_forks:
            return []
        prov = sum(1 for e in forks if e.web is not None and (e.web.cursor_prov == "schema" or "schema_provenance_cursor" in e.web.signals))
        strength = min(w.r14_strength_cap, w.r14_strength + 0.05 * (n - w.r14_min_forks) + (0.05 if prov else 0.0))
        return [RuleFlag(
            "R14", "Parasitic sub-tree forked off a live human session", agent, [atlas_ref("AML.T0075")], round(strength, 3),
            f"{n} request(s) ({prov} with a schema-provenance cursor) ran within {w.r14_window_s * 1000:.0f} ms of a human-branch page load "
            f"on a different path, outside that page's Referer lineage. Consistent with an agent piggybacking inside a person's browser "
            f"session (shared IP / cookies / beacons). Two people sharing one account or a browser extension can look similar.",
            [_ev(e) for e in (forks + partners + collector)[: self.cfg.max_evidence]],
            extra={"forks": n, "schema_provenance_forks": prov, "collector_signal": len(collector),
                   "fork_event_ids": [e.event_id for e in forks], "human_branch_event_ids": [e.event_id for e in partners]})]


# Stable registry used by docs/tests: every rule id and the techniques it may emit.
RULE_ATLAS: Dict[str, List[str]] = {
    "R1": ["AML.T0051"], "R2": ["AML.T0053"], "R3": ["AML.T0086"], "R4": ["AML.T0051"], "R5": ["AML.T0075"],
    # R6/R7 emit a subset of these depending on the evidence (T0051 is always present)
    "R6": ["AML.T0051", "AML.T0053", "AML.T0086"], "R7": ["AML.T0051", "AML.T0053", "AML.T0086"],
    "R8": ["AML.T0075"], "R9": ["AML.T0075"],
    "R10": ["AML.T0075", "AML.T0051", "AML.T0053"],          # v6: T0051 + T0053 only when the llmjacking decoy was used
    "R11": ["AML.T0075"],
    "R12": ["AML.T0080", "AML.T0086"], "R13": ["AML.T0075"], "R14": ["AML.T0075"],
}
assert all(t in ATLAS_TECHNIQUES for ts in RULE_ATLAS.values() for t in ts)

# v6: independent rule FAMILIES for the two-signal corroboration gate.  Rules in one family look at the same kind of fact and can
# never corroborate each other; a flag may name its own families in ``extra["families"]`` (R13: probing + timing).
RULE_FAMILY: Dict[str, str] = {
    "R1": "tool_use", "R2": "tool_use", "R3": "tool_use", "R4": "tool_use", "R12": "tool_use",
    "R5": "probing", "R13": "probing",
    "R6": "honeypot", "R7": "honeypot",
    "R8": "navigation", "R9": "navigation",
    "R10": "web_interaction", "R11": "web_interaction",
    "R14": "session_fork",
}


def rule_families(f: RuleFlag) -> List[str]:
    fams = f.extra.get("families")
    if isinstance(fams, list) and fams:
        return [str(x) for x in fams]
    return [RULE_FAMILY.get(f.rule_id, f.rule_id)]
