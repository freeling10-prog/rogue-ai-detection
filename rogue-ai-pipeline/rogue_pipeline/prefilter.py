"""Commodity-scanner pre-filter (v3).

Internet-wide scanners and exploit kits (zgrab, masscan, censys, shodan, nmap, WordPress/PHP/.env/phpmyadmin probes)
hit every public host all day.  They are not the "autonomous AI agent" population this pipeline looks for, they poison
a benign baseline (huge denied-request counts, probing sensitive-looking paths) and they bury real leads.  So, BEFORE
scoring and BEFORE baseline training, a client is tagged ``commodity_scanner`` and set aside when

* at least ``scanner_path_min_share`` (default 80%) of its web events are scanner-path requests (``/wp-login.php``, ``/.env``, ``/phpmyadmin``, ``*.php`` ...), or
* any of its web events carries a known scanner User-Agent (zgrab, masscan, censys, shodan, nmap ...),

UNLESS it also shows goal-directed evidence (a decoy was used, an MCP tool was called, a schema parameter was sent, a
session canary was presented, a honeypot protocol was engaged).  The User-Agent is trivially spoofable, so a scanner UA
must never be a way to hide: a client that looks like zgrab but calls an MCP tool stays in.

Only events that carry a ``web`` block are ever considered; non-web traffic is never filtered, so existing (non-web)
behaviour is byte-identical.  Filtered clients are COUNTED and reported (``PipelineResult.prefiltered``, the audit log,
the lead report), not silently dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from .config import WebCfg
from .schema import NormalizedEvent

# A bare decoy touch (``decoy_hit`` / ``hidden_link``) is NOT exempting: scanners hit the /.env and /wp-login decoys constantly.
# Using what a decoy *offered* (parsing a schema, calling an MCP tool, presenting a canary) is.
GOAL_DIRECTED_SIGNALS = frozenset({"session_canary", "schema_param", "error_hint_follow", "mcp_tools_call", "mcp_list_then_call",
                                   "fake_credential_use"})


@dataclass
class PrefilterReport:
    agents: int = 0
    events: int = 0
    by_reason: Dict[str, int] = field(default_factory=dict)         # reason -> agents
    kept_scanner_like_with_goal_evidence: int = 0                    # scanner-looking clients retained because of goal-directed evidence
    filtered_agents: List[str] = field(default_factory=list)         # pseudonyms

    def as_dict(self) -> Dict[str, object]:
        return {"agents_filtered": self.agents, "events_filtered": self.events, "by_reason": dict(sorted(self.by_reason.items())),
                "kept_scanner_like_with_goal_evidence": self.kept_scanner_like_with_goal_evidence}


def has_goal_directed_evidence(evs: Sequence[NormalizedEvent]) -> bool:
    return any(e.honeypot or (e.web is not None and (e.web.strong_signal in GOAL_DIRECTED_SIGNALS or e.web.mcp == "tools_call"))
               for e in evs)


def classify_scanner(evs: Sequence[NormalizedEvent], cfg: WebCfg) -> str:
    """'' (not a scanner) | 'scanner_ua' | 'scanner_path' | 'scanner_with_goal_evidence' (looks like one, but is kept)."""
    web = [e for e in evs if e.web is not None]
    if not web or len(web) < cfg.prefilter_min_events or len(web) != len(evs):
        return ""                                             # only clients whose events are ALL web-collector events
    reason = ""
    if any(e.web is not None and e.web.ua_class == "scanner" for e in evs):
        reason = "scanner_ua"
    elif sum(1 for e in evs if e.web is not None and e.web.scanner_path) >= cfg.scanner_path_min_share * len(evs):
        reason = "scanner_path"
    if not reason:
        return ""
    return "scanner_with_goal_evidence" if has_goal_directed_evidence(evs) else reason


def prefilter_by_agent(by_agent: Dict[str, List[NormalizedEvent]], cfg: WebCfg) -> Tuple[Dict[str, List[NormalizedEvent]], PrefilterReport]:
    """Return (kept clients, report).  A no-op (empty report) when disabled."""
    rep = PrefilterReport()
    if not (cfg.enabled and cfg.prefilter):
        return by_agent, rep
    kept: Dict[str, List[NormalizedEvent]] = {}
    for a, evs in by_agent.items():
        why = classify_scanner(evs, cfg)
        if why == "scanner_with_goal_evidence":
            rep.kept_scanner_like_with_goal_evidence += 1
        elif why:
            rep.agents += 1
            rep.events += len(evs)
            rep.by_reason[why] = rep.by_reason.get(why, 0) + 1
            rep.filtered_agents.append(a)
            continue
        kept[a] = evs
    return kept, rep
