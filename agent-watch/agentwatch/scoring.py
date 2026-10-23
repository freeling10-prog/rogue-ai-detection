"""Rules-and-threshold scoring: human vs static bot vs goal-directed agent.

Two explainable scores (0-100) are produced per session:

* automation_score - "is a machine driving this?"  timing regularity/entropy,
  speed, missing browser behaviour, scripted/bot UA, honeytoken contact.
* agent_score      - "is it goal-directed and adaptive?"  adaptation after
  blocks, tool chaining, parameter/header evasion, honeytoken/canary hits,
  deep navigation.

Class label:
    agent_score >= thresholds.agent            -> "agent"
    else automation_score >= thresholds.automation -> "static_bot"
    else                                        -> "human"

Every contributing rule appends a human-readable string to `reasons`.
All weights/thresholds live in config.py / config/thresholds.json.
"""
from __future__ import annotations

import math
import re
import statistics
from dataclasses import dataclass, field
from typing import Any

from .detectors import is_asset, page_requests, run_detectors, ttna_stats
from .models import Finding, Request, Session

SEVERITIES = ("info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------
# timing statistics
# --------------------------------------------------------------------------
def intervals_seconds(reqs: list[Request]) -> list[float]:
    return [(b.ts - a.ts).total_seconds() for a, b in zip(reqs, reqs[1:])]


def interval_entropy(intervals: list[float], edges: list[float]) -> float:
    """Normalised Shannon entropy (0..1) of inter-request intervals.

    Intervals are binned on a log-ish scale (*edges*); 0 means every gap fell
    in one bin (fixed cadence), 1 means gaps spread evenly across all bins.
    """
    if not intervals:
        return 0.0
    bins = [0] * (len(edges) + 1)
    for x in intervals:
        idx = sum(1 for e in edges if x >= e)
        bins[idx] += 1
    n = len(intervals)
    h = -sum((c / n) * math.log2(c / n) for c in bins if c)
    return max(0.0, h) / math.log2(len(bins)) + 0.0


def coefficient_of_variation(intervals: list[float]) -> float:
    """std/mean of intervals; 0 for constant or all-zero (burst) gaps."""
    if len(intervals) < 2:
        return 0.0
    mean = statistics.fmean(intervals)
    if mean < 1e-9:
        return 0.0
    return statistics.pstdev(intervals) / mean


# --------------------------------------------------------------------------
# features
# --------------------------------------------------------------------------
def _matches(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text, re.I) for p in patterns)


def extract_features(session: Session, cfg: dict[str, Any]) -> dict[str, Any]:
    """Compute the numeric features used by the rules."""
    pages = page_requests(session, cfg)
    ivals = intervals_seconds(pages)
    edges = cfg["timing"]["entropy_bin_edges_s"]
    segs = [len([s for s in r.path.split("/") if s]) for r in pages]
    uniq = {r.path for r in pages}
    n = len(session.requests)
    assets = sum(1 for r in session.requests if is_asset(r, cfg))
    blocks = set(cfg["session"]["block_statuses"])
    ua_text = " ".join(session.user_agents)
    tt = ttna_stats(session, cfg) if cfg["ttna"]["enabled"] else None
    return {
        "ttna_pairs": tt["pairs"] if tt else None,
        "ttna_spearman": tt["spearman"] if tt else None,
        "ttna_band_fraction": tt["band_fraction"] if tt else None,
        "requests": n,
        "page_requests": len(pages),
        "duration_s": round((session.end - session.start).total_seconds(), 1),
        "asset_ratio": round(assets / n, 3) if n else 0.0,
        "referer_ratio": round(sum(1 for r in session.requests if r.referer) / n, 3) if n else 0.0,
        "interval_median_s": round(statistics.median(ivals), 3) if ivals else 0.0,
        "interval_cv": round(coefficient_of_variation(ivals), 3),
        "interval_entropy": round(interval_entropy(ivals, edges), 3),
        "max_depth": max(segs) if segs else 0,
        "unique_paths": len(uniq),
        "breadth_ratio": round(len(uniq) / len(pages), 3) if pages else 0.0,
        "blocked_responses": sum(1 for r in session.requests if r.status in blocks),
        "user_agents": len(session.user_agents),
        "bot_ua": _matches(cfg["ua"]["bot_patterns"], ua_text),
        "scripted_ua": _matches(cfg["ua"]["scripted_patterns"], ua_text),
        "benign_ua": bool(session.user_agents) and all(_matches(cfg["ua"]["benign_patterns"], u) for u in session.user_agents),
    }


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------
@dataclass
class SessionResult:
    session: Session
    features: dict[str, Any]
    findings: list[Finding]
    automation_score: int
    agent_score: int
    label: str                       # human | static_bot | agent
    severity: str
    reasons: list[str] = field(default_factory=list)
    benign: bool = False
    benign_reason: str = ""
    actor_type: str = ""             # goal_directed_agent | accidental_scraper | possible_mimic | static_bot | human
    floors: list[str] = field(default_factory=list)   # which single events set a score floor (max-pooling), for the report

    @property
    def honeytoken_hits(self) -> list[Finding]:
        return [f for f in self.findings if f.detector == "honeytoken"]


def _reason_rank(text: str) -> tuple[int, int]:
    m = re.match(r"\+(\d+) ", text)
    return (0, -int(m.group(1))) if m else (1, 0)


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


def _automation(feat: dict[str, Any], findings: list[Finding], cfg: dict[str, Any], reasons: list[str]) -> int:
    w = cfg["weights"]["automation"]
    t = cfg["timing"]
    score = 0
    if feat["page_requests"] >= t["min_requests"]:
        cv, ent, med = feat["interval_cv"], feat["interval_entropy"], feat["interval_median_s"]
        if cv <= t["cv_static_max"]:
            score += w["fixed_interval"]
            reasons.append(f"+{w['fixed_interval']} fixed-interval timing: CV {cv:.2f} <= {t['cv_static_max']} over {feat['page_requests']} requests")
        if ent <= t["entropy_static_max"]:
            score += w["low_entropy"]
            reasons.append(f"+{w['low_entropy']} low timing entropy {ent:.2f} <= {t['entropy_static_max']}")
        if med <= t["fast_median_s"]:
            score += w["fast_requests"]
            reasons.append(f"+{w['fast_requests']} machine-speed requests: median gap {med:.2f}s <= {t['fast_median_s']}s")
        if feat["asset_ratio"] < 0.05 and feat["referer_ratio"] < 0.05:
            score += w["no_assets_no_referer"]
            reasons.append(f"+{w['no_assets_no_referer']} no static assets and no Referer (not browser-like)")
        if feat["asset_ratio"] >= 0.2:
            score += w["human_assets"]
            reasons.append(f"{w['human_assets']} loads static assets like a browser (asset ratio {feat['asset_ratio']:.2f})")
        if cv >= t["cv_human_min"] and ent >= t["entropy_human_min"]:
            score += w["human_timing"]
            reasons.append(f"{w['human_timing']} human-like timing variability: CV {cv:.2f}, entropy {ent:.2f}")
    else:
        reasons.append(f"timing not scored: only {feat['page_requests']} page requests (< {t['min_requests']})")
    if feat["bot_ua"]:
        score += w["bot_ua"]
        reasons.append(f"+{w['bot_ua']} declared bot/crawler User-Agent")
    if feat["scripted_ua"]:
        score += w["scripted_ua"]
        reasons.append(f"+{w['scripted_ua']} scripted-client User-Agent (library/CLI)")
    if any(f.detector == "honeytoken" for f in findings):
        score += w["honeytoken"]
        reasons.append(f"+{w['honeytoken']} touched a honeytoken/decoy (no legitimate reason to)")
    return _clamp(score)


def _agent(feat: dict[str, Any], findings: list[Finding], cfg: dict[str, Any], reasons: list[str]) -> int:
    w = cfg["weights"]["agent"]
    score = 0.0
    # --- adaptation after blocks: points per distinct reaction type, capped
    adapt = [f for f in findings if f.detector == "adaptation" and f.kind != "no_adaptation"]
    kinds = sorted({f.kind for f in adapt}, key=lambda k: -w.get(k, 0))
    if kinds:
        pts = min(w["adaptation_cap"], sum(w[k] for k in kinds))
        score += pts
        n_events = len(adapt)
        reasons.append(f"+{pts} adapted after being blocked ({n_events} reaction(s): {', '.join(kinds)})")
        if any(f.data.get("succeeded") and f.kind in ("ua_change", "param_change", "header_change") for f in adapt):
            score += w["evasion_success"]
            reasons.append(f"+{w['evasion_success']} the changed request succeeded right after the block (evasion worked)")
    elif any(f.kind == "no_adaptation" for f in findings):
        reasons.append("0 blocked but never changed strategy (no adaptation; static retry behaviour)")
    # --- tool chaining
    for f in findings:
        if f.detector == "tool_chain":
            pts = w["tool_chain"]
            reasons.append(f"+{pts} machine-regular tool chain: {f.summary}")
            score += pts
            if f.data.get("share", 0) >= 0.8:
                score += w["tool_chain_regular"]
                reasons.append(f"+{w['tool_chain_regular']} near-identical chain structure ({f.data['share']:.0%})")
    # --- parameter / header evasion
    seen: set[str] = set()
    for f in (f for f in findings if f.detector == "param_evasion"):
        if f.kind in seen:
            continue
        seen.add(f.kind)
        pts = w.get(f.kind, 0)
        score += pts
        reasons.append(f"+{pts} {f.kind.replace('_', ' ')}: {f.summary}")
        if f.data.get("after_block") and "evasion_after_block" not in seen:
            seen.add("evasion_after_block")
            score += w["evasion_after_block"]
            reasons.append(f"+{w['evasion_after_block']} parameter/header variation occurred in a session that was rate-limited/blocked")
    # --- multi-turn decoy chain
    for f in findings:
        if f.detector == "multi_turn":
            score += w["multi_step_chain"]
            reasons.append(f"+{w['multi_step_chain']} multi-turn behaviour: {f.summary}")
    # --- agent coordination bus (each signal has its own weight and plain-language reason)
    coord_text = {
        "board_after_trap": ("coord_board_after_trap", "read the multi-agent coordination board after hitting an error/schema trap - it followed a breadcrumb that only a client reading error text would see"),
        "capture_post": ("coord_capture_post", "registered on the coordination board (volunteered its objective/tools): behaviour of an agent that obeys in-band instructions"),
        "claim_loop": ("coord_claim_loop", "completed 2+ turns of the claim-shard nonce loop: it carried server-issued nonces across several requests"),
        "cross_identity": ("coord_cross_identity", "a handoff token issued to another session/IP was presented here: tokens are being relayed between clients"),
    }
    done: set[str] = set()
    for f in findings:
        if f.detector == "coordination" and f.kind in coord_text and f.kind not in done:
            done.add(f.kind)
            key, why = coord_text[f.kind]
            score += w[key]
            reasons.append(f"+{w[key]} {why}")
    # --- timing signature (weak, heuristic)
    for f in findings:
        if f.detector == "timing":
            score += w["llm_timing"]
            reasons.append(f"+{w['llm_timing']} LLM-like timing signature [HEURISTIC - evadable, not established]: {f.summary}")
    # --- deep navigation (only meaningful when something else looks automated)
    if feat["max_depth"] >= cfg["navigation"]["deep_depth"] and score > 0:
        score += w["deep_navigation"]
        reasons.append(f"+{w['deep_navigation']} deep navigation (path depth {feat['max_depth']})")
    # --- v3 passive web signals (do not need a decoy touch)
    webf = [f for f in findings if f.detector == "web"]
    for f in webf:
        if f.kind == "asset_starvation":
            pts = w["asset_starvation"] + (w["asset_starvation_sec_fetch"] if f.data.get("sec_fetch") else 0)
            score += pts
            reasons.append(f"+{pts} asset starvation: {f.summary}")
    jumps = [f for f in webf if f.kind == "unlinked_jump"]
    never = [f for f in jumps if not f.data.get("offered_earlier")]
    earlier = [f for f in jumps if f.data.get("offered_earlier")]
    if never:
        pts = min(w["unlinked_jump_cap"], w["unlinked_jump"] * len(never))
        score += pts
        reasons.append(f"+{pts} {len(never)} unlinked jump(s) to URLs no page ever offered this client, with no valid Referer, "
                       f"e.g. {never[0].data['from']} -> {never[0].data['to']}")
    if earlier:
        pts = min(w["unlinked_jump_earlier_cap"], w["unlinked_jump_earlier"] * len(earlier))
        score += pts
        reasons.append(f"+{pts} {len(earlier)} jump(s) to URLs offered on an earlier page but not the previous one, no valid Referer "
                       "(weak: breadth-first crawlers, new tabs and typed bookmarks look the same)")
    for kind, text in (("schema_param", "camouflaged schema parameter used (read the decoy openapi.json and used what it advertised)"),
                       ("session_canary_param", "replayed the per-session canary that is only served inside machine-readable docs"),
                       ("mcp_list_then_call", "MCP tools/list followed by a valid tools/call")):
        if any(f.kind == kind for f in webf):
            score += w[kind]
            reasons.append(f"+{w[kind]} {text}")
    # --- honeytokens
    hw = w["honeytoken"]
    hits = [f for f in findings if f.detector == "honeytoken"]
    if hits:
        best = max(hits, key=lambda f: hw.get(f.kind, hw["default"]))
        pts = hw.get(best.kind, hw["default"])
        extra = min(hw["additional_cap"], hw["per_additional_distinct"] * (len(hits) - 1))
        score += pts + extra
        reasons.append(f"+{pts} honeytoken evidence '{best.kind}' ({best.summary})")
        if extra:
            reasons.append(f"+{extra} {len(hits) - 1} additional distinct decoy(s) touched")
    return _clamp(score)


def score_session(session: Session, cfg: dict[str, Any]) -> SessionResult:
    """Detect, score, label and grade one session."""
    findings = run_detectors(session, cfg)
    feat = extract_features(session, cfg)
    reasons: list[str] = []
    auto = _automation(feat, findings, cfg, reasons)
    agent = _agent(feat, findings, cfg, reasons)
    th = cfg["thresholds"]
    hits = [f for f in findings if f.detector == "honeytoken"]
    webf = [f for f in findings if f.detector == "web"]
    ccfg = cfg["contact"]
    passive = set(ccfg["passive_kinds"])
    floors_applied: list[str] = []
    fl = cfg["floors"]
    if fl["enabled"]:
        # max-pooling: a single high-signal event sets a floor that benign padding cannot dilute
        # (a person can type /admin-backup/ or /.env, so those alone do not force a machine label; an invisible link can't be clicked)
        needs_machine = ({f.kind for f in hits} - set(ccfg["human_plausible_kinds"])) \
            or any(f.kind in ("schema_param", "session_canary_param", "mcp_list_then_call") for f in webf)
        if needs_machine:
            if auto < fl["automation_any_decoy"]:
                reasons.append(f"+{fl['automation_any_decoy'] - auto} floor: decoy contact sets the automation score to at least "
                               f"{fl['automation_any_decoy']} (benign padding such as assets or human-like timing cannot dilute it)")
                auto = fl["automation_any_decoy"]
                floors_applied.append("automation:decoy_contact")
        cands = [(fl["agent"][f.kind], f.kind) for f in hits if f.kind in fl["agent"]]
        cands += [(fl["agent"][f.kind], f.kind) for f in webf if f.kind in fl["agent"]]
        if cands:
            value, kind = max(cands)
            if agent < value:
                reasons.append(f"+{value - agent} floor: a single '{kind}' event sets the agent score to at least {value} "
                               f"(benign padding cannot dilute it; still contact, not intent)")
                agent = value
                floors_applied.append(f"agent:{kind}")
    label = "agent" if agent >= th["agent"] else "static_bot" if auto >= th["automation"] else "human"

    # structural observations for static bots (explainability only)
    if label == "static_bot":
        if feat["max_depth"] <= cfg["navigation"]["flat_depth_max"] or feat["unique_paths"] <= 2:
            reasons.append(f"flat navigation: max path depth {feat['max_depth']}, {feat['unique_paths']} unique path(s) over {feat['page_requests']} requests")
        if feat["blocked_responses"] and not any(f.detector == "adaptation" and f.kind != "no_adaptation" for f in findings):
            reasons.append("no adaptation: blocked responses did not change its behaviour")

    agent_evidence = any(f.detector in ("adaptation", "tool_chain", "param_evasion", "honeytoken", "multi_turn", "coordination", "web")
                         and f.kind not in ("no_adaptation", "backoff", "enumeration") for f in findings)
    benign, benign_reason = False, ""
    paths = {r.path for r in session.requests}
    if feat["benign_ua"] and not agent_evidence:
        benign, benign_reason = True, "User-Agent matches the benign allowlist (spoofable; ignored if evasion/honeytoken evidence exists)"
    elif paths and paths <= set(cfg["benign_paths"]) and not agent_evidence:
        benign, benign_reason = True, "only requests allow-listed health/monitoring paths"
    if benign:
        reasons.append(f"benign: {benign_reason}")

    # accidental scraper vs goal-directed agent (a lone invisible-link hit must not read as 'high' while labelled human)
    hit_kinds = {f.kind for f in hits}
    strong = hit_kinds & set(ccfg["strong_kinds"]) or {f.kind for f in webf if f.kind in ("schema_param", "session_canary_param", "mcp_list_then_call")}
    adaptive = any((f.detector in ("tool_chain", "multi_turn", "coordination"))
                   or (f.detector == "adaptation" and f.kind not in ("no_adaptation", "backoff")) for f in findings)
    non_passive = hit_kinds - passive
    goal_directed = label == "agent" or bool(strong) or adaptive or len(non_passive) >= 2
    accidental = (bool(hits) and not non_passive and not goal_directed and len(hits) <= ccfg["accidental_max_distinct_decoys"])
    if goal_directed:
        actor = "goal_directed_agent"
    elif accidental:
        actor = "accidental_scraper"
        reasons.append("classified as a likely accidental scraper, not a goal-directed agent: only passive decoys touched "
                       f"({', '.join(sorted(hit_kinds))}), no adaptation, no schema/MCP/error-hint use. Contact is not intent; "
                       "severity is capped at medium")
    elif any(f.kind == "asset_starvation" or (f.kind == "unlinked_jump" and not f.data.get("offered_earlier")) for f in webf):
        actor = "possible_mimic"
    else:
        actor = label

    if label == "agent":
        sev = "critical" if (agent >= th["critical"] or hits or strong) else "high"
    elif hits:
        sev = "medium" if (accidental or (hit_kinds <= passive)) else "high"
    elif benign:
        sev = "info"
    elif label == "static_bot":
        sev = "medium" if agent >= th["medium"] else "low"
    else:
        sev = "medium" if agent >= th["medium"] else "info"
    reasons.sort(key=_reason_rank)   # biggest contributors first, deductions/notes last
    return SessionResult(session, feat, findings, auto, agent, label, sev, reasons, benign, benign_reason,
                         actor_type=actor, floors=floors_applied)


def analyze_sessions(sessions: list[Session], cfg: dict[str, Any]) -> list[SessionResult]:
    """Score every session; most severe / highest agent score first."""
    results = [score_session(s, cfg) for s in sessions]
    results.sort(key=lambda r: (-SEVERITIES.index(r.severity), -r.agent_score, -r.automation_score))
    return results
