"""Behavioural detectors.  Each takes a Session + config and returns Findings.

They only *observe*; weighting and classification live in scoring.py so that
every point in a score can be traced back to one Finding.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Optional
from urllib.parse import parse_qs

from .models import Finding, Request, Session

_NUM_SEG = re.compile(r"/\d+(?=/|$)")
WEB_HANDLED_KINDS = frozenset({"schema_param_use", "session_canary_param"})


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def is_asset(req: Request, cfg: dict[str, Any]) -> bool:
    """True for static assets (CSS/JS/images/fonts) a browser auto-fetches."""
    path = req.path.lower()
    return any(path.endswith(ext) for ext in cfg["assets"]["extensions"])


def page_requests(session: Session, cfg: dict[str, Any]) -> list[Request]:
    """Requests excluding static assets (the 'deliberate' requests)."""
    return [r for r in session.requests if not is_asset(r, cfg)]


def header_fingerprint(req: Request, names: list[str]) -> tuple[str, ...]:
    return tuple(req.headers.get(n, "") for n in names)


def classify_role(req: Request, cfg: dict[str, Any]) -> Optional[str]:
    """Map a request to a tool-chain role (search/detail/export) or None."""
    target = req.path.lower()
    for role, patterns in cfg["tool_chain"]["roles"].items():
        if any(re.search(p, target) for p in patterns):
            return role
    if any(k in req.params for k in ("q", "query", "search")) and "/api/" not in target:
        return "search"
    return None


def _median_gap(reqs: list[Request]) -> float:
    gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(reqs, reqs[1:])]
    return statistics.median(gaps) if gaps else 0.0


def _query_changed(reqs: list[Request], i: int) -> bool:
    """Did request i+1 change its query relative to blocked request i in a way
    that is NOT just the next step of an ongoing numeric sequence?

    * different parameter *names* (e.g. a cache-buster appeared)  -> change
    * same names, some value differs: if every differing value is numeric and
      advanced by the same step as before the block, it is plain pagination /
      enumeration continuing (not an adaptation); otherwise -> change.
    """
    r, nxt = reqs[i], reqs[i + 1]
    if r.query == nxt.query:
        return False
    a, b = r.params, nxt.params
    if set(a) != set(b):
        return True
    prev = reqs[i - 1].params if i > 0 and reqs[i - 1].path == r.path else None
    for key in a:
        if a[key] == b[key]:
            continue
        try:
            step = int(b[key][0]) - int(a[key][0])
            prior = int(a[key][0]) - int(prev[key][0]) if prev and key in prev else None
        except (ValueError, IndexError):
            return True
        if prior is None or step != prior or step == 0:
            return True
    return False


# --------------------------------------------------------------------------
# 1. adaptation after being blocked
# --------------------------------------------------------------------------
def detect_adaptation(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Find strategy changes immediately after a block/rate-limit response.

    Reactions looked for on the request that follows a 403/429:
      ua_change    - different User-Agent
      param_change - same path, different query parameters (incl. cache-busters)
      header_change- rotating-header fingerprint changed (JSON logs only)
      path_reorder - switched to another path and later resumed the blocked one
      backoff      - waited much longer than the pre-block pace
    A plain unchanged retry is *not* adaptation (it is recorded as data).
    """
    acfg = cfg["adaptation"]
    blocks = set(cfg["session"]["block_statuses"])
    hdr_names = cfg["param_evasion"]["rotating_headers"]
    reqs = session.requests
    findings: list[Finding] = []
    blocked = unchanged = 0

    for i, r in enumerate(reqs[:-1]):
        if r.status not in blocks:
            continue
        blocked += 1
        nxt = reqs[i + 1]
        gap = (nxt.ts - r.ts).total_seconds()
        if gap > acfg["window_s"]:
            continue
        changes: list[tuple[str, str]] = []
        if nxt.ua != r.ua:
            changes.append(("ua_change", f"User-Agent changed after {r.status}"))
        if nxt.path == r.path and _query_changed(reqs, i):
            changes.append(("param_change", f"query parameters changed on {r.path} after {r.status}"))
        if r.headers and nxt.headers and header_fingerprint(r, hdr_names) != header_fingerprint(nxt, hdr_names):
            changes.append(("header_change", f"rotating headers changed after {r.status}"))
        if nxt.path != r.path and any(x.path == r.path for x in reqs[i + 2: i + 2 + acfg["reorder_lookahead"]]):
            changes.append(("path_reorder", f"moved off {r.path} after {r.status} then resumed it"))
        prior = reqs[max(0, i - 5): i + 1]
        pre_gap = _median_gap(prior) if len(prior) > 2 else 0.0
        if gap >= max(acfg["backoff_min_s"], acfg["backoff_factor"] * pre_gap) and not changes:
            changes.append(("backoff", f"paused {gap:.0f}s after {r.status} (pre-block median {pre_gap:.1f}s)"))
        if not changes:
            unchanged += 1
            continue
        success = nxt.status < 400
        for kind, text in changes:
            findings.append(Finding(
                "adaptation", kind, text, [r, nxt],
                {"blocked_status": r.status, "next_status": nxt.status, "succeeded": success},
            ))
    if blocked and not findings:
        findings.append(Finding(
            "adaptation", "no_adaptation",
            f"{blocked} blocked response(s), {unchanged} retried without changing strategy",
            [r for r in reqs if r.status in blocks][:3], {"blocked": blocked, "unchanged": unchanged},
        ))
    return findings


# --------------------------------------------------------------------------
# 2. tool chaining
# --------------------------------------------------------------------------
def detect_tool_chains(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Find repeated search -> detail+ -> export chains with machine regularity."""
    tcfg = cfg["tool_chain"]
    seq = [(r, classify_role(r, cfg)) for r in page_requests(session, cfg)]
    chains: list[list[Request]] = []
    sigs: list[str] = []
    i = 0
    while i < len(seq):
        r, role = seq[i]
        if role != "search":
            i += 1
            continue
        chain = [r]
        j = i + 1
        details = 0
        while j < len(seq) and seq[j][1] == "detail" and (seq[j][0].ts - chain[-1].ts).total_seconds() <= tcfg["step_gap_s"]:
            chain.append(seq[j][0]); details += 1; j += 1
        if details and j < len(seq) and seq[j][1] == "export" and (seq[j][0].ts - chain[-1].ts).total_seconds() <= tcfg["step_gap_s"]:
            chain.append(seq[j][0])
            chains.append(chain)
            sigs.append("S>" + ">".join(["D"] * details) + ">E")
            i = j + 1
        else:
            i += 1
    if len(chains) < tcfg["min_chains"]:
        return []
    sig, count = Counter(sigs).most_common(1)[0]
    share = count / len(chains)
    step_gaps = [(b.ts - a.ts).total_seconds() for c in chains for a, b in zip(c, c[1:])]
    median_step = statistics.median(step_gaps) if step_gaps else 0.0
    if share < tcfg["min_signature_share"] or median_step > tcfg["max_median_step_s"]:
        return []
    evidence = [r for c in chains[:2] for r in c]
    return [Finding(
        "tool_chain", "search_detail_export",
        f"{len(chains)} search->detail->export chains, dominant shape {sig} ({share:.0%} of chains), "
        f"median step gap {median_step:.1f}s",
        evidence, {"chains": len(chains), "signature": sig, "share": share, "median_step_s": median_step},
    )]


# --------------------------------------------------------------------------
# 3. parameter / header evasion
# --------------------------------------------------------------------------
def _template(path: str) -> str:
    return _NUM_SEG.sub("/{id}", path)


def _longest_arith_run(values: list[int], consistency: float) -> int:
    """Longest run of strictly monotonic values with a mostly-constant step."""
    best = 1 if values else 0
    n = len(values)
    for start in range(n - 1):
        step = values[start + 1] - values[start]
        if step == 0:
            continue
        end = start + 1
        while end + 1 < n and values[end + 1] - values[end] == step:
            end += 1
        best = max(best, end - start + 1)
    # allow some noise: fall back to monotonic share when exact run is short
    if n >= 6:
        diffs = [b - a for a, b in zip(values, values[1:])]
        sign = 1 if sum(1 for d in diffs if d > 0) >= sum(1 for d in diffs if d < 0) else -1
        mono = sum(1 for d in diffs if d * sign > 0)
        if mono / len(diffs) >= consistency:
            best = max(best, mono + 1)
    return best


def detect_param_evasion(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Detect enumeration, cache-busting, systematic variation and header rotation."""
    pcfg = cfg["param_evasion"]
    blocks = set(cfg["session"]["block_statuses"])
    claim = cfg["coordination"]["claim_path"]
    # the coordination protocol's own single-use nonces change on every request by design: not cache-busting
    reqs = [r for r in page_requests(session, cfg) if r.path != claim]
    findings: list[Finding] = []
    had_block = any(r.status in blocks for r in session.requests)
    groups: dict[str, list[Request]] = defaultdict(list)
    for r in reqs:
        groups[_template(r.path)].append(r)

    for tmpl, grp in groups.items():
        if len(grp) < 3:
            continue
        enum_keys: set[str] = set()
        # ---- numeric enumeration: path ids and numeric query values
        series: dict[str, list[int]] = {}
        if "{id}" in tmpl:
            ids = [int(m.group(0)[1:]) for r in grp for m in [_NUM_SEG.search(r.path)] if m]
            if len(ids) == len(grp):
                series["<path id>"] = ids
        for key in {k for r in grp for k in r.params}:
            vals = [r.params.get(key, [""])[0] for r in grp]
            if all(v.lstrip("-").isdigit() for v in vals):
                series[key] = [int(v) for v in vals]
        for key, vals in series.items():
            if key in pcfg["cache_bust_names"]:
                continue
            run = _longest_arith_run(vals, pcfg["enum_step_consistency"])
            if run >= pcfg["enum_min_run"] and _median_gap(grp) <= pcfg["enum_max_median_gap_s"]:
                enum_keys.add(key)
                findings.append(Finding(
                    "param_evasion", "enumeration",
                    f"{run}-step enumeration of '{key}' on {tmpl} (median gap {_median_gap(grp):.1f}s)",
                    grp[:2] + grp[-1:], {"key": key, "run": run, "template": tmpl},
                ))
        # ---- cache-busting parameters
        for key in {k for r in grp for k in r.params}:
            vals = [r.params[key][0] for r in grp if key in r.params]
            if len(vals) < pcfg["cache_bust_min"] or len(set(vals)) != len(vals):
                continue
            named = key.lower() in pcfg["cache_bust_names"]
            tokenish = all(re.fullmatch(r"[0-9a-fA-F]{6,}|\d{9,}", v) for v in vals)
            if (named or tokenish) and key not in enum_keys:
                findings.append(Finding(
                    "param_evasion", "cache_busting",
                    f"unique throw-away value in '{key}' on {len(vals)} requests to {tmpl} (cache-busting)",
                    grp[:3], {"key": key, "count": len(vals)},
                ))
        # ---- systematic variation of one parameter at a time
        distinct = []
        for r in grp:
            if r.query not in distinct:
                distinct.append(r.query)
        if len(distinct) >= pcfg["systematic_min_distinct"] and _median_gap(grp) <= pcfg["enum_max_median_gap_s"]:
            parsed = [Counter({k: v[0] for k, v in parse_qs(q, keep_blank_values=True).items()}.items()) for q in distinct]
            one_key = 0
            for a, b in zip(parsed, parsed[1:]):
                if {k for k, _ in a} == {k for k, _ in b} and len(set(a.items()) ^ set(b.items())) == 2:
                    one_key += 1
            if one_key / max(1, len(parsed) - 1) >= pcfg["systematic_share"] and not enum_keys:
                findings.append(Finding(
                    "param_evasion", "systematic_variation",
                    f"{len(distinct)} distinct query strings on {tmpl}, one parameter varied at a time",
                    grp[:3], {"distinct": len(distinct)},
                ))

    # ---- header / UA rotation across the whole session
    if len(session.requests) >= pcfg["header_rotation_min_requests"]:
        for name in pcfg["rotating_headers"]:
            vals = {r.headers[name] for r in session.requests if name in r.headers}
            if len(vals) >= pcfg["header_rotation_min_distinct"]:
                ev = [r for r in session.requests if name in r.headers][:3]
                findings.append(Finding(
                    "param_evasion", "header_rotation",
                    f"header '{name}' took {len(vals)} distinct values in one session",
                    ev, {"header": name, "distinct": len(vals)},
                ))
    if len(session.user_agents) >= pcfg["ua_rotation_min_distinct"]:
        findings.append(Finding(
            "param_evasion", "header_rotation",
            f"{len(session.user_agents)} different User-Agents from one IP within one session",
            session.requests[:1], {"header": "user-agent", "distinct": len(session.user_agents)},
        ))
    # context flag consumed by scoring
    for f in findings:
        f.data["after_block"] = had_block
    return findings


# --------------------------------------------------------------------------
# 4. honeytoken hits (from honeypot leads or decoy paths in access logs)
# --------------------------------------------------------------------------
def detect_honeytokens(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """One Finding per distinct decoy touched (lead records and/or log paths)."""
    prefixes: dict[str, str] = cfg["honeytoken"]["paths"]
    seen: dict[tuple[str, str], Finding] = {}
    for r in session.requests:
        kind: Optional[str] = None
        if r.source == "honeypot":
            kind = r.decoy_kind or "unknown"
        else:
            low = r.path.lower()
            for prefix, k in prefixes.items():
                if low.startswith(prefix.lower()):
                    kind = k
                    break
        if kind is None or kind in WEB_HANDLED_KINDS:
            continue          # schema_param_use / session_canary_param are scored by the v3 web detectors, once
        key = (kind, r.token_id or r.path)
        if key not in seen:
            seen[key] = Finding(
                "honeytoken", kind,
                f"touched decoy '{kind}' at {r.path}" + (f" (token {r.token_id})" if r.token_id else ""),
                [r], {"path": r.path, "token_id": r.token_id},
            )
    return list(seen.values())


# --------------------------------------------------------------------------
# 5. multi-turn decoy chain (server-issued tokens followed across turns)
# --------------------------------------------------------------------------
def detect_dump_chain(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Distinct pages of the stateful fake dump reached by following issued tokens."""
    need = cfg["honeytoken"]["dump_chain_min_steps"]
    steps: dict[str, Request] = {}
    for r in session.requests:
        if r.source == "honeypot":
            if r.decoy_kind in ("stateful_dump_start", "stateful_dump_step") and r.detail.get("chain_valid") is True:
                steps.setdefault(str(r.detail.get("step", r.path)), r)
        elif r.path.startswith("/api/v2/dump/") and r.status == 200:
            steps.setdefault(r.path, r)
    if len(steps) < need:
        return []
    return [Finding("multi_turn", "dump_chain",
                    f"followed server-issued cursor tokens across {len(steps)} consecutive dump pages",
                    list(steps.values())[:3], {"steps": len(steps)})]


# --------------------------------------------------------------------------
# 5b. coordination bus (cognitive capture chatroom)
# --------------------------------------------------------------------------
def _is_trap_touch(r: Request, ccfg: dict[str, Any]) -> bool:
    """A request that hit a schema/error trap (so the board is being followed as a breadcrumb)."""
    if r.source == "honeypot":
        return r.decoy_kind in {"openapi_decoy", "swagger_decoy", "llms_txt_decoy", "ai_plugin_decoy", "graphql_decoy",
                                "error_hint_follow", "mcp_decoy_tool_call"} or r.status in ccfg["trap_statuses"]
    return r.path in ccfg["trap_paths"] or (r.path.startswith("/api/") and r.status in ccfg["trap_statuses"])


def detect_coordination(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Signals from the Agent Coordination Bus honeypot (works from leads and, more weakly, plain logs)."""
    ccfg = cfg["coordination"]
    board, claim = ccfg["board_path"], ccfg["claim_path"]
    out: list[Finding] = []
    trap_seen = False
    after_trap: Optional[Request] = None
    capture_req: Optional[Request] = None
    steps: dict[str, Request] = {}
    cross: Optional[Request] = None
    for r in session.requests:
        is_board = r.path == board
        if is_board and r.method == "GET" and after_trap is None:
            if (r.source == "honeypot" and r.detail.get("after_trap") is True) or (trap_seen and r.status == 200):
                after_trap = r
        if is_board and r.method == "POST" and capture_req is None:
            if r.source == "honeypot" and r.decoy_kind == "coordination_register" and r.detail.get("capture_present"):
                capture_req = r
            elif r.source == "log" and r.status == 200:
                capture_req = r            # accepted registration POST seen only in the access log
        if r.source == "honeypot" and r.decoy_kind == "coordination_claim_step" and r.detail.get("chain_valid") is True:
            steps.setdefault(str(r.detail.get("step", r.token_id)), r)
        elif r.source == "log" and r.path == claim and r.status == 200:
            steps.setdefault(r.query or str(len(steps)), r)
        if cross is None and r.source == "honeypot" and (
                r.detail.get("cross_session") is True or any(e.get("cross_session") is True for e in r.events)):
            cross = r
        if _is_trap_touch(r, ccfg):
            trap_seen = True
    if after_trap:
        out.append(Finding("coordination", "board_after_trap",
                           "read the coordination board right after hitting an error/schema trap (followed a breadcrumb)",
                           [after_trap], {}))
    if capture_req:
        out.append(Finding("coordination", "capture_post",
                           "POSTed a registration to the coordination board (volunteered its objective/tools)",
                           [capture_req], {"capture_visible": bool(capture_req.capture)}))
    if len(steps) >= ccfg["claim_loop_min_steps"]:
        out.append(Finding("coordination", "claim_loop",
                           f"completed {len(steps)} turns of the claim-shard nonce loop",
                           list(steps.values())[:3], {"steps": len(steps)}))
    if cross:
        out.append(Finding("coordination", "cross_identity",
                           "presented a handoff token that was issued to a different session/IP (relay between agents)",
                           [cross], {"cross_ip": bool(cross.detail.get("cross_ip"))}))
    return out


# --------------------------------------------------------------------------
# 6. Time-to-Next-Action vs previous response size  (HEURISTIC, evadable)
# --------------------------------------------------------------------------
def _ranks(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def spearman(xs: list[float], ys: list[float]) -> float:
    """Spearman rank correlation (ties averaged); 0.0 when undefined."""
    if len(xs) != len(ys) or len(xs) < 3:
        return 0.0
    rx, ry = _ranks(xs), _ranks(ys)
    mx, my = statistics.fmean(rx), statistics.fmean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else 0.0


def ttna_pairs(session: Session, cfg: dict[str, Any]) -> list[tuple[float, int, Request]]:
    """(gap to next request, size of the response just before the gap, next request)."""
    tcfg = cfg["ttna"]
    pages = page_requests(session, cfg)
    out = []
    for a, b in zip(pages, pages[1:]):
        gap = (b.ts - a.ts).total_seconds()
        if 0 <= gap <= tcfg["max_gap_s"] and a.size > 0:
            out.append((gap, a.size, b))
    return out


def ttna_stats(session: Session, cfg: dict[str, Any]) -> Optional[dict[str, float]]:
    """Correlation of gap vs previous-response size, band share, size variability."""
    tcfg = cfg["ttna"]
    pairs = ttna_pairs(session, cfg)
    if len(pairs) < tcfg["min_pairs"]:
        return None
    gaps = [p[0] for p in pairs]
    sizes = [float(p[1]) for p in pairs]
    mean_size = statistics.fmean(sizes)
    in_band = sum(1 for g in gaps if tcfg["band_lo_s"] <= g <= tcfg["band_hi_s"]) / len(gaps)
    return {
        "pairs": len(pairs),
        "spearman": round(spearman(sizes, gaps), 3),
        "band_fraction": round(in_band, 3),
        "size_cv": round(statistics.pstdev(sizes) / mean_size, 3) if mean_size else 0.0,
        "median_gap_s": round(statistics.median(gaps), 2),
        "approx_tokens_median": round(statistics.median(sizes) / tcfg["bytes_per_token"]),
    }


def detect_timing_signature(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Flag 'LLM-like' timing: think time inside a band AND scaling with payload size.

    HYPOTHESIS ONLY.  The idea is that an LLM-driven client needs time to read
    (prefill) a response and compose its next action, so the gap *might* grow
    with the size of what it just received and sit in a seconds-long band.
    This is not an established fingerprint: humans reading also scale with
    length, fast tools/caching/streaming break it, and a determined agent can
    randomise or decouple its delays.  It is a weak, low-weight signal.
    """
    tcfg = cfg["ttna"]
    if not tcfg["enabled"]:
        return []
    st = ttna_stats(session, cfg)
    if st is None:
        return []
    n = len(session.requests)
    assets = sum(1 for r in session.requests if is_asset(r, cfg))
    if n and assets / n > tcfg["max_asset_ratio"]:
        return []                                         # browser-like asset loading
    if (st["spearman"] >= tcfg["min_spearman"] and st["band_fraction"] >= tcfg["min_band_fraction"]
            and st["size_cv"] >= tcfg["min_size_cv"]):
        pairs = ttna_pairs(session, cfg)
        return [Finding(
            "timing", "llm_like_ttna",
            f"gap-vs-previous-response-size Spearman {st['spearman']:.2f} over {st['pairs']} pairs; "
            f"{st['band_fraction']:.0%} of gaps within {tcfg['band_lo_s']}-{tcfg['band_hi_s']}s "
            f"(heuristic, evadable)", [pairs[0][2], pairs[-1][2]], dict(st))]
    return []


def run_detectors(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """Run every detector and return all findings."""
    from .webdetectors import run_web_detectors
    out: list[Finding] = []
    for fn in (detect_adaptation, detect_tool_chains, detect_param_evasion, detect_honeytokens,
               detect_dump_chain, detect_coordination, detect_timing_signature):
        out.extend(fn(session, cfg))
    out.extend(run_web_detectors(session, cfg))
    return out
