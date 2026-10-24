"""v6 detectors ("Deep-Cover & Frontier Evasion").  Finding kinds use the exact event-contract names (/workspace/v6-event-contract.md).

R11 family (browser-backed mimic signals; scored once, strongest wins):
* ``beacon_forged``                   a beacon whose challenge proof did not verify (canned / replayed-stale / legacy three-key body);
* ``script_fetched_but_unexecuted``   our .js was fetched and no VALID beacon arrived over >= min_navs click-through navigations
                                      (or a forged one did).  Exempt: js_assets_fetched == 0 (JS off / never fetched), and clients
                                      with coherent Sec-Fetch navigation headers that touched no decoy (ad/tracker blockers block the
                                      beacon; that is what such a person looks like);
* ``dom_visual_inversion_hit``        a browser-backed client followed the link that is FIRST in the DOM but rendered LAST (CSS order:99):
                                      evidence of DOM-order iteration rather than visual reading (a curious person can click a footer
                                      link too, so the bare decoy contact is a passive, human-plausible kind);
* ``vlm_quantized_interaction``       full assets + a valid challenge proof (it renders and runs our JS) but scroll with no momentum
                                      decay AND (no human click kinematics OR the inversion link was hit), on >= vlm_min_beacons beacons;
* ``parasitic_session_fork`` (R14)    interleaved depth on two disjoint subtrees (human tab advancing vs fork with missing/non-parent
                                      Referer + schema provenance), same session; or a second session on the same IP probing while a
                                      human session browses (cross-client). Same-client BFS with Referer:/ never qualifies.
Separate:
* ``schema_provenance_cursor`` (R10)  a cursor that only machine-readable docs hand out, used inside a browsing session (strong); in a
                                      pure API session it is advisory (that is how documented API use looks);
* ``missing_required_cursor``         advisory only, no points (stale bookmarks / pasted URLs produce it).
"""
from __future__ import annotations

from typing import Any, Optional

from .models import Finding, Request, Session
from .webdetectors import _path_of, _sec_fetch_state, asset_kind, claims_browser, is_html_page, transitions

R11_FAMILY = frozenset({"headless_automation_signal", "beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit",
                        "vlm_quantized_interaction", "parasitic_session_fork"})
INVERSION_KIND = "dom_visual_inversion_hit"


def js_assets_fetched(session: Session, cfg: dict[str, Any]) -> int:
    """Successful .js sub-resource fetches in the session (event contract: ``js_assets_fetched``)."""
    return sum(1 for r in session.requests if r.method == "GET" and asset_kind(r, cfg) == "js" and (r.status == 0 or r.status < 400))


def _beacons(session: Session, cfg: dict[str, Any]) -> list[Request]:
    bp = cfg["web"]["headless"]["beacon_path"]
    return [r for r in session.requests if r.method == "POST" and r.path == bp]


def _proof(r: Request) -> Optional[bool]:
    return None if r.beacon is None else r.beacon.get("challenge_proof_ok")


def detect_frontier(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    h = cfg["web"]["headless"]
    reqs = session.requests
    pages = [r for r in reqs if is_html_page(r, cfg)]
    kinds = {asset_kind(r, cfg) for r in reqs} - {None}
    browser_backed = claims_browser(session, cfg) and len(pages) >= 2 and bool(kinds & {"css", "js"})
    beacons = _beacons(session, cfg)
    forged = [r for r in beacons if _proof(r) is False or r.decoy_kind == "beacon_forged"]
    # a v4/v5-era record (no challenge_proof_ok key: None) still counts as a beacon that arrived; only an explicit False is forged
    valid = [r for r in beacons if r.beacon is not None and _proof(r) is not False]
    proven = [r for r in beacons if _proof(r) is True]
    js_n = js_assets_fetched(session, cfg)
    decoys = [r for r in reqs if r.decoy_kind]
    inversion = [r for r in reqs if r.decoy_kind == INVERSION_KIND or r.path == h.get("inversion_path")]
    out: list[Finding] = []
    if forged:
        out.append(Finding("web", "beacon_forged",
                           f"{len(forged)} interaction beacon(s) whose challenge proof did not verify (canned, stale or legacy body): the "
                           "client posted the beacon without running our page script on a rendered page", forged[:3],
                           {"reason": "invalid_challenge_proof", "strong": True, "beacons": len(forged)}))
    offered = {p.path for p in pages if p.beacon_offered}
    navs = [r for r in pages[1:] if r.referer and _path_of(r.referer) in offered]
    coherent = bool(pages) and all(_sec_fetch_state(p) == "coherent" for p in pages if p.headers_logged) \
        and any(p.headers_logged for p in pages)
    if js_n > 0 and (forged or (not valid and len(navs) >= h["min_navs"] and not (coherent and not decoys))):
        out.append(Finding("web", "script_fetched_but_unexecuted",
                           f"fetched our script ({js_n} .js request(s)) but {'sent only forged beacons' if forged else 'never sent a valid beacon'}"
                           f" over {len(navs)} click-through navigation(s) (MODERATE on its own: ad/tracker blockers can block the beacon; "
                           "coherent-header clients with no decoy contact are exempt)", (forged or navs)[:3],
                           {"reason": "forged_beacon" if forged else "no_valid_beacon", "strong": bool(forged),
                            "navigations": len(navs), "js_assets_fetched": js_n}))
    if inversion and browser_backed:
        hit = inversion[0]
        # the click that led there: a valid beacon with pointer movement + human press kinematics shortly before the hit means a
        # person scrolled down and clicked the footer link -> advisory only.  JS off (no script fetched) -> advisory too.
        click = [b for b in proven if b.ts <= hit.ts and (hit.ts - b.ts).total_seconds() <= 30]
        last = click[-1].beacon if click else None
        human_click = last is not None and bool(last.get("pointer_trail_seen")) and bool(last.get("kinematic_dwell_ok"))
        strong = js_n > 0 and not human_click
        out.append(Finding("web" if strong else "web_advisory", "dom_visual_inversion_hit",
                           "a browser-backed client followed the link that is FIRST in the DOM but rendered LAST as a small footer link "
                           "(CSS order:99): " + ("it iterated DOM order instead of reading the page (a curious person whose beacon is "
                                                 "blocked looks the same)" if strong else
                                                 "advisory only: the click came with human pointer kinematics, or no script ran"),
                           inversion[:1], {"reason": "dom_order_iteration", "strong": strong}))
    full_assets = {"css", "js"} <= kinds and bool(kinds & {"image", "favicon"})
    if full_assets and proven:
        quant = [r for r in proven if r.beacon and r.beacon.get("inertial_scroll_ok") is False
                 and (r.beacon.get("kinematic_dwell_ok") is False or bool(inversion))]
        if len(quant) >= h["vlm_min_beacons"]:
            out.append(Finding("web", "vlm_quantized_interaction",
                               f"renders and runs our script (valid challenge proof, full assets) but {len(quant)} beacon(s) report scroll "
                               "without momentum decay and " + ("clicks without human press duration/curved approach"
                                                                 if any(r.beacon and r.beacon.get("kinematic_dwell_ok") is False for r in quant)
                                                                 else "the DOM-order inversion link was followed")
                               + " (pattern of a screenshot-driven agent; notched mouse wheels + keyboard activation can look similar)",
                               quant[:3], {"reason": "quantized_scroll_and_click", "strong": True, "beacons": len(quant)}))
    out += _cursor_findings(session, cfg, pages)
    out += detect_parasitic_fork(session, cfg)
    return out


def _cursor_findings(session: Session, cfg: dict[str, Any], pages: list[Request]) -> list[Finding]:
    out: list[Finding] = []
    schema = [r for r in session.requests if r.cursor_prov == "schema"]
    missing = [r for r in session.requests if "missing_required_cursor" in r.signals or (r.cursor_route and r.cursor_prov is None)]
    browsing = claims_browser(session, cfg) and len(pages) >= 2
    if schema:
        out.append(Finding("web" if browsing else "web_advisory", "schema_provenance_cursor",
                           f"{len(schema)} request(s) used a cursor that only machine-readable docs (/openapi.json, /llms.txt, MCP) hand out"
                           + (" inside a browsing session (the 'browser' read the schema and used what it offered)" if browsing else
                              " (advisory: an API client following the docs looks exactly like this)"),
                           schema[:3], {"strong": browsing, "uses": len(schema)}))
    if missing:
        out.append(Finding("web_advisory", "missing_required_cursor",
                           f"{len(missing)} request(s) to cursor-bearing routes without a valid cursor (400; advisory: stale bookmarks "
                           "and pasted URLs do this)", missing[:3], {"count": len(missing)}))
    return out


def _path_depth(path: str) -> int:
    parts = [p for p in (path or "/").split("/") if p]
    return len(parts)


def _first_segment(path: str) -> str:
    parts = [p for p in (path or "/").split("/") if p]
    return parts[0] if parts else ""


def _referer_is_parent(req: Request) -> bool:
    """True when Referer path is a prefix parent (or exact) of req.path — normal in-tab navigation."""
    if not req.referer:
        return False
    ref = _path_of(req.referer) or "/"
    child = req.path or "/"
    if ref == child:
        return True
    if ref == "/":
        return True  # Referer:/ is the BFS / same-tab root case — not a parasitic non-parent fork
    return child.startswith(ref.rstrip("/") + "/")


def _interleaved_disjoint_depth(human_docs: list[Request], forks: list[Request], window: float) -> bool:
    """Gemini refinement: require interleaved depth progression on two disjoint subtrees.

    Human tab advances (depth increases across >=2 HTML docs) while a fork with missing or non-parent
    Referer lands on a disjoint first-segment subtree within ``window`` of a human advance.
    Same-client BFS that only fans out from Referer:/ never satisfies the non-parent/disjoint fork side.
    """
    if len(human_docs) < 2 or not forks:
        return False
    # human depth progression (sorted by time)
    h_sorted = sorted(human_docs, key=lambda r: r.ts)
    depths = [_path_depth(r.path) for r in h_sorted]
    if max(depths) <= min(depths):
        # still allow / -> /kb (depth 0 -> 1) etc.; need a strict increase somewhere
        if not any(depths[i] > depths[i - 1] for i in range(1, len(depths))):
            # allow distinct paths even at same depth if first segments diverge later with forks
            if len({r.path for r in h_sorted}) < 2:
                return False
    human_segs = {_first_segment(r.path) for r in h_sorted if _first_segment(r.path)}
    for fr in forks:
        if _referer_is_parent(fr) and fr.referer:
            # parent Referer (including /) is the client's own tree — not a disjoint fork signal alone
            # schema + non-parent OR missing Referer required for same-session parasitic claim
            continue
        fseg = _first_segment(fr.path)
        # disjoint: fork first segment not in human-advancing segments, OR human has multi-segment depth
        # while fork sits outside that lineage
        disjoint = False
        if fseg and fseg not in human_segs:
            disjoint = True
        else:
            # same top segment allowed if fork path is not under any human doc's directory prefix
            under_human = False
            for h in h_sorted:
                hp = (h.path or "/").rstrip("/") or "/"
                fp = fr.path or "/"
                if hp != "/" and (fp == hp or fp.startswith(hp + "/")):
                    under_human = True
                    break
                if hp == "/" and _referer_is_parent(fr):
                    under_human = True
                    break
            disjoint = not under_human
        if not disjoint:
            continue
        for h in h_sorted:
            if h.path == fr.path:
                continue
            if abs((fr.ts - h.ts).total_seconds()) <= window:
                return True
    return False


def detect_parasitic_fork(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """R14 (same IP+UA session): interleaved depth on two disjoint subtrees + schema-provenance fork.

    Phase-1 / Gemini fix: a single client's own Referer:/ BFS tree (bare unlinked HTML navigations, asset
    loads, ARIA clicks) must NEVER fire R14. Same-session R14 requires (1) at least one fork with
    ``cursor_prov == "schema"`` whose Referer is missing or non-parent, (2) concurrent with a human
    beacon branch page load on a different path within ``fork_window_s``, and (3) interleaved depth
    progression on two disjoint subtrees. For two distinct clients see ``detect_parasitic_across_clients``.
    """
    h = cfg["web"]["headless"]
    window = float(h["fork_window_s"])
    beacons = _beacons(session, cfg)
    human_branch = any(_proof(r) is True and r.beacon and r.beacon.get("pointer_trail_seen") for r in beacons)
    if not human_branch:
        return []
    trans = transitions(session, cfg)
    docs = [r for r, _, st, _ in trans if is_html_page(r, cfg) and st in ("entry", "linked")]
    # schema-provenance only — bare never_offered/offered_earlier is the client's own crawl (Phase-1 crawler FP)
    suspects = [r for r, _, st, _ in trans if r.cursor_prov == "schema"]
    # Prefer forks whose Referer is missing or non-parent (disjoint from the advancing human tab)
    fork_candidates = [r for r in suspects if not _referer_is_parent(r) or not r.referer]
    if not fork_candidates:
        fork_candidates = []  # parent-Referer schema hits alone are not enough after Gemini interleaved-depth fix
    roots: list[tuple[Request, Request]] = []
    for r in fork_candidates:
        anchor = next((d for d in docs if d is not r and d.path != r.path and abs((r.ts - d.ts).total_seconds()) <= window), None)
        if anchor is not None:
            roots.append((r, anchor))
    if not roots:
        return []
    if not _interleaved_disjoint_depth(docs, [r for r, _ in roots], window):
        return []
    root_ids = {id(r) for r, _ in roots}
    root_paths = {r.path for r, _ in roots}
    steps = [r for r in session.requests if id(r) in root_ids or (r.cursor_prov == "schema" and r.referer and _path_of(r.referer) in root_paths)]
    r0, a0 = roots[0]
    return [Finding("web", "parasitic_session_fork",
                    f"{len(roots)} schema-provenance request(s) on a disjoint subtree (missing/non-parent Referer) interleaved with "
                    f"this session's advancing human tab within {window:.1f}s (e.g. {a0.path} at the same moment as {r0.path}): a second "
                    "actor appears to ride the person's session (browser extension / injected agent reading machine-readable docs)",
                    steps[:20], {"reason": "parasitic_sub_branch", "strong": True, "fork_requests": len(roots),
                                 "branch": [f"{r.method} {r.path}" for r in steps[:20]], "mode": "same_session_schema",
                                 "interleaved_disjoint_depth": True})]


def detect_parasitic_across_clients(sessions: list[Session], cfg: dict[str, Any]) -> dict[str, list[Finding]]:
    """R14 across distinct sessions that share an IP (different UA / session_id).

    Requires: one session with a human-like beacon branch (valid proof + pointer), and another session on the
    same IP whose unlinked or schema-provenance requests land within ``fork_window_s`` of a human HTML page load
    on a different path. A single client's own tree never matches (needs >= 2 sessions).
    Returns mapping of rider ``session_id`` -> findings.
    """
    h = cfg["web"]["headless"]
    window = float(h["fork_window_s"])
    by_ip: dict[str, list[Session]] = {}
    for s in sessions:
        by_ip.setdefault(s.ip, []).append(s)
    out: dict[str, list[Finding]] = {}
    for ip, group in by_ip.items():
        if len(group) < 2:
            continue
        humans = []
        for s in group:
            beacons = _beacons(s, cfg)
            if any(_proof(r) is True and r.beacon and r.beacon.get("pointer_trail_seen") for r in beacons):
                humans.append(s)
        if not humans:
            continue
        human_ids = {h.session_id for h in humans}
        for rider in group:
            forks: list[Request] = []
            anchors: list[Request] = []
            rider_trans = transitions(rider, cfg)
            # Cross-client: the rider's first hit is often transition status "entry" (no prior page in *its* session).
            # Count schema cursors, never_offered jumps, and non-HTML entry probes (APIs / machine paths).
            suspects = []
            for r, _, st, _ in rider_trans:
                if r.cursor_prov == "schema" or st == "never_offered":
                    suspects.append(r)
                elif st == "entry" and not is_html_page(r, cfg) and asset_kind(r, cfg) is None:
                    suspects.append(r)
            if not suspects:
                continue
            for human in humans:
                if human.session_id == rider.session_id:
                    continue
                h_trans = transitions(human, cfg)
                docs = [r for r, _, st, _ in h_trans if is_html_page(r, cfg) and st in ("entry", "linked")]
                for r in suspects:
                    anchor = next((d for d in docs if d.path != r.path and abs((r.ts - d.ts).total_seconds()) <= window), None)
                    if anchor is not None:
                        forks.append(r); anchors.append(anchor)
            if not forks:
                continue
            finding = Finding(
                "web", "parasitic_session_fork",
                f"{len(forks)} request(s) from session {rider.session_id} ran within {window:.1f}s of a human-branch page load "
                f"from a different session on the same IP ({ip}): distinct client riding alongside a person",
                forks[:20],
                {"reason": "parasitic_cross_client", "strong": True, "fork_requests": len(forks),
                 "mode": "cross_client", "human_sessions": [h.session_id for h in humans if h.session_id != rider.session_id],
                 "branch": [f"{r.method} {r.path}" for r in forks[:20]]})
            out.setdefault(rider.session_id, []).append(finding)
    return out
