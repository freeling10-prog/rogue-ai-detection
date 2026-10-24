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
* ``parasitic_session_fork`` (R14)    inside one session (same IP + UA) a Referer sub-tree forks off with unlinked or schema-provenance
                                      requests within <= fork_window_s of a human-looking page load on a different path.
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


def detect_parasitic_fork(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """R14: per-session Referer parent-child tree; a sub-branch of unlinked / schema-provenance requests that appears within
    fork_window_s of a human-looking page load on a DIFFERENT path (a second actor riding the person's session)."""
    h = cfg["web"]["headless"]
    window = float(h["fork_window_s"])
    beacons = _beacons(session, cfg)
    human_branch = any(_proof(r) is True and r.beacon and r.beacon.get("pointer_trail_seen") for r in beacons)
    if not human_branch:
        return []
    trans = transitions(session, cfg)
    docs = [r for r, _, st, _ in trans if is_html_page(r, cfg) and st in ("entry", "linked")]
    suspects = [r for r, _, st, _ in trans if st in ("never_offered", "offered_earlier") or r.cursor_prov == "schema"]
    roots: list[tuple[Request, Request]] = []
    for r in suspects:
        anchor = next((d for d in docs if d is not r and d.path != r.path and abs((r.ts - d.ts).total_seconds()) <= window), None)
        if anchor is not None:
            roots.append((r, anchor))
    if not roots:
        return []
    root_ids = {id(r) for r, _ in roots}
    root_paths = {r.path for r, _ in roots}
    # the parasitic sub-branch: the fork roots plus their Referer children that are themselves unlinked / schema-provenance
    steps = [r for r in session.requests if id(r) in root_ids or (r in suspects and r.referer and _path_of(r.referer) in root_paths)]
    r0, a0 = roots[0]
    return [Finding("web", "parasitic_session_fork",
                    f"{len(roots)} request(s) forked off this session's human branch within {window:.1f}s of a page load on a different "
                    f"path (e.g. {a0.path} at the same moment as {r0.path}"
                    + (", using a schema-provenance cursor" if r0.cursor_prov == "schema" else ", unlinked") +
                    "): a second actor appears to ride the person's session (browser extension / injected agent)",
                    steps[:20], {"reason": "parasitic_sub_branch", "strong": True, "fork_requests": len(roots),
                                 "branch": [f"{r.method} {r.path}" for r in steps[:20]]})]
