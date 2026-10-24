"""v3 passive detectors: signals that do NOT depend on a decoy touch or on session averages.

A live demo showed that a client with a browser User-Agent, human-paced timing and no decoy contact left zero leads
and no alert, because every detector either needed a decoy hit or averaged over the whole session.  These detectors
look at single facts about the request stream instead:

* ``asset_starvation``  (v4 definition) >= N HTML pages from a client that claims to be a browser with zero *core* sub-resources
                        (.css/.js), or contradictory ``Sec-Fetch-*`` on page loads.  Omitting only images/fonts/favicon is how
                        people with images blocked browse and is NOT starvation; coherent ``navigate``/``document`` headers on
                        the starved pages make it advisory-only (they are also what a person with scripts+styles blocked sends);
* ``headless_automation_signal``  (v4) a browser-backed client (it loads assets, so starvation cannot fire) that follows the
                        ARIA fast-path decoy, reports ``webdriver``/automation globals in the client beacon, or clicks through
                        >= 3 pages after fetching our script without ever sending the beacon that script would send;
* ``unlinked_jump``     per transition: the client asked for a URL the previous page never linked and gave no valid
                        Referer.  The honeypot serves its own pages, so the link graph is known exactly (the mirrored
                        access stream records the links each response offered).  Abstains when the log has no link graph;
* ``schema_param``      any request carrying the camouflaged ``client_schema_rev`` parameter that only the decoy
                        ``/openapi.json`` advertises;
* ``session_canary_param``  a per-session canary served only inside machine-readable docs, presented back;
* ``mcp_list_then_call``  MCP ``tools/list`` followed by a valid ``tools/call`` (needs the honeypot lead detail).

All of them are *contact/behaviour* evidence, not intent: a person on a text-mode browser, a reader mode, an aggressive
ad-blocker or a link checker can look like asset starvation; a person who types a URL makes an unlinked jump.
Each finding says so in its summary through the reasons shown in the report.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

from .models import Finding, Request, Session

_NON_PAGE_EXT = (".json", ".txt", ".xml", ".yaml", ".yml", ".csv", ".ndjson")


def _is_asset(req: Request, cfg: dict[str, Any]) -> bool:
    path = req.path.lower()
    return any(path.endswith(ext) for ext in cfg["assets"]["extensions"])


def is_html_page(req: Request, cfg: dict[str, Any]) -> bool:
    """A navigation-style request for an HTML page.  Uses the logged content type when known, else a path heuristic."""
    if req.method != "GET" or _is_asset(req, cfg):
        return False
    if req.content_type:
        return req.content_type.startswith("text/html")
    low = req.path.lower()
    return 200 <= req.status < 400 and not low.endswith(_NON_PAGE_EXT) and "/api/" not in low


def claims_browser(session: Session, cfg: dict[str, Any]) -> bool:
    pats = cfg["web"]["asset_starvation"]["browser_ua_patterns"]
    ua = " ".join(session.user_agents)
    bots = cfg["ua"]["bot_patterns"] + cfg["ua"]["scripted_patterns"]
    return any(re.search(p, ua, re.I) for p in pats) and not any(re.search(p, ua, re.I) for p in bots)


def asset_kind(req: Request, cfg: dict[str, Any]) -> Optional[str]:
    """Sub-resource type of a request path: css | js | font | favicon | image | other, or None if it is not an asset."""
    path = req.path.lower()
    base = path.rsplit("/", 1)[-1]
    types = cfg["web"]["asset_types"]
    for kind in ("favicon", "css", "js", "font", "image", "other"):
        for pat in types.get(kind, []):
            if (pat.startswith(".") and path.endswith(pat)) or (not pat.startswith(".") and base == pat):
                return kind
    return "other" if _is_asset(req, cfg) else None


def _sec_fetch_state(r: Request) -> str:
    """'absent' (no Sec-Fetch-Mode/Dest), 'coherent' (navigate + a document-like destination) or 'contradictory'."""
    mode, dest = r.headers.get("sec-fetch-mode", ""), r.headers.get("sec-fetch-dest", "")
    if not mode and not dest:
        return "absent"
    if mode == "navigate" and dest in ("document", "iframe", "frame", "embed", "object"):
        return "coherent"
    return "contradictory"


def detect_asset_starvation(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    acfg = cfg["web"]["asset_starvation"]
    if not claims_browser(session, cfg):
        return []                     # a client that declares itself a script/bot is not pretending to be a browser
    pages = [r for r in session.requests if is_html_page(r, cfg)]
    states = [_sec_fetch_state(r) for r in pages if r.headers_logged]
    checked = [x for x in states if x != "absent"]
    contra = sum(1 for x in checked if x == "contradictory")
    coherent = sum(1 for x in checked if x == "coherent")
    # (1) contradictory Sec-Fetch-*: a browser engine never sends e.g. Mode=cors with Dest=document on a navigation
    if acfg["sec_fetch_check"] and len(checked) >= acfg["contradictory_min_pages"] and contra / len(checked) >= acfg["contradictory_share"]:
        return [Finding("web", "asset_starvation",
                        f"{contra}/{len(checked)} page loads carry contradictory Sec-Fetch-* headers (a browser engine would not send them)",
                        pages[:3], {"pages": len(pages), "reason": "contradictory_sec_fetch", "sec_fetch": True,
                                    "sec_fetch_checked": len(checked), "sec_fetch_mismatch": contra})]
    if len(pages) < acfg["min_pages"]:
        return []
    kinds = {asset_kind(r, cfg) for r in session.requests} - {None}
    if kinds & {"css", "js"}:
        return []                     # loads stylesheets/scripts: a rendering client, even if it blocks images/fonts/favicon
    note_kinds = f"; sub-resources fetched: {', '.join(sorted(kinds)) or 'none'}"
    if acfg["coherent_weakens"] and checked and coherent / len(checked) >= 0.9:
        # a person with styles AND scripts blocked / a reader mode sends exactly this; a script that copies browser headers does too
        return [Finding("web_advisory", "asset_starvation_coherent",
                        f"{len(pages)} HTML pages with zero .css/.js fetches but coherent Sec-Fetch navigate/document headers on every "
                        f"page{note_kinds} (advisory only: reader modes, blocked styles+scripts and header-copying scripts look the same)",
                        pages[:3], {"pages": len(pages)})]
    mismatch = sum(1 for x in states if x == "absent")
    sec = bool(states) and mismatch / len(states) >= acfg["sec_fetch_min_share"]
    note = (f"; {mismatch}/{len(states)} page loads lack the Sec-Fetch-* headers a browser sends" if states else
            "; Sec-Fetch-* headers are not in this log format (not checked)")
    return [Finding(
        "web", "asset_starvation",
        f"{len(pages)} HTML pages with a browser-like User-Agent and zero .css/.js fetches{note_kinds}{note}",
        pages[:3], {"pages": len(pages), "reason": "no_core_subresources", "sec_fetch_checked": len(states),
                    "sec_fetch_mismatch": mismatch, "sec_fetch": sec})]


def detect_headless(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    """v4: browser-backed clients.  A client that fetches the page's styles/scripts and follows real links looks like a person in
    every HTTP-level feature, so this uses the two non-visual traps: the ARIA fast-path decoy and the interaction beacon.

    The beacon (``POST /api/v1/telemetry/nav``) carries three booleans only: ``webdriver_present``, ``pointer_trail_seen``,
    ``dom_automation_props``.  Conservative by design: missing beacons are only counted when the client fetched our script
    (a JS-disabled browser never fetches it), and a pointer-less trail is advisory only (keyboard / screen-reader users)."""
    h = cfg["web"]["headless"]
    reqs = session.requests
    pages = [r for r in reqs if is_html_page(r, cfg)]
    kinds = {asset_kind(r, cfg) for r in reqs} - {None}
    browser_backed = claims_browser(session, cfg) and len(pages) >= 2 and bool(kinds & {"css", "js"})
    beacons = [r for r in reqs if r.method == "POST" and r.path == h["beacon_path"]]
    parsed = [r for r in beacons if r.beacon is not None]
    out: list[Finding] = []
    reasons: set[str] = set()
    for r in parsed:
        if r.beacon is None:
            continue
        if r.beacon["webdriver_present"] and "webdriver_present" not in reasons:
            reasons.add("webdriver_present")
            out.append(Finding("web", "headless_automation_signal",
                               "the client's own script reported navigator.webdriver === true (browser automation is driving it)",
                               [r], {"reason": "webdriver_present", "strong": True}))
        if r.beacon["dom_automation_props"] and "dom_automation_props" not in reasons:
            reasons.add("dom_automation_props")
            out.append(Finding("web", "headless_automation_signal",
                               "the client's own script found automation bindings on window (Playwright/CDP-style globals)",
                               [r], {"reason": "dom_automation_props", "strong": True}))
    aria = [r for r in reqs if r.decoy_kind == "aria_fastpath" or (r.path == h["aria_path"] and "aria-fastpath" in r.query)]
    if aria and browser_backed:
        out.append(Finding("web", "headless_automation_signal",
                           "a browser-backed client (it loads our styles/scripts) followed the muted ARIA 'AI Assistant Fast-Path' "
                           "element that people do not click (an agent reading the accessibility tree chose it)",
                           aria[:1], {"reason": "aria_fastpath", "strong": True}))
    # a beacon is only EXPECTED when the page the client clicked from embedded it (plain logs from sites without it: never)
    offered = {p.path for p in pages if p.beacon_offered}
    navs = [r for r in pages[1:] if r.referer and _path_of(r.referer) in offered]
    # v6: the v4 "beacon_missing" moderate finding is replaced by frontierdetect's script_fetched_but_unexecuted (challenge-bound,
    # with the js_assets_fetched == 0 and coherent-headers-no-decoy exemptions).
    if not beacons and len(navs) >= h["min_navs"] and "js" not in kinds:
        out.append(Finding("web_advisory", "beacon_absent_no_js",
                           f"{len(navs)} click-through navigations and no beacon, but our script was never fetched (JavaScript off or a "
                           "privacy tool): advisory only", navs[:3], {"navigations": len(navs)}))
    if len(parsed) >= h["min_pointerless_beacons"] and not any(r.beacon and r.beacon["pointer_trail_seen"] for r in parsed):
        out.append(Finding("web_advisory", "no_pointer_trail",
                           f"{len(parsed)} click-through beacons, none preceded by pointer/touch movement (advisory only: keyboard and "
                           "screen-reader users never move a pointer; a stealth browser agent does not either)", parsed[:3],
                           {"beacons": len(parsed)}))
    return out


def _path_of(url: str) -> str:
    return urlsplit(url).path or "/"


def transitions(session: Session, cfg: dict[str, Any]) -> list[tuple[Request, Optional[Request], str, bool]]:
    """Per-request navigation facts: ``(request, previous page, status, referer_valid)``.

    ``status`` is one of ``entry`` (first page / well-known entry points / revisits: nothing to judge), ``unknown`` (the log
    has no link graph), ``linked`` (the previous page offered this URL, or a valid Referer names a page that did),
    ``offered_earlier`` (not linked from the previous page, but some earlier page offered it to this client: breadth-first
    queues, new tabs) and ``never_offered`` (no page ever offered it to this client: guessed / remembered / hallucinated)."""
    entry = set(cfg["web"]["unlinked_jump"]["entry_paths"])
    out: list[tuple[Request, Optional[Request], str, bool]] = []
    visited: set[str] = set()
    served: dict[str, set[str]] = {}          # path -> links that THIS client was shown there
    ever_offered: set[str] = set()            # every link this client has been shown so far
    prev: Optional[Request] = None
    for r in session.requests:
        if r.method != "GET" or _is_asset(r, cfg):
            continue
        target = r.path
        ref_ok = False
        if prev is None or target in entry or target in visited or target.startswith("/.well-known/"):
            status = "entry"
        elif prev.served_links is None:
            status = "unknown"
        else:
            linked = target in prev.served_links
            if r.referer:
                ref_links = served.get(_path_of(r.referer))
                ref_ok = ref_links is not None and target in ref_links      # Referer must be a page we served that links here
            if linked or ref_ok:
                status = "linked"
            else:
                status = "offered_earlier" if target in ever_offered else "never_offered"
        out.append((r, prev, status, ref_ok))
        visited.add(target)
        if r.served_links is not None:
            served[target] = set(r.served_links)
            ever_offered.update(r.served_links)
        prev = r
    return out


def detect_unlinked_jump(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    ucfg = cfg["web"]["unlinked_jump"]
    out: list[Finding] = []
    for r, prev, status, _ in transitions(session, cfg):
        if status in ("never_offered", "offered_earlier") and prev is not None and len(out) < ucfg["max_findings"]:
            # "never_offered": this client was never shown a link to the URL (guessed / remembered / hallucinated);
            # "offered_earlier": it was shown on an earlier page (breadth-first queues, new tabs without Referer)
            earlier = status == "offered_earlier"
            out.append(Finding("web", "unlinked_jump",
                               f"went from {prev.path} to {r.path}, which {prev.path} does not link, with no valid Referer"
                               + (" (but an earlier page offered it)" if earlier else " (no page ever offered it to this client)"),
                               [prev, r], {"from": prev.path, "to": r.path, "referer_present": bool(r.referer),
                                           "offered_earlier": earlier}))
    return out


def detect_schema_param(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    name = cfg["web"]["schema_param"]["name"]
    for r in session.requests:
        if name in r.params or "schema_param_use" in r.tags:
            return [Finding("web", "schema_param",
                            f"sent the camouflaged parameter '{name}' that only the decoy openapi.json advertises (it parsed the schema)",
                            [r], {"path": r.path})]
    return []


def detect_session_canary(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    rx = re.compile(cfg["web"]["session_canary_pattern"])
    for r in session.requests:
        if "session_canary_param" in r.tags or rx.search(r.query):
            return [Finding("web", "session_canary_param",
                            "presented a per-session canary value that is only served inside machine-readable documents",
                            [r], {"path": r.path})]
    return []


def detect_mcp_flow(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    for r in session.requests:
        if r.source == "honeypot" and (r.detail.get("list_then_valid_call") is True or "mcp_list_then_call" in r.tags):
            return [Finding("web", "mcp_list_then_call",
                            "MCP tools/list followed by a valid tools/call (goal-directed tool use; contact, not intent)",
                            [r], {"tool": r.detail.get("tool")})]
    return []


def run_web_detectors(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    if not cfg["web"]["enabled"]:
        return []
    out: list[Finding] = []
    from .frontierdetect import detect_frontier       # v6 (lazy: it imports helpers from this module)
    for fn in (detect_asset_starvation, detect_headless, detect_unlinked_jump, detect_schema_param, detect_session_canary, detect_mcp_flow,
               detect_frontier):
        out.extend(fn(session, cfg))
    return out
