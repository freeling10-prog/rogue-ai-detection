"""v3 passive detectors: signals that do NOT depend on a decoy touch or on session averages.

A live demo showed that a client with a browser User-Agent, human-paced timing and no decoy contact left zero leads
and no alert, because every detector either needed a decoy hit or averaged over the whole session.  These detectors
look at single facts about the request stream instead:

* ``asset_starvation``  >= N HTML pages, a User-Agent that *claims* to be a browser, and zero CSS/JS/image/favicon fetches
                        (plus, when the log carries headers, missing/mismatched ``Sec-Fetch-*`` on the page loads);
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


def detect_asset_starvation(session: Session, cfg: dict[str, Any]) -> list[Finding]:
    acfg = cfg["web"]["asset_starvation"]
    if not claims_browser(session, cfg):
        return []                     # a client that declares itself a script/bot is not pretending to be a browser
    pages = [r for r in session.requests if is_html_page(r, cfg)]
    if len(pages) < acfg["min_pages"]:
        return []
    if any(_is_asset(r, cfg) for r in session.requests):
        return []
    mismatch = 0
    checked = 0
    if acfg["sec_fetch_check"]:
        for r in pages:
            if not r.headers_logged:
                continue
            checked += 1
            mode, dest = r.headers.get("sec-fetch-mode", ""), r.headers.get("sec-fetch-dest", "")
            if not mode or dest not in ("document", "iframe", "frame"):
                mismatch += 1
    sec = bool(checked) and mismatch / checked >= acfg["sec_fetch_min_share"]
    note = (f"; {mismatch}/{checked} page loads lack the Sec-Fetch-* headers a browser sends" if checked else
            "; Sec-Fetch-* headers are not in this log format (not checked)")
    return [Finding(
        "web", "asset_starvation",
        f"{len(pages)} HTML pages with a browser-like User-Agent and zero CSS/JS/image/favicon fetches{note}",
        pages[:3], {"pages": len(pages), "sec_fetch_checked": checked, "sec_fetch_mismatch": mismatch, "sec_fetch": sec})]


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
    for fn in (detect_asset_starvation, detect_unlinked_jump, detect_schema_param, detect_session_canary, detect_mcp_flow):
        out.extend(fn(session, cfg))
    return out
