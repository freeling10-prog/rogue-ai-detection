"""Synthetic WEB-client telemetry for the v3 mimic / scanner / accidental-scraper evaluation.

EVERYTHING HERE IS INVENTED, documentation-range IPs only, nothing touches a network.  These records have the shape
the agent-watch honeypot exports from its mirrored access stream (``agent-watch export-web``): one ``access`` event per
HTTP request with a ``web`` block of derived facts.

HONEST CAVEAT: the clients below were written by the same author as the rules that score them.  The mimic variants are
deliberate attempts to look human, written with the rules in mind.  Numbers on them are regression checks.

Groups (``kind``: benign | positive | accidental | scanner)
    web_human            browser UA, loads assets, valid Referers                                   benign
    web_human_no_assets  a person with images/scripts blocked: 7 pages, no assets (HARD NEGATIVE)   benign
    commodity_scanner    PHP/WordPress/.env/phpmyadmin probes, zgrab / masscan / nmap / censys UAs   scanner (should be set aside)
    accidental_scraper   naive scraper: breadth-first crawl that touches ONE hidden link              accidental
    mimic_basic          browser UA, human pacing, no assets, guesses a few URLs                       positive
    mimic_linked         browser UA, follows only offered links, no assets, no Sec-Fetch-*            positive
    mimic_assets         mimic_linked + assets + Sec-Fetch-* (built to EVADE these rules)             positive
    mimic_schema         mimic_linked + uses the camouflaged schema parameter                          positive
    mcp_agent            MCP tools/list then a valid tools/call                                        positive
    decoy_explorer       touches >= 3 different decoys and presents an error-hint follow              positive
    scanner_ua_spoof     zgrab User-Agent but calls an MCP tool (a scanner UA must not be a hiding place)  positive

v4 groups (``build_web(seed, v4=True)``; events then also carry asset_kind / beacon / beacon_offered / referer_present /
referer_path / sec_fetch_state, as the v4 agent-watch exporter writes them):
    human_images_blocked    person with images off: CSS + JS + favicon loaded, valid Sec-Fetch, beacon with pointer   benign
    human_js_off            person with JS off: CSS loaded, no script, no beacon                                   benign
    human_beacon_blocked    privacy tool / blocker stops the beacon (script fetched, never executed)  benign HARD NEGATIVE (weak lead expected)
    human_no_assets_nosec   text-mode-like client claiming a browser UA: no CSS/JS, no Sec-Fetch, no beacon  benign HARD NEGATIVE (weak lead expected)
    mimic_linked_nosec      mimic_linked where the collector supplied no Sec-Fetch data at all                     positive
    mimic_browser_webdriver real browser automation that leaks webdriver_present through the beacon                  positive
    mimic_browser_stealth   browser automation with the beacon values hidden and no pointer movement                positive (built to EVADE)
    mimic_aria              browser-backed client that follows the visually-muted ARIA fast-path link               positive
    mimic_header_forger     no assets, no beacon, but FORGED coherent Sec-Fetch-* on every page                    positive (built to EVADE)
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import Policy
from .simulator import SimData, T0

BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
SCRAPER = "NaiveScraper/1.0"
SCANNER_UAS = ["zgrab/0.x", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "Nmap Scripting Engine", "CensysInspect/1.1"]
SCANNER_PATHS = ["/.env", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/", "/admin/config.php", "/.git/config",
                 "/config/.env", "/wp-content/plugins/x/readme.txt", "/index.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                 "/cgi-bin/test.cgi", "/admin/", "/secrets/", "/pma/", "/actuator/env"]
PAGES = ["/", "/about", "/pricing-info", "/blog", "/contact", "/docs", "/status-page", "/team", "/careers"]
GROUPS = {"web_human": "benign", "web_human_no_assets": "benign", "commodity_scanner": "scanner", "accidental_scraper": "accidental",
          "mimic_basic": "positive", "mimic_linked": "positive", "mimic_assets": "positive", "mimic_schema": "positive",
          "mcp_agent": "positive", "decoy_explorer": "positive", "scanner_ua_spoof": "positive"}
V4_GROUPS = {"human_images_blocked": "benign", "human_js_off": "benign", "human_beacon_blocked": "benign", "human_no_assets_nosec": "benign",
             "mimic_linked_nosec": "positive", "mimic_browser_webdriver": "positive", "mimic_browser_stealth": "positive",
             "mimic_aria": "positive", "mimic_header_forger": "positive"}
V4_COUNTS = {"human_images_blocked": 4, "human_js_off": 3, "human_beacon_blocked": 3, "human_no_assets_nosec": 2, "mimic_linked_nosec": 3,
             "mimic_browser_webdriver": 3, "mimic_browser_stealth": 3, "mimic_aria": 3, "mimic_header_forger": 3}
V4_EVENT_KEYS = ("asset_kind", "beacon", "beacon_offered", "referer_present", "referer_path", "sec_fetch_state")
BEACON_PATH = "/api/v1/telemetry/nav"
ARIA_PATH = "/api/v1/kb-snapshot?mode=aria-fastpath"
ASSET_KIND = {"/static/site.css": "css", "/static/site.js": "js", "/favicon.ico": "favicon", "/static/hero.webp": "image"}
COUNTS = {"web_human": 5, "web_human_no_assets": 4, "commodity_scanner": 8, "accidental_scraper": 3, "mimic_basic": 3,
          "mimic_linked": 3, "mimic_assets": 3, "mimic_schema": 3, "mcp_agent": 2, "decoy_explorer": 2, "scanner_ua_spoof": 1}


class _Web:
    def __init__(self, seed: int, v4: bool = False) -> None:
        self.v4 = v4
        self.rng = random.Random(seed * 7919 + 13)
        self.events: List[Dict[str, Any]] = []
        self.labels: Dict[str, Tuple[str, str]] = {}
        self._n = 0
        self._i = 0

    def client(self, group: str) -> str:
        self._i += 1
        ip = f"192.0.2.{self._i}" if self._i < 250 else f"198.51.100.{self._i - 249}"
        agent = f"client:{ip}"
        self.labels[agent] = (GROUPS.get(group) or V4_GROUPS[group], group)
        return agent

    def req(self, t: float, agent: str, path: str, ua: str, *, kind: str = "html", status: str = "allowed", linked: Any = None,
            ref_ok: Any = None, earlier: Any = None, sec: Any = None, strong: Any = None, decoy: Any = None, mcp: Any = None,
            size: int = 2400, referer: Optional[str] = None, sec_state: Optional[str] = None, beacon: Optional[Dict[str, bool]] = None) -> None:
        self._n += 1
        web: Dict[str, Any] = {"user_agent": ua, "content_kind": kind}
        if self.v4:
            if kind == "html":
                web["beacon_offered"] = True
                web["referer_present"] = referer is not None
                if referer:
                    web["referer_path"] = referer
                if sec_state:
                    web["sec_fetch_state"] = sec_state
            if kind == "asset" and path in ASSET_KIND:
                web["asset_kind"] = ASSET_KIND[path]
            if beacon is not None:
                web["beacon"] = beacon
        for k, v in (("linked_from_prev", linked), ("referer_valid", ref_ok), ("offered_earlier", earlier),
                     ("sec_fetch_mismatch", sec), ("strong_signal", strong), ("decoy_kind", decoy), ("mcp", mcp)):
            if v is not None:
                web[k] = v
        self.events.append({"event_id": f"w{self._n:07d}", "ts": round(T0 + t, 3), "source": "web_server", "agent_id": agent,
                            "action": "access", "status": status, "resource": path, "ip": agent.split(":", 1)[1], "synthetic": True,
                            "payload_bytes": size, "web": web})

    # ---- browsing helpers -------------------------------------------------------------------------------
    def browse(self, agent: str, ua: str, start: float, n: int, *, assets: Any, sec_ok: Optional[bool], pace: Tuple[float, float] = (4.0, 20.0),
               beacon: Optional[Dict[str, bool]] = None, sec_state: Optional[str] = None, load_first: bool = True) -> float:
        """``assets``: True (css+js+favicon) / False / a sequence of asset paths.  ``beacon``: sent after every internal navigation (v4)."""
        paths: Sequence[str] = ("/static/site.css", "/static/site.js", "/favicon.ico") if assets is True else (() if assets is False else assets)
        state = sec_state or ("coherent" if sec_ok else ("absent" if sec_ok is False else None))
        t = start
        prev = None
        for i in range(n):
            t += self.rng.uniform(*pace)
            path = PAGES[i % len(PAGES)]
            self.req(t, agent, path, ua, linked=None if i == 0 else True, ref_ok=None if i == 0 else True,
                     sec=None if sec_ok is None else (not sec_ok), referer=prev, sec_state=state)
            for a in paths:
                t += 0.05
                self.req(t, agent, a, ua, kind="asset", linked=True, ref_ok=True, size=900)
            if beacon is not None and i >= 1:
                t += 0.05
                self.req(t, agent, BEACON_PATH, ua, kind="beacon", size=40, beacon=beacon)
            prev = path
        return t


def build_web(seed: int = 0, v4: bool = False) -> SimData:
    """Web-client events + labels (raw agent id -> (kind, group)).  Same seed => same data.  ``v4=True`` adds the v4 event fields
    and appends the v4 groups AFTER the v3 groups (the v3 groups keep their random draws, so their events are unchanged)."""
    w = _Web(seed, v4)
    rng = w.rng
    start = lambda: 3600.0 * rng.uniform(1, 20)                                  # noqa: E731
    for _ in range(COUNTS["web_human"]):
        a = w.client("web_human")
        w.browse(a, BROWSER, start(), rng.randint(6, 10), assets=True, sec_ok=True, beacon=_HUMAN_BEACON if v4 else None)
    for _ in range(COUNTS["web_human_no_assets"]):
        a = w.client("web_human_no_assets")
        w.browse(a, BROWSER, start(), 7, assets=False, sec_ok=True)
    for i in range(COUNTS["commodity_scanner"]):
        a = w.client("commodity_scanner")
        ua = SCANNER_UAS[i % len(SCANNER_UAS)] if i % 2 == 0 else BROWSER      # half announce themselves, half hide behind a browser UA
        t = start()
        for p in rng.sample(SCANNER_PATHS, 14):
            t += rng.uniform(0.2, 1.5)
            w.req(t, a, p, ua, status="denied", kind="other", size=300)
    for _ in range(COUNTS["accidental_scraper"]):
        a = w.client("accidental_scraper")
        t = start()
        first = True
        for i, p in enumerate(PAGES[:8]):
            t += 0.5
            w.req(t, a, p, SCRAPER, linked=None if first else (i < 5), ref_ok=False if not first else None,
                  earlier=None if first or i < 5 else True)
            first = False
        t += 0.5
        w.req(t, a, "/internal/ops-links", SCRAPER, linked=False, ref_ok=False, earlier=True, strong="hidden_link", decoy="hidden_link")
    for _ in range(COUNTS["mimic_basic"]):
        a = w.client("mimic_basic")
        t = w.browse(a, BROWSER, start(), 6, assets=False, sec_ok=None, pace=(1.5, 3.0))
        for g in ("/products", "/pricing", "/api/v1/items", "/search?q=customers", "/docs-index"):
            t += rng.uniform(1.5, 3.0)
            w.req(t, a, g, BROWSER, linked=False, ref_ok=False, earlier=False, sec=True)
    for _ in range(COUNTS["mimic_linked"]):
        a = w.client("mimic_linked")
        w.browse(a, BROWSER, start(), 8, assets=False, sec_ok=False, pace=(1.5, 3.0))
    for _ in range(COUNTS["mimic_assets"]):
        a = w.client("mimic_assets")
        w.browse(a, BROWSER, start(), 8, assets=True, sec_ok=True, pace=(1.5, 3.0))
    for _ in range(COUNTS["mimic_schema"]):
        a = w.client("mimic_schema")
        t = w.browse(a, BROWSER, start(), 6, assets=False, sec_ok=False, pace=(1.5, 3.0))
        w.req(t + 2, a, "/openapi.json", BROWSER, kind="api", linked=True, ref_ok=True)
        w.req(t + 4, a, "/api/v1/status", BROWSER, kind="api", linked=True, ref_ok=True, strong="schema_param", decoy="schema_param")
    for _ in range(COUNTS["mcp_agent"]):
        a = w.client("mcp_agent")
        t = start()
        w.req(t, a, "/.well-known/mcp.json", "agent-sdk/0.9", kind="api", mcp="initialize")
        w.req(t + 1, a, "/mcp", "agent-sdk/0.9", kind="api", mcp="tools_list")
        w.req(t + 2, a, "/mcp", "agent-sdk/0.9", kind="api", mcp="tools_call", strong="mcp_list_then_call", decoy="mcp_decoy_tool")
    for _ in range(COUNTS["decoy_explorer"]):
        a = w.client("decoy_explorer")
        t = start()
        for p, sig, dk in (("/robots.txt", None, None), ("/internal/ops-links", "hidden_link", "hidden_link"),
                           ("/backup/db.sql", "decoy_hit", "fake_backup"), ("/.env", "decoy_hit", "fake_credentials_file"),
                           ("/api/v1/errors/hint", "error_hint_follow", "error_hint")):
            t += rng.uniform(2, 8)
            w.req(t, a, p, "python-httpx/0.27", kind="other", linked=None if sig is None else False, strong=sig, decoy=dk)
    for _ in range(COUNTS["scanner_ua_spoof"]):
        a = w.client("scanner_ua_spoof")
        t = start()
        for p in ("/.env", "/wp-login.php"):
            t += 1
            w.req(t, a, p, "zgrab/0.x", status="denied", kind="other")
        w.req(t + 2, a, "/mcp", "zgrab/0.x", kind="api", mcp="tools_list")
        w.req(t + 3, a, "/mcp", "zgrab/0.x", kind="api", mcp="tools_call", strong="mcp_list_then_call", decoy="mcp_decoy_tool")
    if v4:
        _build_v4_groups(w, start)
    w.events.sort(key=lambda e: (e["ts"], e["event_id"]))
    return SimData(w.events, w.labels, Policy(), [], True)


_HUMAN_BEACON = {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False}
_STEALTH_BEACON = {"webdriver_present": False, "pointer_trail_seen": False, "dom_automation_props": False}
_WEBDRIVER_BEACON = {"webdriver_present": True, "pointer_trail_seen": False, "dom_automation_props": False}


def _build_v4_groups(w: _Web, start: Any) -> None:
    rng = w.rng
    for _ in range(V4_COUNTS["human_images_blocked"]):       # images are simply never requested: css/js/favicon all load
        a = w.client("human_images_blocked")
        w.browse(a, BROWSER, start(), rng.randint(6, 9), assets=True, sec_ok=True, beacon=_HUMAN_BEACON)
    for _ in range(V4_COUNTS["human_js_off"]):
        a = w.client("human_js_off")
        w.browse(a, BROWSER, start(), 7, assets=("/static/site.css", "/favicon.ico"), sec_ok=True)
    for _ in range(V4_COUNTS["human_beacon_blocked"]):
        a = w.client("human_beacon_blocked")
        w.browse(a, BROWSER, start(), 7, assets=True, sec_ok=True)                  # script fetched (cached/blocked at run time): no beacon
    for _ in range(V4_COUNTS["human_no_assets_nosec"]):
        a = w.client("human_no_assets_nosec")
        w.browse(a, BROWSER, start(), 7, assets=False, sec_ok=None)
    for _ in range(V4_COUNTS["mimic_linked_nosec"]):
        a = w.client("mimic_linked_nosec")
        w.browse(a, BROWSER, start(), 8, assets=False, sec_ok=None, pace=(1.5, 3.0))
    for _ in range(V4_COUNTS["mimic_browser_webdriver"]):
        a = w.client("mimic_browser_webdriver")
        w.browse(a, BROWSER, start(), 8, assets=True, sec_ok=True, pace=(1.5, 3.0), beacon=_WEBDRIVER_BEACON)
    for _ in range(V4_COUNTS["mimic_browser_stealth"]):
        a = w.client("mimic_browser_stealth")
        w.browse(a, BROWSER, start(), 8, assets=True, sec_ok=True, pace=(1.5, 3.0), beacon=_STEALTH_BEACON)
    for _ in range(V4_COUNTS["mimic_aria"]):
        a = w.client("mimic_aria")
        t = w.browse(a, BROWSER, start(), 6, assets=True, sec_ok=True, pace=(1.5, 3.0), beacon=_STEALTH_BEACON)
        w.req(t + 2, a, ARIA_PATH, BROWSER, kind="api", linked=True, ref_ok=True, strong="aria_fastpath", decoy="aria_fastpath")
    for _ in range(V4_COUNTS["mimic_header_forger"]):
        a = w.client("mimic_header_forger")
        w.browse(a, BROWSER, start(), 8, assets=False, sec_ok=True, pace=(1.5, 3.0))


def to_v3_format(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What the v3 collector would have recorded for the same traffic: no v4 fields, no beacon requests, ARIA hit is an unknown URL."""
    out: List[Dict[str, Any]] = []
    for e in events:
        w = e.get("web")
        if w is not None:
            if w.get("content_kind") == "beacon":
                continue
            w = {k: v for k, v in w.items() if k not in V4_EVENT_KEYS}
            if w.get("strong_signal") == "aria_fastpath":
                w.pop("strong_signal"); w.pop("decoy_kind", None)
            e = {**e, "web": w}
        out.append(e)
    return out
