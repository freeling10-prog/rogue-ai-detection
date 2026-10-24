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
from .schema import V6_SIGNALS

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
        self.labels[agent] = (GROUPS.get(group) or V4_GROUPS.get(group) or V6_GROUPS[group], group)
        return agent

    def req(self, t: float, agent: str, path: str, ua: str, *, kind: str = "html", status: str = "allowed", linked: Any = None,
            ref_ok: Any = None, earlier: Any = None, sec: Any = None, strong: Any = None, decoy: Any = None, mcp: Any = None,
            size: int = 2400, referer: Optional[str] = None, sec_state: Optional[str] = None, beacon: Optional[Dict[str, bool]] = None,
            extra: Optional[Dict[str, Any]] = None) -> None:
        self._n += 1
        web: Dict[str, Any] = {"user_agent": ua, "content_kind": kind, **(extra or {})}
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


def build_web(seed: int = 0, v4: bool = False, v6: bool = False) -> SimData:
    """Web-client events + labels (raw agent id -> (kind, group)).  Same seed => same data.  ``v4=True`` adds the v4 event fields
    and appends the v4 groups AFTER the v3 groups (the v3 groups keep their random draws, so their events are unchanged).
    ``v6=True`` (implies v4) is what the v6 agent-watch collector would record for the same site with the v6 traps: six-boolean beacons,
    ``js_assets_fetched``, ``cursor_prov``, ``signals``; the v4 header forger / browser-stealth clients behave as they would on that
    site (post-processing with a SEPARATE random stream, so every v3/v4 draw is unchanged); and the v6 groups are appended."""
    v4 = v4 or v6
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
    if v6:
        _build_v6(w, seed, start)
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


# ======================================================================================================================== v6
# SAME-AUTHOR SYNTHETIC COHORTS.  Every evader below was written by the author of the v6 rules, knowing them.  To keep them from
# being trivially tailored, each cohort mixes variants that the rules are NOT expected to catch (humanized kinematics, cursor-free
# HTML-only readers, riders whose timing falls outside the fork window, swarms whose inheritance is late or partial).  Numbers on
# them are regression checks.
V6_GROUPS = {"human_accessibility": "benign", "human_flaky_network": "benign", "slow_legit_crawler": "benign", "human_two_tabs": "benign",
             "human_kb_reader": "benign",
             "mimic_vlm_os": "positive", "mimic_schema_sanitizer": "positive", "mimic_parasitic_rider": "positive",
             "swarm_schelling_overlap": "positive", "swarm_disjoint_partition": "positive", "llmjacking_prober": "positive"}
V6_COUNTS = {"human_accessibility": 3, "human_flaky_network": 3, "slow_legit_crawler": 3, "human_two_tabs": 3, "human_kb_reader": 6,
             "mimic_vlm_os": 3, "mimic_schema_sanitizer": 3, "mimic_parasitic_rider": 3, "swarm_schelling_overlap": 6,
             "swarm_disjoint_partition": 3, "llmjacking_prober": 2}
V6_EVENT_KEYS = ("js_assets_fetched", "cursor_prov", "signals", "llmjacking")
V6_ONLY_DECOYS = ("dom_visual_inversion_hit", "llmjacking_probe", "beacon_forged")
INVERSION_PATH = "/kb/archive/diagnostic"
LLM_PATH = "/v1/chat/completions"
KB = [f"/kb/article-{i}" for i in range(1, 71)]
CRAWLER_UA = "ExampleSearchBot/2.1 (+https://search.example/bot)"
_BEACON_OK6 = {"challenge_proof_ok": True, "kinematic_dwell_ok": True, "inertial_scroll_ok": True}


def _cur(rng: random.Random) -> str:
    return "".join(rng.choice("abcdef0123456789") for _ in range(12))


def _b6(base: Dict[str, bool], proof: Optional[bool], dwell: Optional[bool], inertial: Optional[bool]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(base)
    for k, v in (("challenge_proof_ok", proof), ("kinematic_dwell_ok", dwell), ("inertial_scroll_ok", inertial)):
        if v is not None:
            out[k] = v
    return out


def _upgrade_v4_cohorts(w: _Web, seed: int) -> None:
    """What the v4 cohorts look like to the v6 collector (separate random stream; the v3/v4 draws are untouched)."""
    rng = random.Random(seed * 104729 + 6)
    by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for e in w.events:
        by_agent.setdefault(e["agent_id"], []).append(e)
    extra: List[Dict[str, Any]] = []
    forger_i = stealth_i = 0
    for agent, evs in sorted(by_agent.items()):
        grp = w.labels[agent][1]
        evs.sort(key=lambda e: e["ts"])
        for e in evs:
            b = e["web"].get("beacon")
            if b is None:
                continue
            if grp in ("mimic_browser_stealth", "mimic_aria"):        # CDP clicks: zero dwell, no pointer; scrollIntoView jumps
                e["web"]["beacon"] = _b6(b, True, False, False)
            elif grp == "mimic_browser_webdriver":
                e["web"]["beacon"] = _b6(b, True, False, rng.random() < 0.5)
            else:                                                     # people: our JS ran, natural kinematics
                e["web"]["beacon"] = _b6(b, True, True, rng.random() < 0.9)
        if grp == "mimic_header_forger":
            if forger_i % 3 != 2:                                     # 2 of 3 post a CANNED beacon they never computed
                for e in evs:
                    if e["web"].get("content_kind") == "html" and e["web"].get("referer_present"):
                        w._n += 1
                        extra.append({**{k: e[k] for k in ("source", "agent_id", "ip", "synthetic")}, "event_id": f"w{w._n:07d}",
                                      "ts": round(e["ts"] + 0.4, 3), "action": "access", "status": "allowed", "resource": BEACON_PATH,
                                      "payload_bytes": 40, "web": {"user_agent": e["web"]["user_agent"], "content_kind": "beacon",
                                                                   "beacon": _b6(_HUMAN_BEACON, False, True, True), "signals": ["beacon_forged"],
                                                                   "decoy_kind": "beacon_forged"}})
            forger_i += 1                                              # the third posts nothing: indistinguishable from a NoScript reader
        if grp == "mimic_browser_stealth":
            if stealth_i % 3 != 2:                                    # DOM-order link pickers hit the inverted link on the first page
                first = next(e for e in evs if e["web"].get("content_kind") == "html")
                w._n += 1
                extra.append({**{k: first[k] for k in ("source", "agent_id", "ip", "synthetic")}, "event_id": f"w{w._n:07d}",
                              "ts": round(first["ts"] + 1.1, 3), "action": "access", "status": "allowed", "resource": INVERSION_PATH,
                              "payload_bytes": 1800, "web": {"user_agent": first["web"]["user_agent"], "content_kind": "html", "linked_from_prev": True,
                                                             "referer_valid": True, "referer_present": True, "referer_path": first["resource"],
                                                             "beacon_offered": True, "sec_fetch_state": "coherent", "sec_fetch_mismatch": False,
                                                             "strong_signal": "decoy_hit", "decoy_kind": "dom_visual_inversion_hit",
                                                             "signals": ["dom_visual_inversion_hit"]}})
            stealth_i += 1                                             # the third picks links by visible text: no inversion hit
    w.events += extra


class _V6:
    def __init__(self, w: _Web, seed: int) -> None:
        self.w = w
        self.rng = random.Random(seed * 15485863 + 66)

    def page(self, t: float, a: str, path: str, ua: str = BROWSER, *, prev: Optional[str], linked: Any = True, status: str = "allowed",
             sec: Optional[str] = "coherent", cursor_prov: Optional[str] = None, signals: Sequence[str] = (), decoy: Optional[str] = None,
             strong: Optional[str] = None, kind: str = "html", earlier: Any = None, offered: bool = True) -> None:
        ex: Dict[str, Any] = {}
        if cursor_prov:
            ex["cursor_prov"] = cursor_prov
        if signals:
            assert all(x in V6_SIGNALS for x in signals)
            ex["signals"] = list(signals)
        self.w.req(t, a, path, ua, kind=kind, status=status, linked=None if prev is None and linked is True else linked,
                   ref_ok=(True if prev is not None and linked else (False if linked is False else None)), earlier=earlier,
                   sec=None if sec is None else sec != "coherent", referer=prev if linked is not False else None,
                   sec_state=sec if kind == "html" else None, strong=strong, decoy=decoy, extra=ex)
        if kind == "html" and not offered:
            self.w.events[-1]["web"].pop("beacon_offered", None)

    def assets(self, t: float, a: str, ua: str = BROWSER) -> float:
        for p in ("/static/site.css", "/static/site.js", "/favicon.ico"):
            t += 0.05
            self.w.req(t, a, p, ua, kind="asset", linked=True, ref_ok=True, size=900)
        return t

    def beacon(self, t: float, a: str, b: Dict[str, Any], ua: str = BROWSER) -> None:
        self.w.req(t, a, BEACON_PATH, ua, kind="beacon", size=40, beacon=b)

    def human_nav(self, a: str, t: float, paths: Sequence[str], *, pace: Tuple[float, float] = (5.0, 25.0), beacon_p: float = 1.0,
                  b: Optional[Dict[str, Any]] = None) -> float:
        rng = self.rng
        prev: Optional[str] = None
        for i, p in enumerate(paths):
            t += rng.uniform(*pace)
            cp = "html" if p.startswith("/kb/article") else None
            self.page(t, a, p + (f"?cursor=h{_cur(rng)}" if cp else ""), prev=prev, cursor_prov=cp)
            t = self.assets(t, a)
            if i >= 1 and rng.random() < beacon_p:
                self.beacon(t + 0.1, a, b or _b6(_HUMAN_BEACON, True, True, rng.random() < 0.9))
            prev = p
        return t


def _js_counts(w: _Web) -> None:
    """``js_assets_fetched`` on every event of a session, as the v6 exporter writes it."""
    n: Dict[str, int] = {}
    for e in w.events:
        if e["web"].get("asset_kind") == "js" and e["status"] == "allowed":
            n[e["agent_id"]] = n.get(e["agent_id"], 0) + 1
    for e in w.events:
        e["web"]["js_assets_fetched"] = n.get(e["agent_id"], 0)


def _build_v6(w: _Web, seed: int, start: Any) -> None:
    _upgrade_v4_cohorts(w, seed)
    v = _V6(w, seed)
    rng = v.rng
    st = lambda: 3600.0 * rng.uniform(1, 20)                                    # noqa: E731
    kb_paths = lambda n: rng.sample(KB, n)                                       # noqa: E731
    # ------------------------------------------------------------------ benign
    for i in range(V6_COUNTS["human_kb_reader"]):          # ordinary readers of the knowledge base (cursor from the HTML page)
        a = w.client("human_kb_reader")
        v.human_nav(a, st(), ["/", "/kb/"] + kb_paths(rng.randint(5, 12)))
    for i in range(V6_COUNTS["human_accessibility"]):      # keyboard / screen reader: DOM order, PageDown jumps, no pointer
        a = w.client("human_accessibility")
        t = st()
        prev: Optional[str] = None
        paths = ["/", "/kb/"] + kb_paths(rng.randint(4, 8))
        for k, p in enumerate(paths):
            t += rng.uniform(8, 40)
            cp = "html" if p.startswith("/kb/article") else None
            v.page(t, a, p + (f"?cursor=h{_cur(rng)}" if cp else ""), prev=prev, cursor_prov=cp)
            t = v.assets(t, a)
            if k == 1 and rng.random() < 0.6:              # tabbing in DOM order reaches the inverted archive link first
                t += rng.uniform(4, 12)
                v.page(t, a, INVERSION_PATH, prev=p, signals=["dom_visual_inversion_hit"], decoy="dom_visual_inversion_hit", strong="decoy_hit")
                t = v.assets(t, a)
            if k >= 1:
                v.beacon(t + 0.1, a, _b6({"webdriver_present": False, "pointer_trail_seen": False, "dom_automation_props": False}, True,
                                        None if rng.random() < 0.7 else True, False))
            prev = p
    for i in range(V6_COUNTS["human_flaky_network"]):      # timeouts, proxy 502/504s and retries; half the beacons are lost
        a = w.client("human_flaky_network")
        t = st()
        prev = None
        for k, p in enumerate(["/"] + PAGES[1:] + kb_paths(4)):
            t += rng.uniform(4, 20)
            cp = "html" if p.startswith("/kb/article") else None
            q = p + (f"?cursor=h{_cur(rng)}" if cp else "")
            if rng.random() < 0.3:                           # failed attempt(s), then a retry of the SAME URL
                for _ in range(rng.randint(1, 2)):
                    v.page(t, a, q, prev=prev, status="denied", cursor_prov=cp)
                    t += rng.uniform(1.0, 6.0)
            v.page(t, a, q, prev=prev, cursor_prov=cp)
            t = v.assets(t, a)
            if k >= 1 and rng.random() < 0.5:
                v.beacon(t + 0.3, a, _b6(_HUMAN_BEACON, True, True, True))
            prev = p
    for i in range(V6_COUNTS["slow_legit_crawler"]):       # declared search crawler: robots, sitemap order, slow, dead links 404
        a = w.client("slow_legit_crawler")
        t = st()
        v.page(t, a, "/robots.txt", CRAWLER_UA, prev=None, kind="other", sec=None)
        v.page(t + 2, a, "/sitemap.xml", CRAWLER_UA, prev=None, kind="other", sec=None)
        for p in rng.sample(PAGES + KB, 40):
            t += rng.uniform(30, 120)
            dead = rng.random() < 0.06
            cp = "html" if p.startswith("/kb/article") else None
            v.page(t, a, p + (f"?cursor=h{_cur(rng)}" if cp else ""), CRAWLER_UA, prev=None, linked=False, earlier=True,
                   status="denied" if dead else "allowed", sec=None, cursor_prov=cp)
    for i in range(V6_COUNTS["human_two_tabs"]):           # opens several links in background tabs at once (all linked, valid Referer)
        a = w.client("human_two_tabs")
        t = st()
        v.page(t, a, "/kb/", prev=None)
        t = v.assets(t, a)
        for _ in range(3):
            t += rng.uniform(5, 20)
            for p in kb_paths(rng.randint(2, 3)):
                t += rng.uniform(0.08, 0.35)
                v.page(t, a, p + f"?cursor=h{_cur(rng)}", prev="/kb/", cursor_prov="html")
                v.assets(t, a)
            v.beacon(t + 0.5, a, _b6(_HUMAN_BEACON, True, True, True))
    # ------------------------------------------------------------------ positives (same-author; mixed variants)
    for i in range(V6_COUNTS["mimic_vlm_os"]):             # pixel-space VLM driving a real browser with OS cursor jumps
        a = w.client("mimic_vlm_os")
        humanized = i % 3 == 2                             # one in three synthesizes human dwell + curved paths: expected miss
        t = st()
        prev = None
        for k, p in enumerate(["/", "/kb/"] + kb_paths(rng.randint(5, 8))):
            t += rng.uniform(3, 12)
            cp = "html" if p.startswith("/kb/article") else None
            v.page(t, a, p + (f"?cursor=h{_cur(rng)}" if cp else ""), prev=prev, cursor_prov=cp)
            t = v.assets(t, a)
            if k == 1 and rng.random() < 0.1:              # it SEES visual order, so it rarely clicks the inverted link
                t += 2
                v.page(t, a, INVERSION_PATH, prev=p, signals=["dom_visual_inversion_hit"], decoy="dom_visual_inversion_hit", strong="decoy_hit")
            if k >= 1:
                scrolled = rng.random() < 0.8
                v.beacon(t + 0.2, a, _b6(_HUMAN_BEACON, True, True if humanized else rng.random() < 0.15,
                                        not scrolled))       # quantized OS scroll jumps when it scrolls
            prev = p
    for i in range(V6_COUNTS["mimic_schema_sanitizer"]):   # Dual-LLM quarantined reader + privileged planner
        a = w.client("mimic_schema_sanitizer")
        variant = i % 3
        t = st()
        for p in ("/llms.txt", "/openapi.json"):
            t += rng.uniform(1, 3)
            v.page(t, a, p, prev=None, kind="api", sec=None)
        prev = None
        for k, p in enumerate(["/", "/kb/"] + kb_paths(rng.randint(5, 8))):
            t += rng.uniform(2, 6)
            if not p.startswith("/kb/article"):
                v.page(t, a, p, prev=prev)
            elif variant == 0:                             # keeps the cursor it read in the schema (load-bearing)
                v.page(t, a, p + f"?cursor=s{_cur(rng)}", prev=prev, cursor_prov="schema", signals=["schema_provenance_cursor"])
            elif variant == 1 and k < 6:                   # strips "optional-looking" parameters -> 400, then retries via the HTML link
                v.page(t, a, p, prev=prev, status="denied", signals=["missing_required_cursor"])
                t += rng.uniform(1, 3)
                v.page(t, a, p + f"?cursor=h{_cur(rng)}", prev=prev, cursor_prov="html")
            else:                                          # uses only cursors the HTML handed out: expected miss
                v.page(t, a, p + f"?cursor=h{_cur(rng)}", prev=prev, cursor_prov="html")
            prev = p
    for i in range(V6_COUNTS["mimic_parasitic_rider"]):    # agent riding inside a real person's browser session
        a = w.client("mimic_parasitic_rider")
        t = st()
        prev = None
        for k, p in enumerate(["/", "/kb/"] + kb_paths(rng.randint(6, 9))):
            t += rng.uniform(5, 25)
            cp = "html" if p.startswith("/kb/article") else None
            v.page(t, a, p + (f"?cursor=h{_cur(rng)}" if cp else ""), prev=prev, cursor_prov=cp)
            if k >= 1 and rng.random() < 0.55:             # background request; offset sometimes outside the 500 ms window
                off = rng.uniform(0.05, 1.3)
                target = rng.choice(KB)
                if i % 2 == 0:
                    v.page(t + off, a, target + f"?cursor=s{_cur(rng)}", prev=None, linked=False, kind="api", sec=None,
                           cursor_prov="schema", signals=["schema_provenance_cursor"], earlier=False)
                else:
                    v.page(t + off, a, target, prev=None, linked=False, kind="api", sec=None, earlier=True)
            t = v.assets(t, a)
            if k >= 1:
                v.beacon(t + 0.1, a, _b6(_HUMAN_BEACON, True, True, True))        # the person's real, valid beacon
            prev = p
    # swarms: never on the same IP, de-synchronised start times
    probes = [f"/kb/internal-{x}" for x in ("admin", "export", "backup", "dump", "keys", "staff", "old", "dev", "test", "private", "tmp", "legacy")]
    for s_i in range(V6_COUNTS["swarm_schelling_overlap"] // 3):
        members = [w.client("swarm_schelling_overlap") for _ in range(3)]
        base = st()
        shared = kb_paths(8)                               # ~30% of each member's article reads are common (Schelling points)
        vault: List[str] = []
        for m_i, a in enumerate(members):
            t = base + m_i * rng.uniform(600, 3600)
            inherited = list(vault)                         # discoveries teammates made before this member started
            own = shared[: rng.randint(5, 7)] + rng.sample([x for x in KB if x not in shared], 14)
            rng.shuffle(own)
            prev = None
            for p in ["/kb/"] + own:
                t += rng.uniform(2, 9)
                v.page(t, a, p + (f"?cursor=h{_cur(rng)}" if p != "/kb/" else ""), prev=prev, cursor_prov="html" if p != "/kb/" else None)
                prev = "/kb/"
            for f_ in inherited:
                if rng.random() < 0.85:                    # goes straight to a teammate's discovery (sometimes below it), skipping its 404s
                    t += rng.uniform(5, 30)
                    v.page(t, a, f_ + ("/export" if rng.random() < 0.4 else ""), prev=None, linked=False, earlier=False)
            if m_i == 0 or rng.random() < 0.4:             # the scout (and sometimes another member) guesses URLs itself
                for g in rng.sample(probes, rng.randint(3, 6)):
                    t += rng.uniform(2, 6)
                    v.page(t, a, g, prev=None, linked=False, earlier=False, status="denied")
                found = f"/kb/vault/{_cur(rng)[:6]}"
                t += rng.uniform(2, 6)
                v.page(t, a, found, prev=None, linked=False, earlier=False)
                vault.append(found)
    for s_i in range(V6_COUNTS["swarm_disjoint_partition"] // 3):
        members = [w.client("swarm_disjoint_partition") for _ in range(3)]
        order = KB[:]
        rng.shuffle(order)
        base = st()
        for m_i, a in enumerate(members):                  # each takes a disjoint shard of the sitemap, hours apart
            t = base + m_i * rng.uniform(1800, 7200)
            shard = order[m_i * 22:(m_i + 1) * 22]
            for p in shard:
                t += rng.uniform(3, 15)
                v.page(t, a, p + f"?cursor=h{_cur(rng)}", prev=None, linked=False, earlier=True, cursor_prov="html")
    for i in range(V6_COUNTS["llmjacking_prober"]):
        a = w.client("llmjacking_prober")
        t = st()
        v.page(t, a, "/robots.txt", "python-httpx/0.27", prev=None, kind="other", sec=None)
        v.page(t + 1, a, "/.well-known/mcp.json", "python-httpx/0.27", prev=None, kind="api", sec=None)
        agentic = i % 2 == 1
        for k in range(rng.randint(1, 3)):
            t += rng.uniform(1, 4)
            w.req(t, a, LLM_PATH, "python-httpx/0.27", kind="api", decoy="llmjacking_probe", strong="decoy_hit", size=200,
                  extra={"signals": ["llmjacking_probe"],
                         "llmjacking": {"tool_count": 6 if agentic else 0, "system_prompt_len_bucket": "1001-4000" if agentic else "1-200",
                                        "autonomous_loop_directive": agentic}})
    _js_counts(w)


def to_v5_format(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What the v5 collector would have recorded for the same traffic: three-boolean beacons, no v6 fields, no v6-only decoys (the
    inverted link, the forged-beacon tag and the LLM endpoint did not exist: the endpoint answers 404, the inverted link is an ordinary
    page, a forged beacon is just a beacon), and no cursor requirement (a request without a cursor succeeds)."""
    out: List[Dict[str, Any]] = []
    for e in events:
        w = e.get("web")
        if w is not None:
            sig = set(w.get("signals", []))
            w = {k: v for k, v in w.items() if k not in V6_EVENT_KEYS}
            if isinstance(w.get("beacon"), dict):
                w["beacon"] = {k: w["beacon"][k] for k in ("webdriver_present", "pointer_trail_seen", "dom_automation_props")}
            if w.get("decoy_kind") in V6_ONLY_DECOYS:
                dk = w.pop("decoy_kind")
                w.pop("strong_signal", None)
                if dk == "llmjacking_probe":
                    e = {**e, "status": "denied"}
            if "missing_required_cursor" in sig:
                e = {**e, "status": "allowed"}
            e = {**e, "web": w}
        out.append(e)
    return out
