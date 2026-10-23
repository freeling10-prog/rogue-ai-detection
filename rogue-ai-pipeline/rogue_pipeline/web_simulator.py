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
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Tuple

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
COUNTS = {"web_human": 5, "web_human_no_assets": 4, "commodity_scanner": 8, "accidental_scraper": 3, "mimic_basic": 3,
          "mimic_linked": 3, "mimic_assets": 3, "mimic_schema": 3, "mcp_agent": 2, "decoy_explorer": 2, "scanner_ua_spoof": 1}


class _Web:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed * 7919 + 13)
        self.events: List[Dict[str, Any]] = []
        self.labels: Dict[str, Tuple[str, str]] = {}
        self._n = 0
        self._i = 0

    def client(self, group: str) -> str:
        self._i += 1
        ip = f"192.0.2.{self._i}" if self._i < 250 else f"198.51.100.{self._i - 249}"
        agent = f"client:{ip}"
        self.labels[agent] = (GROUPS[group], group)
        return agent

    def req(self, t: float, agent: str, path: str, ua: str, *, kind: str = "html", status: str = "allowed", linked: Any = None,
            ref_ok: Any = None, earlier: Any = None, sec: Any = None, strong: Any = None, decoy: Any = None, mcp: Any = None,
            size: int = 2400) -> None:
        self._n += 1
        web: Dict[str, Any] = {"user_agent": ua, "content_kind": kind}
        for k, v in (("linked_from_prev", linked), ("referer_valid", ref_ok), ("offered_earlier", earlier),
                     ("sec_fetch_mismatch", sec), ("strong_signal", strong), ("decoy_kind", decoy), ("mcp", mcp)):
            if v is not None:
                web[k] = v
        self.events.append({"event_id": f"w{self._n:07d}", "ts": round(T0 + t, 3), "source": "web_server", "agent_id": agent,
                            "action": "access", "status": status, "resource": path, "ip": agent.split(":", 1)[1], "synthetic": True,
                            "payload_bytes": size, "web": web})

    # ---- browsing helpers -------------------------------------------------------------------------------
    def browse(self, agent: str, ua: str, start: float, n: int, *, assets: bool, sec_ok: Optional[bool], pace: Tuple[float, float] = (4.0, 20.0)) -> float:
        t = start
        for i in range(n):
            t += self.rng.uniform(*pace)
            path = PAGES[i % len(PAGES)]
            self.req(t, agent, path, ua, linked=None if i == 0 else True, ref_ok=None if i == 0 else True,
                     sec=None if sec_ok is None else (not sec_ok))
            if assets:
                for a in ("/static/site.css", "/static/site.js", "/favicon.ico"):
                    t += 0.05
                    self.req(t, agent, a, ua, kind="asset", linked=True, ref_ok=True, size=900)
        return t


def build_web(seed: int = 0) -> SimData:
    """Web-client events + labels (raw agent id -> (kind, group)).  Same seed => same data."""
    w = _Web(seed)
    rng = w.rng
    start = lambda: 3600.0 * rng.uniform(1, 20)                                  # noqa: E731
    for _ in range(COUNTS["web_human"]):
        a = w.client("web_human")
        w.browse(a, BROWSER, start(), rng.randint(6, 10), assets=True, sec_ok=True)
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
    w.events.sort(key=lambda e: (e["ts"], e["event_id"]))
    return SimData(w.events, w.labels, Policy(), [], True)
