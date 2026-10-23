"""Simulated *web* clients for the honeypot: browsers, a scraper, a crawler and four "mimic" agents.

Like ``simagent.py`` the logic is transport-agnostic (a ``fetch(method, path, headers, body)`` callable), so the demo
drives the in-process Flask test client with a fake clock and ``scripts/simulated_agent.py`` can drive a loopback server.
Nothing here touches a network; it only parses the honeypot's own HTML.

HONEST CAVEAT: these simulated clients were written by the same author as the detectors that score them, and each mimic
is a deliberate *attempt to look human* written with knowledge of the detectors.  Results on them are regression checks,
not a measure of how real LLM agents behave.

Variants (``run_web_client``):

========================  =====================================================================================
human                     browser UA, Referer + Sec-Fetch-*, loads CSS/JS/logo/favicon with every page, think time
human_no_assets           the same person with images/scripts blocked or a text-mode browser (assets never fetched)
scraper_naive             "NaiveScraper/1.0": breadth-first over every href incl. the invisible one, fixed pace, no Referer
crawler_declared          declared search crawler UA, breadth-first, follows the invisible link too (crawlers do)
mimic_basic               browser UA + Referer + human pacing, never touches a decoy, no assets; guesses a few URLs
mimic_linked              like mimic_basic but follows ONLY links the pages offer (no guessed URLs); no assets
mimic_assets              mimic_linked + fetches the page's assets, sends Sec-Fetch-*: an honest EVADER of these detectors
mimic_schema              mimic_linked + reads /openapi.json and uses what it advertises (client_schema_rev)
--- v4 additions: sub-resource types, JavaScript and the interaction beacon -------------------------------------
human_images_blocked      a person with images blocked: loads CSS/JS/favicon but no images; JS runs, beacon with pointer movement
human_js_off              JavaScript disabled / privacy tool: loads CSS, images, favicon but never fetches the script; no beacon
human_beacon_blocked      a person whose ad/tracker blocker silently drops the beacon POST (honest false-positive cohort)
mimic_assets (changed)    loads ALL assets incl. the script file but does not EXECUTE it (HTTP client + HTML parser): no beacon
mimic_browser_stealth     a real browser engine driven by automation with `webdriver` hidden: runs the script, beacon is all-False
mimic_browser_webdriver   the same engine WITHOUT hiding `navigator.webdriver` (beacon reports webdriver_present=true)
mimic_aria                browser-backed agent that reads the accessibility tree and clicks the ARIA "fast-path" control
mimic_header_forger       HTTP client that copies a browser's UA + coherent Sec-Fetch-* headers but fetches no sub-resources
(human) changed          now runs the script: beacon with pointer movement before each click-through
========================  =====================================================================================
"""
from __future__ import annotations

import json
import random  # noqa: F401  (type annotation of pace_for)
import re
from typing import Callable, Optional
from urllib.parse import urlsplit

Fetch = Callable[[str, str, dict[str, str], Optional[str]], tuple[int, str]]
BeforeStep = Callable[[int], None]

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
SCRAPER_UA = "NaiveScraper/1.0"
CRAWLER_UA = "SynthBot-Search/2.1 (+http://localhost/synthbot)"

_A = re.compile(r"<a\s[^>]*?href='([^']*)'([^>]*)>", re.I)
_ASSET = re.compile(r"(?:<link[^>]*?href|<script[^>]*?src|<img[^>]*?src)='([^']*)'", re.I)
VARIANTS_V3 = ("human", "human_no_assets", "scraper_naive", "crawler_declared", "mimic_basic", "mimic_linked",
               "mimic_assets", "mimic_schema")
VARIANTS_V4 = ("human_images_blocked", "human_js_off", "human_beacon_blocked", "mimic_browser_stealth",
               "mimic_browser_webdriver", "mimic_aria", "mimic_header_forger")
VARIANTS = VARIANTS_V3 + VARIANTS_V4
BEACON_PATH = "/api/v1/telemetry/nav"
ARIA_RE = re.compile(r"<a\s[^>]*?href='([^']*)'[^>]*?data-agent-action='fast-export'", re.I)

# per-variant behaviour knobs (everything else is the legacy logic below)
#   assets: all | no_images | none         js: run | fetch_only | off          pointer/webdriver/props: beacon values
SPEC: dict[str, dict[str, object]] = {
    "human": {"assets": "all", "js": "run", "pointer": True},
    "human_no_assets": {"assets": "none", "js": "off"},
    "human_images_blocked": {"assets": "no_images", "js": "run", "pointer": True},
    "human_js_off": {"assets": "no_script", "js": "off"},
    "human_beacon_blocked": {"assets": "all", "js": "run", "pointer": True, "beacon_blocked": True},
    "mimic_assets": {"assets": "all", "js": "fetch_only"},
    "mimic_browser_stealth": {"assets": "all", "js": "run", "pointer": False},
    "mimic_browser_webdriver": {"assets": "all", "js": "run", "pointer": False, "webdriver": True},
    "mimic_aria": {"assets": "all", "js": "run", "pointer": False, "aria": True},
    "mimic_header_forger": {"assets": "none", "js": "off"},
}


def visible_links(html: str, include_hidden: bool) -> list[str]:
    out = []
    for href, rest in _A.findall(html):
        if not href.startswith("/") or href.startswith("//"):
            continue
        if not include_hidden and "display:none" in rest.replace(" ", ""):
            continue
        if href not in out:
            out.append(href)
    return out


def page_assets(html: str) -> list[str]:
    return [a for a in dict.fromkeys(_ASSET.findall(html)) if a.startswith("/")]


class WebClient:
    def __init__(self, fetch: Fetch, ua: str, before_step: Optional[BeforeStep], *, browser_headers: bool,
                 send_referer: bool) -> None:
        self.fetch, self.ua, self.before = fetch, ua, before_step
        self.browser_headers, self.send_referer = browser_headers, send_referer
        self.last_bytes = 0
        self.log: list[tuple[str, str, int]] = []
        self.current = ""             # path of the page we are "on" (Referer for the next click)
        self.page_html = ""           # HTML of the page we are on (its script, if it runs, sends the beacon on a click)
        self.runs_js = False          # a JS engine executes the page's script
        self.beacon_blocked = False   # a content blocker drops the beacon request client-side
        self.pointer, self.webdriver, self.props = False, False, False

    def get(self, target: str, *, via: Optional[str] = None, dest: str = "document", think: bool = True) -> str:
        if think and self.before:
            self.before(self.last_bytes)
        if via and dest == "document" and self.runs_js and not self.beacon_blocked and BEACON_PATH in self.page_html:
            self.send_beacon()                          # the script on the page we are leaving fires on the click
        headers = {"User-Agent": self.ua}
        if self.browser_headers:
            headers.update({"Accept": "text/html,application/xhtml+xml,*/*;q=0.8" if dest == "document" else "*/*",
                            "Accept-Language": "en-US,en;q=0.5", "Sec-Fetch-Dest": dest,
                            "Sec-Fetch-Mode": "navigate" if dest == "document" else "no-cors",
                            "Sec-Fetch-Site": "same-origin" if via else "none"})
        if self.send_referer and via:
            headers["Referer"] = "http://127.0.0.1" + via
        status, text = self.fetch("GET", target, headers, None)
        self.log.append(("GET", target, status))
        if dest == "document":
            self.last_bytes = len(text.encode("utf-8", "replace"))
            self.current = urlsplit(target).path
            self.page_html = text
        return text

    def send_beacon(self) -> None:
        headers = {"User-Agent": self.ua, "Content-Type": "application/json", "Accept": "*/*"}
        if self.browser_headers:
            headers.update({"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"})
        if self.send_referer:
            headers["Referer"] = "http://127.0.0.1" + self.current
        body = json.dumps({"webdriver_present": self.webdriver, "pointer_trail_seen": self.pointer,
                           "dom_automation_props": self.props})
        status, _ = self.fetch("POST", BEACON_PATH, headers, body)
        self.log.append(("POST", BEACON_PATH, status))

    def load_assets(self, html: str, policy: str = "all") -> None:
        for a in page_assets(html):
            kind = "style" if a.endswith(".css") else "script" if a.endswith(".js") else "image"
            icon = a.endswith("favicon.ico")
            if policy == "no_images" and kind == "image" and not icon:
                continue                                  # images blocked; styles, scripts and the favicon still load
            if policy == "no_script" and kind == "script":
                continue                                  # JavaScript disabled: the browser never requests the script
            self.get(a, via=self.current, dest=kind, think=False)


def run_web_client(fetch: Fetch, variant: str, before_step: Optional[BeforeStep] = None, *, pages: int = 9,
                   user_agent: Optional[str] = None) -> list[tuple[str, str, int]]:
    """Run one simulated web client against the honeypot; returns the (method, path, status) list."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}")
    spec = SPEC.get(variant, {})
    human_like = variant in ("human", "human_no_assets", "mimic_assets") or variant in SPEC
    ua = user_agent or {"scraper_naive": SCRAPER_UA, "crawler_declared": CRAWLER_UA}.get(variant, BROWSER_UA)
    c = WebClient(fetch, ua, before_step, browser_headers=human_like,
                  send_referer=variant not in ("scraper_naive", "crawler_declared"))
    asset_policy = str(spec.get("assets", "all" if variant in ("human", "mimic_assets") else "none"))
    js = str(spec.get("js", "off"))
    c.runs_js = js == "run"
    c.beacon_blocked = bool(spec.get("beacon_blocked", False))
    c.pointer, c.webdriver, c.props = bool(spec.get("pointer", False)), bool(spec.get("webdriver", False)), bool(spec.get("props", False))
    loads_assets = asset_policy != "none"
    breadth_first = variant in ("scraper_naive", "crawler_declared")
    include_hidden = breadth_first
    follows_aria = breadth_first or bool(spec.get("aria", False))      # the muted control is a plain anchor to a DOM/anchor parser

    def links_of(html: str) -> list[str]:
        out = visible_links(html, include_hidden)
        return [x for x in out if follows_aria or "kb-snapshot" not in x]

    home = c.get("/")
    if loads_assets:
        c.load_assets(home, asset_policy)
    queue: list[tuple[str, str]] = [(link, "/") for link in links_of(home)]   # (target, page that linked it)
    seen = {"/"}
    n = 1
    aria_done = False
    while queue and n < pages:
        target, parent = queue.pop(0)
        if target in seen:
            continue
        if "kb-snapshot" in target:
            if aria_done:
                continue
            aria_done = True
        seen.add(target)
        # a person (or a careful mimic) sends the TRUE parent page as Referer, e.g. after pressing Back
        html = c.get(target, via=parent)
        n += 1
        if loads_assets and "<html" in html:
            c.load_assets(html, asset_policy)
        if "<html" in html:
            for link in links_of(html):
                machine_doc = link.startswith(("/openapi", "/llms"))
                if link not in seen and all(link != q[0] for q in queue) and (not machine_doc or variant in
                                                                              ("mimic_schema", "scraper_naive", "crawler_declared")):
                    queue.append((link, urlsplit(target).path))

    if variant == "mimic_basic":
        # an agent that "knows" what it wants guesses URLs a human on this site would not have been shown
        for guess in ("/products", "/pricing", "/api/v1/items", "/search?q=customers", "/docs"):
            c.get(guess, via=c.current)
    elif variant == "mimic_schema":
        spec_doc = c.get("/openapi.json", via=c.current, dest="empty")
        try:
            doc = json.loads(spec_doc)
            param = doc["paths"]["/api/v1/status"]["get"]["parameters"][0]
            q = f"{param['name']}={param['schema']['default']}"
        except (ValueError, KeyError, IndexError, TypeError):
            q = ""
        c.get("/api/v1/status" + (f"?{q}" if q else ""), via="/openapi.json", dest="empty")
    return c.log


# ---- shared plan for the extended demo / evaluation (variant, ground-truth label, note, copies, benign allow-listed) ----
WEB_PLAN: list[tuple[str, str, str, int, bool]] = [
    ("human", "human", "browser UA, Referer, Sec-Fetch-*, loads assets, think time", 3, False),
    ("human_no_assets", "human", "a person with images/scripts blocked or a text-mode browser (HARD NEGATIVE)", 3, False),
    ("scraper_naive", "static_bot", "breadth-first crawl incl. the invisible link, fixed 0.5 s, no Referer", 2, False),
    ("crawler_declared", "static_bot", "declared search crawler; follows the invisible link too", 1, True),
    ("mimic_basic", "agent", "browser UA + human pacing; never touches a decoy; guesses a few URLs; no assets", 3, False),
    ("mimic_linked", "agent", "like mimic_basic but follows only offered links, true-parent Referer; no assets", 3, False),
    ("mimic_assets", "agent", "mimic_linked + loads assets and sends Sec-Fetch-* (built to evade these detectors)", 3, False),
    ("mimic_schema", "agent", "mimic_linked + reads openapi.json and uses client_schema_rev", 3, False),
]


# v4 cohorts (appended to the demo / evaluation; see SPEC for what each does)
WEB_PLAN_V4: list[tuple[str, str, str, int, bool]] = [
    ("human_images_blocked", "human", "a person with images blocked: CSS/JS/favicon load, images do not; beacon with pointer movement", 3, False),
    ("human_js_off", "human", "JavaScript disabled / privacy tool: CSS+images load, the script is never requested, no beacon (HARD NEGATIVE)", 3, False),
    ("human_beacon_blocked", "human", "an ad/tracker blocker silently drops the beacon POST (HARD NEGATIVE, expected false positive)", 3, False),
    ("mimic_browser_stealth", "agent", "real browser engine driven by automation with navigator.webdriver hidden; beacon all-False (EVADER)", 3, False),
    ("mimic_browser_webdriver", "agent", "same engine without hiding navigator.webdriver: the beacon says webdriver_present=true", 3, False),
    ("mimic_aria", "agent", "browser-backed agent that reads the accessibility tree and clicks the ARIA 'fast-path' control", 3, False),
    ("mimic_header_forger", "agent", "HTTP client with a browser UA + coherent Sec-Fetch-* headers that fetches no sub-resources (EVADER of v4 starvation)", 3, False),
]


def pace_for(variant: str, rng: "random.Random") -> Callable[[int], float]:
    """Seconds of (simulated) think time before each page request, by variant."""
    import math
    think = lambda mean, sigma, lo: max(lo, rng.lognormvariate(math.log(mean), sigma))      # noqa: E731
    if variant.startswith("human"):
        return lambda b: think(8.0, 0.7, 2.0)
    if variant == "scraper_naive":
        return lambda b: 0.5
    if variant == "crawler_declared":
        return lambda b: rng.uniform(2.0, 4.0)
    return lambda b: rng.uniform(1.5, 3.0)           # every mimic variant: human-like 1.5-3 s jitter


def actor_ip(n: int, label: str) -> str:
    """Documentation-range address for the n-th web actor of a ground-truth class."""
    return f"192.0.2.{100 + n}" if label == "agent" else f"198.51.100.{100 + n}" if label == "human" else f"203.0.113.{100 + n}"
