"""Synthetic traffic generator for the demo and tests.

Everything here is invented: documentation-range IPs (RFC 5737 / 2544),
made-up user agents, a toy rate-limiting gateway.  Nothing is sent anywhere;
the output is plain log files.

Scenarios (ground truth is returned so results can be compared honestly):
  humans            browse with assets, referers and irregular think time
  busy human        ~90 page views, search, pagination, one export
  static bots       fixed-interval crawler, jittered search-engine-style
                    crawler, cron poller, health check, naive scraper that
                    ignores 429s
  adaptive agents   A: search->detail->export chains; rotates UA + adds
                    cache-busters after 429/403
                    B: ID enumeration; rotates headers/UA after 429 and
                    wanders into decoys
                    C: gullible "RAG" agent: obeys a canary instruction,
                    reuses a fake key
  timing variants   (all three also walk the honeypot's machine-readable surfaces)
                    F: fast scripted agent - ~0.3s gaps, ignores 429/403
                    L: LLM-like agent - think time scales with the size of the
                       previous response, inside a 1.5-8s band (the *assumed*
                       signature; this is our hypothesis, not a measured fact)
                    H: human-like agent - browser UA, assets, think time
                       independent of payload size
                    plus a "reading human" whose think time also scales with page
                    size (shows why the timing feature is weak)
"""
from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .honeypot import create_honeypot_app
from .simagent import run_board_reader, run_coordination_agent, run_discovery_agent, run_mcp_runner, run_obedient_agent
from .webagents import WEB_PLAN, WEB_PLAN_V4, WEB_PLAN_V6, actor_ip, pace_for, run_web_client

T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
]
KEYWORDS = ["laptops", "monitors", "keyboards", "routers", "cables", "chargers", "webcams", "speakers", "drives", "hubs"]


@dataclass
class Event:
    t: float                      # seconds since T0
    ip: str
    method: str
    path: str
    query: str
    status: int
    ua: str
    referer: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    size: int = 0


@dataclass
class Truth:
    name: str
    label: str                    # human | static_bot | agent
    ip: str
    note: str = ""
    benign: bool = False


class ToyGateway:
    """Per-(ip, UA) sliding-window rate limiter on /api/ plus a WAF-ish rule.

    * more than `limit` /api/ calls in `window_s` seconds -> 429
    * /api/v1/export from a UA containing 'python'        -> 403
    """

    def __init__(self, limit: int = 12, window_s: float = 10.0) -> None:
        self.limit, self.window_s = limit, window_s
        self._hist: dict[tuple[str, str], list[float]] = {}

    def handle(self, ip: str, ua: str, t: float, path: str) -> int:
        if not path.startswith("/api/"):
            return 200 if not path.startswith("/nope") else 404
        if path.startswith("/api/v1/export") and "python" in ua.lower():
            return 403
        hist = [x for x in self._hist.get((ip, ua), []) if t - x < self.window_s]
        if len(hist) >= self.limit:
            self._hist[(ip, ua)] = hist
            return 429
        hist.append(t)
        self._hist[(ip, ua)] = hist
        return 200


class Generator:
    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.gw = ToyGateway()
        self.events: list[Event] = []
        self.truth: list[Truth] = []
        self.lead_clock = T0
        self._seed = seed
        self.trails: list[dict[str, Any]] = []     # honeypot walks to run after the log events are made

    # -- helpers ---------------------------------------------------------
    def req(self, ip: str, ua: str, t: float, path: str, query: str = "", referer: str = "",
            headers: Optional[dict[str, str]] = None, status: Optional[int] = None,
            size: Optional[int] = None) -> int:
        st = self.gw.handle(ip, ua, t, path) if status is None else status
        self.events.append(Event(t, ip, "GET", path, query, st, ua, referer, headers or {},
                                 self.rng.randint(300, 9000) if size is None else size))
        return st

    def think(self, mean: float, sigma: float = 0.9, lo: float = 1.5) -> float:
        return max(lo, self.rng.lognormvariate(math.log(mean), sigma))

    # -- humans ----------------------------------------------------------
    def human(self, name: str, ip: str, start: float, pages: int, mean_think: float = 8.0, busy: bool = False) -> None:
        ua = self.rng.choice(BROWSER_UAS)
        t, prev = start, ""
        for i in range(pages):
            choice = self.rng.random()
            if choice < 0.25:
                path, query = "/products", f"page={self.rng.randint(1, 4)}"
            elif choice < 0.65:
                path, query = f"/products/{self.rng.randint(1, 400)}", ""
            elif choice < 0.8:
                path, query = "/search", f"q={self.rng.choice(KEYWORDS)}"
            else:
                path, query = self.rng.choice(["/", "/about", "/support"]), ""
            self.req(ip, ua, t, path, query, prev)
            if i == 0 or self.rng.random() < 0.3:
                for k, asset in enumerate(["/static/app.css", "/static/app.js", "/static/logo.png"]):
                    self.req(ip, ua, t + 0.05 + 0.12 * k, asset, "", prev or "https://example.invalid/")
            if path == "/search":
                self.req(ip, ua, t + 0.8, "/api/v1/suggest", f"q={self.rng.choice(KEYWORDS)[:3]}", prev)
            if self.rng.random() < 0.04:
                self.req(ip, ua, t + 2.0, "/nope-missing-page", "", prev, status=404)
            if busy and i == pages // 2:
                self.req(ip, ua, t + 3.0, "/api/v1/export", "format=csv", prev)   # a single manual export
            if busy and self.rng.random() < 0.08:                                    # reload
                self.req(ip, ua, t + 4.0, path, query, prev)
            prev = f"https://shop.example.invalid{path}"
            t += self.think(mean_think)
        self.truth.append(Truth(name, "human", ip, "busy human" if busy else "browses with assets/referer"))

    # -- static bots -----------------------------------------------------
    def fixed_crawler(self, ip: str, start: float, pages: int = 40) -> None:
        ua = "ExampleCrawler/1.0 (+http://localhost/bot)"
        self.req(ip, ua, start, "/robots.txt")
        for n in range(1, pages + 1):
            self.req(ip, ua, start + 2.0 * n, "/products", f"page={n}")
        self.truth.append(Truth("fixed-interval crawler", "static_bot", ip, "2s cadence, flat /products?page=N"))

    def search_engine_crawler(self, ip: str, start: float, pages: int = 60) -> None:
        ua = "SynthBot-Search/2.1 (+http://localhost/synthbot)"
        self.req(ip, ua, start, "/robots.txt")
        t = start
        for _ in range(pages):
            t += self.rng.uniform(2.0, 4.0)
            self.req(ip, ua, t, f"/products/{self.rng.randint(1, 400)}")
        self.truth.append(Truth("search-engine-style crawler", "static_bot", ip, "jittered 2-4s, declared bot UA", benign=True))

    def cron_poller(self, ip: str, start: float, n: int = 30) -> None:
        for k in range(n):
            self.req(ip, "curl/8.4.0", start + 60.0 * k, "/api/v1/status.json")
        self.truth.append(Truth("cron poller", "static_bot", ip, "one endpoint every 60s"))

    def health_check(self, ip: str, start: float, n: int = 60) -> None:
        for k in range(n):
            self.req(ip, "SynthMonitor/1.0", start + 10.0 * k, "/healthz")
        self.truth.append(Truth("monitoring health check", "static_bot", ip, "GET /healthz every 10s", benign=True))

    def naive_scraper(self, ip: str, start: float, n: int = 60) -> None:
        ua = "python-requests/2.31.0"
        for k in range(n):       # fixed 0.5s loop; ignores 429s, keeps paginating
            self.req(ip, ua, start + 0.5 * k, "/api/v1/items", f"page={k + 1}&limit=100")
        self.truth.append(Truth("naive scraper (ignores 429)", "static_bot", ip, "0.5s loop, no adaptation"))

    # -- adaptive agents -------------------------------------------------
    def agent_a(self, ip: str, start: float, chains: int = 10) -> None:
        """search -> detail x2 -> export chains; rotates UA and cache-busts after blocks."""
        uas = ["python-httpx/0.27.0"] + BROWSER_UAS
        ui, bust, t = 0, False, start
        for kw in KEYWORDS[:chains]:
            ids = [self.rng.randint(1, 400) for _ in range(2)]
            steps = [("/api/v1/search", f"q={kw}"), (f"/api/v1/items/{ids[0]}", ""),
                     (f"/api/v1/items/{ids[1]}", ""), ("/api/v1/export", f"ids={ids[0]},{ids[1]}")]
            for path, q in steps:
                t += self.rng.uniform(0.4, 0.9)
                for _try in range(3):
                    qq = q + (("&" if q else "") + f"_={int((T0.timestamp() + t) * 1000)}") if bust else q
                    st = self.req(ip, uas[ui], t, path, qq)
                    if st < 400:
                        break
                    ui, bust = min(ui + 1, len(uas) - 1), True      # react to 403/429
                    t += self.rng.uniform(1.0, 2.0)
        self.truth.append(Truth("adaptive agent A (chains)", "agent", ip, "search->detail->export; rotates UA + cache-busts"))

    def agent_b(self, ip: str, start: float, ids: int = 90) -> None:
        """Sequential ID enumeration with header rotation; wanders into decoys."""
        ua_pool = ["python-httpx/0.27.0"] + BROWSER_UAS
        ui, rot, t = 0, 0, start

        def hdrs() -> dict[str, str]:
            return {"user-agent": ua_pool[ui], "accept-language": ["en-US", "de-DE", "fr-FR", "ja-JP", "es-ES"][rot % 5],
                    "x-forwarded-for": f"198.18.{rot % 250}.{(rot * 7) % 250 + 1}"}

        extra = ""
        for k in range(ids):
            t += self.rng.uniform(0.3, 0.5)
            st = self.req(ip, ua_pool[ui], t, f"/api/v1/items/{1000 + k}", extra, headers=hdrs())
            if st == 429:
                ui, rot = (ui + 1) % len(ua_pool), rot + 1
                extra = f"fields={self.rng.getrandbits(24):06x}"
                t += self.rng.uniform(1.0, 2.0)
                self.req(ip, ua_pool[ui], t, f"/api/v1/items/{1000 + k}", extra, headers=hdrs())
        self.trails.append({"ip": ip, "ua": ua_pool[ui], "at": t + 1.0, "kinds": ["decoys"], "delay": lambda b: 0.6})
        self.truth.append(Truth("adaptive agent B (enumeration)", "agent", ip, "ID enumeration, header+UA rotation, touches decoys"))

    def agent_c(self, ip: str, start: float) -> None:
        """Slower, gullible agent: search->detail->export with LLM-like pauses, then follows canary."""
        ua = "python-requests/2.31.0"
        t = start
        for kw in KEYWORDS[:5]:
            i = self.rng.randint(1, 400)
            for path, q in [("/api/v1/search", f"q={kw}"), (f"/api/v1/items/{i}", ""), (f"/api/v1/items/{i + 1}", ""),
                            ("/api/v1/export", f"ids={i},{i + 1}")]:
                t += self.rng.uniform(1.0, 2.5)
                st = self.req(ip, ua, t, path, q)
                if st == 403:                       # WAF blocked the library UA -> switch identity and retry
                    ua = BROWSER_UAS[0]
                    t += 1.0
                    self.req(ip, ua, t, path, q)
        self.trails.append({"ip": ip, "ua": ua, "at": t + 2.0, "kinds": ["classic"], "delay": lambda b: 1.2})
        self.truth.append(Truth("gullible RAG agent C", "agent", ip, "403->UA switch; obeys canary text; reuses fake key"))

    # -- timing variants -------------------------------------------------
    def _llm_delay(self, prev_bytes: int) -> float:
        """ASSUMED LLM-like think time: grows with previous payload (~bytes/4 tokens), clipped to 1.5-8s."""
        tokens = prev_bytes / 4.0
        return min(8.0, max(1.5, 1.0 + tokens / 300.0 + self.rng.gauss(0, 0.35)))

    def _api_loop(self, ip: str, ua: str, t: float, delay, chains: int, referer: str = "", assets: bool = False) -> float:
        """search -> detail x2 -> export chains; `delay(prev_bytes)` gives the gap after each response."""
        for kw in KEYWORDS[:chains]:
            i = self.rng.randint(1, 400)
            for path, q in [("/api/v1/search", f"q={kw}"), (f"/api/v1/items/{i}", ""), (f"/api/v1/items/{i + 1}", ""),
                            ("/api/v1/export", f"ids={i},{i + 1}")]:
                size = self.rng.randint(1000, 8000)
                self.req(ip, ua, t, path, q, referer, size=size)
                if assets:
                    for k, a in enumerate(["/static/app.css", "/static/app.js", "/static/logo.png"]):
                        self.req(ip, ua, t + 0.05 + 0.1 * k, a, "", referer, size=400)
                t += delay(size)
        return t

    def fast_agent(self, ip: str, start: float) -> None:
        ua = "python-requests/2.31.0"
        t = self._api_loop(ip, ua, start, lambda b: self.rng.uniform(0.25, 0.35), chains=5)
        self.trails.append({"ip": ip, "ua": ua, "at": t, "kinds": ["discovery", "classic"],
                            "delay": lambda b: self.rng.uniform(0.2, 0.3)})
        self.truth.append(Truth("fast scripted agent (timing variant F)", "agent", ip,
                                "~0.3s gaps, no adaptation; caught via decoys"))

    def llm_like_agent(self, ip: str, start: float) -> None:
        ua = "agent-framework-synth/0.3"
        t = self._api_loop(ip, ua, start, self._llm_delay, chains=5)
        self.trails.append({"ip": ip, "ua": ua, "at": t, "kinds": ["discovery", "classic"], "delay": self._llm_delay})
        self.truth.append(Truth("LLM-like delay-scaling agent (timing variant L)", "agent", ip,
                                "think time scales with previous payload, 1.5-8s band"))

    def coordination_agent(self, ip: str, start: float) -> None:
        """Gullible multi-agent worker: follows the 429 breadcrumb, registers on the board, loops claim-shard."""
        ua = "agent-framework-synth/0.3"
        t = self._api_loop(ip, ua, start, self._llm_delay, chains=3)
        self.trails.append({"ip": ip, "ua": ua, "at": t, "kinds": ["coordination"], "delay": self._llm_delay})
        self.truth.append(Truth("coordination-bus agent (follows breadcrumb, registers, loops)", "agent", ip,
                                "429 peer_hint -> board -> POST registration -> claim-shard loop"))

    def relay_pair(self, ip_a: str, ip_b: str, start: float) -> None:
        """Two identities on different IPs: A reads the board, B presents A's handoff_token."""
        ua = "agent-framework-synth/0.3"
        ta = self._api_loop(ip_a, ua, start, self._llm_delay, chains=2)
        tb = self._api_loop(ip_b, ua, start + 5, self._llm_delay, chains=2)
        self.trails.append({"ip": ip_a, "ip2": ip_b, "ua": ua, "ua2": ua, "at": max(ta, tb) + 3.0,
                            "kinds": ["relay"], "delay": self._llm_delay})
        self.truth.append(Truth("relay agent A (reads board, hands token on)", "agent", ip_a,
                                "reads the board only; its token is presented from another IP"))
        self.truth.append(Truth("relay agent B (presents A's token from another IP)", "agent", ip_b,
                                "registers + loops using a token issued to a different IP"))

    def human_like_agent(self, ip: str, start: float) -> None:
        ua = self.rng.choice(BROWSER_UAS)
        t = self._api_loop(ip, ua, start, lambda b: self.think(6.0, 0.8), chains=5,
                           referer="https://shop.example.invalid/", assets=True)
        self.trails.append({"ip": ip, "ua": ua, "at": t, "kinds": ["discovery", "classic"],
                            "delay": lambda b: self.think(6.0, 0.8)})
        self.truth.append(Truth("human-like agent (timing variant H)", "agent", ip,
                                "human timing + assets; payload-independent; caught only via decoys"))

    def reading_human(self, name: str, ip: str, start: float, pages: int = 40) -> None:
        """A person whose reading time grows with page size, loading assets like a browser."""
        ua = self.rng.choice(BROWSER_UAS)
        t, prev = start, ""
        for _ in range(pages):
            size = self.rng.randint(2000, 20000)
            self.req(ip, ua, t, f"/products/{self.rng.randint(1, 400)}", "", prev, size=size)
            for k, a in enumerate(["/static/app.css", "/static/app.js", "/static/logo.png"]):
                self.req(ip, ua, t + 0.05 + 0.1 * k, a, "", prev or "https://example.invalid/", size=400)
            t += max(1.5, 1.0 + size / 4.0 / 800.0 + self.rng.gauss(0, 0.4))
            prev = "https://shop.example.invalid/products"
        self.truth.append(Truth(name, "human", ip, "reading time grows with page size (+ assets)"))

    def mcp_runner(self, name: str, ip: str, start: float) -> None:
        """v5 (extended demo only): a thin MCP client library: initialize -> tools/list -> tools/call and nothing else."""
        self.trails.append({"ip": ip, "ua": "mcp-client-synth/0.2", "at": start, "kinds": ["mcp_runner"], "delay": lambda b: self.rng.uniform(0.6, 1.4)})
        self.truth.append(Truth(name, "agent", ip, "JSON-RPC 2.0 initialize -> tools/list -> tools/call with structured args, no browsing"))

    # -- v3 web clients (extended demo only): browsers, scraper, crawler and four mimics ------------------------
    def web_client(self, name: str, ip: str, start: float, variant: str, label: str, note: str, *, benign: bool = False) -> None:
        """A simulated web client that browses the honeypot's own pages (see webagents.py for what each variant does)."""
        pace = pace_for(variant, self.rng)
        self.trails.append({"ip": ip, "ua": "(set by the client)", "at": start, "kinds": [f"web:{variant}"], "delay": pace})
        self.truth.append(Truth(name, label, ip, note, benign))

    # -- honeypot interaction (in-process, no sockets) -------------------
    def honeypot_leads(self, out: Path) -> Path:
        """Drive the real honeypot app in-process (fake clock, no sockets) for every recorded trail."""
        state = {"t": T0}
        app = create_honeypot_app(out, seed=f"demo-{self._seed}", clock=lambda: state["t"])
        client = app.test_client()
        for trail in self.trails:
            ip, ua = trail["ip"], trail["ua"]
            now = {"t": float(trail["at"])}

            def advance(prev_bytes: int, trail=trail, now=now) -> None:
                now["t"] += trail["delay"](prev_bytes)
                state["t"] = T0 + timedelta(seconds=now["t"])

            def fetch(method: str, path: str, headers: dict[str, str], body: Optional[str],
                      ip: str = ip) -> tuple[int, str]:
                resp = client.open(path, method=method, headers=headers, data=body,
                                   environ_overrides={"REMOTE_ADDR": ip})
                return resp.status_code, resp.get_data(as_text=True)

            for kind in trail["kinds"]:
                if kind == "decoys":      # enumerator wanders to robots.txt Disallow paths only
                    for path in ("/robots.txt", "/admin-backup/", "/api/v1/admin"):
                        advance(0)
                        fetch("GET", path, {"User-Agent": ua}, None)
                elif kind == "classic":
                    run_obedient_agent(fetch, ua, before_step=advance)
                elif kind.startswith("web:"):
                    run_web_client(fetch, kind[4:], before_step=advance)
                elif kind == "mcp_runner":
                    run_mcp_runner(fetch, ua, before_step=advance)
                elif kind == "coordination":
                    run_coordination_agent(fetch, ua, before_step=advance)
                elif kind == "relay":
                    ip2 = trail["ip2"]

                    def fetch2(method: str, path: str, headers: dict[str, str], body: Optional[str],
                               ip2: str = ip2) -> tuple[int, str]:
                        resp = client.open(path, method=method, headers=headers, data=body,
                                           environ_overrides={"REMOTE_ADDR": ip2})
                        return resp.status_code, resp.get_data(as_text=True)

                    _, token = run_board_reader(fetch, ua, before_step=advance)
                    advance(0)
                    run_coordination_agent(fetch2, trail["ua2"], before_step=advance, handoff={"token": token}, max_turns=3)
                else:
                    run_discovery_agent(fetch, ua, before_step=advance)
        return out


def _combined_line(e: Event) -> str:
    ts = (T0 + timedelta(seconds=e.t)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    target = f"{e.path}?{e.query}" if e.query else e.path
    return f'{e.ip} - - [{ts}] "{e.method} {target} HTTP/1.1" {e.status} {e.size} "{e.referer or "-"}" "{e.ua}"'


def _json_line(e: Event) -> str:
    ts = (T0 + timedelta(seconds=e.t)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    headers = e.headers or {"user-agent": e.ua}
    return json.dumps({
        "timestamp": ts, "client_ip": e.ip, "method": e.method, "path": e.path, "query": e.query,
        "status": e.status, "bytes": e.size, "latency_ms": 12, "headers": headers,
        "user_agent": e.ua,
    }, separators=(",", ":"))


def add_web_actors(g: "Generator") -> None:
    """The v3 extended demo: browsers and scrapers on the honeypot site plus the four mimic variants (see webagents.WEB_PLAN)."""
    n = 0
    for variant, label, note, copies, benign in WEB_PLAN + WEB_PLAN_V4 + WEB_PLAN_V6:
        for k in range(copies):
            g.web_client(f"web:{variant} #{k + 1}", actor_ip(n, label), 600 + 40 * n, variant, label, note, benign=benign)
            n += 1
    for k in range(2):                                    # v5: a pure MCP tool runner cohort (harness fingerprinting needs one)
        g.mcp_runner(f"mcp:tool_runner #{k + 1}", f"192.0.2.{200 + k}", 600 + 40 * (n + k))


def generate_demo(out_dir: str | Path, seed: int = 7, extended: bool = False) -> dict[str, Any]:
    """Write synthetic access.log, gateway.jsonl, honeypot leads (+ mirrored access stream) and truth.json.

    ``extended=True`` adds the v3 web clients (browsers, scrapers, mimic variants) that browse the honeypot site.
    Returns {"access_log","gateway_log","leads","access_mirror","truth"(list of Truth)}.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    g = Generator(seed)
    rng = g.rng
    # humans (198.51.100.0/24)
    for i in range(1, 5):
        g.human(f"human {i}", f"198.51.100.{i}", rng.uniform(0, 300), rng.randint(15, 30))
    g.human("busy human", "198.51.100.50", 30, 90, mean_think=6.0, busy=True)
    # static bots (203.0.113.0/24)
    g.fixed_crawler("203.0.113.10", 40)
    g.search_engine_crawler("203.0.113.11", 60)
    g.cron_poller("203.0.113.12", 0)
    g.health_check("203.0.113.13", 0)
    gateway_ips = {"203.0.113.14"}
    g.naive_scraper("203.0.113.14", 100)
    # adaptive agents (192.0.2.0/24)
    gateway_ips.add("192.0.2.21")
    g.agent_a("192.0.2.20", 200)
    g.agent_b("192.0.2.21", 220)
    g.agent_c("192.0.2.22", 260)
    # timing variants (192.0.2.30-32) and a reading human
    gateway_ips.add("192.0.2.30")
    g.fast_agent("192.0.2.30", 300)
    g.llm_like_agent("192.0.2.31", 330)
    g.human_like_agent("192.0.2.32", 380)
    g.coordination_agent("192.0.2.40", 420)
    g.relay_pair("192.0.2.41", "192.0.2.42", 450)
    g.reading_human("reading human (time scales with page size)", "198.51.100.60", 40)
    if extended:
        add_web_actors(g)
    # gateway-format IPs: naive scraper + agent B go to the JSON-lines API-gateway log
    events = sorted(g.events, key=lambda e: e.t)
    access = out / "access.log"
    gateway = out / "gateway.jsonl"
    access.write_text("\n".join(_combined_line(e) for e in events if e.ip not in gateway_ips) + "\n", encoding="utf-8")
    gateway.write_text("\n".join(_json_line(e) for e in events if e.ip in gateway_ips) + "\n", encoding="utf-8")
    leads = out / "leads.jsonl"
    leads.write_text("", encoding="utf-8")
    g.honeypot_leads(leads)
    truth = [t.__dict__ for t in g.truth]
    (out / "truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    return {"access_log": access, "gateway_log": gateway, "leads": leads,
            "access_mirror": Path(str(leads) + ".access.jsonl"), "truth": g.truth}
