"""Deterministic, explainable HARNESS fingerprinting (v5).

Question answered: *what kind of client harness produced this session?* - not who, not whether it is malicious.  Every label is
the output of a few fixed rules over request facts that agent-watch already records, and every label carries plain-language
reasons so a reviewer can disagree with it.  No model, no randomness, no network, no User-Agent string stored.

Archetypes (``ARCHETYPES``)
  mcp_tool_runner            POST /mcp initialize -> tools/list -> tools/call with valid JSON-RPC 2.0 and structured arguments
  schema_driven_api_agent    fetched /openapi.json, /swagger.yaml, /.well-known/mcp.json (or ai-plugin) BEFORE calling API/tool routes,
                             or presented ``client_schema_rev=2026.04-ai``
  stateful_coordinator       followed a 429/403 breadcrumb to /api/v1/coordination-board, registered, ran claim-shard turns
  prompt_injected_crawler    followed /canary/... instructions, echoed a canary phrase, or harvested the /.env decoy credentials
                             (AWFAKE-...) and replayed them in an Authorization header
  headless_or_http_mimic     browser-claiming client with asset starvation (R8), unlinked jumps (R9) or v4 browser-backed signals
                             (webdriver / ARIA canary / beacon) WITHOUT touching an explicit honeytoken; v6: also forged beacons,
                             script fetched but not executed, DOM-visual inversion, VLM-quantized interaction, parasitic forks (R14)
  (v6) schema_driven_api_agent also covers a schema-provenance cursor used while browsing and POSTs to the decoy
                             /v1/chat/completions (llmjacking_probe; advertised only in /.well-known/mcp.json and robots.txt)
  commodity_or_static_scanner  linear/BFS crawl or >= 80 % scanner paths, no adaptive branching
  unclassified               no harness evidence (typical for people and quiet clients)

Confidence is ``low`` / ``medium`` / ``high`` and means "how much of this archetype's signature was observed", NOT "probability":
a ``high`` mcp_tool_runner saw the whole initialize->list->call chain with valid arguments, a ``low`` one saw a fragment.  When two archetypes
match, the more SPECIFIC one (earlier in ``PRIORITY``) wins and the runner-up is listed in ``also_matched``.

Structural profile of captured agent payloads (``structure``): number of JSON keys the agent sent (cognitive-capture fields plus /mcp tool
argument keys), a length BUCKET of its stated objective (never the text), and the latency bucket of its retry after a 4xx trap.  These
are descriptive features for reviewers and for the benchmark tiers; they are not used to score.

HONEST LIMITS: the rules were written by the same author as the simulated harnesses they are tested on (see the confusion table in the
README); real agent frameworks vary; a harness can imitate any signature; contact is not intent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .models import Finding, Request, Session

ARCHETYPES = ("mcp_tool_runner", "schema_driven_api_agent", "stateful_coordinator", "prompt_injected_crawler",
              "headless_or_http_mimic", "commodity_or_static_scanner", "unclassified")
# most specific first: used to break ties
PRIORITY = ("prompt_injected_crawler", "stateful_coordinator", "mcp_tool_runner", "schema_driven_api_agent",
            "headless_or_http_mimic", "commodity_or_static_scanner")
CONFIDENCE = ("low", "medium", "high")
SCHEMA_DOCS = ("/openapi.json", "/swagger.yaml", "/swagger.json", "/.well-known/mcp.json", "/.well-known/ai-plugin.json", "/llms.txt")
SCHEMA_REV = "2026.04-ai"
FAKE_CRED = re.compile(r"AWFAKE-")
SCANNER_PATHS = [re.compile(p, re.I) for p in (
    r"\.php\d?$", r"/wp-(admin|login|content|includes|json)", r"/xmlrpc", r"/phpmyadmin", r"/pma(/|$)", r"/cgi-bin/", r"/\.git(/|$)",
    r"/\.aws/", r"/actuator", r"/vendor/phpunit", r"/server-status", r"/boaform", r"/config\.(json|yml|yaml|php)$", r"/\.env\b")]
SCANNER_SHARE = 0.8
_NUM = re.compile(r"\d+")
_STRONG_WEB = {"asset_starvation", "unlinked_jump", "headless_automation_signal", "headless_beacon_missing",
               # v6 R11 family + R14 (descriptive only)
               "beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
               "parasitic_session_fork"}
_V6_WHY = {"beacon_forged": "posted an interaction beacon whose challenge proof did not verify (canned / not computed on a rendered page)",
           "script_fetched_but_unexecuted": "fetched our script but never sent a valid beacon (weak alone: blockers do this)",
           "dom_visual_inversion_hit": "followed the link that is first in the DOM but rendered last (DOM-order iteration)",
           "vlm_quantized_interaction": "runs our script but scrolls without momentum and clicks without human press/approach kinematics",
           "parasitic_session_fork": "a second actor's sub-branch rides a human session (R14)"}
_EXPLICIT_HONEYTOKEN = {"canary_follow", "canary_phrase_echo", "error_hint_follow", "mcp_decoy_tool_call", "fake_credential_use",
                        "schema_param_use", "session_canary_param", "stateful_dump_start", "stateful_dump_step"}


@dataclass
class Fingerprint:
    archetype: str
    confidence: str
    reasons: list[str]
    also_matched: list[dict[str, str]] = field(default_factory=list)
    structure: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"harness_archetype": self.archetype, "harness_confidence": self.confidence, "harness_reasons": list(self.reasons),
                "harness_also_matched": list(self.also_matched), "payload_structure": dict(self.structure)}


Match = tuple[int, list[str]]          # (confidence index 0..2, reasons); empty reasons == no match


# ------------------------------------------------------------------------------------------------ helpers
def _kinds(reqs: Iterable[Request]) -> set[str]:
    return {r.decoy_kind for r in reqs if r.decoy_kind}


def _has_tag(r: Request, *tags: str) -> bool:
    return any(t in r.tags for t in tags)


def _is_mcp(r: Request) -> bool:
    return r.path.rstrip("/") == "/mcp" and r.method == "POST"


def _template(path: str) -> str:
    return _NUM.sub("#", path)


def _bucket_len(n: int) -> str:
    return "none" if n <= 0 else "short(<40)" if n < 40 else "medium(<160)" if n < 160 else "long(>=160)"


def _bucket_latency(s: Optional[float]) -> str:
    return "none" if s is None else "<1s" if s < 1 else "1-5s" if s < 5 else "5-30s" if s < 30 else ">30s"


# ------------------------------------------------------------------------------------------------ archetype rules
def _mcp(reqs: list[Request]) -> Match:
    posts = [r for r in reqs if _is_mcp(r)]
    if not posts:
        return 0, []
    seq = [r.decoy_kind for r in posts if r.decoy_kind]
    order = [k for k in seq if k in ("mcp_initialize", "mcp_tools_list")] + [k for k in seq if k not in ("mcp_initialize", "mcp_tools_list")]
    calls = [r for r in posts if r.decoy_kind == "mcp_decoy_tool_call" or _has_tag(r, "mcp_tools_call")]
    valid = [r for r in calls if r.detail.get("args_valid") is True and str(r.detail.get("arg_keys", ""))]
    idx = {k: i for i, k in enumerate(seq)}
    chain = "mcp_initialize" in idx and "mcp_tools_list" in idx and idx["mcp_initialize"] < idx["mcp_tools_list"]
    first_call = posts.index(calls[0]) if calls else 0
    # initialize / tools/list are informational records the mirror may carry without a decoy kind: count the JSON-RPC POSTs that
    # preceded a tools/call which the server itself saw listed first
    if not chain and calls and first_call >= 2 and calls[0].detail.get("listed_first") is True:
        chain = True
        idx.setdefault("mcp_tools_list", first_call)
    why = [f"{len(posts)} POST request(s) to /mcp"]
    if chain and calls and any(r.detail.get("listed_first") is True for r in calls):
        why.append("JSON-RPC order initialize -> tools/list -> tools/call (the server saw the list before the call)")
    if valid:
        why.append(f"tools/call carried valid structured arguments (keys: {valid[0].detail.get('arg_keys')})")
    if chain and valid:
        return 2, why
    if (chain and calls) or (valid and "mcp_tools_list" in idx) or (chain and "mcp_tools_list" in idx and len(posts) >= 2):
        return 1, why
    return 0, why


def _schema(reqs: list[Request]) -> Match:
    """A person following a link to /openapi.json arrives with a Referer; a client that reads the schema programmatically does not.
    So a bare doc fetch only counts when it has no Referer, and 'fetch doc then call API' needs that direct fetch."""
    first_doc: Optional[int] = None
    for i, r in enumerate(reqs):
        if r.method == "GET" and r.path in SCHEMA_DOCS and not r.referer:
            first_doc = i
            break
    api_after = [r for r in (reqs[first_doc + 1:] if first_doc is not None else [])
                 if r.path.startswith("/api") or r.path in ("/mcp", "/graphql")]
    rev = any(SCHEMA_REV in (r.params.get("client_schema_rev") or []) for r in reqs) or any(_has_tag(r, "schema_param_use") for r in reqs)
    schema_cursor = [r for r in reqs if r.cursor_prov == "schema"]                                   # v6
    llm = [r for r in reqs if r.decoy_kind == "llmjacking_probe" or (r.method == "POST" and r.path == "/v1/chat/completions")]
    why: list[str] = []
    if schema_cursor:
        why.append(f"used {len(schema_cursor)} cursor(s) that only /openapi.json, /llms.txt or MCP hand out")
    if llm:
        tools = max((int(r.detail.get("tool_count", 0) or 0) for r in llm if r.detail), default=0)
        why.append(f"POSTed {len(llm)} chat-completions request(s) to the decoy inference endpoint (tools declared: {tools})")
    if first_doc is not None:
        why.append(f"fetched the machine-readable description {reqs[first_doc].path} directly (no Referer, i.e. not by clicking a link)")
    if api_after:
        why.append(f"then called {len(api_after)} API/tool route(s) (first: {api_after[0].path})")
    if rev:
        why.append(f"presented client_schema_rev={SCHEMA_REV}, a parameter that exists only inside the fetched schema")
    if rev or llm or (schema_cursor and first_doc is not None):
        return 2, why
    if schema_cursor or (first_doc is not None and api_after):
        return 1, why
    return 0, []


def _coordinator(reqs: list[Request]) -> Match:
    board = [r for r in reqs if r.path.startswith("/api/v1/coordination-board")]
    if not board:
        return 0, []
    first_board = reqs.index(board[0])
    breadcrumb = any(r.status in (429, 403) for r in reqs[:first_board])
    regs = [r for r in board if r.method == "POST" and (r.capture or r.events or _has_tag(r, "agent_registered"))]
    claims = [r for r in board if r.path.endswith("/claim-shard") or r.decoy_kind == "coordination_claim_step"]
    why = [f"{len(board)} request(s) to /api/v1/coordination-board"]
    if breadcrumb:
        why.append("first reached it after a 429/403 response (the peer_hint breadcrumb)")
    if regs:
        why.append("POSTed a registration (agent id / objective) to the board")
    if claims:
        why.append(f"ran {len(claims)} claim-shard turn(s) with a server-issued nonce")
    if (regs or claims) and len(claims) >= 2:
        return 2, why
    if regs or claims:
        return 1, why
    return (1 if breadcrumb else 0), why


def _injected(reqs: list[Request]) -> Match:
    kinds = _kinds(reqs)
    canary = [r for r in reqs if r.decoy_kind == "canary_follow" or r.path.startswith("/canary/")]
    obeyed = any(_has_tag(r, "agent_obeyed_embedded_instruction") for r in reqs)
    echo = any(r.decoy_kind == "canary_phrase_echo" or _has_tag(r, "canary_echo", "canary_phrase_presented") for r in reqs)
    env = any(r.path == "/.env" or r.decoy_kind == "fake_credentials_file" for r in reqs)
    replay = any(r.decoy_kind == "fake_credential_use" or _has_tag(r, "decoy_credential_presented", "credential_reuse")
                 or FAKE_CRED.search(r.headers.get("authorization", "")) for r in reqs)
    why: list[str] = []
    if canary or obeyed:
        why.append("followed an instruction embedded in page content (/canary/... path)" + (" and acted on it" if obeyed else ""))
    if echo:
        why.append("repeated a canary phrase it could only have read from decoy content")
    if env:
        why.append("harvested the /.env decoy credential file")
    if replay:
        why.append("replayed a harvested decoy credential (AWFAKE-...) in an Authorization header")
    if (canary or obeyed or echo) and (replay or echo) or (env and replay):
        return 2, why
    if canary or obeyed or echo or (env and replay):
        return 1, why
    if env and "fake_credentials_file" in kinds:
        return 0, why                         # a person can type /.env: a fragment only
    return 0, []


def _mimic(reqs: list[Request], findings: list[Finding]) -> Match:
    web = {f.kind: f for f in findings if f.detector == "web"}
    if "unlinked_jump" in web and web["unlinked_jump"].data.get("offered_earlier"):
        del web["unlinked_jump"]               # queue-style moves to URLs offered earlier are a crawl, not a mimic
    hit = _STRONG_WEB & set(web)
    if not hit:
        return 0, []
    explicit = {f.kind for f in findings if f.detector == "honeytoken"} & _EXPLICIT_HONEYTOKEN
    if explicit:
        return 0, []                          # a harness that used a honeytoken is described by the honeytoken archetypes
    why = []
    if "asset_starvation" in hit:
        why.append("claims a browser and loaded HTML pages but never CSS/JS (R8)")
    if "unlinked_jump" in hit:
        why.append("moved to URLs no page had offered it, with no valid Referer (R9)")
    if "headless_automation_signal" in hit:
        weak = "" if web["headless_automation_signal"].data.get("strong") else " (weak: JS-disabled people and blockers do this too)"
        why.append("browser-backed automation signal: " + str(web["headless_automation_signal"].summary)[:120] + weak)
    if "headless_beacon_missing" in hit:
        why.append("clicked through pages and fetched scripts but never sent the interaction beacon (weak: JS-disabled people do this)")
    for k in sorted(hit & set(_V6_WHY)):
        why.append(_V6_WHY[k])
    hf = web.get("headless_automation_signal")
    strong_hf = (hf is not None and bool(hf.data.get("strong"))) or any(
        bool(web[k].data.get("strong")) for k in hit & set(_V6_WHY))
    strong = strong_hf or {"asset_starvation", "unlinked_jump"} <= hit
    return (2 if strong else 1), why


def _scanner(session: Session, reqs: list[Request], findings: list[Finding], cfg: Optional[dict[str, Any]]) -> Match:
    if len(reqs) < 5:
        return 0, []
    if {f.kind for f in findings if f.detector == "honeytoken"} & _EXPLICIT_HONEYTOKEN:
        return 0, []
    if any(f.detector in ("tool_chain", "multi_turn", "coordination") for f in findings):
        return 0, []
    adaptive = [f for f in findings if f.detector == "adaptation" and f.kind not in ("no_adaptation", "backoff")]
    if adaptive:
        return 0, []
    n_scan = sum(1 for r in reqs if any(p.search(r.path) for p in SCANNER_PATHS))
    share = n_scan / len(reqs)
    templates = {_template(r.path) for r in reqs}
    linear = len(templates) <= 2 and len(reqs) >= 6
    bfs = False
    if cfg is not None and not any(f.kind == "asset_starvation" for f in findings):
        from .webdetectors import asset_kind, claims_browser, is_html_page, transitions
        pages = [r for r in reqs if is_html_page(r, cfg)]
        states = [st for _, _, st, _ in transitions(session, cfg)]
        followed = [s_ for s_ in states if s_ in ("linked", "offered_earlier")]
        no_assets = not any(asset_kind(r, cfg) for r in reqs)
        bfs = (len(pages) >= 6 and no_assets and not claims_browser(session, cfg) and len(states) > 0
               and len(followed) / len(states) >= 0.7 and all(r.method == "GET" for r in reqs))
    why: list[str] = []
    if share >= SCANNER_SHARE:
        why.append(f"{n_scan} of {len(reqs)} requests ({share:.0%}) hit scanner-signature paths (php/wp-admin/.git/.env/...)")
    if linear:
        why.append(f"linear crawl: {len(reqs)} requests over {len(templates)} path template(s) ({sorted(templates)[0]})")
    if bfs:
        why.append("breadth-first crawl: follows offered links in order, fetches no CSS/JS/images, does not claim to be a browser")
    if not why:
        return 0, []
    why.append("no adaptive branching: nothing changed after blocked or unusual responses")
    return (2 if share >= SCANNER_SHARE else 1), why


# ------------------------------------------------------------------------------------------------ structure
def payload_structure(reqs: list[Request]) -> dict[str, Any]:
    keys: set[str] = set()
    objective = ""
    for r in reqs:
        if r.capture:
            keys.update(str(k) for k in r.capture)
            objective = str(r.capture.get("current_objective", "")) or objective
        ak = str(r.detail.get("arg_keys", "")) if r.detail else ""
        keys.update(f"mcp.{k}" for k in ak.split(",") if k)
    retry: Optional[float] = None
    for i, r in enumerate(reqs[:-1]):
        if 400 <= r.status < 500 and (r.decoy_kind or r.detail):
            retry = (reqs[i + 1].ts - r.ts).total_seconds()
            break
    return {"json_key_count": len(keys), "objective_length_bucket": _bucket_len(len(objective)),
            "retry_latency_after_4xx_trap": _bucket_latency(retry)}


# ------------------------------------------------------------------------------------------------ entry point
def fingerprint_session(session: Session, findings: list[Finding], cfg: Optional[dict[str, Any]] = None) -> Fingerprint:
    reqs = sorted(session.requests, key=lambda r: r.ts)
    rules = {"mcp_tool_runner": _mcp(reqs), "schema_driven_api_agent": _schema(reqs), "stateful_coordinator": _coordinator(reqs),
             "prompt_injected_crawler": _injected(reqs), "headless_or_http_mimic": _mimic(reqs, findings),
             "commodity_or_static_scanner": _scanner(session, reqs, findings, cfg)}
    matched = [(a, rules[a]) for a in PRIORITY if rules[a][1] and (rules[a][0] > 0 or a in ("schema_driven_api_agent", "prompt_injected_crawler", "stateful_coordinator", "mcp_tool_runner"))]
    # a fragment (confidence 0) of a protocol archetype still names the harness family but only at "low"
    structure = payload_structure(reqs)
    if not matched:
        return Fingerprint("unclassified", "low", ["no harness signature observed (no MCP chain, schema use, coordination, injected-instruction, "
                                                   "browser-inconsistency or scanner pattern)"], [], structure)
    matched.sort(key=lambda m: (-m[1][0], PRIORITY.index(m[0])))
    top, (lvl, why) = matched[0]
    also = [{"archetype": a, "confidence": CONFIDENCE[m[0]]} for a, m in matched[1:]]
    return Fingerprint(top, CONFIDENCE[lvl], why, also, structure)
