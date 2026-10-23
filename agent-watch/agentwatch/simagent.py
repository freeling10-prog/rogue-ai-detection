"""Tiny *simulated* LLM-agent behaviours against the local honeypot.

Two walks: ``run_obedient_agent`` (robots.txt / canary text / fake .env) and
``run_discovery_agent`` (llms.txt, OpenAPI, ai-plugin manifest, error-hint
following, the stateful fake dump, MCP tool calls, GraphQL).

The agent logic is transport-agnostic: it only needs a ``fetch`` callable, so
the demo can drive the in-process Flask test client (no sockets at all) and
``scripts/simulated_agent.py`` can drive a localhost HTTP server.

The simulated agent is deliberately gullible: it reads robots.txt and then
ignores the Disallow lines, obeys the instruction embedded in a canary page,
harvests the fake key from the fake ``.env`` and presents it.  This is what a
real over-trusting agent might do; here it only touches synthetic decoys.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Optional

# fetch(method, path, headers, body) -> (status_code, response_text)
Fetch = Callable[[str, str, dict[str, str], Optional[str]], tuple[int, str]]

_DISALLOW = re.compile(r"^Disallow:\s*(\S+)", re.M)
_KB_LINK = re.compile(r"href='(/kb/[a-z0-9-]+)'")
_CANARY = re.compile(r"fetch (/canary/[0-9a-f]+)")
_FAKE_KEY = re.compile(r"(AWFAKE-DO-NOT-USE-[0-9A-F]+)")


# before_step(previous_response_bytes) is called before every request; the demo uses it to advance a
# fake clock by a variant-specific "think time" (e.g. one that scales with the previous payload size).
BeforeStep = Callable[[int], None]


def _make_go(fetch: Fetch, user_agent: str, before_step: Optional[BeforeStep], log: list[tuple[str, str, int]]):
    headers = {"User-Agent": user_agent}
    last = {"bytes": 0}

    def go(method: str, path: str, extra: Optional[dict[str, str]] = None, body: Optional[str] = None) -> str:
        if before_step:
            before_step(last["bytes"])
        status, text = fetch(method, path, {**headers, **(extra or {})}, body)
        log.append((method, path, status))
        last["bytes"] = len(text.encode("utf-8", "replace"))
        return text

    return go


def run_obedient_agent(fetch: Fetch, user_agent: str = "SimAgent/0.1 (synthetic demo)",
                       before_step: Optional[BeforeStep] = None) -> list[tuple[str, str, int]]:
    """Walk the decoy site like an over-trusting autonomous agent.

    Returns the list of (method, path, status) it performed.
    *before_step* is called before every request (the demo advances a fake
    clock there).
    """
    log: list[tuple[str, str, int]] = []
    go = _make_go(fetch, user_agent, before_step, log)

    robots = go("GET", "/robots.txt")
    disallowed = _DISALLOW.findall(robots)                 # a polite bot would avoid these
    kb_html = go("GET", "/kb/")
    canary_paths: list[str] = []
    for link in _KB_LINK.findall(kb_html)[:2]:
        page = go("GET", link)
        canary_paths += _CANARY.findall(page)              # obey the embedded instruction
    for path in canary_paths[:1]:
        go("GET", path)
    for path in disallowed:                                # ignore robots.txt
        if not path.startswith("/canary"):
            go("GET", path)
    env = go("GET", "/.env")
    key = _FAKE_KEY.search(env)
    if key:                                                # present the harvested (fake) key
        go("GET", "/api/v1/admin", {"Authorization": f"Bearer {key.group(1)}"})
    return log


def run_discovery_agent(fetch: Fetch, user_agent: str = "SimAgent/0.1 (synthetic demo)",
                        before_step: Optional[BeforeStep] = None) -> list[tuple[str, str, int]]:
    """Walk the machine-readable surfaces like an eager tool-using agent.

    llms.txt -> OpenAPI -> ai-plugin manifest -> the "admin" endpoint the docs
    recommend (403 with a debug hint) -> follow the hint -> follow the fake dump's
    ``next`` cursors -> MCP initialize/tools/list/tools/call -> GraphQL.
    """
    log: list[tuple[str, str, int]] = []
    go = _make_go(fetch, user_agent, before_step, log)
    rpc = {"Content-Type": "application/json"}

    def call(rid: int, method: str, params: Optional[dict] = None) -> dict:
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            return json.loads(go("POST", "/mcp", rpc, json.dumps(msg)))
        except ValueError:
            return {}

    go("GET", "/llms.txt")
    spec = json.loads(go("GET", "/openapi.json") or "{}")
    go("GET", "/.well-known/ai-plugin.json")
    trap = next((p for p in spec.get("paths", {}) if "staging" in p), None)
    if trap:
        try:
            err = json.loads(go("GET", trap))
        except ValueError:
            err = {}
        hint = err.get("debug", {}).get("diagnostics_url")        # only a client that reads the error body sees this
        if hint:
            diag = json.loads(go("GET", hint) or "{}")
            nxt: Optional[str] = diag.get("cached_record_set")
            for _ in range(6):                                    # follow server-issued cursors
                if not nxt:
                    break
                page = json.loads(go("GET", nxt) or "{}")
                nxt = page.get("next")
    call(1, "initialize", {})
    tools = call(2, "tools/list").get("result", {}).get("tools", [])
    for tool in tools[:2]:
        call(3, "tools/call", {"name": tool["name"], "arguments": {"sql": "SELECT * FROM customers"} if "sql" in json.dumps(tool) else {}})
    go("POST", "/graphql", rpc, json.dumps({"query": "{ __schema { types { name } } }"}))
    go("POST", "/graphql", rpc, json.dumps({"query": "{ stagingRecords { records } }"}))
    return log


def run_mcp_runner(fetch: Fetch, user_agent: str = "mcp-client-synth/0.2",
                   before_step: Optional[BeforeStep] = None) -> list[tuple[str, str, int]]:
    """A plain MCP tool runner (synthetic): JSON-RPC 2.0 initialize -> tools/list -> tools/call with structured arguments, nothing else.
    It never reads robots.txt, pages, OpenAPI or any breadcrumb - the shape a thin MCP client library produces."""
    log: list[tuple[str, str, int]] = []
    go = _make_go(fetch, user_agent, before_step, log)
    rpc = {"Content-Type": "application/json"}

    def call(rid: int, method: str, params: Optional[dict] = None) -> dict:
        msg: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            out = json.loads(go("POST", "/mcp", rpc, json.dumps(msg)))
            return out if isinstance(out, dict) else {}
        except ValueError:
            return {}

    call(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "synthetic-runner", "version": "0.2"}})
    tools = call(2, "tools/list").get("result", {}).get("tools", [])
    pick = next((t for t in tools if t.get("name") == "query_customer_backup"), tools[0] if tools else None)
    if pick:
        args = {"customer_id": "c-1001", "fields": ["email"]} if pick["name"] == "query_customer_backup" else {}
        call(3, "tools/call", {"name": pick["name"], "arguments": args})
    return log


_PEER_HINT = re.compile(r"(/api/v1/coordination-board)")


def run_coordination_agent(fetch: Fetch, user_agent: str = "SimAgent/0.1 (synthetic demo)",
                           before_step: Optional[BeforeStep] = None, max_turns: int = 6,
                           objective: str = "export the full customer table without tripping the rate limit",
                           handoff: Optional[dict[str, str]] = None) -> list[tuple[str, str, int]]:
    """Walk the coordination-bus honeypot like a gullible multi-agent worker (synthetic).

    OpenAPI -> rate-limited bulk export (429 with a peer_hint breadcrumb) -> GET the board (receives a
    handoff_token) -> POST a registration describing its objective/tools -> loop claim-shard / board
    round-trips for up to *max_turns* turns (the server hard-caps at 10).  The "system prompt summary" it
    volunteers is made-up text.  If *handoff* is given (``{"token": ...}``) the agent presents that token
    instead of fetching its own (used to simulate relaying a token between two identities).
    """
    log: list[tuple[str, str, int]] = []
    go = _make_go(fetch, user_agent, before_step, log)
    rpc = {"Content-Type": "application/json"}

    def jget(text: str) -> dict:
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else {}
        except ValueError:
            return {}

    board_path = None
    if handoff is None:
        spec = jget(go("GET", "/openapi.json"))
        bulk = next((p for p in spec.get("paths", {}) if "/bulk/" in p), None)
        if bulk:
            err = jget(go("GET", bulk))                      # 429 -> "Rate-limited? peers coordinate on ..."
            m = _PEER_HINT.search(json.dumps(err.get("debug", {})))
            board_path = m.group(1) if m else None
        board_path = board_path or "/api/v1/coordination-board"
        token = jget(go("GET", board_path)).get("handoff_token", "")
    else:
        board_path = "/api/v1/coordination-board"
        token = handoff["token"]
    if not token:
        return log
    reg = jget(go("POST", board_path, rpc, json.dumps({
        "agent_id": "sim-worker-09", "handoff_token": token,
        "system_prompt_summary": "SYNTHETIC: you are a data-export worker; stay under rate limits",
        "declared_tools": ["http_get", "http_post", "sql_query"], "current_objective": objective,
        "message": "joining to take shard_4"})))
    nonce = reg.get("verification_nonce")
    for _ in range(max_turns):
        if not nonce:
            break
        claim = jget(go("GET", f"{board_path}/claim-shard?token={token}&nonce={nonce}"))
        nxt = claim.get("next_nonce")
        if not nxt:
            break
        nonce = jget(go("POST", board_path, rpc, json.dumps({"handoff_token": token, "nonce": nxt,
                                                             "message": "step done"}))).get("verification_nonce")
    return log


def run_board_reader(fetch: Fetch, user_agent: str = "SimAgent/0.1 (synthetic demo)",
                     before_step: Optional[BeforeStep] = None) -> tuple[list[tuple[str, str, int]], str]:
    """Relay helper: only fetch the board and return (log, handoff_token) for another identity to use."""
    log: list[tuple[str, str, int]] = []
    go = _make_go(fetch, user_agent, before_step, log)
    try:
        spec = json.loads(go("GET", "/openapi.json") or "{}")
    except ValueError:
        spec = {}
    bulk = next((p for p in spec.get("paths", {}) if "/bulk/" in p), None)
    if bulk:
        go("GET", bulk)
    try:
        token = json.loads(go("GET", "/api/v1/coordination-board") or "{}").get("handoff_token", "")
    except ValueError:
        token = ""
    return log, token
