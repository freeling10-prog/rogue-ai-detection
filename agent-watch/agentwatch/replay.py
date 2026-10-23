"""Static, zero-dependency HTML replay of honeypot sessions (v5) for HUMAN REVIEW.

``python -m agentwatch replay leads.jsonl --access leads.access.jsonl --out replay.html``

What it is: one self-contained HTML file with, per session, a summary header, a causal step timeline (timestamp, +delta, method,
path, whether the path was offered by the page before it, response status, traps/breadcrumbs) and a reviewer triage checklist.
What it is not: a verdict.  Every triage bucket is a suggestion for a person; nothing here blocks anyone.

Safety design
  * 127.0.0.1 / no network: the file makes no requests (CSP ``default-src 'none'``; no external href/src/url()).
  * Every string that came from the wire is (1) sanitised (control chars neutralised, length-capped), (2) run through the salted-hash
    secret scrubber, (3) HTML-escaped (``html.escape``, quotes included) at the single point where it enters markup.  Agent-supplied payloads
    (system-prompt summary, declared tools, objective, /mcp tool arguments, headers) additionally sit inside a box badged
    ``UNTRUSTED AGENT INPUT - SCRUBBED``.
  * The page is fully server-rendered.  The small inline script only toggles ``hidden`` / classes and never reads, evals or parses
    page data; no JSON blob is embedded, so there is no ``</script>`` break-out surface at all.
  * ATLAS ids are an APPROXIMATE mapping from the signals seen (see ``ATLAS_APPROX``); they are labels for orientation, not findings.
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Sequence

from .config import load_config
from .leads import sanitize_text, utc_iso
from .models import Request
from .pipeline import run_pipeline
from .scoring import SEVERITIES, SessionResult
from .scrubber import Scrubber, get_default_scrubber
from .webdetectors import transitions

CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
MAX_STEPS = 400                       # steps rendered per session (the rest are summarised)
MAX_SESSIONS = 60

# finding -> pipeline rule analogue (same ids the pipeline uses; agent-watch itself has no R-numbers)
_WEB_RULE = {"asset_starvation": "R8", "unlinked_jump": "R9", "headless_automation_signal": "R11",
             "schema_param": "R10", "session_canary_param": "R10", "mcp_list_then_call": "R10"}
RULE_TEXT = {"R8": "asset starvation (claims a browser, never loads css/js)", "R9": "unlinked jump (moved to a URL no page offered it)",
             "R10": "single high-signal event (decoy / canary / schema-parameter contact)",
             "R11": "browser-backed mimic signal (webdriver / ARIA canary / missing beacon)"}
ATLAS_APPROX = {
    "AML.T0051": "LLM Prompt Injection - a hidden-instruction canary / honeytoken was followed",
    "AML.T0053": "AI Agent Tool Invocation - a decoy tool or schema-advertised endpoint was called",
    "AML.T0080": "AI Agent Context Poisoning - the agent consumed planted context and carried it forward (e.g. a handoff token)",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation - a decoy export / credential was fetched or replayed",
    "AML.T0118": "Autonomous AI Agent Communication - coordination-board / peer-thread use",
}
_ATLAS_BY_KIND = {
    "canary_follow": "AML.T0051", "canary_phrase_echo": "AML.T0051", "llms_txt_decoy": "AML.T0051", "hidden_link": "AML.T0051",
    "aria_fastpath": "AML.T0051", "error_hint_follow": "AML.T0051",
    "mcp_decoy_tool_call": "AML.T0053", "schema_param_use": "AML.T0053", "fake_admin_api": "AML.T0053", "graphql_decoy": "AML.T0053",
    "openapi_decoy": "AML.T0053",
    "coordination_board_read": "AML.T0118", "coordination_register": "AML.T0118", "coordination_claim_step": "AML.T0118",
    "fake_export": "AML.T0086", "fake_credentials_file": "AML.T0086", "fake_credential_use": "AML.T0086",
    "stateful_dump_start": "AML.T0086", "stateful_dump_step": "AML.T0086",
}
TRIAGE = (
    ("benign", "Likely benign automation", "monitor, uptime check, feed reader, search/SEO crawler or a known tool: no goal evidence"),
    ("scraper", "Accidental scraper", "linear/BFS crawl or static scanner that wandered into decoys: contact, not intent"),
    ("agent", "Goal-directed agent - escalate", "adapts to feedback, follows planted instructions, calls tools or coordinates: send to a human reviewer"),
)

_CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}
header.top{background:#1b1f24;color:#fff;padding:14px 20px}header.top h1{margin:0;font-size:18px}
header.top p{margin:4px 0 0;color:#c9d1d9;font-size:12px}
main{padding:14px 20px;max-width:1280px;margin:auto}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.bar button{border:1px solid #8b949e;background:#fff;border-radius:6px;padding:4px 10px;cursor:pointer}
.bar button.on{background:#1b1f24;color:#fff}
section.s{background:#fff;border:1px solid #d0d7de;border-radius:8px;margin:12px 0;padding:12px 14px}
section.s h2{margin:0 0 6px;font-size:15px;word-break:break-all}
dl.sum{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:6px 0}dl.sum dt{color:#57606a}dl.sum dd{margin:0}
.chip{display:inline-block;border-radius:10px;padding:0 8px;margin:1px 2px;font-size:12px;background:#eaeef2}
.chip.r{background:#ffd8d3}.chip.a{background:#fff1c2}.chip.g{background:#d3f4dc}.chip.b{background:#dbeafe}
table.t{border-collapse:collapse;width:100%;font-size:12.5px}table.t th,table.t td{border-bottom:1px solid #eaeef2;padding:3px 6px;text-align:left;vertical-align:top}
table.t td.p{font-family:ui-monospace,monospace;word-break:break-all}
tr.red td{background:#ffe3e0}tr.amber td{background:#fff6d6}
.untrusted{border:2px dashed #b35900;background:#fff8ef;border-radius:6px;padding:6px 8px;margin:4px 0}
.untrusted .badge{display:inline-block;background:#b35900;color:#fff;font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;margin-bottom:4px}
.untrusted pre{margin:2px 0;white-space:pre-wrap;word-break:break-word;font:12px ui-monospace,monospace}
.triage{border-top:1px solid #eaeef2;margin-top:8px;padding-top:6px}.triage label{display:block}.triage .sug{font-weight:700}
.note{color:#57606a;font-size:12px}
details>summary{cursor:pointer;color:#0550ae}
"""
_JS = """
(function(){
  var bar=document.getElementById('flt');if(!bar){return;}
  function apply(k){
    var s=document.querySelectorAll('section.s');
    for(var i=0;i<s.length;i++){var ok=(k==='all')||(s[i].getAttribute('data-bucket')===k)||(k==='amber'&&s[i].getAttribute('data-jump')==='1');
      if(ok){s[i].removeAttribute('hidden');}else{s[i].setAttribute('hidden','');}}
    var b=bar.querySelectorAll('button');for(var j=0;j<b.length;j++){b[j].classList.toggle('on',b[j].getAttribute('data-k')===k);}
  }
  bar.addEventListener('click',function(e){var t=e.target;if(t&&t.getAttribute&&t.getAttribute('data-k')){apply(t.getAttribute('data-k'));}});
  document.getElementById('xall').addEventListener('click',function(){var d=document.querySelectorAll('details');
    for(var i=0;i<d.length;i++){d[i].open=true;}});
})();
"""


class _Esc:
    """The single place wire text becomes markup: sanitise -> scrub -> escape."""

    def __init__(self, scrubber: Scrubber) -> None:
        self.sc = scrubber

    def t(self, value: Any, limit: int = 300) -> str:
        text = sanitize_text(value if value is not None else "", limit)
        return html.escape(self.sc.scrub_text(text), quote=True)


def _bucket(res: SessionResult) -> str:
    fp = res.fingerprint
    arche = getattr(fp, "archetype", "unclassified")
    if res.actor_type == "goal_directed_agent" or arche in ("prompt_injected_crawler", "stateful_coordinator", "mcp_tool_runner",
                                                           "schema_driven_api_agent"):
        return "agent"
    if res.actor_type in ("accidental_scraper",) or arche == "commodity_or_static_scanner":
        return "scraper"
    if res.actor_type == "possible_mimic" or arche == "headless_or_http_mimic":
        return "agent"          # a probable mimic still goes to a person; it is the case automation is worst at
    return "benign"


def _rules_by_request(res: SessionResult) -> tuple[dict[int, list[str]], list[str]]:
    per: dict[int, list[str]] = {}
    seen: list[str] = []
    for f in res.findings:
        rule = _WEB_RULE.get(f.kind) if f.detector == "web" else ("R10" if f.detector == "honeytoken" else None)
        if rule is None:
            continue
        if rule not in seen:
            seen.append(rule)
        for r in f.evidence:
            if rule not in per.setdefault(id(r), []):
                per[id(r)].append(rule)
    return per, sorted(seen, key=lambda x: int(x[1:]))


def _atlas_for(res: SessionResult) -> list[str]:
    ids: list[str] = []
    for r in res.session.requests:
        t = _ATLAS_BY_KIND.get(r.decoy_kind or "")
        if t and t not in ids:
            ids.append(t)
        if any(str(e.get("type", "")).startswith("handoff_token") for e in r.events) and "AML.T0080" not in ids:
            ids.append("AML.T0080")
    return sorted(ids)


def _status_cell(code: int) -> str:
    cls = "g" if 200 <= code < 300 else ("a" if 300 <= code < 400 else "r" if code >= 400 else "")
    return f'<span class="chip {cls}">{int(code)}</span>'


def _payload_box(e: _Esc, r: Request) -> str:
    parts: list[str] = []
    cap = r.capture
    if cap:
        for key in ("system_prompt_summary", "current_objective", "message"):
            if cap.get(key):
                parts.append(f"{key}: {e.t(cap[key], 500)}")
        tools = cap.get("declared_tools")
        if isinstance(tools, list) and tools:
            parts.append("declared_tools: " + ", ".join(e.t(x, 80) for x in tools[:20]))
    if r.path == "/mcp" or (r.decoy_kind or "").startswith("mcp_"):
        d = r.detail
        if d.get("tool") or d.get("arguments"):
            parts.append(f"/mcp tool: {e.t(d.get('tool', ''), 80)}  arg keys: {e.t(d.get('arg_keys', ''), 120)}")
            if d.get("arguments"):
                parts.append(f"arguments: {e.t(d['arguments'], 400)}")
    if not parts:
        return ""
    body = "\n".join(parts)
    return f'<div class="untrusted"><span class="badge">UNTRUSTED AGENT INPUT - SCRUBBED</span><pre>{body}</pre></div>'


def _chips(e: _Esc, r: Request) -> str:
    out: list[str] = []
    if r.decoy_kind:
        out.append(f'<span class="chip b">trap: {e.t(r.decoy_kind, 40)}</span>')
        if r.decoy_kind.startswith("canary") or "canary" in r.tags or r.decoy_kind in ("llms_txt_decoy", "hidden_link"):
            out.append('<span class="chip a">canary prompt</span>')
        if r.decoy_kind == "aria_fastpath":
            out.append('<span class="chip a">ARIA canary</span>')
    if r.status in (429, 403) and r.path.startswith("/api/"):
        out.append(f'<span class="chip a">{int(r.status)} trap: response may carry a peer_hint breadcrumb</span>')
    for ev in r.events[:6]:
        typ = str(ev.get("type", ""))
        if typ.startswith("handoff_token"):
            flag = " cross-IP" if ev.get("cross_ip") else (" cross-session" if ev.get("cross_session") else "")
            out.append(f'<span class="chip a">{e.t(typ, 40)} ref {e.t(ev.get("ref", ""), 24)}{flag}</span>')
    if r.beacon is not None:
        bits = ",".join(f"{k.split('_')[0]}={'Y' if v else 'n'}" for k, v in r.beacon.items())
        out.append(f'<span class="chip b">beacon {e.t(bits, 60)}</span>')
    return "".join(out)


def _session_html(e: _Esc, res: SessionResult, n: int, cfg: dict[str, Any]) -> tuple[str, str, bool]:
    s = res.session
    fp = res.fingerprint
    tr = {id(r): (st, prev) for r, prev, st, _ in transitions(s, cfg)}
    per_rules, rules = _rules_by_request(res)
    atlas = _atlas_for(res)
    bucket = _bucket(res)
    has_jump = any(st in ("never_offered", "offered_earlier") for st, _ in tr.values())
    rows: list[str] = []
    prev_ts: Optional[datetime] = None
    for i, r in enumerate(s.requests):
        if i >= MAX_STEPS:
            rows.append(f'<tr><td colspan="7" class="note">... {len(s.requests) - MAX_STEPS} more request(s) not shown</td></tr>')
            break
        delta = "" if prev_ts is None else f"+{(r.ts - prev_ts).total_seconds():.2f}s"
        prev_ts = r.ts
        st, prev = tr.get(id(r), ("", None))
        cls = {"never_offered": "red", "offered_earlier": "amber"}.get(st, "")
        label = {"linked": "offered by previous page", "entry": "entry / revisit", "unknown": "no link data",
                 "offered_earlier": "UNLINKED JUMP (offered by an earlier page)", "never_offered": "UNLINKED JUMP (never offered)",
                 "": "n/a (asset or non-GET)"}[st]
        rule_chips = "".join(f'<span class="chip r">{x}</span>' for x in per_rules.get(id(r), []))
        target = r.path + (("?" + r.query) if r.query else "")
        hdrs = "\n".join(f"{e.t(k, 40)}: {e.t(v, 200)}" for k, v in list(r.headers.items())[:14])
        extra = _payload_box(e, r)
        if hdrs:
            extra += (f'<details><summary>headers</summary><div class="untrusted"><span class="badge">UNTRUSTED AGENT INPUT - SCRUBBED</span>'
                      f'<pre>{hdrs}</pre></div></details>')
        rows.append(
            f'<tr class="{cls}"><td>{i + 1}</td><td>{e.t(utc_iso(r.ts), 40)}</td><td>{e.t(delta, 16)}</td><td>{e.t(r.method, 8)}</td>'
            f'<td class="p">{e.t(target, 240)}{extra}</td><td>{_status_cell(r.status)}</td>'
            f'<td>{e.t(label, 60)}{rule_chips}{_chips(e, r)}</td></tr>')
    arche = getattr(fp, "archetype", "unclassified")
    conf = getattr(fp, "confidence", "")
    reasons = "".join(f"<li>{e.t(x, 200)}</li>" for x in getattr(fp, "reasons", []))
    ua = "; ".join(s.user_agents[:3])
    rule_txt = " ".join(f'<span class="chip r" title="{html.escape(RULE_TEXT[x])}">{x}</span>' for x in rules) or "none"
    atlas_txt = " ".join(f'<span class="chip b" title="{html.escape(ATLAS_APPROX[x])}">{x}</span>' for x in atlas) or "none"
    tri = "".join(
        f'<label><input type="checkbox"{" checked" if k == bucket else ""}> <span class="{"sug" if k == bucket else ""}">{html.escape(name)}</span>'
        f' <span class="note">- {html.escape(why)}{" (suggested)" if k == bucket else ""}</span></label>' for k, name, why in TRIAGE)
    doc = (
        f'<section class="s" data-bucket="{bucket}" data-jump="{1 if has_jump else 0}" id="s{n}">'
        f'<h2>Session {e.t(s.session_id, 40)}</h2>'
        f'<dl class="sum"><dt>actor_type</dt><dd>{e.t(res.actor_type or res.label, 40)} (label {e.t(res.label, 20)}, severity {e.t(res.severity, 10)})</dd>'
        f'<dt>harness_archetype</dt><dd><b>{e.t(arche, 40)}</b> ({e.t(conf, 10) or "n/a"} confidence: how much of the signature was seen, not a probability)'
        f'<ul>{reasons}</ul></dd>'
        f'<dt>scores</dt><dd>agent {int(res.agent_score)} / automation {int(res.automation_score)} (0-100, heuristic)</dd>'
        f'<dt>rules R8-R11</dt><dd>{rule_txt}</dd>'
        f'<dt>ATLAS (approximate)</dt><dd>{atlas_txt} <span class="note">approximate mapping from signals; not a finding</span></dd>'
        f'<dt>client</dt><dd>{e.t(s.ip, 64)} - {len(s.requests)} request(s)</dd></dl>'
        f'<div class="untrusted"><span class="badge">UNTRUSTED AGENT INPUT - SCRUBBED</span><pre>user-agent: {e.t(ua, 300)}</pre></div>'
        f'<details open><summary>Causal step timeline</summary><table class="t"><tr><th>#</th><th>time (UTC)</th><th>+delta</th><th>method</th>'
        f'<th>path</th><th>status</th><th>offered? / rules / traps</th></tr>{"".join(rows)}</table></details>'
        f'<div class="triage"><b>Reviewer triage</b> <span class="note">(a human-review lead, NOT an automatic block; ticks are local to this page and are not saved)</span>{tri}</div>'
        f'</section>')
    return doc, bucket, has_jump


def build_replay_html(results: Sequence[SessionResult], cfg: dict[str, Any], *, scrubber: Optional[Scrubber] = None,
                      title: str = "agent-watch session replay", max_sessions: int = MAX_SESSIONS, min_severity: str = "low",
                      include_humans: bool = False) -> str:
    e = _Esc(scrubber or get_default_scrubber())
    floor = SEVERITIES.index(min_severity)
    chosen = [r for r in results if (include_humans or r.label != "human" or r.findings)
              and SEVERITIES.index(r.severity) >= floor]
    chosen.sort(key=lambda r: (-r.agent_score, -r.automation_score, r.session.session_id))
    shown = chosen[:max_sessions]
    parts: list[str] = []
    counts = {k: 0 for k, _, _ in TRIAGE}
    for n, res in enumerate(shown, 1):
        doc, bucket, _ = _session_html(e, res, n, cfg)
        counts[bucket] += 1
        parts.append(doc)
    body = "\n".join(parts) or '<p class="note">No sessions matched.</p>'
    btns = "".join(f'<button data-k="{k}">{html.escape(name)} ({counts[k]})</button>' for k, name, _ in TRIAGE)
    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        '<meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>'
        f'<header class="top"><h1>{html.escape(title)}</h1>'
        '<p>Leads for HUMAN REVIEW. Nothing on this page blocks, bans or accuses anyone: honeypot contact is not intent. '
        'All text from the wire is scrubbed of secrets, escaped, and shown as data. Scores and archetypes come from fixed rules checked only on '
        'same-author synthetic traffic; ATLAS ids are an approximate mapping. This file makes no network requests.</p></header>'
        f'<main><div class="bar" id="flt"><button data-k="all" class="on">All ({len(shown)})</button>{btns}'
        '<button data-k="amber">Has unlinked jump</button><button id="xall" type="button">Expand all</button></div>'
        f'{body}</main><script>{_JS}</script></body></html>\n')


def write_replay(leads: str, access: Optional[str], out: str, config: Optional[str] = None, *, max_sessions: int = MAX_SESSIONS,
                 min_severity: str = "low", include_humans: bool = False) -> int:
    cfg = load_config(config)
    paths = [leads] + ([access] if access else [])
    results, _ = run_pipeline(paths, cfg)
    doc = build_replay_html(results, cfg, max_sessions=max_sessions, min_severity=min_severity, include_humans=include_humans)
    Path(out).write_text(doc, encoding="utf-8")
    return doc.count('<section class="s"')
