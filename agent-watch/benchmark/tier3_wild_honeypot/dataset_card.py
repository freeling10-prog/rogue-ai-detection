"""Tier-3 statistics and DATASET_CARD.md.

Everything is computed from the log files themselves (no dependency on detector internals, which may be changing):
cohort counts, commodity-scanner filter stats (a local MIRROR of rogue_pipeline/prefilter.py's rule, which may drift), rule firing
distributions (from lead records, plus detector findings in any bundled agentwatch.report/1 file), and harness-archetype
breakdowns (read from a ``harness_archetype`` key on log records or report sessions; absent -> 'unlabelled').
Client identifiers (IPs) are used only as in-memory grouping keys and are never written to the card.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional

from ..common import BAD_LINE, iter_jsonl
from .validator import Tier3Input, parse_ts, pick

SCANNER_UA = re.compile(r"zgrab|masscan|censys|shodan|nmap|nikto|sqlmap|nuclei|expanse|internet-?measurement|netcraft|leakix|l9explore", re.I)
SCANNER_PATH = [re.compile(p, re.I) for p in (r"\.php\d?(\?|$|/)", r"/wp-(admin|login|content|includes|json)", r"/xmlrpc", r"/\.env\b",
                                               r"/\.git\b", r"/phpmyadmin|/pma\b", r"/cgi-bin/", r"/actuator\b", r"/vendor/phpunit")]
SCANNER_PATH_MIN_SHARE = 0.8
UNLABELLED = "unlabelled"
COHORTS = ("commodity_scanner_filtered", "scanner_like_kept_goal_evidence", "decoy_touching", "passive_visitor")


def _archetype(rec: dict[str, Any]) -> Optional[str]:
    v = rec.get("harness_archetype")
    if v is None and isinstance(rec.get("detail"), dict):
        v = rec["detail"].get("harness_archetype")
    return str(v)[:64] if isinstance(v, str) and v.strip() else None


def _goal_evidence(rec: dict[str, Any]) -> bool:
    m = rec.get("matches") if isinstance(rec.get("matches"), dict) else {}
    d = rec.get("detail") if isinstance(rec.get("detail"), dict) else {}
    return bool(m.get("credential_token_ids") or m.get("canary_ids") or d.get("tool") or d.get("mcp") or rec.get("event_type") in ("mcp_tools_call",))


def collect_stats(inp: Tier3Input) -> dict[str, Any]:
    clients: dict[str, dict[str, Any]] = defaultdict(lambda: {"reqs": 0, "scan_paths": 0, "scanner_ua": False, "leads": 0, "hits": 0, "goal": False, "arch": Counter()})
    ts: list[Any] = []
    n_access = n_leads = 0
    rule_events: Counter = Counter()
    rule_decoys: Counter = Counter()
    rule_tags: Counter = Counter()
    rule_clients: dict[str, set] = defaultdict(set)
    for f in inp.access_files:
        for _, rec in iter_jsonl(f):
            if rec is BAD_LINE or not isinstance(rec, dict):
                continue
            n_access += 1
            c = clients[str(pick(rec, "ip"))]
            c["reqs"] += 1
            path = str(pick(rec, "path") or "")
            c["scan_paths"] += any(rx.search(path) for rx in SCANNER_PATH)
            c["scanner_ua"] |= bool(SCANNER_UA.search(str(rec.get("user_agent") or rec.get("http_user_agent") or "")))
            a = _archetype(rec)
            if a:
                c["arch"][a] += 1
            t = parse_ts(pick(rec, "ts"))
            if t:
                ts.append(t)
    for f in inp.lead_files:
        for _, rec in iter_jsonl(f):
            if rec is BAD_LINE or not isinstance(rec, dict):
                continue
            n_leads += 1
            ip = str(pick(rec, "ip"))
            c = clients[ip]
            c["leads"] += 1
            c["scanner_ua"] |= bool(SCANNER_UA.search(str(rec.get("user_agent") or "")))
            if rec.get("event_type") == "honeytoken_hit":
                c["hits"] += 1
            c["goal"] |= _goal_evidence(rec)
            a = _archetype(rec)
            if a:
                c["arch"][a] += 1
            ev = str(rec.get("event_type"))[:48]
            dk = str(rec.get("decoy_kind") or (rec.get("decoy") or {}).get("kind") or "none")[:48] if isinstance(rec.get("decoy", {}), dict) else "none"
            rule_events[ev] += 1
            rule_decoys[dk] += 1
            rule_clients[f"decoy_kind:{dk}"].add(ip)
            for tag in (rec.get("tags") or []) if isinstance(rec.get("tags"), list) else []:
                rule_tags[str(tag)[:48]] += 1
                rule_clients[f"tag:{str(tag)[:48]}"].add(ip)
            t = parse_ts(pick(rec, "ts"))
            if t:
                ts.append(t)
    # bundled detector reports: detector/kind firing + session archetypes (joined by IP, in memory only)
    det: Counter = Counter()
    report_arch: dict[str, str] = {}
    sessions_in_reports = 0
    for f in inp.report_files:
        try:
            rep = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for s in rep.get("sessions", []):
            sessions_in_reports += 1
            for fd in s.get("findings", []):
                det[f"{fd.get('detector')}:{fd.get('kind')}"] += 1
            a = s.get("harness_archetype")
            if isinstance(a, str) and a and s.get("ip"):
                report_arch[str(s["ip"])] = a[:64]
    cohort_n: Counter = Counter()
    filt_reason: Counter = Counter()
    removed_reqs = 0
    cross: dict[str, Counter] = {k: Counter() for k in COHORTS}
    arch_field_seen = bool(report_arch) or any(c["arch"] for c in clients.values())
    for ip, c in clients.items():
        total = c["reqs"]
        path_scanner = bool(total) and c["scan_paths"] >= SCANNER_PATH_MIN_SHARE * total
        looks_scanner = c["scanner_ua"] or path_scanner
        if looks_scanner and not c["goal"]:
            coh = "commodity_scanner_filtered"
            filt_reason["scanner_ua" if c["scanner_ua"] else "scanner_path"] += 1
            removed_reqs += total
        elif looks_scanner:
            coh = "scanner_like_kept_goal_evidence"
        elif c["hits"]:
            coh = "decoy_touching"
        else:
            coh = "passive_visitor"
        cohort_n[coh] += 1
        arch = c["arch"].most_common(1)[0][0] if c["arch"] else report_arch.get(ip, UNLABELLED)
        cross[coh][arch] += 1
    arch_total: Counter = Counter()
    for k in COHORTS:
        arch_total.update(cross[k])
    return {
        "records": {"access": n_access, "leads": n_leads, "report_sessions": sessions_in_reports},
        "window": {"first_record_utc": min(ts).isoformat() + "Z" if ts else None, "last_record_utc": max(ts).isoformat() + "Z" if ts else None},
        "clients": len(clients),
        "cohorts": {k: cohort_n.get(k, 0) for k in COHORTS},
        "scanner_filter": {"clients_filtered": cohort_n.get("commodity_scanner_filtered", 0), "by_reason": dict(sorted(filt_reason.items())),
                           "access_requests_removed": removed_reqs,
                           "kept_scanner_like_with_goal_evidence": cohort_n.get("scanner_like_kept_goal_evidence", 0)},
        "rule_firing": {"lead_event_types": dict(rule_events.most_common()), "decoy_kinds": dict(rule_decoys.most_common()),
                        "lead_tags": dict(rule_tags.most_common(30)),
                        "clients_per_rule": {k: len(v) for k, v in sorted(rule_clients.items())},
                        "detector_findings_from_reports": dict(det.most_common()) if inp.report_files else None},
        "harness_archetypes": {"field_present": arch_field_seen, "clients_by_archetype": dict(arch_total.most_common()),
                               "cohort_x_archetype": {k: dict(v.most_common()) for k, v in cross.items() if v}},
    }


def _table(d: dict[str, Any], head: tuple[str, str]) -> list[str]:
    if not d:
        return ["_none_", ""]
    return [f"| {head[0]} | {head[1]} |", "|---|---|"] + [f"| {k} | {v} |" for k, v in d.items()] + [""]


def build_card(inp: Tier3Input, stats: Optional[dict[str, Any]], bundle_info: Optional[dict[str, Any]] = None) -> str:
    """Markdown dataset card.  ``stats=None`` (or an empty slot) gives the honest 'no wild data yet' card."""
    L = ["# Dataset card - tier 3: wild honeypot traffic", ""]
    if stats is None or inp.empty:
        L += ["**STATUS: NO WILD DATA YET.** This slot is empty. No live traffic has been collected, packaged, or analysed, so there are",
              "**no cohort counts, no filter statistics, no rule-firing distributions and no archetype breakdowns** - and none are implied.",
              "",
              "Nothing in tier 1 (same-author synthetic regression) or tier 2 (local real-LLM traces) may be quoted as a tier-3 result.",
              "",
              "To fill this slot see docs/benchmark-protocol.md, section 'Tier 3': pull `*.access.jsonl` / `*.leads.jsonl` from an isolated",
              "edge host into `benchmark/tier3_wild_honeypot/slot/` with a `provenance.json`; the packer refuses anything containing raw secrets.",
              ""]
        return "\n".join(L)
    p = inp.provenance
    L += ["**STATUS: wild data present.** Real internet traffic hit an isolated honeypot. Descriptive statistics only: there is **no ground truth** "
          "for who is an AI agent, so no precision/recall/accuracy is reported or possible from this tier.", "",
          "## Provenance (operator assertions, not verified by the toolkit)", "",
          f"- host label: {p.get('host_label')}; isolated edge host: {p.get('isolated_edge_host')}; servers: {', '.join(p.get('servers', []))}",
          f"- pulled at: {p.get('pulled_at')}; window: {p.get('window_start')} -> {p.get('window_end')}",
          f"- archetype labels written by: {p.get('archetype_labels', 'not stated')}",
          f"- first/last record seen: {stats['window']['first_record_utc']} / {stats['window']['last_record_utc']}", ""]
    if bundle_info:
        L += [f"- secret gate: {bundle_info.get('secret_gate')}", ""]
    L += ["## Counts", "", *_table({"access records": stats["records"]["access"], "lead records": stats["records"]["leads"],
                                     "detector report sessions bundled": stats["records"]["report_sessions"], "distinct clients": stats["clients"]}, ("what", "n"))]
    L += ["## Cohorts (clients; mutually exclusive)", "",
          "Definitions: `commodity_scanner_filtered` = scanner User-Agent, or >=80% scanner-path requests, and NO goal-directed evidence "
          "(credential/canary match or tool use on a lead); `scanner_like_kept_goal_evidence` = scanner-looking but kept because of that evidence; "
          "`decoy_touching` = non-scanner with >=1 honeytoken hit; `passive_visitor` = everything else.", "",
          *_table(stats["cohorts"], ("cohort", "clients"))]
    sf = stats["scanner_filter"]
    L += ["## Commodity-scanner filter", "",
          f"- clients filtered: {sf['clients_filtered']} (by reason: {sf['by_reason'] or 'none'})",
          f"- access requests removed with them: {sf['access_requests_removed']}",
          f"- scanner-looking clients kept for goal-directed evidence: {sf['kept_scanner_like_with_goal_evidence']}",
          "- this is a local mirror of `rogue_pipeline/prefilter.py`; the two may drift and are not guaranteed identical.", ""]
    rf = stats["rule_firing"]
    L += ["## Rule firing distributions", "", "### Lead event types (records)", "", *_table(rf["lead_event_types"], ("event_type", "records")),
          "### Decoy kinds hit (records)", "", *_table(rf["decoy_kinds"], ("decoy_kind", "records")),
          "### Lead tags (records, top 30)", "", *_table(rf["lead_tags"], ("tag", "records"))]
    if rf["detector_findings_from_reports"] is not None:
        L += ["### Detector findings in bundled reports (findings)", "", *_table(rf["detector_findings_from_reports"], ("detector:kind", "findings"))]
    else:
        L += ["_No agentwatch.report/1 file bundled, so detector-rule firing is not reported (only lead-level firing above)._", ""]
    ha = stats["harness_archetypes"]
    L += ["## Harness archetypes (clients)", ""]
    if not ha["field_present"]:
        L += ["No record or report carries a `harness_archetype`; all clients are reported as **unlabelled**.", ""]
    L += [*_table(ha["clients_by_archetype"], ("archetype", "clients"))]
    L += ["Archetypes are descriptive signatures, not verdicts and not ground truth; their source is stated in the provenance above.", "",
          "## What this tier can and cannot claim", "",
          "- CAN: describe what hits a public honeypot, how much is commodity-scanner noise, which decoys/rules fire.",
          "- CANNOT: give detector accuracy (no labels); say any client is an AI agent; compare against tier 1 or tier 2 numbers.",
          "- Client identifiers are not published in this card; raw logs in the bundle may still contain IP addresses (not treated as secrets) - "
          "review before sharing outside your team.", ""]
    return "\n".join(L)
