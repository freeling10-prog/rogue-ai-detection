"""Cohort -> archetype confusion table for the harness fingerprint (v5).  SAME-AUTHOR SYNTHETIC: the rules and the simulated harnesses were
written by one person, so this table checks the code does what its author intended; it is NOT a benchmark of real agent frameworks.

``EXPECTED`` lists, for every simulated cohort, the archetype a correct fingerprint SHOULD give.  Cohorts the fingerprint is known to get
wrong (a stealth browser agent, a header forger, a person whose browser blocks the beacon) keep their TRUE expectation so the table shows
the miss instead of hiding it.
"""
from __future__ import annotations

import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .config import load_config
from .parser import merge_results, parse_file
from .pipeline import merge_mirror
from .scoring import analyze_sessions
from .sessions import build_sessions
from .synthetic import generate_demo

# (cohort, regex on the truth name, expected archetype, note)
EXPECTED: list[tuple[str, str, str, str]] = [
    ("human", r"^(human \d|busy human|reading human|web:human #)", "unclassified", ""),
    ("human_no_assets/images_blocked/js_off", r"^web:human_(no_assets|images_blocked|js_off)", "unclassified", ""),
    ("human_beacon_blocked", r"^web:human_beacon_blocked", "unclassified", "KNOWN false positive: ad-blocked beacon looks like a missing beacon"),
    ("static scanners / crawlers", r"^(fixed-interval|search-engine|cron poller|monitoring)", "commodity_or_static_scanner", ""),
    ("naive_scraper", r"^(naive scraper|web:scraper_naive|web:crawler_declared)", "commodity_or_static_scanner", ""),
    ("classic agents C/F/L/H (canary, creds)", r"^(gullible RAG|fast scripted|LLM-like|human-like agent)", "prompt_injected_crawler", ""),
    ("classic adaptive A/B (chains, enumeration)", r"^adaptive agent", "unclassified", "no distinctive harness signature exists for these"),
    ("coordination", r"^(coordination-bus|relay agent)", "stateful_coordinator", ""),
    ("mcp tool runner", r"^mcp:tool_runner", "mcp_tool_runner", ""),
    ("mimic_basic", r"^web:mimic_basic", "headless_or_http_mimic", ""),
    ("mimic_linked", r"^web:mimic_linked", "headless_or_http_mimic", ""),
    ("mimic_assets", r"^web:mimic_assets", "headless_or_http_mimic", ""),
    ("mimic_schema", r"^web:mimic_schema", "schema_driven_api_agent", ""),
    ("mimic_aria / webdriver", r"^web:mimic_(aria|browser_webdriver)", "headless_or_http_mimic", ""),
    ("mimic_browser_stealth", r"^web:mimic_browser_stealth", "headless_or_http_mimic", "KNOWN miss: nothing observable distinguishes it"),
    ("mimic_header_forger", r"^web:mimic_header_forger", "headless_or_http_mimic", "KNOWN miss: forged coherent Sec-Fetch is trusted"),
]


def cohort_of(name: str) -> tuple[str, str] | None:
    for cohort, rx, expected, _ in EXPECTED:
        if re.search(rx, name):
            return cohort, expected
    return None


def collect(seeds: Iterable[int]) -> list[tuple[int, str, str, str, str]]:
    """Run the extended demo per seed -> rows (seed, cohort, expected, got, confidence)."""
    rows: list[tuple[int, str, str, str, str]] = []
    cfg = load_config()
    for seed in seeds:
        with tempfile.TemporaryDirectory() as d:
            art = generate_demo(d, seed=seed, extended=True)
            parsed = merge_results([parse_file(p) for p in (art["access_log"], art["gateway_log"], art["leads"], art["access_mirror"])])
            reqs, _ = merge_mirror(parsed.requests)
            res = analyze_sessions(build_sessions(reqs, cfg), cfg)
        by_ip: dict[str, Any] = {}
        for r in res:
            cur = by_ip.get(r.session.ip)
            if cur is None or len(r.session.requests) > len(cur.session.requests):
                by_ip[r.session.ip] = r
        for t in art["truth"]:
            hit = cohort_of(t.name)
            r = by_ip.get(t.ip)
            if hit is None or r is None or r.fingerprint is None:
                continue
            rows.append((seed, hit[0], hit[1], r.fingerprint.archetype, r.fingerprint.confidence))
    return rows


def confusion_markdown(rows: list[tuple[int, str, str, str, str]]) -> str:
    cohorts = [c for c, _, _, _ in EXPECTED]
    notes = {c: n for c, _, _, n in EXPECTED}
    expected = {c: e for c, _, e, _ in EXPECTED}
    got: dict[str, Counter[str]] = defaultdict(Counter)
    for _, c, _, g, _ in rows:
        got[c][g] += 1
    labels = sorted({g for c in got.values() for g in c} | {"unclassified"})
    out = ["| cohort | expected | n | " + " | ".join(labels) + " | correct | note |", "|---|---|---|" + "---|" * len(labels) + "---|---|"]
    tot = ok = 0
    for c in cohorts:
        n = sum(got[c].values())
        if not n:
            continue
        right = got[c][expected[c]]
        tot += n
        ok += right
        out.append(f"| {c} | {expected[c]} | {n} | " + " | ".join(str(got[c][g]) if got[c][g] else "." for g in labels)
                   + f" | {right}/{n} | {notes[c]} |")
    out.append(f"\nOverall {ok}/{tot} sessions got their intended archetype.  Same-author synthetic cohorts; not a benchmark.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="harness fingerprint confusion table (same-author synthetic)")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    rows = collect(range(a.seeds))
    text = ("# Harness fingerprint: cohort x archetype confusion table\n\n"
            f"Seeds 0..{a.seeds - 1}, `demo --extended` cohorts, counts pooled over seeds.  SAME-AUTHOR SYNTHETIC: rules and simulated harnesses "
            "share an author; this is a regression check, not a benchmark of real frameworks.  Labels describe a harness, not intent.\n\n"
            + confusion_markdown(rows) + "\n")
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0
