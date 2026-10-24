"""Commodity-scanner pre-filter (offline).

Tags obvious scanners / bots before rule scoring so SOC noise stays out of leads.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from .parse import Event

SCANNER_UA = re.compile(
    r"(?i)\b(masscan|zgrab|zmap|nuclei|nikto|sqlmap|dirbuster|gobuster|wfuzz|"
    r"nmap\s|nessus|openvas|burpcollaborator|httpx|katana|ffuf|"
    r"python-requests/|go-http-client|curl/\d|wget/\d|scrapy|"
    r"petalbot|bytespider|gptbot|claudebot|ccbot|amazonbot|semrush|ahrefs|"
    r"bingbot|googlebot|yandexbot|baiduspider|duckduckbot)\b"
)

SENSITIVE_HINT = re.compile(
    r"(?i)(/admin|/wp-login|\.env|/credentials|/api/v\d+/internal|/graphql|"
    r"/mcp|/openapi|/llms\.txt|/server-status)"
)


def is_commodity_scanner(events: list[Event]) -> tuple[bool, str]:
    if len(events) < 3:
        return False, ""
    uas = {e.ua for e in events}
    ua = next(iter(uas)) if len(uas) == 1 else ""
    if ua and SCANNER_UA.search(ua):
        # Known commodity scanner UAs are always prefiltered (including .env probes).
        return True, "scanner_ua"
    # high fan-out, all 404, no referers → commodity probe
    n404 = sum(1 for e in events if e.status == 404)
    noref = sum(1 for e in events if not e.referer or e.referer == "-")
    if len(events) >= 20 and n404 / len(events) >= 0.85 and noref / len(events) >= 0.9:
        return True, "fanout_404"
    return False, ""


def partition(events: Iterable[Event]) -> tuple[dict[str, list[Event]], dict[str, str]]:
    """Group by ip|ua; return (kept_by_key, prefiltered_reason_by_key)."""
    by: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by[f"{e.ip}|{e.ua[:80]}"].append(e)
    kept: dict[str, list[Event]] = {}
    filtered: dict[str, str] = {}
    for k, evs in by.items():
        yes, reason = is_commodity_scanner(evs)
        if yes:
            filtered[k] = reason
        else:
            kept[k] = evs
    return kept, filtered
