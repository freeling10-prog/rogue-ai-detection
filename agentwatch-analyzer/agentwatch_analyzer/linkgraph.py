"""Referer link-graph helpers for offline R9.

With a sitemap (or links[] in JSON access streams), parent→child edges are known.
With plain nginx, we only know Referer path → current path (weaker; documented).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .parse import Event

LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.I)


def load_sitemap_paths(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    paths: set[str] = set()
    # Prefer stdlib XML; fall back to regex for broken sitemaps
    try:
        root = ET.fromstring(text)
        for el in root.iter():
            if el.tag.endswith("loc") and el.text:
                p = urlsplit(el.text.strip()).path or "/"
                paths.add(p)
    except ET.ParseError:
        for m in LOC_RE.finditer(text):
            p = urlsplit(m.group(1).strip()).path or "/"
            paths.add(p)
    return paths


def build_offered_graph(events: list[Event], sitemap_paths: set[str] | None = None) -> dict[str, set[str]]:
    """Map page path -> set of paths it offered (from JSON links[] and/or sitemap as universal offer)."""
    graph: dict[str, set[str]] = {}
    for e in events:
        if e.links:
            graph.setdefault(e.path, set()).update(
                (urlsplit(x).path or x.split("?")[0] or "/") for x in e.links
            )
    if sitemap_paths:
        # Without per-response links, treat sitemap URLs as mutually reachable from site root
        graph.setdefault("/", set()).update(sitemap_paths)
        for p in sitemap_paths:
            graph.setdefault(p, set())
    return graph


def classify_transition(
    ev: Event,
    prev: Event | None,
    graph: dict[str, set[str]],
    entry_paths: set[str] | None = None,
) -> str:
    """Return entry|linked|never_offered|offered_earlier."""
    entry_paths = entry_paths or {"/", "/index.html", "/index.htm"}
    if ev.path in entry_paths and (not prev):
        return "entry"
    ref = ev.referer_path()
    if ref and ref in graph and ev.path in graph[ref]:
        return "linked"
    if any(ev.path in offered for offered in graph.values()):
        return "offered_earlier"
    if ref and prev and ref == prev.path and ev.path in graph.get(ref, set()):
        return "linked"
    # nginx-only: same-site Referer that is a path-prefix parent counts as weak-linked
    if ref and (ev.path.startswith(ref.rstrip("/") + "/") or ref == "/"):
        if graph:
            return "never_offered" if ev.path not in graph.get(ref, set()) and ev.path not in entry_paths else "linked"
        return "linked_by_referer_parent"  # weak signal without sitemap
    if not ref or ref == "":
        return "entry" if ev.path in entry_paths else "never_offered"
    return "never_offered"
