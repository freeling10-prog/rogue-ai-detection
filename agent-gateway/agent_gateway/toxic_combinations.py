"""Static toxic-flow and reachability graph over a tool inventory.

Input is a tool list (MCP ``tools/list`` shape: ``name``, ``description``,
``inputSchema``) where each tool may carry a class label: ``external_read``,
``internal_read``, ``sensitive_read``, ``write``, ``send``, or
``credential_use``. Unlabelled tools are classified from the gateway egress
table, then from the tool name; anything unrecognized is treated as
``write`` (fail closed, same as the PEP).

Graph: in an agent loop any tool output can steer any later call, so an
edge ``A -> B`` exists when B can carry data. Into a read the edge always
exists (the injected text chooses what to read). Into a sink it exists only
when the sink has a free-text channel: a string argument with no ``enum``,
``const``, ``pattern``, or short ``maxLength``, a string array or open
object, or no schema at all. Sinks are ``write``, ``send``,
``credential_use``, and ``external_read`` tools whose arguments can carry
data out (query / URL parameters).

Toxic combinations (approximate AML.T0086):

- 2-hop: ``external_read -> sensitive_read | internal_read -> sink``
- 3-hop: ``external_read -> read -> read -> sink`` (two different reads)

A path is protected when its sink sits behind a hard ``agw1.`` capability
boundary (the tool, or the whole inventory, sets ``agw1_boundary: true``),
because the PEP appends ``allow_egress=false`` on untrusted ingest and holds
the sink for a bound one-time OOB approval. Every other path is toxic.

This is static analysis of declared capabilities. It does not call the tools
and is not a penetration test.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from itertools import permutations
from pathlib import Path
from typing import Any, Iterable

from .taint import (
    EGRESS_BUS,
    EGRESS_CREDS,
    EGRESS_EXTERNAL_READ,
    EGRESS_INTERNAL_READ,
    EGRESS_SEND,
    EGRESS_SPAWN,
    EGRESS_WRITE,
    SENSITIVE_READ_TOOLS,
    TOOL_EGRESS,
)

SCHEMA = "agent-gateway.toxic-combinations/1"
ATLAS_EXFIL = "AML.T0086"
CLASSES = ("external_read", "internal_read", "sensitive_read", "write", "send", "credential_use")
READ_CLASSES = frozenset({"internal_read", "sensitive_read"})
SINK_CLASSES = frozenset({"write", "send", "credential_use"})
MAX_LISTED_PATHS = 500
MAX_TOOLS = 400
SHORT_MAX_LENGTH = 16

_ALIASES = {
    "creds": "credential_use", "credential": "credential_use", "credentials": "credential_use",
    "credential_use": "credential_use", "secret_read": "sensitive_read", "sensitive": "sensitive_read",
    "external": "external_read", "untrusted_read": "external_read", "read": "internal_read",
    "internal": "internal_read", "egress": "send", "bus": "send", "spawn": "write",
}
_EGRESS_TO_CLASS = {
    EGRESS_EXTERNAL_READ: "external_read",
    EGRESS_INTERNAL_READ: "internal_read",
    EGRESS_WRITE: "write",
    EGRESS_SEND: "send",
    EGRESS_CREDS: "credential_use",
    EGRESS_BUS: "send",
    EGRESS_SPAWN: "write",
}
_SENSITIVE_WORDS = ("secret", "vault", "credential", "password", "passwd", "api_key", "apikey", "token",
                    "private_key", "ssn", "payroll")
_NAME_RULES = (
    ("send", ("send", "email", "mail", "webhook", "notify", "post_message", "slack", "sms", "upload", "publish", "tweet")),
    ("external_read", ("fetch", "http", "browse", "browser", "web", "url", "crawl", "scrape", "search", "download", "rss")),
    ("write", ("write", "update", "create", "delete", "put", "save", "insert", "commit", "push", "exec", "run", "shell", "set_")),
    ("internal_read", ("read", "get", "list", "lookup", "query", "find", "describe", "show", "cat", "grep")),
)
_PARAM_KEYS = frozenset({"query", "q", "search", "url", "uri", "href", "endpoint", "params", "path", "body", "data"})


def _label(tool: dict) -> str:
    for key in ("class", "tool_class", "egress_class", "category", "kind"):
        raw = tool.get(key)
        if isinstance(raw, str) and raw.strip():
            v = raw.strip().lower().replace("-", "_").replace(" ", "_")
            v = _ALIASES.get(v, v)
            if v in CLASSES:
                return v
    return ""


def tool_class(tool: dict) -> str:
    """Declared class, else the gateway egress table, else the name, else ``write``."""
    label = _label(tool)
    if label:
        return label
    name = str(tool.get("name") or "")
    if name in SENSITIVE_READ_TOOLS:
        return "sensitive_read"
    if name in TOOL_EGRESS:
        return _EGRESS_TO_CLASS.get(TOOL_EGRESS[name], "write")
    # Match words at token starts so "frobnicate" is not "cat".
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    norm = "_" + "_".join(t for t in re.split(r"[^a-z0-9]+", spaced) if t) + "_"

    def has(word: str) -> bool:
        return "_" + word.rstrip("_") in norm

    sensitive = any(has(w) for w in _SENSITIVE_WORDS)
    for cls, words in _NAME_RULES:
        if any(has(w) for w in words):
            if sensitive and cls in ("internal_read", "external_read"):
                return "sensitive_read"
            if sensitive and cls == "write":
                return "credential_use"
            return cls
    return "credential_use" if sensitive else "write"


def _free_text_props(schema: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Argument paths that can carry arbitrary text."""
    if depth > 6:
        return [prefix or "*"]
    if not isinstance(schema, dict) or not schema:
        return [prefix or "*"]
    if "enum" in schema or "const" in schema:
        return []
    types = schema.get("type")
    types = [types] if isinstance(types, str) else (types or [])
    for key in ("anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            out: list[str] = []
            for sub in schema[key]:
                out.extend(_free_text_props(sub, prefix, depth + 1))
            return sorted(set(out))
    if "string" in types or (not types and "properties" not in schema and "items" not in schema):
        if schema.get("pattern") or schema.get("format") in ("date", "date-time", "uuid", "email", "ipv4", "ipv6", "time"):
            return []
        max_len = schema.get("maxLength")
        if isinstance(max_len, int) and max_len <= SHORT_MAX_LENGTH:
            return []
        if "string" in types or not types:
            return [prefix or "*"]
    out = []
    if "array" in types or "items" in schema:
        out.extend(_free_text_props(schema.get("items"), f"{prefix}[]", depth + 1))
    if "object" in types or "properties" in schema:
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for name, sub in props.items():
            out.extend(_free_text_props(sub, f"{prefix}.{name}" if prefix else str(name), depth + 1))
        if schema.get("additionalProperties", True) is not False and not props:
            out.append(f"{prefix}.*" if prefix else "*")
        elif isinstance(schema.get("additionalProperties"), dict):
            out.extend(_free_text_props(schema["additionalProperties"], f"{prefix}.*" if prefix else "*", depth + 1))
    return sorted(set(out))


@dataclass
class ToolNode:
    name: str
    cls: str
    channels: list[str]
    boundary: bool

    @property
    def is_read(self) -> bool:
        return self.cls in READ_CLASSES

    @property
    def is_source(self) -> bool:
        return self.cls == "external_read"

    @property
    def is_sink(self) -> bool:
        if not self.channels:
            return False
        if self.cls in SINK_CLASSES:
            return True
        # external_read that can carry parameters out (query / URL)
        return self.cls == "external_read"

    @property
    def sink_kind(self) -> str:
        return "param_egress" if self.cls == "external_read" else self.cls


@dataclass
class ToxicReport:
    nodes: list[ToolNode]
    paths: list[dict] = field(default_factory=list)
    totals: dict = field(default_factory=dict)
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "atlas": ATLAS_EXFIL,
            "atlas_approximate": True,
            "tools": len(self.nodes),
            "classes": {n.name: n.cls for n in self.nodes},
            "sinks": [{"tool": n.name, "kind": n.sink_kind, "channels": n.channels[:8], "agw1_boundary": n.boundary}
                      for n in self.nodes if n.is_sink],
            "constrained_sinks": [n.name for n in self.nodes if n.cls in SINK_CLASSES and not n.channels],
            "totals": self.totals,
            "paths": self.paths,
            "truncated": self.truncated,
            "note": ("Static reachability over declared tool capabilities. Every listed toxic path "
                     "lacks a hard agw1. capability boundary at its sink. Not a penetration test."),
        }


def load_inventory(doc: Any) -> tuple[list[dict], bool]:
    """(tools, inventory-wide agw1 boundary). Accepts a list, {"tools": [...]}, or a tools/list result."""
    default_boundary = False
    tools: Any = doc
    if isinstance(doc, dict):
        default_boundary = bool(doc.get("agw1_boundary"))
        tools = doc.get("tools")
        if tools is None and isinstance(doc.get("result"), dict):
            tools = doc["result"].get("tools")
    if not isinstance(tools, list):
        raise ValueError("tool inventory must be a list of tools or an object with a tools list")
    return [t for t in tools if isinstance(t, dict) and t.get("name")][:MAX_TOOLS], default_boundary


def build_nodes(tools: Iterable[dict], default_boundary: bool = False) -> list[ToolNode]:
    nodes = []
    seen = set()
    for tool in tools:
        name = str(tool.get("name"))[:120]
        if name in seen:
            continue
        seen.add(name)
        cls = tool_class(tool)
        schema = tool.get("inputSchema", tool.get("input_schema", tool.get("parameters")))
        channels = _free_text_props(schema) if cls in SINK_CLASSES or cls == "external_read" else []
        if cls == "external_read" and channels and isinstance(schema, dict):
            # An external read is a sink only through parameters that leave with the request.
            channels = [c for c in channels if c.split(".")[0].split("[")[0].lower() in _PARAM_KEYS or c == "*"]
        boundary = bool(tool.get("agw1_boundary", default_boundary))
        nodes.append(ToolNode(name=name, cls=cls, channels=channels, boundary=boundary))
    return nodes


def _severity(classes: list[str]) -> str:
    if "sensitive_read" in classes or classes[-1] == "credential_use":
        return "critical"
    return "high"


def analyze(inventory: Any) -> ToxicReport:
    """Enumerate 2-hop and 3-hop toxic combinations."""
    tools, default_boundary = load_inventory(inventory)
    nodes = build_nodes(tools, default_boundary)
    sources = [n for n in nodes if n.is_source]
    reads = [n for n in nodes if n.is_read]
    sinks = [n for n in nodes if n.is_sink]
    rep = ToxicReport(nodes=nodes)
    counts = {"toxic_2hop": 0, "toxic_3hop": 0, "protected_2hop": 0, "protected_3hop": 0}

    def emit(chain: list[ToolNode]) -> None:
        hops = len(chain) - 1
        protected = chain[-1].boundary
        key = f"{'protected' if protected else 'toxic'}_{hops}hop"
        counts[key] += 1
        if len(rep.paths) >= MAX_LISTED_PATHS:
            rep.truncated = True
            return
        classes = [n.cls for n in chain[:-1]] + [chain[-1].sink_kind]
        rep.paths.append({
            "hops": hops,
            "path": [n.name for n in chain],
            "classes": classes,
            "channel": chain[-1].channels[:4],
            "severity": _severity(classes),
            "protected_by_agw1": protected,
            "toxic": not protected,
        })

    for src in sources:
        for r in reads:
            for sink in sinks:
                if sink.name != r.name:
                    emit([src, r, sink])
    for src in sources:
        for r1, r2 in permutations(reads, 2):
            for sink in sinks:
                if sink.name not in (r1.name, r2.name):
                    emit([src, r1, r2, sink])
    rep.paths.sort(key=lambda p: (p["protected_by_agw1"], p["severity"] != "critical", p["hops"], p["path"]))
    rep.totals = {**counts, "toxic": counts["toxic_2hop"] + counts["toxic_3hop"],
                  "protected": counts["protected_2hop"] + counts["protected_3hop"],
                  "sources": len(sources), "reads": len(reads), "sinks": len(sinks)}
    return rep


def load_inventory_file(path: Path) -> dict:
    return analyze(json.loads(Path(path).read_text(encoding="utf-8"))).as_dict()


# --- rendering ---------------------------------------------------------------

def _x(text: Any) -> str:
    return html.escape(str(text), quote=True)


def render_svg(report: dict, max_nodes: int = 30) -> str:
    """Three-column reachability graph: sources, reads, sinks. Inline SVG, no script."""
    classes = report.get("classes") or {}
    sink_names = [s["tool"] for s in report.get("sinks") or []]
    cols = [
        [n for n, c in classes.items() if c == "external_read"][:max_nodes],
        [n for n, c in classes.items() if c in READ_CLASSES][:max_nodes],
        sink_names[:max_nodes],
    ]
    titles = ("external_read (untrusted)", "internal / sensitive read", "sink (write / send / creds / params)")
    width, col_w, row_h, top = 900, 230, 26, 44
    xs = (20, 335, 650)
    height = top + row_h * max(1, max(len(c) for c in cols)) + 20
    pos: dict[tuple[int, str], tuple[int, int]] = {}
    for ci, col in enumerate(cols):
        for ri, name in enumerate(col):
            pos[(ci, name)] = (xs[ci], top + ri * row_h)
    edges: dict[tuple[str, str, str, str], bool] = {}
    for p in report.get("paths") or []:
        chain = p["path"]
        toxic = p["toxic"]
        a, b = (0, chain[0]), (1, chain[1])
        z = (2, chain[-1])
        for u, v in ((a, b), ((1, chain[-2]), z)):
            k = (str(u[0]), u[1], str(v[0]), v[1])
            edges[k] = edges.get(k, False) or toxic
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' width='100%' role='img' "
        f"aria-label='Toxic combination reachability graph'>",
        "<style>text{font:12px sans-serif;fill:#1c1917}.t{font-weight:600}.n{fill:#fff;stroke:#a8a29e}"
        ".tox{stroke:#9f1239;stroke-width:1.6;fill:none;opacity:.75}.ok{stroke:#166534;stroke-width:1.2;"
        "stroke-dasharray:4 3;fill:none;opacity:.6}</style>",
    ]
    for ci, title in enumerate(titles):
        parts.append(f"<text class='t' x='{xs[ci]}' y='22'>{_x(title)}</text>")
    for (u_col, u, v_col, v), toxic in sorted(edges.items()):
        pu, pv = pos.get((int(u_col), u)), pos.get((int(v_col), v))
        if pu is None or pv is None:
            continue
        x1, y1 = pu[0] + col_w, pu[1] + 9
        x2, y2 = pv[0], pv[1] + 9
        mid = (x1 + x2) // 2
        parts.append(f"<path class='{'tox' if toxic else 'ok'}' d='M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}'/>")
    for (ci, name), (x, y) in pos.items():
        cls = classes.get(name, "")
        parts.append(f"<rect class='n' x='{x}' y='{y}' width='{col_w}' height='18' rx='4'/>")
        parts.append(f"<text x='{x + 6}' y='{y + 13}'>{_x(name[:30])} <tspan fill='#57534e'>{_x(cls)}</tspan></text>")
    parts.append("</svg>")
    return "".join(parts)


def render_table(report: dict, limit: int = 60) -> str:
    paths = report.get("paths") or []
    if not paths:
        return "<p class='empty'>No multi-hop path from an external read to a sink in this inventory.</p>"
    rows = []
    for p in paths[:limit]:
        rows.append(
            "<tr>"
            f"<td>{p['hops']}</td>"
            f"<td>{_x(' → '.join(p['path']))}</td>"
            f"<td>{_x(' → '.join(p['classes']))}</td>"
            f"<td>{_x(', '.join(p['channel']) or '—')}</td>"
            f"<td>{_x(p['severity'])}</td>"
            f"<td>{'agw1. boundary' if p['protected_by_agw1'] else '<strong>toxic</strong>'}</td>"
            "</tr>"
        )
    more = len(paths) - limit
    tail = f"<p class='note'>{more} more path(s) in findings.json.</p>" if more > 0 else ""
    return ("<table><thead><tr><th>Hops</th><th>Path</th><th>Classes</th><th>Channel</th><th>Severity</th>"
            "<th>Status</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" + tail)
