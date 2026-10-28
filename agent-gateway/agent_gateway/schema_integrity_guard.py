"""MCP tool-schema digest pinning and tool-name collision check (approximate AML.T0051).

Two deterministic configuration checks over ``tools/list`` registrations:

1. **Schema digest pinning.** The first registration of a tool on a server
   pins ``sha256(canonical {name, description, inputSchema})`` to
   ``(server_id, tool_name)``. Canonical JSON follows the RFC 8785 layout
   (object keys sorted, no insignificant whitespace, UTF-8); numbers use
   Python's ``json`` rendering, which matches RFC 8785 for integers and
   ordinary floats but is not a full JCS number serializer. Runs of
   whitespace in ``description`` are collapsed first, so re-wrapped text does
   not count as a change. A later registration whose digest differs from the
   pin is ``SCHEMA_DRIFT_DENIED`` unless it carries a manifest entry for the
   new digest signed with the gateway HMAC key (``manifest_mac``). The pin
   is not replaced on drift, and calls to the drifted tool are denied until a
   signed update arrives.

2. **Tool-name collision.** Names are normalized (NFKC, case-folded, a small
   table of Cyrillic / Greek lookalike letters mapped to Latin, zero-width
   characters and ``-_. `` separators removed). A server that registers a
   name whose normalized form equals, or is within Levenshtein distance 1
   of, a tool already pinned on a *different* server is
   ``TOOL_SHADOWING_DENIED``. The same server re-listing its own tool is not
   a collision.

Scope: the lookalike table covers common Latin-script confusables, not the
full Unicode confusables data. Distance 1 can flag legitimately similar names
on two servers (``get_user`` / ``get_users``); such pairs need an explicit
``allow_pair`` entry. No network, no model call.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .capability import hmac_key

SCHEMA_DRIFT_DENIED = "SCHEMA_DRIFT_DENIED"
TOOL_SHADOWING_DENIED = "TOOL_SHADOWING_DENIED"
ATLAS_TOOL_DEFINITION = "AML.T0051"
MAX_NAME_CHARS = 256

# Lookalike letters mapped to the Latin letter they render as.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
})
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))
_SEPARATORS = re.compile(r"[\s\-_.]+")
_WS = re.compile(r"\s+")


def canonical_json(obj: Any) -> bytes:
    """RFC 8785-style canonical bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False, default=str).encode("utf-8")


def schema_digest(tool: dict) -> str:
    """SHA-256 over the pinned fields of one tool definition."""
    desc = tool.get("description")
    if isinstance(desc, str):
        desc = _WS.sub(" ", desc).strip()
    pinned = {"name": tool.get("name"), "description": desc, "inputSchema": tool.get("inputSchema")}
    return hashlib.sha256(canonical_json(pinned)).hexdigest()


def normalize_name(name: str) -> str:
    """Comparison form of a tool name (see module docstring)."""
    text = unicodedata.normalize("NFKC", str(name or "")[:MAX_NAME_CHARS]).translate(_ZERO_WIDTH)
    text = text.casefold().translate(_CONFUSABLES)
    return _SEPARATORS.sub("", text)


def within_one_edit(a: str, b: str) -> bool:
    """Levenshtein distance between ``a`` and ``b`` is at most 1."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    if la == lb:
        return a[i + 1:] == b[i + 1:]  # one substitution
    return a[i:] == b[i + 1:]  # one insertion into the shorter string


def manifest_mac(server_id: str, tool_name: str, digest: str, *, key: Optional[bytes] = None) -> str:
    """HMAC over one manifest entry. Only a holder of the gateway key can sign an update."""
    root = hmac_key() if key is None else key
    msg = f"schema-manifest|{server_id}|{tool_name}|{digest}".encode("utf-8")
    return hmac.new(root, msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SchemaPin:
    server_id: str
    tool_name: str
    digest: str
    normalized: str


@dataclass
class SchemaVerdict:
    ok: bool
    code: str = ""
    server_id: str = ""
    tool_name: str = ""
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": self.ok, "server_id": self.server_id, "tool": self.tool_name, **self.detail}
        if self.code:
            out.update({"code": self.code, "atlas": ATLAS_TOOL_DEFINITION, "atlas_approximate": True})
        return out


class SchemaIntegrityGuard:
    """Per-gateway pins keyed by ``(server_id, tool_name)``."""

    def __init__(self, *, key: Optional[bytes] = None, allow_pairs: Iterable[tuple[str, str]] = ()):
        self._key = key
        self.pins: dict[tuple[str, str], SchemaPin] = {}
        self.drifted: dict[tuple[str, str], dict] = {}
        self._allow = {frozenset((normalize_name(a), normalize_name(b))) for a, b in allow_pairs}

    def allow_pair(self, a: str, b: str) -> None:
        """Declare two names on different servers as an expected, non-colliding pair."""
        self._allow.add(frozenset((normalize_name(a), normalize_name(b))))

    def _collision(self, server_id: str, normalized: str) -> Optional[SchemaPin]:
        for pin in self.pins.values():
            if pin.server_id == server_id:
                continue
            if frozenset((pin.normalized, normalized)) in self._allow:
                continue
            if within_one_edit(pin.normalized, normalized):
                return pin
        return None

    def _signed(self, server_id: str, tool_name: str, digest: str, mac: Optional[str]) -> bool:
        if not mac:
            return False
        expect = manifest_mac(server_id, tool_name, digest, key=self._key)
        return len(mac) == len(expect) and hmac.compare_digest(mac, expect)

    def register(self, server_id: str, tool: dict, manifest_mac_hex: Optional[str] = None) -> SchemaVerdict:
        """Pin, re-confirm, or reject one tool definition from ``server_id``."""
        server_id = str(server_id or "unknown")
        name = str((tool or {}).get("name") or "")
        digest = schema_digest(tool or {})
        slot = (server_id, name)
        pinned = self.pins.get(slot)
        if pinned is not None:
            if pinned.digest == digest:
                return SchemaVerdict(True, server_id=server_id, tool_name=name,
                                     detail={"status": "pinned", "sha256": digest})
            if self._signed(server_id, name, digest, manifest_mac_hex):
                self.pins[slot] = SchemaPin(server_id, name, digest, pinned.normalized)
                self.drifted.pop(slot, None)
                return SchemaVerdict(True, server_id=server_id, tool_name=name,
                                     detail={"status": "manifest_update", "previous_sha256": pinned.digest,
                                             "sha256": digest})
            detail = {"pinned_sha256": pinned.digest, "seen_sha256": digest}
            self.drifted[slot] = detail
            return SchemaVerdict(False, SCHEMA_DRIFT_DENIED, server_id, name, dict(detail))
        normalized = normalize_name(name)
        other = self._collision(server_id, normalized)
        if other is not None:
            return SchemaVerdict(False, TOOL_SHADOWING_DENIED, server_id, name, {
                "normalized": normalized, "pinned_server_id": other.server_id,
                "pinned_tool": other.tool_name, "pinned_normalized": other.normalized,
            })
        self.pins[slot] = SchemaPin(server_id, name, digest, normalized)
        return SchemaVerdict(True, server_id=server_id, tool_name=name, detail={"status": "pinned", "sha256": digest})

    def register_listing(self, server_id: str, tools: Iterable[dict],
                         manifest: Optional[dict[str, str]] = None) -> list[SchemaVerdict]:
        """Register every tool in one ``tools/list`` result. ``manifest`` maps tool name -> MAC."""
        manifest = manifest or {}
        return [self.register(server_id, t, manifest.get(str(t.get("name") or "")))
                for t in tools if isinstance(t, dict)]

    def check_call(self, server_id: str, tool_name: str) -> SchemaVerdict:
        """A call to a tool whose schema drifted (and was not re-signed) is denied."""
        slot = (str(server_id or "unknown"), str(tool_name or ""))
        detail = self.drifted.get(slot)
        if detail is not None:
            return SchemaVerdict(False, SCHEMA_DRIFT_DENIED, slot[0], slot[1], dict(detail))
        return SchemaVerdict(True, server_id=slot[0], tool_name=slot[1])
