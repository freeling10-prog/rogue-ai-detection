"""Deterministic scanner for injection and smuggling in untrusted tool outputs.

Runs on ``external_read`` results and on MCP ``tools/call`` and
``resources/read`` results before they return to the agent loop. Every check
is a character-class test or a regular expression. Approximate ATLAS mapping:
AML.T0051 (LLM Prompt Injection).

Checks:

- ``unicode_tag_smuggling``: Unicode tag characters U+E0000-U+E007F. Tags
  U+E0020-U+E007E mirror printable ASCII and are invisible in most UIs; the
  hidden text is decoded so a reviewer can read it.
- ``zero_width``: U+200B, U+200C, U+200D (except inside emoji sequences),
  U+2060-U+2064, U+180E, and U+FEFF anywhere but the first character.
- ``bidi_override``: U+202A-U+202E and U+2066-U+2069.
- ``delimiter_spoof``: chat-template and tool-result delimiters
  (``</tool_result>``, ``<|im_start|>``, ``[INST]``, ``<<SYS>>``,
  ``\\n\\nHuman:`` ...), matched after NFKC folding and with invisible
  characters removed, so full-width or zero-width-split spellings still match.
  Text decoded from tag characters is checked as well.
- ``jsonrpc_envelope_spoof``: text that carries a JSON-RPC 2.0 envelope
  (``"jsonrpc": "2.0"`` with a ``method``, ``result``, or ``error``).
- ``cross_tool_shadowing``: the output names a registered ``write``,
  ``send``, or ``credential_use`` tool from the session inventory.

``sanitize`` removes the invisible characters and leaves everything else as is.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

ATLAS_INJECTION = "AML.T0051"
MAX_SCAN_CHARS = 200_000

TAG_RANGE = (0xE0000, 0xE007F)
BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF})

_DELIMITERS = [
    ("tool_result_tag", re.compile(r"</?\s*(?:tool_result|tool_use|function_results?|function_calls?|tool_call|tool_response)\b[^>]{0,80}>", re.I)),
    ("chatml_token", re.compile(r"<\|\s*(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\s*\|>", re.I)),
    ("llama_inst", re.compile(r"\[/?INST\]|<<\s*/?SYS\s*>>")),
    ("role_turn", re.compile(r"(?:^|\n)\s*\n\s*(?:Human|Assistant|System)\s*:", re.I)),
    ("role_tag", re.compile(r"</?\s*(?:system|assistant|admin|developer)(?:_message|_prompt)?\s*>", re.I)),
]
_JSONRPC_RE = re.compile(r"[\"']jsonrpc[\"']\s*:\s*[\"']2\.0[\"']", re.I)
_JSONRPC_BODY_RE = re.compile(r"[\"'](?:method|result|error)[\"']\s*:", re.I)

SINK_CLASSES = frozenset({"write", "send", "credential_use", "creds"})


@dataclass
class OutputFinding:
    kind: str
    count: int
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "count": self.count, **self.detail,
                "atlas": ATLAS_INJECTION, "atlas_approximate": True}


def _is_tag(cp: int) -> bool:
    return TAG_RANGE[0] <= cp <= TAG_RANGE[1]


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or cp in (0xFE0F, 0x20E3)
        or 0x1F3FB <= cp <= 0x1F3FF or 0x2190 <= cp <= 0x21FF or 0x2B00 <= cp <= 0x2BFF
    )


def _invisible(text: str) -> tuple[list[int], list[int], list[int]]:
    tags, zw, bidi = [], [], []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if _is_tag(cp):
            tags.append(i)
        elif cp in BIDI:
            bidi.append(i)
        elif cp in ZERO_WIDTH:
            if cp == 0xFEFF and i == 0:
                continue
            if cp == 0x200D and 0 < i < len(text) - 1 and _is_emoji(text[i - 1]) and _is_emoji(text[i + 1]):
                continue  # emoji ZWJ sequence
            zw.append(i)
    return tags, zw, bidi


def sanitize(text: str) -> str:
    """Drop tag, zero-width (keeping emoji ZWJ), and BiDi override characters."""
    tags, zw, bidi = _invisible(text)
    drop = set(tags) | set(zw) | set(bidi)
    if not drop:
        return text
    return "".join(ch for i, ch in enumerate(text) if i not in drop)


def decode_tags(text: str) -> str:
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


def _folded(text: str) -> str:
    return unicodedata.normalize("NFKC", sanitize(text))


def _name_variants(name: str) -> set[str]:
    base = name.strip().lower()
    out = {base}
    for a, b in (("_", "."), (".", "_"), ("_", "-"), ("-", "_"), ("/", "_")):
        out.add(base.replace(a, b))
    return {v for v in out if len(v) >= 4}


def scan_text(text: str, sink_tools: Iterable[str] = ()) -> list[OutputFinding]:
    if not isinstance(text, str) or not text:
        return []
    text = text[:MAX_SCAN_CHARS]
    findings: list[OutputFinding] = []
    tags, zw, bidi = _invisible(text)
    hidden = ""
    if tags:
        hidden = decode_tags(text)
        findings.append(OutputFinding("unicode_tag_smuggling", len(tags), {
            "decoded_chars": len(hidden), "decoded_preview": hidden[:160],
        }))
    if zw:
        cps = sorted({f"U+{ord(text[i]):04X}" for i in zw})
        findings.append(OutputFinding("zero_width", len(zw), {"codepoints": cps}))
    if bidi:
        cps = sorted({f"U+{ord(text[i]):04X}" for i in bidi})
        findings.append(OutputFinding("bidi_override", len(bidi), {"codepoints": cps}))

    # Text hidden in tag characters is checked too: it is what the model may read.
    folded = _folded(text) + ("\n" + _folded(hidden) if hidden else "")
    for label, rx in _DELIMITERS:
        hits = rx.findall(folded)
        if hits:
            findings.append(OutputFinding("delimiter_spoof", len(hits), {
                "pattern": label, "sample": str(hits[0])[:60].strip(),
            }))
    if _JSONRPC_RE.search(folded) and _JSONRPC_BODY_RE.search(folded):
        findings.append(OutputFinding("jsonrpc_envelope_spoof", len(_JSONRPC_RE.findall(folded)), {}))

    lowered = folded.lower()
    shadowed = []
    for name in sorted(set(sink_tools)):
        for variant in _name_variants(name):
            if re.search(r"(?<![a-z0-9_.\-])" + re.escape(variant) + r"(?![a-z0-9_\-])", lowered):
                shadowed.append(name)
                break
    if shadowed:
        findings.append(OutputFinding("cross_tool_shadowing", len(shadowed), {"tools": shadowed[:20]}))
    return findings


def _iter_text(obj: Any, depth: int = 0) -> Iterable[str]:
    if depth > 12:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and len(k) > 1:
                yield k
            yield from _iter_text(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_text(v, depth + 1)


def scan_output(result: Any, sink_tools: Iterable[str] = ()) -> list[OutputFinding]:
    """Scan every string in a tool or resource result. Findings of a kind are merged."""
    sinks = list(sink_tools)
    merged: dict[str, OutputFinding] = {}
    for text in _iter_text(result):
        for f in scan_text(text, sinks):
            key = f.kind + "|" + str(f.detail.get("pattern", ""))
            prev = merged.get(key)
            if prev is None:
                merged[key] = f
            else:
                prev.count += f.count
                if f.kind == "cross_tool_shadowing":
                    prev.detail["tools"] = sorted(set(prev.detail["tools"]) | set(f.detail["tools"]))[:20]
    return list(merged.values())


def sanitize_output(result: Any, depth: int = 0) -> Any:
    """Copy of ``result`` with invisible characters removed from every string."""
    if depth > 12:
        return result
    if isinstance(result, str):
        return sanitize(result)
    if isinstance(result, dict):
        return {k: sanitize_output(v, depth + 1) for k, v in result.items()}
    if isinstance(result, list):
        return [sanitize_output(v, depth + 1) for v in result]
    return result


def sink_tools_from(inventory: Optional[Iterable[dict]]) -> list[str]:
    """Names of write / send / credential_use tools in an inventory."""
    from .toxic_combinations import tool_class

    out = []
    for tool in inventory or []:
        if isinstance(tool, dict) and tool.get("name") and tool_class(tool) in SINK_CLASSES:
            out.append(str(tool["name"]))
    return out
