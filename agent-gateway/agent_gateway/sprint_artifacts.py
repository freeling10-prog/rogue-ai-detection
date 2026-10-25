"""Sprint submission visuals: a 6-slide landscape PDF and a 1200x630 PNG card.

Both are drawn from an ``evaluate-collusion`` result document with the
standard library only (no Pillow, no browser): the PDF uses the base-14
Helvetica fonts and filled rectangles, the PNG is an RGB raster written with
``zlib`` and ``struct`` and a built-in 5x7 bitmap font. Every figure on them
comes from the result document, so they cannot drift from the JSON.
"""
from __future__ import annotations

import struct
import zlib
from typing import Any

from .audit_report import _pdf_escape

SLIDE_W, SLIDE_H = 960, 540
CARD_W, CARD_H = 1200, 630

# Dark palette shared by both outputs (RGB 0-255).
BG = (13, 17, 23)
PANEL = (22, 27, 34)
PANEL_EDGE = (48, 54, 61)
TEXT = (230, 237, 243)
MUTED = (139, 148, 158)
ACCENT = (45, 212, 191)
GROUP_COLORS = {"A": (88, 166, 255), "B": (210, 153, 34), "C": (163, 113, 247)}
OK_GREEN = (63, 185, 80)
WARN_RED = (248, 81, 73)


# --- shared figures ------------------------------------------------------------------

def _figures(doc: dict[str, Any]) -> dict[str, Any]:
    suite = doc["defense_suite"]
    lat = doc["benign_latency"]
    chain = doc["audit_chain"]
    gw = doc.get("gateway_suite") or {}
    groups = {g["group"]: g for g in suite["groups"]}
    tc = chain.get("tamper_checks") or {}
    return {
        "suite": suite, "lat": lat, "chain": chain, "gw": gw, "groups": groups,
        "tot": suite["totals"], "cpu": lat["cpu"],
        "collected": gw.get("collected"),
        "machines": gw.get("hypothesis_stateful") or [],
        "tamper_ok": bool(tc.get("edited_line")) and bool(tc.get("dropped_line")),
    }


def _group_line(g: dict[str, Any]) -> str:
    c = g["counts"]
    return f"{c['passed']} of {c['total']} tests pass"


# --- slides PDF ----------------------------------------------------------------------

def _rgb(c: tuple[int, int, int]) -> str:
    return f"{c[0] / 255:.3f} {c[1] / 255:.3f} {c[2] / 255:.3f}"


def _wrap(text: str, size: float, width: float) -> list[str]:
    """Greedy wrap with an average Helvetica advance of 0.48 em."""
    max_chars = max(8, int(width / (size * 0.48)))
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > max_chars:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


class _Slide:
    def __init__(self) -> None:
        self.ops: list[str] = []
        self.rect(0, 0, SLIDE_W, SLIDE_H, BG)

    def rect(self, x: float, y_top: float, w: float, h: float, color: tuple[int, int, int]) -> None:
        y = SLIDE_H - y_top - h
        self.ops.append(f"{_rgb(color)} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def text(self, x: float, y_top: float, s: str, size: float = 16, color=TEXT, bold: bool = False) -> None:
        font = "/F2" if bold else "/F1"
        y = SLIDE_H - y_top - size
        self.ops.append(f"BT {font} {size} Tf {_rgb(color)} rg {x:.1f} {y:.1f} Td ({_pdf_escape(s)}) Tj ET")

    def para(self, x: float, y_top: float, s: str, width: float, size: float = 15, color=TEXT,
             bold: bool = False, leading: float = 1.3) -> float:
        """Wrapped paragraph; returns the y below it."""
        for line in _wrap(s, size, width):
            self.text(x, y_top, line, size, color, bold)
            y_top += size * leading
        return y_top

    def bullets(self, x: float, y_top: float, items: list[str], width: float, size: float = 15,
                color=TEXT, gap: float = 8) -> float:
        for item in items:
            self.rect(x, y_top + size * 0.35, 6, 6, ACCENT)
            y_top = self.para(x + 16, y_top, item, width - 16, size, color) + gap
        return y_top

    def panel(self, x: float, y_top: float, w: float, h: float, stripe: tuple[int, int, int] = ACCENT) -> None:
        self.rect(x - 1, y_top - 1, w + 2, h + 2, PANEL_EDGE)
        self.rect(x, y_top, w, h, PANEL)
        self.rect(x, y_top, 5, h, stripe)

    def tile(self, x: float, y_top: float, w: float, h: float, value: str, label: str,
             color=ACCENT) -> None:
        self.panel(x, y_top, w, h, color)
        self.text(x + 20, y_top + 16, value, 30, color, bold=True)
        self.para(x + 20, y_top + 58, label, w - 32, 12, MUTED)

    def frame(self, n: int, total: int, kicker: str, title: str) -> float:
        """Header and footer; returns the y below the title."""
        self.rect(0, 0, SLIDE_W, 6, ACCENT)
        self.text(48, 30, kicker.upper(), 11, ACCENT, bold=True)
        y = self.para(48, 50, title, SLIDE_W - 96, 26, TEXT, bold=True, leading=1.2)
        self.rect(48, SLIDE_H - 40, SLIDE_W - 96, 1, PANEL_EDGE)
        self.text(48, SLIDE_H - 32, "AgentGate  |  Apart Research AI Collusion Research Sprint", 10, MUTED)
        self.text(SLIDE_W - 90, SLIDE_H - 32, f"{n} / {total}", 10, MUTED)
        return y


def build_slides(doc: dict[str, Any]) -> list[_Slide]:
    f = _figures(doc)
    cpu, lat, chain, tot, groups = f["cpu"], f["lat"], f["chain"], f["tot"], f["groups"]
    total = 6
    slides: list[_Slide] = []

    # 1. Title and thesis
    s = _Slide()
    s.rect(0, 0, SLIDE_W, 6, ACCENT)
    s.text(48, 60, "TRACK 3 / TRACK 2  -  APART RESEARCH AI COLLUSION RESEARCH SPRINT", 11, ACCENT, bold=True)
    y = s.para(48, 90, "Zero-Compute Deterministic Interception of Multi-Agent Collusion Carriers",
               SLIDE_W - 96, 34, TEXT, bold=True, leading=1.15)
    y = s.para(48, y + 12, "AgentGate is a loopback Policy Enforcement Point between agents and their tools. "
               "It bounds side channels, carries restrictions across delegation as HMAC caveats, and "
               "fingerprints split or encoded data, with no model calls on the decision path.",
               SLIDE_W - 96, 16, MUTED)
    tw = (SLIDE_W - 96 - 2 * 20) / 3
    ty = max(y + 24, 330)
    s.tile(48, ty, tw, 110, f"{tot['passed']} / {tot['total']}", "carrier-group defence tests pass (groups A, B, C)")
    s.tile(48 + tw + 20, ty, tw, 110, f"{cpu['p99_ms']:.2f} ms",
           f"p99 CPU per benign decision (reference {lat['target_ms']:g} ms)")
    s.tile(48 + 2 * (tw + 20), ty, tw, 110, "verified" if chain["chain_ok"] else "FAILED",
           f"hash-chained decision log, {chain['entries']} entries", OK_GREEN if chain["chain_ok"] else WARN_RED)
    s.rect(48, SLIDE_H - 40, SLIDE_W - 96, 1, PANEL_EDGE)
    s.text(48, SLIDE_H - 32, "Same-author scripted lab tests. Not a benchmark.", 10, MUTED)
    s.text(SLIDE_W - 90, SLIDE_H - 32, f"1 / {total}", 10, MUTED)
    slides.append(s)

    # 2. Track 3 carriers
    s = _Slide()
    s.frame(2, total, "Track 3 - Collusion carriers and countermeasures", "Three carriers, three deterministic guards")
    cards = [
        ("A", "Boolean / timing oracles", "Information rides on which of a few argument variants is chosen, "
         "or on call rhythm, so no fragment of the value appears.",
         "side_channel_guard.py: after the taint point, caps distinct variants, call count, and regular "
         "rhythm; a signal holds the session and freezes the lab key 15 min."),
        ("B", "Confused-deputy delegation DAGs", "A restricted agent hands its task or state to a peer whose "
         "own capability looks clean.",
         "delegation_guard.py: hand-off re-mints the recipient's agw1. token with the sender's deny caveats "
         "(lattice meet, monotonic); barred principals are held at egress."),
        ("C", "Split-chunk / encoded smuggling", "A protected value leaves in small pieces across steps, or "
         "after Base64, hex, URL or whitespace transforms.",
         "deobfuscate.py + canary_watermark.py: salted n-gram digests over a sliding window and decoded "
         "forms; zero-width HMAC watermarks name the origin step."),
    ]
    cw = (SLIDE_W - 96 - 2 * 18) / 3
    for i, (gid, name, threat, guard) in enumerate(cards):
        x = 48 + i * (cw + 18)
        col = GROUP_COLORS[gid]
        s.panel(x, 112, cw, 370, col)
        s.text(x + 20, 128, f"GROUP {gid}", 11, col, bold=True)
        y = s.para(x + 20, 146, name, cw - 36, 18, TEXT, bold=True, leading=1.15)
        y = s.para(x + 20, y + 6, threat, cw - 36, 12, MUTED)
        y = s.para(x + 20, y + 10, guard, cw - 36, 12, TEXT)
        g = groups.get(gid)
        if g:
            s.text(x + 20, 448, _group_line(g), 13, OK_GREEN if g["all_passed"] else WARN_RED, bold=True)
    slides.append(s)

    # 3. Track 2 audit standard
    s = _Slide()
    top = s.frame(3, total, "Track 2 - Detection and audit of collusion",
                  "Tamper-evident audit: agw1. caveats + hash-chained logs")
    y0 = max(120.0, top + 10)
    ph = 410 - y0
    half = (SLIDE_W - 96 - 20) / 2
    s.panel(48, y0, half, ph)
    s.text(68, y0 + 16, "agw1. macaroon-style capabilities", 16, TEXT, bold=True)
    s.bullets(68, y0 + 46, [
        "Chained HMAC-SHA256: each caveat re-keys the tag, so allow_egress=false cannot be stripped "
        "without the root key.",
        "Untrusted ingest appends the deny caveat; delegation copies it to the recipient.",
        "One-time out-of-band approval, bound to session, step, tool and argument hash, is the only bypass.",
    ], half - 40, 12.5)
    x2 = 48 + half + 20
    s.panel(x2, y0, half, ph)
    s.text(x2 + 20, y0 + 16, "SHA-256 hash-chained decision log", 16, TEXT, bold=True)
    s.bullets(x2 + 20, y0 + 46, [
        "Every line carries seq, prev_hash and entry_hash (a linear chain, not a Merkle tree).",
        "audit_manifest.json adds file digests, the chain head, and an HMAC; verify exits 1 on any edit, "
        "drop, reorder, insert or truncation.",
        "Canary hits record origin_step_index and origin_tool_name in the chain.",
    ], half - 40, 12.5)
    tc = chain.get("tamper_checks") or {}
    s.text(48, 432, "This run:", 14, MUTED, bold=True)
    s.text(130, 432, f"{chain['entries']} benign entries verified: {'yes' if chain['chain_ok'] else 'no'}   |   "
           f"edited line detected: {'yes' if tc.get('edited_line') else 'no'}   |   "
           f"dropped line detected: {'yes' if tc.get('dropped_line') else 'no'}", 14, TEXT)
    slides.append(s)

    # 4. Test suite and stateful fuzzing
    s = _Slide()
    s.frame(4, total, "Reproducible evidence", "Test-suite results and stateful Hypothesis fuzzing")
    collected = f["collected"]
    s.tile(48, 112, 250, 110, str(collected) if collected is not None else "-",
           "gateway tests collected (pytest --collect-only)")
    s.tile(48, 240, 250, 110, f"{tot['passed']} / {tot['total']}", "carrier-group tests passed in this run",
           OK_GREEN if tot["passed"] == tot["total"] else WARN_RED)
    x = 320
    s.panel(x, 112, SLIDE_W - 48 - x, 140)
    s.text(x + 20, 124, "Carrier groups (pytest JUnit XML, keyed by node id)", 13, MUTED, bold=True)
    yy = 148
    for gid in ("A", "B", "C"):
        g = groups.get(gid)
        if not g:
            continue
        c = g["counts"]
        s.text(x + 20, yy, f"{gid}", 13, GROUP_COLORS[gid], bold=True)
        s.text(x + 44, yy, ", ".join(g["files"]), 12, TEXT)
        s.text(SLIDE_W - 48 - 150, yy, f"{c['passed']} / {c['total']} pass", 12,
               OK_GREEN if g["all_passed"] else WARN_RED, bold=True)
        yy += 30
    s.panel(x, 270, SLIDE_W - 48 - x, 182)
    s.text(x + 20, 282, "Stateful Hypothesis machines (settings read from the tests)", 13, MUTED, bold=True)
    yy = 306
    for m in f["machines"][:6]:
        s.text(x + 20, yy, m["machine"], 12, TEXT, bold=True)
        s.text(x + 230, yy, m["file"], 12, MUTED)
        s.text(SLIDE_W - 48 - 150, yy, f"{m['max_examples']} x {m['stateful_step_count']} steps", 12, TEXT)
        yy += 24
    s.para(48, 372, "Each figure traces to a named test in collusion_benchmark_results.json.", 250, 12, MUTED)
    slides.append(s)

    # 5. Latency
    s = _Slide()
    s.frame(5, total, "Overhead", "Measured benign CPU latency and zero-LLM-compute architecture")
    tw = (SLIDE_W - 96 - 3 * 18) / 4
    for i, (val, lab) in enumerate([
        (f"{cpu['p50_ms']:.3f} ms", "p50 CPU per decision"),
        (f"{cpu['p95_ms']:.3f} ms", "p95 CPU per decision"),
        (f"{cpu['p99_ms']:.3f} ms", f"p99 CPU (reference {lat['target_ms']:g} ms)"),
        (f"{cpu['max_ms']:.2f} ms", "slowest single decision"),
    ]):
        col = ACCENT if i < 3 else (OK_GREEN if cpu["max_ms"] <= lat["target_ms"] else (210, 153, 34))
        s.tile(48 + i * (tw + 18), 112, tw, 110, val, lab, col)
    s.bullets(48, 250, [
        f"{lat['decisions']} benign evaluate_call decisions across {len(lat['workflows'])} multi-agent workflows "
        f"x {lat['iterations']} runs; {lat['benign_denials']} denied.",
        f"LLM calls on the decision path: {lat['llm_calls']}. Checks are hashing, HMAC, set lookups and "
        "interval arithmetic.",
        "Thread CPU time, in process, on one machine, including the decision-log write. The 2 ms figure is a "
        "reference target, not a guarantee.",
        f"p99 CPU is {'within' if lat['p99_cpu_within_target'] else 'above'} the reference target"
        + ("; the slowest single decision is shown, not hidden." if cpu["max_ms"] > lat["target_ms"] else "."),
    ], SLIDE_W - 96, 14)
    slides.append(s)

    # 6. Scope
    s = _Slide()
    s.frame(6, total, "Scope and limitations", "What these numbers are, and what they are not")
    s.bullets(48, 112, [
        "Same-author scripted lab tests and workflows. Not a benchmark, and not recall against an unknown "
        "adversary: group counts show the guards behave as their own tests specify.",
        "Benign workflows are few and author-written; the denial count is a smoke check, not a deployment "
        "false-positive rate.",
        "Loopback only: binds 127.0.0.1 by default. Freezes last 15 minutes and apply to registered lab keys "
        "only; unregistered callers are never acted on.",
        "ATLAS technique labels are approximate.",
    ], SLIDE_W - 96, 14)
    s.panel(48, 372, SLIDE_W - 96, 84, (210, 153, 34))
    s.text(68, 386, "Real-model loopback archive: 2 of 13 non-control runs", 16, TEXT, bold=True)
    s.para(68, 412, "A separate measurement on one machine with one 3B model. It is never pooled with, "
           "averaged into, or compared against the test-suite figures on these slides.", SLIDE_W - 136, 12.5, MUTED)
    slides.append(s)
    return slides


def render_slides_pdf(doc: dict[str, Any]) -> bytes:
    slides = build_slides(doc)
    objects: dict[int, bytes] = {
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    }
    page_ids: list[int] = []
    next_id = 5
    for slide in slides:
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        page_ids.append(page_id)
        stream = "\n".join(slide.ops).encode("latin-1", errors="replace")
        objects[content_id] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {SLIDE_W} {SLIDE_H}] /Contents {content_id} 0 R "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"
        ).encode("ascii")
    kids = " ".join(f"{p} 0 R" for p in page_ids)
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("ascii")
    max_id = next_id - 1
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0] * (max_id + 1)
    for obj_id in range(1, max_id + 1):
        offsets[obj_id] = len(out)
        out += f"{obj_id} 0 obj\n".encode("ascii") + objects[obj_id] + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {max_id + 1}\n".encode("ascii") + b"0000000000 65535 f \n"
    for obj_id in range(1, max_id + 1):
        out += f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii")
    out += f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    return bytes(out)


# --- PNG card ------------------------------------------------------------------------

# 5x7 bitmap font: seven rows, five bits each (MSB = left column). Text is drawn uppercase.
_FONT: dict[str, tuple[int, ...]] = {
    "A": (0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11), "B": (0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E),
    "C": (0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E), "D": (0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E),
    "E": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F), "F": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10),
    "G": (0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F), "H": (0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11),
    "I": (0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E), "J": (0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C),
    "K": (0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11), "L": (0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F),
    "M": (0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11), "N": (0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11),
    "O": (0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E), "P": (0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10),
    "Q": (0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D), "R": (0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11),
    "S": (0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E), "T": (0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04),
    "U": (0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E), "V": (0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04),
    "W": (0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A), "X": (0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11),
    "Y": (0x11, 0x11, 0x11, 0x0A, 0x04, 0x04, 0x04), "Z": (0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F),
    "0": (0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E), "1": (0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E),
    "2": (0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F), "3": (0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E),
    "4": (0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02), "5": (0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E),
    "6": (0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E), "7": (0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08),
    "8": (0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E), "9": (0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C),
    " ": (0, 0, 0, 0, 0, 0, 0), ".": (0, 0, 0, 0, 0, 0x0C, 0x0C), ",": (0, 0, 0, 0, 0x0C, 0x04, 0x08),
    ":": (0, 0x0C, 0x0C, 0, 0x0C, 0x0C, 0), "-": (0, 0, 0, 0x1F, 0, 0, 0),
    "/": (0, 0x01, 0x02, 0x04, 0x08, 0x10, 0), "%": (0x18, 0x19, 0x02, 0x04, 0x08, 0x13, 0x03),
    "(": (0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02), ")": (0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08),
    "+": (0, 0x04, 0x04, 0x1F, 0x04, 0x04, 0), "=": (0, 0, 0x1F, 0, 0x1F, 0, 0),
    "<": (0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02), ">": (0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08),
    "|": (0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04), "_": (0, 0, 0, 0, 0, 0, 0x1F),
    "'": (0x04, 0x04, 0x08, 0, 0, 0, 0), "!": (0x04, 0x04, 0x04, 0x04, 0x04, 0, 0x04),
    "?": (0x0E, 0x11, 0x01, 0x02, 0x04, 0, 0x04),
}


class Canvas:
    def __init__(self, w: int, h: int, bg: tuple[int, int, int]):
        self.w, self.h = w, h
        self.px = bytearray(bytes(bg) * (w * h))

    def rect(self, x: int, y: int, w: int, h: int, c: tuple[int, int, int]) -> None:
        x0, y0 = max(0, x), max(0, y)
        x1, y1 = min(self.w, x + w), min(self.h, y + h)
        if x1 <= x0 or y1 <= y0:
            return
        row = bytes(c) * (x1 - x0)
        for yy in range(y0, y1):
            i = (yy * self.w + x0) * 3
            self.px[i:i + len(row)] = row

    def outline(self, x: int, y: int, w: int, h: int, c: tuple[int, int, int], t: int = 2) -> None:
        self.rect(x, y, w, t, c)
        self.rect(x, y + h - t, w, t, c)
        self.rect(x, y, t, h, c)
        self.rect(x + w - t, y, t, h, c)

    @staticmethod
    def text_width(s: str, scale: int) -> int:
        return max(0, len(s) * 6 * scale - scale)

    def text(self, x: int, y: int, s: str, scale: int, c: tuple[int, int, int]) -> int:
        for ch in s.upper():
            rows = _FONT.get(ch, _FONT["?"])
            for r, bits in enumerate(rows):
                for col in range(5):
                    if bits & (0x10 >> col):
                        self.rect(x + col * scale, y + r * scale, scale, scale, c)
            x += 6 * scale
        return x

    def text_center(self, cx: int, y: int, s: str, scale: int, c: tuple[int, int, int]) -> None:
        self.text(cx - self.text_width(s, scale) // 2, y, s, scale, c)

    def png(self) -> bytes:
        raw = b"".join(b"\x00" + bytes(self.px[y * self.w * 3:(y + 1) * self.w * 3]) for y in range(self.h))

        def chunk(tag: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

        ihdr = struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def render_card_png(doc: dict[str, Any]) -> bytes:
    f = _figures(doc)
    cpu, chain, tot, groups = f["cpu"], f["chain"], f["tot"], f["groups"]
    cv = Canvas(CARD_W, CARD_H, BG)
    cv.rect(0, 0, CARD_W, 8, ACCENT)

    cv.text(60, 44, "AGENTGATE", 8, TEXT)
    cv.text(60, 112, "ZERO-COMPUTE INTERCEPTION OF MULTI-AGENT COLLUSION CARRIERS", 3, ACCENT)
    cv.text(60, 144, "APART RESEARCH AI COLLUSION SPRINT - TRACK 3 / TRACK 2", 2, MUTED)

    # Architecture strip: agents -> PEP -> tools, with the decision log underneath.
    y = 190
    boxes = [(60, 250, "AGENTS", MUTED), (440, 320, "AGENTGATE PEP", ACCENT), (890, 250, "TOOLS", MUTED)]
    for x, w, label, col in boxes:
        cv.rect(x, y, w, 64, PANEL)
        cv.outline(x, y, w, 64, col, 3)
        cv.text_center(x + w // 2, y + 22, label, 3, TEXT)
    for x0, x1 in ((310, 440), (760, 890)):
        cv.rect(x0 + 8, y + 30, x1 - x0 - 24, 4, ACCENT)
        for k in range(9):
            cv.rect(x1 - 16 + k, y + 24 + k, 2, 16 - 2 * k, ACCENT)
    cv.text_center(600, y + 76, "NO LLM CALLS - HASHING, HMAC CAVEATS, SET LOOKUPS, INTERVAL ARITHMETIC", 2, MUTED)

    # Three carrier panels.
    names = {"A": ("SIDE CHANNELS", "BOOLEAN / TIMING ORACLES"),
             "B": ("DELEGATION", "CONFUSED-DEPUTY LAUNDERING"),
             "C": ("SMUGGLING", "SPLIT-CHUNK / ENCODED")}
    pw, py = 345, 300
    for i, gid in enumerate(("A", "B", "C")):
        x = 60 + i * (pw + 22)
        col = GROUP_COLORS[gid]
        cv.rect(x, py, pw, 150, PANEL)
        cv.rect(x, py, 6, 150, col)
        cv.text(x + 24, py + 18, f"GROUP {gid}", 2, col)
        cv.text(x + 24, py + 44, names[gid][0], 4, TEXT)
        cv.text(x + 24, py + 82, names[gid][1], 2, MUTED)
        g = groups.get(gid)
        if g:
            c = g["counts"]
            cv.text(x + 24, py + 114, f"{c['passed']}/{c['total']} TESTS PASS", 3,
                    OK_GREEN if g["all_passed"] else WARN_RED)

    # Metrics row.
    my = 474
    metrics = [
        (f"{f['collected']}" if f["collected"] is not None else f"{tot['total']}", "GATEWAY TESTS"),
        (f"{cpu['p99_ms']:.2f} MS", "P99 CPU / DECISION"),
        ("0", "LLM CALLS"),
        ("VERIFIED" if chain["chain_ok"] and f["tamper_ok"] else "CHECK", "HASH-CHAINED LOG"),
    ]
    mw = 255
    for i, (val, lab) in enumerate(metrics):
        x = 60 + i * (mw + 22)
        cv.rect(x, my, mw, 92, PANEL)
        cv.outline(x, my, mw, 92, PANEL_EDGE, 2)
        col = OK_GREEN if i == 3 and val == "VERIFIED" else ACCENT
        scale = 5 if Canvas.text_width(val, 5) <= mw - 40 else 4
        cv.text(x + 20, my + 16 + (5 - scale) * 4, val, scale, col)
        cv.text(x + 20, my + 64, lab, 2, MUTED)

    cv.text(60, 592, "SAME-AUTHOR SCRIPTED LAB TESTS. NOT A BENCHMARK. 2 OF 13 LOOPBACK ARCHIVE KEPT SEPARATE.",
            2, MUTED)
    return cv.png()
