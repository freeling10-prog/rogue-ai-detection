"""Slides PDF and PNG card rendered from an evaluate-collusion result document."""
from __future__ import annotations

import re
import struct
import zlib

import pytest

from agent_gateway import sprint_artifacts as sa


def _doc(failed: int = 0, max_ms: float = 2.6) -> dict:
    def group(gid, files, n):
        return {"group": gid, "title": gid, "module": "", "files": files,
                "counts": {"total": n, "passed": n - (failed if gid == "B" else 0),
                           "failed": failed if gid == "B" else 0, "error": 0, "skipped": 0},
                "all_passed": not (failed and gid == "B"), "tests": []}
    groups = [group("A", ["test_side_channel_guard.py"], 8), group("B", ["test_delegation_guard.py"], 8),
              group("C", ["test_deobfuscate.py", "test_canary_watermark.py"], 41)]
    passed = sum(g["counts"]["passed"] for g in groups)
    return {
        "defense_suite": {"groups": groups, "totals": {"total": 57, "passed": passed, "failed": failed,
                                                       "error": 0, "skipped": 0}},
        "gateway_suite": {"collected": 262, "files": 21, "hypothesis_stateful": [
            {"file": "test_delegation_guard.py", "machine": "DelegationDagMachine",
             "max_examples": 120, "stateful_step_count": 24}]},
        "benign_latency": {"cpu": {"p50_ms": 0.07, "p95_ms": 0.55, "p99_ms": 0.63, "mean_ms": 0.1, "max_ms": max_ms},
                           "target_ms": 2.0, "p99_cpu_within_target": True, "decisions": 750, "iterations": 50,
                           "workflows": {"w": {}}, "benign_denials": 0, "llm_calls": 0},
        "audit_chain": {"chain_ok": True, "entries": 750, "tamper_checks": {"edited_line": True, "dropped_line": True}},
    }


def _png_info(data: bytes) -> tuple[int, int, bytes]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat = 8, b""
    w = h = 0
    while pos < len(data):
        (n,) = struct.unpack(">I", data[pos:pos + 4])
        tag, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
        (crc,) = struct.unpack(">I", data[pos + 8 + n:pos + 12 + n])
        assert crc == zlib.crc32(tag + body) & 0xFFFFFFFF
        if tag == b"IHDR":
            w, h = struct.unpack(">II", body[:8])
            assert body[8:10] == b"\x08\x02"  # 8-bit RGB
        elif tag == b"IDAT":
            idat += body
        pos += 12 + n
    return w, h, zlib.decompress(idat)


def test_slides_pdf_has_six_landscape_pages():
    pdf = sa.render_slides_pdf(_doc())
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"/Count 6" in pdf
    assert pdf.count(b"/MediaBox [0 0 960 540]") == 6
    text = pdf.decode("latin-1")
    for needle in ("Zero-Compute Deterministic Interception", "TRACK 3", "TRACK 2", "hash-chained",
                   "Hypothesis", "p99", "2 of 13", "never pooled", "127.0.0.1", "15 minutes",
                   "DelegationDagMachine", "120 x 24 steps", "262"):
        assert needle in text, needle
    assert "not a Merkle tree" in text  # linear chain, stated plainly


def test_slides_show_failures_and_slow_max():
    text = sa.render_slides_pdf(_doc(failed=1, max_ms=3.1)).decode("latin-1")
    assert "7 of 8 tests pass" in text
    assert "3.10 ms" in text and "shown, not hidden" in text


def test_card_png_dimensions_and_pixels():
    w, h, raw = _png_info(sa.render_card_png(_doc()))
    assert (w, h) == (sa.CARD_W, sa.CARD_H)
    assert len(raw) == h * (1 + w * 3)
    rows = [raw[y * (1 + w * 3) + 1:(y + 1) * (1 + w * 3)] for y in range(h)]
    assert all(raw[y * (1 + w * 3)] == 0 for y in range(h))  # filter byte
    # Background corner is the dark palette; the top accent bar is drawn.
    assert tuple(rows[h - 1][:3]) == sa.BG
    assert tuple(rows[2][:3]) == sa.ACCENT
    assert sum(1 for i in range(0, len(rows[70]), 3) if tuple(rows[70][i:i + 3]) == sa.TEXT) > 50


@pytest.mark.parametrize("s", ["AGENTS", "0.63 MS", "8/8 TESTS PASS"])
def test_bitmap_font_covers_card_text(s):
    assert all(ch in sa._FONT for ch in s)
    assert sa.Canvas.text_width(s, 2) == len(s) * 12 - 2


def test_unknown_glyph_falls_back():
    cv = sa.Canvas(40, 12, (0, 0, 0))
    assert cv.text(0, 0, "~", 1, (255, 255, 255)) == 6
