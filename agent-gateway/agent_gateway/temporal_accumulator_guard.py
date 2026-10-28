"""Bounded sliding-window stream validator for multi-call token and watermark checks."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

ZERO_WIDTH_CHARS: Set[str] = {"​", "‌", "‍", "⁠", "﻿"}


def _count_watermarks(text: str) -> int:
    return sum(1 for ch in text if ch in ZERO_WIDTH_CHARS or (0xE0020 <= ord(ch) <= 0xE007F))


def _extract_fragments(args: Any) -> Tuple[str, str]:
    raw_parts: List[str] = []
    norm_parts: List[str] = []

    def _walk(val: Any) -> None:
        if isinstance(val, bool) or val is None:
            return
        if isinstance(val, str):
            raw_parts.append(val)
            norm_parts.append("".join(ch for ch in val if 32 <= ord(ch) <= 126))
        elif isinstance(val, int) and 32 <= val <= 126:
            norm_parts.append(chr(val))
        elif isinstance(val, (list, tuple)):
            for item in val:
                _walk(item)
        elif isinstance(val, dict):
            for k in sorted(val.keys()):
                _walk(val[k])

    _walk(args)
    return "".join(raw_parts), "".join(norm_parts)


@dataclass(frozen=True)
class AccumulatorDecision:
    allowed: bool
    verdict_code: str
    matched_rule: Optional[str] = None
    window_length: int = 0


class TemporalAccumulatorGuard:
    """Per-(session, destination) rolling window validator for split tokens and watermarks."""

    def __init__(
        self,
        protected_tokens: Optional[Iterable[str]] = None,
        max_window_chars: int = 4096,
        ngram_size: int = 8,
        watermark_threshold: int = 4,
    ) -> None:
        if not isinstance(max_window_chars, int) or isinstance(max_window_chars, bool) or max_window_chars < 64:
            raise ValueError("max_window_chars must be an int >= 64")
        self._max_window = max_window_chars
        self._ngram_size = max(4, ngram_size)
        self._watermark_threshold = max(1, watermark_threshold)
        self._raw_windows: Dict[Tuple[str, str], str] = {}
        self._norm_windows: Dict[Tuple[str, str], str] = {}
        self._protected: List[str] = []
        self._ngram_hashes: Set[str] = set()
        for tok in protected_tokens or ():
            self.register_protected_token(tok)

    def register_protected_token(self, token: str) -> None:
        if not isinstance(token, str) or not token:
            return
        self._protected.append(token)
        if len(token) >= self._ngram_size:
            for i in range(len(token) - self._ngram_size + 1):
                gram = token[i : i + self._ngram_size].encode("utf-8")
                self._ngram_hashes.add(hashlib.sha256(gram).hexdigest()[:16])

    def reset_session(self, session_id: str) -> None:
        for key in [k for k in self._raw_windows if k[0] == session_id]:
            self._raw_windows.pop(key, None)
            self._norm_windows.pop(key, None)

    def _match_stream(self, window: str) -> Optional[str]:
        for tok in self._protected:
            if tok in window:
                return "DIRECT_STREAM_MATCH"
            b64 = base64.b64encode(tok.encode("utf-8")).decode("ascii").rstrip("=")
            if b64 and b64 in window:
                return "BASE64_STREAM_MATCH"
            hx = binascii.hexlify(tok.encode("utf-8")).decode("ascii")
            if hx and hx.lower() in window.lower():
                return "HEX_STREAM_MATCH"
        if self._ngram_hashes and len(window) >= self._ngram_size:
            hits = sum(
                1
                for i in range(len(window) - self._ngram_size + 1)
                if hashlib.sha256(window[i : i + self._ngram_size].encode("utf-8")).hexdigest()[:16]
                in self._ngram_hashes
            )
            if hits >= 2:
                return "NGRAM_STREAM_MATCH"
        return None

    def evaluate_call(self, session_id: str, destination_class: str, tool_args: Any) -> AccumulatorDecision:
        key = (str(session_id), str(destination_class))
        raw_frag, norm_frag = _extract_fragments(tool_args)
        raw_win = (self._raw_windows.get(key, "") + raw_frag)[-self._max_window :]
        norm_win = (self._norm_windows.get(key, "") + norm_frag)[-self._max_window :]
        self._raw_windows[key] = raw_win
        self._norm_windows[key] = norm_win

        if _count_watermarks(raw_win) >= self._watermark_threshold:
            return AccumulatorDecision(False, "SHARDED_EXFIL_DENIED", "CUMULATIVE_WATERMARK_THRESHOLD", len(norm_win))
        matched = self._match_stream(norm_win)
        if matched is not None:
            return AccumulatorDecision(False, "SHARDED_EXFIL_DENIED", matched, len(norm_win))
        return AccumulatorDecision(True, "STREAM_CLEAN", None, len(norm_win))
