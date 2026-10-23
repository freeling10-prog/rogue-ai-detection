"""Secret detection for bundles (refuse-to-package gate) and an opt-in scrub pass.

Detection reuses the project's scrubber patterns (``agentwatch.scrubber.PATTERNS``: sk- keys, GitHub tokens, AWS access keys,
JWTs, Bearer tokens, emails) and adds the honeypot's fake-credential prefix (``AWFAKE``).  Each text is checked in several
VIEWS so encoded or split secrets are not missed:

  raw           the text as stored
  project view  ``agentwatch.scrubber._match_view`` (percent-decode x2, ``\\uXXXX``, newline/zero-width gaps) when importable
  local view    our own equivalent: NFKC, percent-decode x2, ``\\uXXXX``, literal ``\\n``/``\\r``/``\\t`` and control/format
                characters removed - so ``user%40example.com``, ``user\\u0040example.com`` and ``sk-abc...\\n...xyz`` all fire

The local view is the safety net if the other worker changes scrubber internals; the project patterns are used when available
and a frozen copy otherwise.  Findings carry (file, line, kind) only - never the matched text.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import unicodedata
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

from .common import SecretsFound

_FALLBACK_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("OPENAI_ANTHROPIC_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{16,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[a-zA-Z0-9]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]*")),
    ("BEARER", re.compile(r"(?i:bearer)(?:\s|\+)+[a-zA-Z0-9._\-]+")),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")),
]
EXTRA_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("DECOY_FAKE_KEY", re.compile(r"AWFAKE[-_][A-Za-z0-9][-A-Za-z0-9_]{3,}")),
]

try:                                        # project patterns, tolerant of the other worker's edits
    from agentwatch import scrubber as _aw_scrubber           # type: ignore
    _proj = list(getattr(_aw_scrubber, "PATTERNS"))
    PROJECT_PATTERNS_USED = bool(_proj)
    _project_view = getattr(_aw_scrubber, "_match_view", None)
except Exception:                                              # pragma: no cover - import problems must not weaken the scan
    _proj, PROJECT_PATTERNS_USED, _project_view, _aw_scrubber = [], False, None, None

# union: project patterns first, then our frozen copy (a pattern the project drops is still enforced here), then extras
PATTERNS: list[tuple[str, "re.Pattern[str]"]] = list(_proj) + [p for p in _FALLBACK_PATTERNS if p[0] not in {n for n, _ in _proj}] + EXTRA_PATTERNS

_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_LIT_WS = re.compile(r"\\[nrt]")
_CTRL = re.compile("[\x00-\x1f\x7f-\x9f]")


def _decode_u(s: str) -> str:
    return _UESC.sub(lambda m: chr(int(m.group(1), 16)) if not 0xD800 <= int(m.group(1), 16) <= 0xDFFF else "", s)


def local_view(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    for _ in range(2):
        t = _decode_u(unquote(t, errors="replace"))
    t = _LIT_WS.sub("", t)
    t = "".join(c for c in _CTRL.sub("", t) if unicodedata.category(c) != "Cf")
    return t


def _views(text: str) -> list[str]:
    views = [text, local_view(text)]
    if _project_view is not None:
        try:
            views.append(_project_view(unicodedata.normalize("NFKC", text))[0])
        except Exception:                                      # pragma: no cover
            pass
    return views


def scan_text(text: str) -> list[str]:
    """Kinds of secret pattern found in *text* in any view (empty list == clean)."""
    kinds: list[str] = []
    for v in _views(text):
        for name, rx in PATTERNS:
            if name not in kinds and rx.search(v):
                kinds.append(name)
    return kinds


def _leaves(obj: Any, depth: int = 0) -> Iterable[str]:
    if depth > 40:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _leaves(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _leaves(v, depth + 1)


def scan_obj(obj: Any) -> list[str]:
    kinds: list[str] = []
    for s in _leaves(obj):
        for k in scan_text(s):
            if k not in kinds:
                kinds.append(k)
    return kinds


def scan_file(path: Path, label: str | None = None) -> list[dict[str, Any]]:
    """Findings for one file.  JSONL: per line (raw line + every decoded string).  Everything else: whole text, then per line."""
    label = label or path.name
    findings: list[dict[str, Any]] = []
    data = path.read_bytes().decode("utf-8", errors="replace")
    if path.suffix == ".jsonl":
        for n, line in enumerate(data.splitlines(), 1):
            if not line.strip():
                continue
            kinds = scan_text(line)
            try:
                for k in scan_obj(json.loads(line)):
                    if k not in kinds:
                        kinds.append(k)
            except ValueError:
                pass
            findings += [{"file": label, "line": n, "kind": k} for k in kinds]
        return findings
    kinds = scan_text(data)                                     # whole file: catches newline-split secrets in prose/JSON
    for k in kinds:
        line_no = next((n for n, ln in enumerate(data.splitlines(), 1) if k in scan_text(ln)), 0)
        findings.append({"file": label, "line": line_no, "kind": k})
    if path.suffix == ".json":
        try:
            for k in scan_obj(json.loads(data)):
                if k not in kinds:
                    findings.append({"file": label, "line": 0, "kind": k})
        except ValueError:
            pass
    return findings


_TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".log", ".csv", ".ndjson", ""}


def scan_tree(root: Path) -> list[dict[str, Any]]:
    """Scan every file under *root* (unknown binary-looking suffixes are scanned too, as text with replacement)."""
    out: list[dict[str, Any]] = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out += scan_file(p, p.relative_to(root).as_posix())
    return out


def require_clean(paths: Iterable[Path], root: Path | None = None) -> None:
    """Raise SecretsFound if any file has a finding."""
    findings: list[dict[str, Any]] = []
    for p in paths:
        findings += scan_file(p, p.relative_to(root).as_posix() if root else p.name)
    if findings:
        raise SecretsFound(findings)


# ------------------------------------------------------------------------------------------------ opt-in scrubbing
class _FallbackScrubber:
    """Weaker stand-in used only when ``agentwatch.scrubber`` cannot be imported; the post-scrub scan still gates packaging."""

    def __init__(self) -> None:
        self._salt = secrets.token_bytes(32)

    def scrub_text(self, text: str) -> str:
        t = local_view(text) if scan_text(text) else text
        for name, rx in PATTERNS:
            t = rx.sub(lambda m, n=name: f"[REDACTED_{n}_SHA256:{hashlib.sha256(self._salt + m.group(0).encode()).hexdigest()[:10]}]", t)
        return t

    def scrub(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub_text(obj)
        if isinstance(obj, dict):
            return {self.scrub_text(k) if isinstance(k, str) else k: self.scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v) for v in obj]
        return obj


_DECOY = EXTRA_PATTERNS[0][1]


class BundleScrubber:
    """Project scrubber (salted hashes, salt NEVER stored in a bundle) + decoy-token redaction."""

    def __init__(self) -> None:
        impl: Any = None
        if _aw_scrubber is not None:
            try:
                os.environ.setdefault("AGENT_WATCH_SALT_FILE", os.path.join(os.environ.get("TMPDIR", "/tmp"), f"aw-bench-salt-{os.getuid()}", "scrub.salt"))
                impl = _aw_scrubber.Scrubber.from_env()
            except Exception:                                  # pragma: no cover
                impl = None
        self.impl = impl or _FallbackScrubber()
        self.uses_project_scrubber = impl is not None

    def scrub(self, obj: Any) -> Any:
        return self._decoy(self.impl.scrub(obj))

    def scrub_text(self, text: str) -> str:
        return self._decoy(self.impl.scrub_text(text))

    def _decoy(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return _DECOY.sub("[REDACTED_DECOY_FAKE_KEY]", local_view(obj) if _DECOY.search(local_view(obj)) else obj)
        if isinstance(obj, dict):
            return {self._decoy(k) if isinstance(k, str) else k: self._decoy(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._decoy(v) for v in obj]
        return obj
