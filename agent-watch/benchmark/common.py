"""Shared helpers: bounded JSONL reading, hashing, errors.  Standard library only; never opens a network connection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

MAX_LINE_BYTES = 1_000_000
MAX_FILE_BYTES = 512 * 1024 * 1024


class BenchmarkError(Exception):
    """Validation / packaging failure.  Messages never contain raw record content (only file names, line numbers, pattern kinds)."""


class SecretsFound(BenchmarkError):
    """The bundle or an input contains something the scrubber would redact.  Packaging is refused."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        kinds = sorted({f["kind"] for f in findings})
        super().__init__(f"refusing to package: {len(findings)} secret-pattern finding(s) ({', '.join(kinds)}); first at "
                         f"{findings[0]['file']}:{findings[0]['line']}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def iter_jsonl(path: Path) -> Iterator[tuple[int, Any]]:
    """Yield (line_no, parsed_or_ERR).  Malformed lines yield ``(n, BAD_LINE)`` rather than raising (callers count them)."""
    if path.stat().st_size > MAX_FILE_BYTES:
        raise BenchmarkError(f"{path.name}: file too large")
    with open(path, "rb") as fh:
        for n, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            if len(raw) > MAX_LINE_BYTES:
                yield n, BAD_LINE
                continue
            try:
                yield n, json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                yield n, BAD_LINE


class _Bad:
    def __repr__(self) -> str:
        return "BAD_LINE"


BAD_LINE = _Bad()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True, ensure_ascii=True) + "\n")


def file_entry(root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
