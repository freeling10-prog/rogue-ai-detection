"""Collector interface and implementations.

Design: every data source implements ``Collector.collect()`` and yields validated
``Event`` objects. The prototype ships with:

* SyntheticCollector        - generated data (the default and only data used in demos)
* JSONLFileCollector        - import of community-contributed event files (validated, PII-redacted)
* LiveNetworkCollectorStub  - intentionally DISABLED. It documents what a real collector must
                              satisfy (see docs/ethics_and_compliance.md) and refuses to run.
"""
from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import replace
from typing import Iterable, Iterator, List, Optional

from .schema import Event, validate_event_dict
from . import synthetic

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\+?\d[\d\s().-]{8,}\d")
_SECRET = re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+")


def redact_pii(text: str) -> str:
    """Best-effort redaction of emails, phone numbers and credential-looking strings."""
    text = _EMAIL.sub("<email>", text)
    text = _SECRET.sub(r"\1=<redacted>", text)
    text = _PHONE.sub("<phone>", text)
    return text


def pseudonymize(agent_id: str, salt: str) -> str:
    h = hashlib.sha256((salt + "|" + agent_id).encode()).hexdigest()[:10]
    return f"agent-{h}"


class Collector(ABC):
    """Interface every data source must implement."""

    name = "base"

    @abstractmethod
    def collect(self) -> Iterator[Event]:
        """Yield validated events."""

    def collect_all(self) -> List[Event]:
        return sorted(self.collect(), key=lambda e: e.ts)


class SyntheticCollector(Collector):
    name = "synthetic"

    def __init__(self, seed: int = 7, n_normal: int = 40, stealth: bool = False):
        self.seed, self.n_normal, self.stealth = seed, n_normal, stealth
        self.roles = {}

    def collect(self) -> Iterator[Event]:
        events, self.roles = synthetic.generate(self.seed, self.n_normal, self.stealth)
        yield from events


class JSONLFileCollector(Collector):
    """Import a JSON-lines file of events (one JSON object per line).

    Safeguards: schema validation (unknown fields rejected), PII redaction of free text,
    optional salted pseudonymization of agent ids, bad lines counted and skipped, and the
    ``source`` label forced to the file name so provenance is never lost.
    """

    name = "jsonl"

    def __init__(self, path: str, pseudonymize_ids: bool = False, salt: str = "", require_synthetic: bool = False):
        self.path, self.pseudo, self.salt = path, pseudonymize_ids, salt
        self.require_synthetic = require_synthetic
        self.rejected: List[str] = []

    def collect(self) -> Iterator[Event]:
        self.rejected = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ev = validate_event_dict(json.loads(line))
                except (ValueError, json.JSONDecodeError) as exc:
                    self.rejected.append(f"line {lineno}: {exc}")
                    continue
                if self.require_synthetic and not ev.synthetic:
                    self.rejected.append(f"line {lineno}: non-synthetic event refused")
                    continue
                aid = pseudonymize(ev.agent_id, self.salt) if self.pseudo else ev.agent_id
                tgt = ev.target
                if self.pseudo and ev.kind == "message":
                    tgt = pseudonymize(tgt, self.salt)
                yield replace(ev, agent_id=aid, target=tgt, text=redact_pii(ev.text),
                              source=f"file:{self.path.split('/')[-1]}")


class LiveNetworkCollectorStub(Collector):
    """Placeholder for a real platform collector. It is deliberately not implemented.

    Before implementing one, work through the checklist in docs/ethics_and_compliance.md:
    terms of service / official API route, robots.txt, rate limits, legal review (CFAA, GDPR),
    data minimization, pseudonymization, retention limit, and ethics review.
    """

    name = "live-network-disabled"

    def collect(self) -> Iterator[Event]:
        raise NotImplementedError(
            "Live collection is disabled in this prototype. It only uses synthetic data. "
            "See docs/ethics_and_compliance.md before building a real collector."
        )


def write_jsonl(events: Iterable[Event], path: str, header: Optional[str] = None) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        if header:
            for h in header.splitlines():
                fh.write(f"# {h}\n")
        for e in events:
            fh.write(json.dumps(e.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
            n += 1
    return n
