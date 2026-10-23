"""Normalization layer: validate, quarantine, pseudonymize.

Order of operations (enforced by types): raw dict -> ``RawEvent`` validation -> policy checks ->
pseudonymization -> ``NormalizedEvent``. Only ``NormalizedEvent`` can enter feature extraction.

Malformed events are never silently dropped: each produces a ``QuarantineRecord`` with machine-readable
reasons. Quarantine records deliberately contain NO raw values (only a SHA-256 of the input and the names
of the fields that were present) so that the quarantine file itself cannot leak personal data.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Union

from pydantic import ValidationError

from .config import NormalizationCfg, WebCfg
from .pseudonymize import Pseudonymizer
from .identity import IdentityGate
from .scrub import Scrubber
from .schema import REDACTION_RE, NormalizedEvent, RawEvent, WebFlags

_NUM = re.compile(r"\d+")
_BLOB = re.compile(r"[A-Za-z0-9+/=]{24,}")
_URL = re.compile(r"https?://\S+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_WS = re.compile(r"\s+")


def categorize(raw: RawEvent, sensitive: bool, external: bool, tool_classes: Dict[str, str]) -> str:
    """Coarse, path-free action category used by the sequence model. Examples: ``read:untrusted``,
    ``tool:egress:ext``, ``access:sensitive!denied``, ``message``. Timing is deliberately NOT part of it."""
    if raw.honeypot:
        c = f"honeypot:{raw.honeypot}"
    elif raw.action == "read":
        c = "read:untrusted" if raw.untrusted_content else "read:sensitive" if sensitive else "read:ext" if external else "read:int"
    elif raw.action == "tool_call":
        c = f"tool:{tool_classes.get(raw.tool or '', 'other')}" + (":ext" if external else "")
    elif raw.action == "access":
        c = "access:sensitive" if sensitive else "access:other"
    elif raw.action == "write":
        c = "write:ext" if external else "write:int"
    else:
        c = "message"
    return c + ("!denied" if raw.status == "denied" else "")


@dataclass
class QuarantineRecord:
    index: int                      # position in the input stream
    reasons: List[str]
    input_sha256: str
    fields_present: List[str]


@dataclass
class NormalizationReport:
    events: List[NormalizedEvent] = field(default_factory=list)
    quarantined: List[QuarantineRecord] = field(default_factory=list)
    identity_counts: Dict[str, int] = field(default_factory=dict)     # verified / failed / absent / exempt_events

    @property
    def counts(self) -> Dict[str, int]:
        reasons: Dict[str, int] = {}
        for q in self.quarantined:
            for r in q.reasons:
                key = r.split(":", 1)[0]
                reasons[key] = reasons.get(key, 0) + 1
        return {"accepted": len(self.events), "quarantined": len(self.quarantined), **{f"reason.{k}": v for k, v in sorted(reasons.items())}}

    def write_quarantine(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for q in self.quarantined:
                fh.write(json.dumps(asdict(q), sort_keys=True) + "\n")


def normalize_text(text: str) -> str:
    """Canonical form used for content similarity: lowercase, emails/URLs/blobs/numbers masked.

    Masking digits makes "job 17 done" and "job 93 done" the same template, so similarity measures *template
    reuse*, not exact strings, and strips most incidental personal data before hashing."""
    t = _EMAIL.sub("<email>", REDACTION_RE.sub("<redacted>", text).lower())
    t = _URL.sub("<url>", t)
    t = _BLOB.sub("<blob>", t)
    t = _NUM.sub("#", t)
    return _WS.sub(" ", t).strip()


def shingle_set(text: str, size: int, cap: int) -> List[str]:
    """Word shingles of the normalized text. Texts shorter than ``size`` words yield one shingle."""
    toks = normalize_text(text).split(" ")
    if len(toks) < size:
        return [" ".join(toks)] if toks and toks[0] else []
    seen: List[str] = []
    for i in range(len(toks) - size + 1):
        s = " ".join(toks[i : i + size])
        if s not in seen:
            seen.append(s)
        if len(seen) >= cap:
            break
    return seen


class Normalizer:
    """Validate raw telemetry and emit pseudonymized events."""

    def __init__(self, cfg: NormalizationCfg, pseudo: Pseudonymizer, identity: Optional[IdentityGate] = None,
                 web: Optional[WebCfg] = None) -> None:
        self.cfg = cfg
        self.pseudo = pseudo
        self.identity = identity
        self.web = web or WebCfg()
        # v4: encoded-secret scrubber (keyed by the pseudonymization key, domain "scrub") applied to raw free-text fields at ingest
        self.scrubber: Optional[Scrubber] = Scrubber(lambda v: pseudo.token("scrub", v, "")) if cfg.scrub_raw_fields else None
        self._sens = [re.compile(p, re.I) for p in cfg.sensitive_patterns]
        self._scan_ua = [re.compile(p, re.I) for p in self.web.scanner_ua_patterns]
        self._scan_path = [re.compile(p, re.I) for p in self.web.scanner_path_patterns]
        self._bot_ua = [re.compile(p, re.I) for p in self.web.declared_bot_ua_patterns]
        self._browser_ua = [re.compile(p) for p in self.web.browser_ua_patterns]

    def web_flags(self, raw: RawEvent) -> Optional[WebFlags]:
        """Reduce the collector's web block to flags.  The raw User-Agent is classified here and never stored."""
        w = raw.web
        if w is None:
            return None
        ua = w.user_agent or ""
        if not ua:
            ua_class = "none"
        elif any(p.search(ua) for p in self._scan_ua):
            ua_class = "scanner"
        elif any(p.search(ua) for p in self._bot_ua):
            ua_class = "declared_bot"
        elif any(p.search(ua) for p in self._browser_ua):
            ua_class = "browser"
        else:
            ua_class = "other"
        return WebFlags(
            content_kind=w.content_kind, ua_class=ua_class, scanner_path=any(p.search(raw.resource) for p in self._scan_path),
            referer_valid=w.referer_valid, linked_from_prev=w.linked_from_prev, offered_earlier=w.offered_earlier,
            sec_fetch_mismatch=w.sec_fetch_mismatch, strong_signal=w.strong_signal, decoy_kind=w.decoy_kind, mcp=w.mcp,
            has_ja4=w.ja4 is not None, asset_kind=w.asset_kind,
            beacon=None if w.beacon is None else (w.beacon.webdriver_present, w.beacon.pointer_trail_seen, w.beacon.dom_automation_props),
            beacon_offered=w.beacon_offered, referer_present=w.referer_present, sec_fetch_state=w.sec_fetch_state,
            harness_archetype=w.harness_archetype, harness_confidence=w.harness_confidence,
            referer_key=self.pseudo.resource(w.referer_path) if w.referer_path else None,
            path_key=self.pseudo.resource(raw.resource.split("?", 1)[0]),
            is_entry=raw.resource.split("?", 1)[0] in self.web.link_entry_paths)

    # -- helpers -----------------------------------------------------------------------------------
    def _is_external(self, host: Optional[str]) -> bool:
        if not host:
            return False
        return not any(host == s.lstrip(".") or host.endswith(s) for s in self.cfg.internal_domain_suffixes)

    def _is_sensitive(self, resource: str) -> bool:
        return any(p.search(resource) for p in self._sens)

    def _reasons_from_validation(self, exc: ValidationError) -> List[str]:
        out = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"]) or "event"
            kind = "unknown_field" if e["type"] == "extra_forbidden" else "invalid_field"
            if e["type"] == "missing":
                kind = "missing_field"
            out.append(f"{kind}:{loc}:{e['msg']}")
        return out

    def _scrub_raw(self, raw: RawEvent) -> RawEvent:
        """Replace secrets (also percent/\\u-encoded or newline/tab-split ones) in free-text fields by keyed markers BEFORE anything is
        hashed, so a raw secret can never reach a shingle, a token pseudonym or a resource key."""
        sc = self.scrubber
        if sc is None:
            return raw
        upd: Dict[str, Any] = {"resource": sc.scrub_text(raw.resource)}
        if raw.text:
            upd["text"] = sc.scrub_text(raw.text)
        if raw.request_token:
            upd["request_token"] = sc.scrub_text(raw.request_token)
        if raw.response_tokens:
            upd["response_tokens"] = [sc.scrub_text(t) for t in raw.response_tokens]
        if raw.capture is not None and self.cfg.keep_capture:
            c = raw.capture
            upd["capture"] = c.model_copy(update={"system_prompt_summary": sc.scrub_text(c.system_prompt_summary),
                                                  "current_objective": sc.scrub_text(c.current_objective), "message": sc.scrub_text(c.message),
                                                  "declared_tools": [sc.scrub_text(t) for t in c.declared_tools]})
        return raw.model_copy(update=upd)

    def to_normalized(self, raw: RawEvent) -> NormalizedEvent:
        orig = raw                                    # identity verification must see the event exactly as it was signed
        raw = self._scrub_raw(raw)
        p = self.pseudo
        is_msg = raw.action == "message"
        shingles = frozenset(
            p.shingle(s) for s in shingle_set(raw.text, self.cfg.shingle_size, self.cfg.max_shingles_per_event)
        ) if raw.text else frozenset()
        # Scrubber markers are opaque, correlatable tokens: we only compare them (keyed hash), never resolve them.
        found: set = set()
        for v in [raw.text or "", raw.resource, raw.request_token or "", *raw.response_tokens]:
            found.update(m.group(0) for m in REDACTION_RE.finditer(v))
        marker = lambda t: bool(REDACTION_RE.fullmatch(t))
        sens = self._is_sensitive(raw.resource)
        ext = self._is_external(raw.dest_host)
        dec = self.identity.evaluate(orig) if self.identity is not None else None
        return NormalizedEvent(
            event_id=raw.event_id,
            ts=raw.ts,
            source=raw.source,
            agent=p.agent(raw.agent_id),
            action=raw.action,
            status=raw.status,
            tool=raw.tool,
            resource_key=p.agent(raw.resource) if is_msg else p.resource(raw.resource),
            sensitive=sens,
            dest_host=raw.dest_host,
            dest_external=ext,
            untrusted=raw.untrusted_content,
            payload_bytes=raw.payload_bytes,
            shingles=shingles,
            ip=p.ip(raw.ip) if raw.ip else None,
            user=p.user(raw.user_id) if raw.user_id else None,
            category=categorize(raw, sens, ext, self.cfg.tool_classes),
            issued=frozenset(p.token("token", t, "tk_") for t in raw.response_tokens if not marker(t)),
            presented=p.token("token", raw.request_token, "tk_") if raw.request_token and not marker(raw.request_token) else None,
            redactions=frozenset(p.token("redaction", m, "rd_") for m in found),
            honeypot=raw.honeypot, token_class=raw.token_class,
            capture=raw.capture if self.cfg.keep_capture else None,
            web=self.web_flags(raw),
            identity=dec.status if dec else "absent",
            exempt_rules=dec.exempt_rules if dec else frozenset(),
        )

    # -- main entry --------------------------------------------------------------------------------
    def process(self, items: Iterable[Union[Dict[str, Any], str]]) -> NormalizationReport:
        """Validate every item (a dict or a JSON line). Never raises on bad data; quarantines instead."""
        report = NormalizationReport()
        seen_ids: Set[str] = set()
        for idx, item in enumerate(items):
            digest = hashlib.sha256((item if isinstance(item, str) else json.dumps(item, sort_keys=True, default=str)).encode("utf-8", "replace")).hexdigest()
            if isinstance(item, str):
                try:
                    item = json.loads(item)
                except json.JSONDecodeError:
                    report.quarantined.append(QuarantineRecord(idx, ["invalid_json"], digest, []))
                    continue
            if not isinstance(item, dict):
                report.quarantined.append(QuarantineRecord(idx, ["not_an_object"], digest, []))
                continue
            fields = sorted(str(k) for k in item)
            try:
                raw = RawEvent.model_validate(item)
            except ValidationError as exc:
                report.quarantined.append(QuarantineRecord(idx, self._reasons_from_validation(exc), digest, fields))
                continue
            reasons: List[str] = []
            if self.cfg.require_synthetic and not raw.synthetic:
                reasons.append("policy:synthetic_only: event is not labeled synthetic=true")
            if raw.text is not None and len(raw.text) > self.cfg.max_text_len:
                reasons.append(f"policy:text_too_long: more than {self.cfg.max_text_len} characters")
            if raw.event_id in seen_ids:
                reasons.append("duplicate_event_id: event_id already seen in this batch")
            if reasons:
                report.quarantined.append(QuarantineRecord(idx, reasons, digest, fields))
                continue
            seen_ids.add(raw.event_id)
            ne = self.to_normalized(raw)
            report.events.append(ne)
            report.identity_counts[ne.identity] = report.identity_counts.get(ne.identity, 0) + 1
            if ne.exempt_rules:
                report.identity_counts["exempt_events"] = report.identity_counts.get("exempt_events", 0) + 1
        return report
