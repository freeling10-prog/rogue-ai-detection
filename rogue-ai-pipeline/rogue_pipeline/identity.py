"""Verified agent identity (HTTP Message Signatures / Web Bot Auth style) and IP/ASN allowlists.

SIMULATED and OFFLINE. A real Web Bot Auth deployment verifies Ed25519 signatures against a key directory the
operator publishes at a well-known URL. This module deliberately does neither fetching nor asymmetric crypto:
it verifies an HMAC-SHA256 signature (``alg="hmac-sha256"``, one of the RFC 9421 registered algorithms) against a
LOCALLY CONFIGURED registry whose keys come from environment variables. The signature base follows the RFC 9421
shape over fields the event already carries.

What identity buys (and what it does not)
  * A verified event is exempted from the rules listed in its registry entry (default R3/R4: "new external
    destination"), and only when its destination is inside the entry's ``allow_dest_suffixes``. Verified identity
    is not blanket trust: a verified partner posting somewhere unexpected is still scored.
  * Exemption is per EVENT. Unsigned or badly signed events that merely claim a partner's agent id are scored
    normally, so a spoofer cannot hide behind a real partner's stream.
  * A signature that is PRESENT but FAILS vetoes every allowlist for that event (IP/ASN included).
  * IP and ASN allowlists are weaker evidence than signatures (shared hosting, NAT, proxies, stale ranges): keep
    them narrow. They apply the same per-event, per-rule exemption and are only applied when no signature failed.
  * Exemptions apply to Layer 2 rules only. Layer 1 and Layer 3 still see every event.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

from .config import IdentityCfg, IdentityKeyCfg, IdentityRegistryFile
from .schema import RawEvent

ALG = "hmac-sha256"


class RegistryError(Exception):
    """The identity registry is unusable (missing key material etc.). Fails closed."""


@dataclass(frozen=True)
class IdentityEntry:
    keyid: str
    key: bytes = field(repr=False)
    operator: str
    agents: FrozenSet[str] = frozenset()
    allow_dest_suffixes: Tuple[str, ...] = ()
    exempt_rules: FrozenSet[str] = frozenset({"R3", "R4"})


def signature_base(action: str, resource: str, dest_host: Optional[str], created: int, keyid: str) -> bytes:
    """RFC 9421-shaped signature base over the covered components (@method, @target-uri, @authority)."""
    return (f'"@method": {action}\n"@target-uri": {resource}\n"@authority": {dest_host or ""}\n'
            f'"@signature-params": ("@method" "@target-uri" "@authority");created={created};keyid="{keyid}";alg="{ALG}"'
            ).encode("utf-8")


def sign_event(event: Dict[str, Any], keyid: str, key: bytes, created: Optional[int] = None) -> Dict[str, Any]:
    """Return a copy of a raw event dict with a ``signature`` block (used by the simulator/tests to play the
    partner's gateway)."""
    created = int(event["ts"]) if created is None else created
    base = signature_base(event["action"], event.get("resource", ""), event.get("dest_host"), created, keyid)
    out = dict(event)
    out["signature"] = {"keyid": keyid, "created": created, "value": hmac.new(key, base, hashlib.sha256).hexdigest()}
    return out


class IdentityRegistry:
    def __init__(self, entries: List[IdentityEntry]) -> None:
        self._by_id: Dict[str, IdentityEntry] = {e.keyid: e for e in entries}
        if len(self._by_id) != len(entries):
            raise RegistryError("duplicate keyid in identity registry")

    def __repr__(self) -> str:
        return f"IdentityRegistry(keyids={sorted(self._by_id)})"

    def get(self, keyid: str) -> Optional[IdentityEntry]:
        return self._by_id.get(keyid)

    @classmethod
    def from_file(cls, path: str | Path, env: Optional[Mapping[str, str]] = None, min_key_bytes: int = 16) -> "IdentityRegistry":
        env = os.environ if env is None else env
        spec = IdentityRegistryFile(**json.loads(Path(path).read_text(encoding="utf-8")))
        entries: List[IdentityEntry] = []
        for k in spec.keys:
            raw = env.get(k.key_env)
            if not raw or len(raw.encode()) < min_key_bytes:
                raise RegistryError(f"key for keyid {k.keyid!r}: environment variable {k.key_env} is unset or shorter than "
                                    f"{min_key_bytes} bytes (registry fails closed)")
            entries.append(_entry(k, raw.encode()))
        return cls(entries)


def _entry(k: IdentityKeyCfg, key: bytes) -> IdentityEntry:
    return IdentityEntry(k.keyid, key, k.operator, frozenset(k.agents), tuple(k.allow_dest_suffixes), frozenset(k.exempt_rules))


@dataclass(frozen=True)
class IdentityDecision:
    status: str                      # "verified" | "failed" | "absent"
    exempt_rules: FrozenSet[str]
    reasons: Tuple[str, ...] = ()    # human-readable, no secrets


def _dest_ok(host: Optional[str], suffixes: Tuple[str, ...] | List[str]) -> bool:
    if not suffixes:
        return True
    return host is not None and any(host == s.lstrip(".") or host.endswith(s) for s in suffixes)


class IdentityGate:
    """Decides, per raw event, whether it is verified and which rules it is exempt from."""

    def __init__(self, cfg: IdentityCfg, registry: Optional[IdentityRegistry] = None) -> None:
        self.cfg = cfg
        self.registry = registry
        self._nets = [(ipaddress.ip_network(e.cidr, strict=False), e) for e in cfg.ip_allowlist]
        self._asns = {e.asn: e for e in cfg.asn_allowlist}

    @property
    def active(self) -> bool:
        return self.cfg.enabled and (self.registry is not None or bool(self._nets) or bool(self._asns))

    def evaluate(self, raw: RawEvent) -> IdentityDecision:
        if not self.cfg.enabled:
            return IdentityDecision("absent", frozenset())
        status, reasons = "absent", []
        exempt: set = set()
        if raw.signature is not None:
            status, why = self._verify(raw)
            if status == "failed":
                return IdentityDecision("failed", frozenset(), (why,))        # failure vetoes all allowlists
            entry = self.registry.get(raw.signature.keyid) if self.registry else None
            if entry is not None and _dest_ok(raw.dest_host, entry.allow_dest_suffixes):
                exempt |= entry.exempt_rules
                reasons.append(f"verified:{entry.operator}")
            elif entry is not None:
                reasons.append("verified but destination outside the registry entry's allow list: not exempt")
        if raw.ip:
            try:
                ip = ipaddress.ip_address(raw.ip)
                for net, e in self._nets:
                    if ip.version == net.version and ip in net and _dest_ok(raw.dest_host, e.allow_dest_suffixes):
                        exempt |= set(e.exempt_rules)
                        reasons.append(f"ip_allowlist:{e.label}")
            except ValueError:
                pass
        if raw.asn is not None and raw.asn in self._asns:
            ae = self._asns[raw.asn]
            if _dest_ok(raw.dest_host, ae.allow_dest_suffixes):
                exempt |= set(ae.exempt_rules)
                reasons.append(f"asn_allowlist:{ae.label}")
        return IdentityDecision(status, frozenset(exempt), tuple(reasons))

    def _verify(self, raw: RawEvent) -> Tuple[str, str]:
        sig = raw.signature
        assert sig is not None
        entry = self.registry.get(sig.keyid) if self.registry else None
        if entry is None:
            return "failed", "unknown_keyid"
        if entry.agents and raw.agent_id not in entry.agents:
            return "failed", "agent_not_bound_to_key"
        if abs(raw.ts - sig.created) > self.cfg.max_skew_s:
            return "failed", "stale_or_future_signature"
        base = signature_base(raw.action, raw.resource, raw.dest_host, sig.created, sig.keyid)
        expect = hmac.new(entry.key, base, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig.value):
            return "failed", "bad_signature"
        return "verified", "ok"
