"""Multi-agent confused-deputy and delegation guard.

A delegation (``parent -> subagent``, or ``agent_a -> agent_b`` message
passing) must not let one agent launder its restrictions through a cleaner
peer or an orchestrator. The guard models each agent's capability as a point
in a small lattice and enforces that a hand-off can only move *down* it (more
restricted), never up:

- ``allow_egress``   : meet is AND  (either side closed => closed)
- ``allow_sampling`` : meet is AND
- ``sensitive_read`` : join is OR   (sensitive history is sticky)
- ``taint_sources``  : union        (provenance accumulates)

``meet`` (``&``) of two profiles is the hand-off result: the recipient keeps
every restriction either party carried. This is monotonic, so re-delegating
can never restore egress or drop a taint source.

The lattice is also enforced cryptographically. ``attenuate_for_handoff``
returns a fresh ``agw1.`` token for the recipient's own session that carries
the sender's deny caveats (``allow_egress=false``, ``allow_sampling=false``,
``taint_source=...``). Because caveats are appended with the chained HMAC, a
recipient that does not hold the root key cannot strip them: the laundering
attempt fails ``capability.verify`` or still reads ``allows_egress=False``.

``confused_deputy_delegation_blocked`` (approximate AML.T0051 / AML.T0086) is
raised when a delegated agent attempts an egress-class call that its
delegating chain was barred from making.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from . import capability
from .taint import BLOCKED_EGRESS_WHILE_TAINTED, egress_class

ATLAS_CONFUSED_DEPUTY = "AML.T0051"
ATLAS_EXFIL = "AML.T0086"


def taint_source_hash(source: str) -> str:
    """Stable, privacy-safe id for a taint source (no raw secret in the ledger)."""
    safe = capability.sanitize_source(source or "")
    return hashlib.sha256(("taint|" + safe).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class CapProfile:
    """The restriction state that travels with an agent across a hand-off."""
    allow_egress: bool = True
    allow_sampling: bool = False
    sensitive_read: bool = False
    taint_sources: frozenset[str] = field(default_factory=frozenset)

    def __and__(self, other: "CapProfile") -> "CapProfile":
        """Meet: the recipient of a hand-off keeps every restriction either side had."""
        return CapProfile(
            allow_egress=self.allow_egress and other.allow_egress,
            allow_sampling=self.allow_sampling and other.allow_sampling,
            sensitive_read=self.sensitive_read or other.sensitive_read,
            taint_sources=self.taint_sources | other.taint_sources,
        )

    def restricts_at_least(self, other: "CapProfile") -> bool:
        """True when ``self`` is at or below ``other`` in the lattice (no laundering)."""
        return (
            (other.allow_egress or not self.allow_egress)
            and (other.allow_sampling or not self.allow_sampling)
            and (self.sensitive_read or not other.sensitive_read)
            and other.taint_sources <= self.taint_sources
        )

    @property
    def tainted(self) -> bool:
        return not self.allow_egress or bool(self.taint_sources) or self.sensitive_read

    def as_dict(self) -> dict:
        return {
            "allow_egress": self.allow_egress,
            "allow_sampling": self.allow_sampling,
            "sensitive_read": self.sensitive_read,
            "taint_sources": sorted(self.taint_sources),
        }


def profile_from_token(
    token: str, *, sensitive_read: bool = False, key: Optional[bytes] = None,
) -> Optional[CapProfile]:
    """Derive a profile from a verified ``agw1.`` token. ``None`` if it does not verify."""
    cap = capability.verify(token, key=key)
    if cap is None:
        return None
    sources = frozenset(
        taint_source_hash(c[len("taint_source="):])
        for c in cap.caveats
        if c.startswith("taint_source=")
    )
    return CapProfile(
        allow_egress=cap.allows_egress,
        allow_sampling=capability.allows_sampling(cap, key=key),
        sensitive_read=sensitive_read,
        taint_sources=sources,
    )


def attenuate_for_handoff(
    sender_token: str, recipient_token: str, *, key: Optional[bytes] = None,
) -> Optional[str]:
    """Return a recipient token that carries the sender's deny caveats.

    The recipient keeps its own session/agent binding; the sender's
    restrictions are appended, so the result is at or below both in the
    lattice. ``None`` if either token fails to verify.
    """
    sender = capability.verify(sender_token, key=key)
    recipient = capability.verify(recipient_token, key=key)
    if sender is None or recipient is None:
        return None
    cap = recipient
    if not sender.allows_egress and cap.allows_egress:
        cap = capability.attenuate(cap, capability.CAVEAT_DENY_EGRESS)
    if not capability.allows_sampling(sender, key=key) and capability.allows_sampling(cap, key=key):
        cap = capability.attenuate(cap, capability.CAVEAT_DENY_SAMPLING)
    for c in sender.caveats:
        if c.startswith("taint_source=") and c not in cap.caveats:
            cap = capability.attenuate(cap, c)
    return capability.serialize(cap)


@dataclass
class DelegationEdge:
    src: str
    dst: str
    at_step: int


class DelegationLedger:
    """Per-principal effective profile after every hand-off seen so far.

    ``principal`` is whatever identifies an agent across sessions (the PEP
    uses the Root Parent Principal key). The ledger is monotonic: a profile
    only ever moves down the lattice.
    """

    def __init__(self):
        self._profiles: dict[str, CapProfile] = {}
        self._delegated: set[str] = set()  # principals that actually received a hand-off
        self.edges: list[DelegationEdge] = []

    def observe(self, principal: str, profile: CapProfile) -> CapProfile:
        """Fold a freshly observed profile into the principal's ledger entry."""
        current = self._profiles.get(principal)
        merged = profile if current is None else (current & profile)
        self._profiles[principal] = merged
        return merged

    def profile(self, principal: str) -> CapProfile:
        return self._profiles.get(principal, CapProfile())

    def delegate(self, src: str, dst: str, at_step: int = 0) -> CapProfile:
        """Record ``src -> dst`` and push ``src``'s restrictions into ``dst``.

        Returns the recipient's new effective profile (meet of both).
        """
        self.edges.append(DelegationEdge(src=src, dst=dst, at_step=at_step))
        self._delegated.add(dst)
        merged = self.profile(src) & self.profile(dst)
        self._profiles[dst] = merged
        return merged

    def would_launder(self, src: str, dst: str) -> bool:
        """True when routing through ``dst`` would drop a restriction ``src`` holds."""
        return not (self.profile(src) & self.profile(dst)).restricts_at_least(self.profile(src))

    def is_delegated(self, principal: str) -> bool:
        """True only for a principal that actually received a hand-off edge."""
        return principal in self._delegated

    def check_egress(self, principal: str, tool_name: str) -> Optional[dict]:
        """A confused-deputy finding when a *delegated* barred principal attempts egress.

        Only principals that received a hand-off are checked, so two
        independent sessions of the same agent are never conflated.
        """
        if principal not in self._delegated:
            return None
        profile = self.profile(principal)
        if profile.allow_egress:
            return None
        if egress_class(tool_name) not in BLOCKED_EGRESS_WHILE_TAINTED:
            return None
        return {
            "kind": "confused_deputy_delegation_blocked",
            "principal_hash": hashlib.sha256(("p|" + principal).encode()).hexdigest()[:16],
            "tool": tool_name,
            "profile": profile.as_dict(),
            "atlas": [ATLAS_CONFUSED_DEPUTY, ATLAS_EXFIL],
            "atlas_approximate": True,
        }
