"""Monotone two-level taint and a precommitted, single-use-step DAG.

Call objects are built by trusted method adapters, not deserialized directly.
All manifest fields are supplied by the authorized job compiler. This reference
gates every step, a deliberate strengthening of gating only after EXTERNAL.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from threading import RLock
from types import MappingProxyType

from .common import Denied, digest, scalar_text


class Label(IntEnum):
    VERIFIED = 0
    EXTERNAL = 1


def path_parts(path: str, *, pattern=False) -> tuple[str, ...]:
    scalar_text(path, 4096)
    if not path.startswith("/") or path.startswith("//") or "\0" in path:
        raise Denied("RESOURCE_PATH")
    parts = tuple(path.split("/")[1:])
    if len(parts) > 64 or any(p in {"", ".", ".."} for p in parts):
        raise Denied("NONCANONICAL_RESOURCE")
    for i, p in enumerate(parts):
        if any(c in p for c in "*?[]"):
            if not pattern or p not in {"*", "**"} or (p == "**" and i != len(parts) - 1):
                raise Denied("RESOURCE_PATTERN")
    return parts


def match_parts(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    recursive = pattern[-1:] == ("**",)
    fixed = pattern[:-1] if recursive else pattern
    if len(path) < len(fixed) or (not recursive and len(path) != len(fixed)):
        return False
    return all(a == "*" or a == b for a, b in zip(fixed, path))


def path_match(pattern: str, path: str) -> bool:
    return match_parts(path_parts(pattern, pattern=True), path_parts(path))


@dataclass(frozen=True, slots=True)
class MethodPolicy:
    high_impact: bool
    external_result: bool


@dataclass(frozen=True, slots=True)
class Step:
    step_id: str
    provider: str
    method: str
    pin: str
    # Exactly one resource per role in this restricted reference profile.
    resources: tuple[tuple[str, str], ...] = ()
    predecessors: frozenset[str] = frozenset()
    # If set, bind all canonical parameters, including non-resource arguments.
    args_digest: str | None = None


@dataclass(frozen=True, slots=True)
class Call:
    request_key: str
    step_id: str
    provider: str
    method: str
    pin: str
    resources: tuple[tuple[str, str], ...]
    args_digest: str


@dataclass(frozen=True, slots=True)
class Ticket:
    sequence: int
    call: Call
    label: Label


class Gate:
    def __init__(self, job_id: str, steps: tuple[Step, ...],
                 policies: dict[tuple[str, str], MethodPolicy]):
        scalar_text(job_id, 128)
        if not 1 <= len(steps) <= 128:
            raise Denied("MANIFEST_LIMIT")
        steps = tuple(Step(s.step_id, s.provider, s.method, s.pin,
                           tuple((r, p) for r, p in s.resources),
                           frozenset(s.predecessors), s.args_digest) for s in steps)
        compiled = {}
        table = {}
        for step in steps:
            scalar_text(step.step_id, 128)
            if step.step_id in table or (step.provider, step.method) not in policies:
                raise Denied("MANIFEST_METHOD_OR_ID")
            if len(step.resources) > 16:
                raise Denied("RESOURCE_LIMIT")
            roles = [r for r, _ in step.resources]
            if len(set(roles)) != len(roles):
                raise Denied("DUPLICATE_ROLE")
            compiled[step.step_id] = tuple(
                (role, path_parts(p, pattern=True)) for role, p in step.resources)
            table[step.step_id] = step
        done = set()
        while len(done) < len(table):
            next_ids = {k for k, s in table.items()
                        if k not in done and s.predecessors <= done}
            if not next_ids:
                raise Denied("MANIFEST_CYCLE_OR_MISSING_PARENT")
            done |= next_ids
        self.steps = MappingProxyType(table)
        self.policies = MappingProxyType(dict(policies))
        self._compiled = compiled
        self.commitment = digest("workflow-manifest-v1", {
            "job": job_id, "steps": [
                {"id": s.step_id, "provider": s.provider, "method": s.method,
                 "pin": s.pin, "resources": [list(r) for r in s.resources],
                 "predecessors": sorted(s.predecessors), "args": s.args_digest,
                 "highImpact": policies[(s.provider, s.method)].high_impact,
                 "externalResult": policies[(s.provider, s.method)].external_result}
                for s in sorted(steps, key=lambda s: s.step_id)]})
        self.label = Label.VERIFIED
        self._status = {k: "NEW" for k in table}
        self._labels: dict[str, Label] = {}
        self._tickets: dict[str, Ticket] = {}
        self._outbox = deque()
        self._lock = RLock()

    def ingest(self, label: Label) -> None:
        # Trusted connector/lineage adapter only. Never accept a JSON label.
        with self._lock:
            self.label = Label(max(self.label, Label(label)))

    def begin(self, call: Call) -> Ticket:
        """Atomically validate, consume the step, and enqueue once.

        Returned ticket is a receipt. Only the outbox may drive dispatch.
        Production: use a durable transactional outbox and downstream idempotency.
        """
        with self._lock:
            call = Call(call.request_key, call.step_id, call.provider, call.method,
                        call.pin, tuple((r, p) for r, p in call.resources),
                        call.args_digest)
            scalar_text(call.request_key, 128)
            previous = self._tickets.get(call.request_key)
            if previous is not None:
                if previous.call != call:
                    raise Denied("IDEMPOTENCY_CONFLICT")
                return previous
            step = self.steps.get(call.step_id)
            if step is None or self._status[call.step_id] != "NEW":
                raise Denied("STEP_UNAVAILABLE")
            if (call.provider, call.method, call.pin) != (step.provider, step.method, step.pin):
                raise Denied("CAPABILITY_METHOD")
            if any(self._status[p] != "DONE" for p in step.predecessors):
                raise Denied("PREDECESSOR")
            if step.args_digest is not None and call.args_digest != step.args_digest:
                raise Denied("CAPABILITY_ARGS")
            if len(call.resources) > 16:
                raise Denied("RESOURCE_LIMIT")
            actual = dict(call.resources)
            expected = self._compiled[step.step_id]
            if len(actual) != len(call.resources) or set(actual) != {r for r, _ in expected}:
                raise Denied("RESOURCE_ROLES")
            for role, pattern in expected:
                if not match_parts(pattern, path_parts(actual[role])):
                    raise Denied("CAPABILITY_RESOURCE")
            policy = self.policies[(call.provider, call.method)]
            inherited = max((self._labels[p] for p in step.predecessors),
                            default=Label.VERIFIED)
            # Conservatively taint at dispatch admission, before an unverified
            # connector can return data, errors, redirects, or status metadata.
            self.label = Label(max(self.label, inherited,
                                   Label.EXTERNAL if policy.external_result else Label.VERIFIED))
            ticket = Ticket(len(self._tickets) + 1, call, self.label)
            self._tickets[call.request_key] = ticket
            self._status[call.step_id] = "QUEUED"
            self._outbox.append(ticket)
            return ticket

    def take(self) -> Ticket | None:
        """Local outbox model; recheck registry/fs epochs in the real dispatcher."""
        with self._lock:
            if not self._outbox:
                return None
            ticket = self._outbox.popleft()
            self._status[ticket.call.step_id] = "DISPATCHED"
            return ticket

    def complete(self, ticket: Ticket, outcome: str) -> None:
        with self._lock:
            if outcome not in {"DONE", "FAILED", "UNKNOWN"}:
                raise Denied("OUTCOME")
            known = self._tickets.get(ticket.call.request_key)
            if known != ticket or self._status[ticket.call.step_id] != "DISPATCHED":
                raise Denied("COMPLETION_REPLAY")
            self._status[ticket.call.step_id] = outcome
            self._labels[ticket.call.step_id] = Label(max(self.label, ticket.label))
            # Failed/unknown work is never automatically reauthorized.

    def status(self, step_id: str) -> str:
        with self._lock:
            return self._status[step_id]
