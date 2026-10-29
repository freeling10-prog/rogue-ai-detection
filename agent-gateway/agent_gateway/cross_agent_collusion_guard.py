"""Multi-agent provenance DAG and split-chain laundering guard.

Single-session taint tracking can be split across agents: agent A reads a
secret or untrusted content and writes a shared file, memory key, or
message; agent B reads it and sends. Each session alone looks clean. This
guard keeps one provenance graph across agents:

- artifact nodes ``file:<normalized path>``, ``mem:<key>``,
  ``msg:<channel id>``, and agent nodes ``agent:<id>``;
- taint labels ``UNTRUSTED`` and ``SECRET_TAINTED``, each with the set of
  agents it originated from;
- toxic-chain stages ``READ_SENSITIVE``, ``UNTRUSTED_INGEST``,
  ``EXTERNAL_SINK``, ``PRIVILEGED_EXEC``, each with its contributing agents.

A write copies the writer's labels onto the artifact; a read copies the
artifact's labels onto the reader; a delegation copies the parent's labels
onto the child. Labels only grow (a clean overwrite does not clear an
artifact), so no sequence of hand-offs can drop a taint.

Rule codes, from ``check_sink`` (``EXTERNAL_SINK`` or ``PRIVILEGED_EXEC``)
and ``record_write``:

- ``COLLUSION_SPLIT_TOXIC_CHAIN``: the sink would complete a chain whose
  ``READ_SENSITIVE`` and ``UNTRUSTED_INGEST`` stages came from two or more
  distinct agents (one of them not the sinking agent).
- ``COLLUSION_CROSS_AGENT_LAUNDERING``: the sinking agent carries
  ``UNTRUSTED`` or ``SECRET_TAINTED`` that originated with another agent.
- ``COLLUSION_CYCLIC_AMPLIFICATION``: the same artifact has changed hands
  between different writing agents more than ``max_handoff_depth`` times
  without approval (``approve_artifact``).

Taint an agent picked up by itself is left to the single-session gates
(``pep.py``); this guard acts on what crossed between agents. Decisions and
denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). Only routed reads, writes, messages, and
delegations are seen.
"""
from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .audit_chain import ChainWriter

LAUNDERING = "COLLUSION_CROSS_AGENT_LAUNDERING"
SPLIT_CHAIN = "COLLUSION_SPLIT_TOXIC_CHAIN"
AMPLIFICATION = "COLLUSION_CYCLIC_AMPLIFICATION"
RULE_CODES = (LAUNDERING, SPLIT_CHAIN, AMPLIFICATION)

UNTRUSTED, SECRET = "UNTRUSTED", "SECRET_TAINTED"
READ_SENSITIVE, UNTRUSTED_INGEST = "READ_SENSITIVE", "UNTRUSTED_INGEST"
EXTERNAL_SINK, PRIVILEGED_EXEC = "EXTERNAL_SINK", "PRIVILEGED_EXEC"
SINKS = (EXTERNAL_SINK, PRIVILEGED_EXEC)
DEFAULT_MAX_HANDOFF_DEPTH = 8


def artifact_id(kind: str, name: str) -> str:
    """``file:<normalized path>``, ``mem:<key>``, or ``msg:<channel>``."""
    if kind == "file":
        name = posixpath.normpath(str(name).replace("\\", "/")).casefold()
    return f"{kind}:{name}"


@dataclass
class _Label:
    taints: dict[str, set[str]] = field(default_factory=dict)  # taint -> origin agents
    stages: dict[str, set[str]] = field(default_factory=dict)  # stage -> contributing agents

    def merge(self, other: "_Label") -> None:
        for k, v in other.taints.items():
            self.taints.setdefault(k, set()).update(v)
        for k, v in other.stages.items():
            self.stages.setdefault(k, set()).update(v)

    def snapshot(self) -> dict:
        return {"taints": {k: sorted(v) for k, v in sorted(self.taints.items())},
                "stages": {k: sorted(v) for k, v in sorted(self.stages.items())}}


@dataclass
class _Artifact:
    label: _Label = field(default_factory=_Label)
    writers: list[str] = field(default_factory=list)
    last_writer: str = ""
    handoffs: int = 0


@dataclass(frozen=True)
class CollusionDecision:
    allowed: bool
    rule_code: str
    agent: str = ""
    detail: str = ""
    origins: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "agent": self.agent, "detail": self.detail,
                "origins": list(self.origins)}


ALLOW = CollusionDecision(True, "COLLUSION_CLEAR")


class CrossAgentCollusionGuard:
    """Provenance graph of agents and shared artifacts with monotone taint and stage labels."""

    def __init__(self, *, max_handoff_depth: int = DEFAULT_MAX_HANDOFF_DEPTH, audit_log: Optional[Path] = None) -> None:
        self.max_handoff_depth = max(1, int(max_handoff_depth))
        self.agents: dict[str, _Label] = {}
        self.artifacts: dict[str, _Artifact] = {}
        self.edges: list[tuple[str, str, str]] = []  # (from node, to node, kind)
        self.approved: set[str] = set()
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None

    def _agent(self, agent: str) -> _Label:
        return self.agents.setdefault(str(agent), _Label())

    def _log(self, **fields: Any) -> None:
        if self.chain is not None:
            self.chain.append({"ts": round(time.time(), 6), **fields})

    # --- events -----------------------------------------------------------------------

    def record_source(self, agent: str, kind: str) -> None:
        """``kind`` is ``"sensitive"`` (a sensitive read) or ``"untrusted"`` (untrusted ingest)."""
        label = self._agent(agent)
        taint, stage = (SECRET, READ_SENSITIVE) if kind == "sensitive" else (UNTRUSTED, UNTRUSTED_INGEST)
        label.taints.setdefault(taint, set()).add(str(agent))
        label.stages.setdefault(stage, set()).add(str(agent))

    def record_write(self, agent: str, artifact: str) -> CollusionDecision:
        agent = str(agent)
        art = self.artifacts.setdefault(artifact, _Artifact())
        if art.last_writer and art.last_writer != agent:
            art.handoffs += 1
        art.label.merge(self._agent(agent))
        art.writers.append(agent)
        art.last_writer = agent
        self.edges.append((f"agent:{agent}", artifact, "write"))
        if art.handoffs > self.max_handoff_depth and artifact not in self.approved:
            return self._deny(CollusionDecision(
                False, AMPLIFICATION, agent, f"{artifact} changed hands {art.handoffs} times "
                                             f"(limit {self.max_handoff_depth})", tuple(sorted(set(art.writers)))))
        return ALLOW

    def record_read(self, agent: str, artifact: str) -> None:
        art = self.artifacts.get(artifact)
        if art is None:
            return
        self._agent(agent).merge(art.label)
        self.edges.append((artifact, f"agent:{agent}", "read"))

    def record_delegation(self, parent: str, child: str) -> None:
        self._agent(child).merge(self._agent(parent))
        self.edges.append((f"agent:{parent}", f"agent:{child}", "delegate"))

    def approve_artifact(self, artifact: str) -> None:
        """Allow a known ping-pong artifact (a shared work queue a person signed off on)."""
        self.approved.add(artifact)

    # --- decisions ----------------------------------------------------------------------

    def check_sink(self, agent: str, sink: str = EXTERNAL_SINK) -> CollusionDecision:
        """Decide an ``EXTERNAL_SINK`` or ``PRIVILEGED_EXEC`` call by ``agent``."""
        if sink not in SINKS:
            raise ValueError(f"unknown sink stage: {sink!r}")
        agent = str(agent)
        label = self._agent(agent)
        foreign = {t: origins - {agent} for t, origins in label.taints.items() if origins - {agent}}
        sens = label.stages.get(READ_SENSITIVE, set())
        untr = label.stages.get(UNTRUSTED_INGEST, set())
        contributors = sens | untr | {agent}
        if sens and untr and len(contributors) >= 2 and (sens | untr) - {agent}:
            return self._deny(CollusionDecision(
                False, SPLIT_CHAIN, agent, f"{READ_SENSITIVE} by {sorted(sens)}, {UNTRUSTED_INGEST} by "
                                           f"{sorted(untr)}, {sink} by {agent}", tuple(sorted(contributors))))
        if foreign:
            origins = sorted(set().union(*foreign.values()))
            return self._deny(CollusionDecision(
                False, LAUNDERING, agent, f"{', '.join(sorted(foreign))} from {origins} reached {sink}",
                tuple(origins)))
        return ALLOW

    def _deny(self, d: CollusionDecision) -> CollusionDecision:
        self._log(kind=d.rule_code, verdict="DENY", rule_code=d.rule_code, agent=d.agent, detail=d.detail[:200],
                  origins=list(d.origins))
        return d

    def snapshot(self) -> dict:
        return {"agents": {a: lab.snapshot() for a, lab in sorted(self.agents.items())},
                "artifacts": {k: {**v.label.snapshot(), "writers": v.writers[-8:], "handoffs": v.handoffs}
                              for k, v in sorted(self.artifacts.items())},
                "edges": len(self.edges)}
