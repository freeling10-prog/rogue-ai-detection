"""Registered internal agent API keys (lab). Freeze keys to Root Parent Principal."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AgentRecord:
    agent_id: str
    api_key: str
    ephemeral_credential: str
    max_delegation_depth: int = 1
    max_children_per_parent: int = 3
    root_parent_key: str = ""  # empty => self is root
    frozen_until: float = 0.0  # unix ts; 0 = not frozen

    def is_frozen(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) < self.frozen_until

    @property
    def principal_key(self) -> str:
        return self.root_parent_key or self.api_key


@dataclass
class Registry:
    agents: dict[str, AgentRecord] = field(default_factory=dict)  # keyed by api_key
    path: Optional[Path] = None
    freeze_seconds: float = 900.0
    max_children_per_parent: int = 3

    @classmethod
    def load(cls, path: Path) -> "Registry":
        data = json.loads(path.read_text(encoding="utf-8"))
        reg = cls(path=path)
        reg.freeze_seconds = float(data.get("freeze_seconds", 900))
        reg.max_children_per_parent = int(data.get("max_children_per_parent", 3))
        for a in data.get("agents") or []:
            rec = AgentRecord(
                agent_id=a["agent_id"],
                api_key=a["api_key"],
                ephemeral_credential=a.get("ephemeral_credential", ""),
                max_delegation_depth=int(a.get("max_delegation_depth", 1)),
                max_children_per_parent=int(a.get("max_children_per_parent", reg.max_children_per_parent)),
                root_parent_key=a.get("root_parent_key") or "",
            )
            reg.agents[rec.api_key] = rec
        return reg

    def get(self, api_key: str) -> Optional[AgentRecord]:
        return self.agents.get(api_key)

    def freeze_root(self, api_key: str, seconds: Optional[float] = None, now: Optional[float] = None) -> list[str]:
        """Freeze the Root Parent Principal and all keys that share that root. Returns agent_ids frozen."""
        rec = self.agents.get(api_key)
        if not rec:
            return []
        root = rec.principal_key
        until = (now or time.time()) + (seconds if seconds is not None else self.freeze_seconds)
        frozen_ids = []
        for k, r in self.agents.items():
            if r.principal_key == root or r.api_key == root:
                r.frozen_until = until
                frozen_ids.append(r.agent_id)
        return frozen_ids

    def freeze(self, api_key: str, seconds: float = 900.0, now: Optional[float] = None) -> bool:
        return bool(self.freeze_root(api_key, seconds=seconds, now=now))

    def lift_expired(self, now: Optional[float] = None) -> list[str]:
        n = now or time.time()
        lifted = []
        for k, rec in self.agents.items():
            if rec.frozen_until and rec.frozen_until <= n:
                rec.frozen_until = 0.0
                lifted.append(rec.agent_id)
        return lifted

    def is_frozen_key(self, api_key: str, now: Optional[float] = None) -> bool:
        rec = self.agents.get(api_key)
        if not rec:
            return False
        if rec.is_frozen(now):
            return True
        # also check root
        root = self.agents.get(rec.principal_key)
        if root and root.is_frozen(now):
            return True
        return False
