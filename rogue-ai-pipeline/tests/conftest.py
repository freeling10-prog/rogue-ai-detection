"""Shared fixtures. Everything is synthetic; nothing touches the network."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rogue_pipeline.config import Config, Policy, ResolvedPolicy
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import NormalizedEvent
from rogue_pipeline.simulator import build

KEY = b"unit-test-key-0123456789abcdef"


@pytest.fixture(scope="session")
def cfg() -> Config:
    return Config()


@pytest.fixture(scope="session")
def pseudo() -> Pseudonymizer:
    return Pseudonymizer(KEY)


@pytest.fixture(scope="session")
def sim():
    return build(0, n_malformed=14)


@pytest.fixture(scope="session")
def pipeline_run(sim, cfg, pseudo):
    res = Pipeline(cfg, sim.policy, pseudo).run(sim.all_items())
    inv = {pseudo.agent(a): a for a in sim.labels}
    return res, inv


def raw(i: int, ts: float, agent: str = "a1", action: str = "read", **kw: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {"event_id": f"ev{i}", "ts": ts, "source": "api_gateway", "agent_id": agent, "action": action, "synthetic": True}
    d.update(kw)
    return d


def normalize(events: List[Dict[str, Any]], cfg: Optional[Config] = None, pseudo: Optional[Pseudonymizer] = None) -> List[NormalizedEvent]:
    cfg = cfg or Config()
    pseudo = pseudo or Pseudonymizer(KEY)
    rep = Normalizer(cfg.normalization, pseudo).process(events)
    assert not rep.quarantined, rep.quarantined
    return rep.events


def empty_policy() -> ResolvedPolicy:
    return ResolvedPolicy()


# ---- v1.1 fixtures: extended simulator, frozen baseline --------------------------------------------------------------
@pytest.fixture(scope="session")
def ext_sim():
    return build(0, extended=True)


@pytest.fixture(scope="session")
def ref_baseline(cfg):
    from rogue_pipeline.baseline import train_baseline
    from rogue_pipeline.evaluation import _reference_by_agent
    return train_baseline(_reference_by_agent(cfg, (1000, 1001), 60), cfg, created_at="2026-01-01T00:00:00+00:00")


@pytest.fixture(scope="session")
def ext_run(ext_sim, cfg, ref_baseline):
    """Full v1.1 run on the extended simulator: frozen baseline + sequence model + identity allow-listing."""
    from rogue_pipeline.simulator import sim_identity
    reg, idcfg = sim_identity()
    ps = Pseudonymizer(KEY)
    res = Pipeline(cfg.model_copy(update={"identity": idcfg}), ext_sim.policy, ps, baseline=ref_baseline, identity=reg).run(ext_sim.events, alternatives=True)
    return res, {ps.agent(a): a for a in ext_sim.labels}


@pytest.fixture(scope="session")
def ext_run_noid(ext_sim, cfg, ref_baseline):
    ps = Pseudonymizer(KEY)
    res = Pipeline(cfg, ext_sim.policy, ps, baseline=ref_baseline).run(ext_sim.events)
    return res, {ps.agent(a): a for a in ext_sim.labels}
