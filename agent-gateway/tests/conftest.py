from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_gateway.pep import PepConfig, PolicyEngine, create_app
from agent_gateway.registry import Registry
from agent_gateway.taint import SharedState


ROOT = Path(__file__).resolve().parents[1]
REG = ROOT / "config" / "agents.json"
KEY_A = "agk_demo_registered_0001"
KEY_B = "agk_demo_registered_0002"
CHILD_KEY = "agk_demo_child_0001"


@pytest.fixture(autouse=True)
def _hmac_key_env(monkeypatch):
    # hmac_key() fails closed without an explicit key.
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", "test-hmac-key-agent-gateway-lab!!")


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "gw-state"
    d.mkdir()
    monkeypatch.setenv("AGENT_GATEWAY_STATE_DIR", str(d))
    monkeypatch.setenv("AGENT_GATEWAY_HMAC_KEY", "test-hmac-key-agent-gateway-lab!!")
    return d


@pytest.fixture()
def engine(state_dir):
    cfg = PepConfig(registry_path=REG, alert_log=state_dir / "alerts.jsonl")
    reg = Registry.load(REG)
    return PolicyEngine(reg, shared=SharedState(), cfg=cfg)


@pytest.fixture()
def client(state_dir):
    cfg = PepConfig(registry_path=REG, alert_log=state_dir / "alerts.jsonl")
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client()
