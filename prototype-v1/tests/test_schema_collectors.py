import json

import pytest

from rogue_detect.collectors import (JSONLFileCollector, LiveNetworkCollectorStub, SyntheticCollector,
                                     pseudonymize, redact_pii, write_jsonl)
from rogue_detect.schema import Event, validate_event_dict
from rogue_detect.synthetic import generate


def test_generator_is_deterministic_and_labeled_synthetic():
    a, ra = generate(3)
    b, rb = generate(3)
    assert [e.to_dict() for e in a[:200]] == [e.to_dict() for e in b[:200]] and ra == rb
    c, _ = generate(4)
    assert [e.ts for e in a[:50]] != [e.ts for e in c[:50]]
    assert all(e.synthetic for e in a) and all(e.source == "synthetic-generator" for e in a)
    assert all(e.agent_id.startswith("agent-") for e in a)


def test_synthetic_collector_yields_events_sorted():
    col = SyntheticCollector(seed=1)
    evs = col.collect_all()
    assert evs and all(isinstance(e, Event) for e in evs)
    assert [e.ts for e in evs] == sorted(e.ts for e in evs)
    assert set(col.roles.values()) >= {"normal", "rogue_collusion_ring"}


@pytest.mark.parametrize("bad", [
    {"agent_id": "a", "kind": "post"},                          # missing ts
    {"ts": 1, "agent_id": "a", "kind": "nope"},                 # bad kind
    {"ts": 1, "agent_id": "a", "kind": "post", "email": "x"},   # unknown field
    {"ts": "x", "agent_id": "a", "kind": "post"},
    {"ts": 1, "agent_id": "", "kind": "post"},
    {"ts": 1, "agent_id": "a", "kind": "post", "status": "weird"},
    {"ts": 1, "agent_id": "a", "kind": "post", "text": "x" * 2001},
    {"ts": 1, "agent_id": "a", "kind": "post", "payload_bytes": -1},
])
def test_schema_rejects_bad_events(bad):
    with pytest.raises(ValueError):
        validate_event_dict(bad)


def test_jsonl_collector_validates_redacts_and_pseudonymizes(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join([
        "# comment",
        json.dumps({"ts": 5, "agent_id": "alice-bot", "kind": "message", "target": "bob-bot",
                    "text": "mail me at jane@example.com token=abc123 or +1 415 555 0100"}),
        "not json",
        json.dumps({"ts": 6, "agent_id": "x", "kind": "post", "extra": 1}),
        json.dumps({"ts": 7, "agent_id": "alice-bot", "kind": "post", "synthetic": False}),
    ]))
    col = JSONLFileCollector(str(p), pseudonymize_ids=True, salt="s")
    evs = list(col.collect())
    assert len(evs) == 2 and len(col.rejected) == 2
    assert "jane@example.com" not in evs[0].text and "abc123" not in evs[0].text and "555" not in evs[0].text
    assert evs[0].agent_id == pseudonymize("alice-bot", "s") and evs[0].agent_id != "alice-bot"
    assert evs[0].target == pseudonymize("bob-bot", "s")
    assert evs[0].source == "file:c.jsonl"
    strict = JSONLFileCollector(str(p), require_synthetic=True)
    assert len(list(strict.collect())) == 1


def test_redact_pii():
    assert redact_pii("a@b.co") == "<email>"


def test_live_collector_is_disabled():
    with pytest.raises(NotImplementedError):
        list(LiveNetworkCollectorStub().collect())


def test_write_and_roundtrip(tmp_path):
    evs, _ = generate(2, n_normal=5)
    p = tmp_path / "e.jsonl"
    n = write_jsonl(evs[:50], str(p), header="SYNTHETIC")
    assert n == 50
    back = list(JSONLFileCollector(str(p)).collect())
    assert len(back) == 50 and back[0].ts == evs[0].ts
