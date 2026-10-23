"""Normalization, schema validation, quarantine and pseudonymization."""
import dataclasses
import inspect
import json
import re
from pathlib import Path

import pytest

from rogue_pipeline import pseudonymize
from rogue_pipeline.config import Config
from rogue_pipeline.features import build_feature_table
from rogue_pipeline.normalize import Normalizer, normalize_text, shingle_set
from rogue_pipeline.pseudonymize import KeyConfigError, MissingKeyError, Pseudonymizer, load_key
from rogue_pipeline.schema import NormalizedEvent, RawEvent

from conftest import KEY, raw


def norm(items):
    return Normalizer(Config().normalization, Pseudonymizer(KEY)).process(items)


def test_valid_event_is_accepted_and_pseudonymized():
    ev = {**raw(1, 1_770_000_000), "agent_id": "agent-secret-name", "ip": "10.1.2.3", "user_id": "alice.example", "resource": "/secrets/db"}
    rep = norm([ev])
    assert len(rep.events) == 1 and not rep.quarantined
    flat = json.dumps(dataclasses.asdict(rep.events[0]), default=list)
    for secret in ("agent-secret-name", "10.1.2.3", "alice.example", "/secrets/db"):
        assert secret not in flat, f"raw value {secret!r} leaked into the normalized event"
    assert rep.events[0].sensitive is True           # sensitivity derived BEFORE the path was discarded


@pytest.mark.parametrize("patch,reason", [
    ({"agent_id": None}, "invalid_field:agent_id"),
    ({"ts": "yesterday"}, "invalid_field:ts"),
    ({"ts": 1e30}, "invalid_field:ts"),
    ({"ip": "300.1.1.1"}, "invalid_field:ip"),
    ({"payload_bytes": "many"}, "invalid_field:payload_bytes"),
    ({"payload_bytes": -5}, "invalid_field:payload_bytes"),
    ({"action": "teleport"}, "invalid_field:action"),
    ({"extra_field": 1}, "unknown_field:extra_field"),
    ({"dest_host": "not a host"}, "invalid_field:dest_host"),
    ({"agent_id": "bad id with spaces"}, "invalid_field:agent_id"),
    ({"synthetic": False}, "policy:synthetic_only"),
    ({"action": "tool_call"}, "invalid_field:event"),        # tool required for tool_call
    ({"text": "x" * 3000}, "policy:text_too_long"),
])
def test_malformed_events_are_quarantined_with_reasons(patch, reason):
    ev = {**raw(1, 1_770_000_000), **patch}
    rep = norm([ev])
    assert not rep.events and len(rep.quarantined) == 1
    assert any(r.startswith(reason) for r in rep.quarantined[0].reasons), rep.quarantined[0].reasons


def test_missing_required_field_and_non_objects_and_bad_json():
    ev = raw(1, 1_770_000_000)
    del ev["action"]
    rep = norm([ev, "{not json", [1, 2], "42"])
    reasons = [q.reasons[0] for q in rep.quarantined]
    assert len(rep.quarantined) == 4 and not rep.events
    assert reasons[0].startswith("missing_field:action") and reasons[1] == "invalid_json" and reasons[2] == "not_an_object" == reasons[3]


def test_duplicate_event_ids_quarantined_second_copy_only():
    rep = norm([raw(1, 1_770_000_000), raw(1, 1_770_000_001)])
    assert len(rep.events) == 1 and rep.quarantined[0].reasons[0].startswith("duplicate_event_id")


def test_quarantine_records_contain_no_raw_values(tmp_path):
    ev = {**raw(1, 1_770_000_000), "agent_id": "very-private-agent", "ip": "999.9.9.9", "user_id": "carol"}
    rep = norm([ev])
    out = tmp_path / "q.jsonl"
    rep.write_quarantine(out)
    text = out.read_text()
    assert "very-private-agent" not in text and "999.9.9.9" not in text and "carol" not in text
    rec = json.loads(text.splitlines()[0])
    assert len(rec["input_sha256"]) == 64 and "agent_id" in rec["fields_present"]


def test_json_lines_input_is_parsed():
    rep = norm([json.dumps(raw(1, 1_770_000_000))])
    assert len(rep.events) == 1


def test_iso_timestamp_requires_timezone():
    assert norm([{**raw(1, 0), "ts": "2026-03-02T00:00:00Z"}]).events
    assert norm([{**raw(2, 0), "ts": "2026-03-02T00:00:00"}]).quarantined


def test_schema_forbids_extra_and_is_frozen():
    r = RawEvent.model_validate(raw(1, 1_770_000_000))
    with pytest.raises(Exception):
        r.agent_id = "x"          # frozen
    with pytest.raises(Exception):
        RawEvent.model_validate({**raw(1, 1_770_000_000), "bogus": 1})


def test_external_destination_detection():
    n = Normalizer(Config().normalization, Pseudonymizer(KEY))
    rep = n.process([{**raw(1, 1_770_000_000), "dest_host": "api.corp.example"}, {**raw(2, 1_770_000_001), "dest_host": "evil.example.org"}])
    assert [e.dest_external for e in rep.events] == [False, True]


# ---- pseudonymization ----------------------------------------------------------------------------------
def test_hmac_is_deterministic_keyed_and_domain_separated():
    a, b = Pseudonymizer(KEY), Pseudonymizer(b"another-key-another-key-0000")
    assert a.agent("x") == a.agent("x") != b.agent("x")
    assert a.agent("x") != a.user("x") != a.ip("x") != a.resource("x")       # same string, different roles
    assert a.agent("x").startswith("ag_") and a.ip("1.2.3.4").startswith("ip_") and a.user("u").startswith("us_")


def test_key_is_hidden_and_validated():
    p = Pseudonymizer(KEY)
    assert "unit-test-key" not in repr(p)
    with pytest.raises(KeyConfigError):
        Pseudonymizer(b"short")


def test_key_comes_from_environment_never_source(monkeypatch):
    monkeypatch.delenv("X_KEY", raising=False)
    with pytest.raises(MissingKeyError):
        load_key("X_KEY")
    monkeypatch.setenv("X_KEY", "z" * 32)
    key, eph = load_key("X_KEY")
    assert key == b"z" * 32 and eph is False
    monkeypatch.setenv("X_KEY", "tooshort")
    with pytest.raises(KeyConfigError):
        load_key("X_KEY")
    monkeypatch.delenv("X_KEY")
    key, eph = load_key("X_KEY", allow_ephemeral=True)
    assert eph is True and len(key) == 32


def test_no_hardcoded_key_material_in_package_or_config():
    root = Path(__file__).resolve().parents[1]
    for path in list((root / "rogue_pipeline").glob("*.py")) + [root / "config" / "default.toml", root / "run.py"]:
        src = path.read_text()
        assert not re.search(r"hmac\.new\(\s*b['\"]", src), path
        assert not re.search(r"(?i)(secret|hmac)[_a-z]*key\s*=\s*['\"][^'\"]{8,}['\"]", src), path


def test_features_refuse_unpseudonymized_input():
    """Pseudonymization-before-features is a type-level guarantee: only NormalizedEvent is accepted."""
    with pytest.raises(TypeError):
        build_feature_table([raw(1, 1_770_000_000)])                     # dict
    with pytest.raises(TypeError):
        build_feature_table([RawEvent.model_validate(raw(1, 1_770_000_000))])   # validated but not pseudonymized
    assert "agent_id" not in {f.name for f in dataclasses.fields(NormalizedEvent)}


def test_text_normalization_masks_numbers_and_shingles_are_keyed():
    assert normalize_text("Job 17 done at 10:30 http://x.test/a?b=1 a@b.co") == "job # done at #:# <url> <email>"
    assert shingle_set("job 17 done", 3, 10) == shingle_set("job 93 done", 3, 10)
    p, q = Pseudonymizer(KEY), Pseudonymizer(b"another-key-another-key-0000")
    assert p.shingle("job # done") != q.shingle("job # done")


def test_simulated_malformed_records_all_quarantined(sim, pipeline_run):
    res, _ = pipeline_run
    assert len(sim.malformed) == 14
    # 14 defects: one of the duplicate-id pair is accepted, every other defect is quarantined
    assert len(res.normalization.quarantined) == 13
