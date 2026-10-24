"""Layer 2: deterministic rules. Each rule has a positive case, a near-miss negative, and evidence/ATLAS checks."""
from pathlib import Path

import pytest

from rogue_pipeline.atlas import ATLAS_MAPPING_NOTE, ATLAS_TECHNIQUES, verify_against_yaml
from rogue_pipeline.config import Config, ResolvedPolicy
from rogue_pipeline.features import group_events
from rogue_pipeline.layer2_rules import RULE_ATLAS, RuleEngine

from conftest import normalize, raw

T = 1_770_000_000.0
HOST_OK = "hooks.partner-1.example.net"
HOST_NEW = "drop-1.example.org"


def baseline(n=30, tools=("search",), hosts=(HOST_OK,)):
    """30 events over ~1h: reads + routine tool calls + a routine external post."""
    evs = []
    for i in range(n):
        t = T + i * 120
        if i % 3 == 0:
            evs.append(raw(i, t, "a", "tool_call", tool=tools[i % len(tools)], dest_host="api.corp.example"))
        elif i == 5:
            evs.append(raw(i, t, "a", "tool_call", tool="http_post", dest_host=hosts[0], payload_bytes=500))
        else:
            evs.append(raw(i, t, "a", "read", dest_host="api.corp.example"))
    return evs


def run(evs, declared=None, cfg=None):
    cfg = cfg or Config()
    g = group_events(normalize(evs))
    agent = next(iter(g))                      # tests use a single agent
    pol = ResolvedPolicy(declared_tools={agent: frozenset(declared["a"])} if declared else {})
    return RuleEngine(cfg.layer2, cfg.tools, pol).evaluate(g)


def ids(flags):
    return sorted(f.rule_id for f in flags)


LATE = T + 4 * 3600


def test_r1_untrusted_then_new_tool_flags_with_evidence():
    evs = baseline() + [raw(100, LATE, "a", "read", untrusted_content=True, dest_host="x.example.net"),
                        raw(101, LATE + 20, "a", "tool_call", tool="upload_file", dest_host="api.corp.example")]
    flags = run(evs)
    f = [x for x in flags if x.rule_id == "R1"]
    assert len(f) == 1 and {e.event_id for e in f[0].evidence} == {"ev100", "ev101"}
    assert f[0].atlas[0]["id"] == "AML.T0051"


def test_r1_negatives_known_tool_declared_tool_late_call_and_no_untrusted():
    base = baseline()
    assert "R1" not in ids(run(base + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 20, "a", "tool_call", tool="search")]))
    assert "R1" not in ids(run(base + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 20, "a", "tool_call", tool="upload_file")],
                               declared={"a": ["search", "upload_file"]}))
    assert "R1" not in ids(run(base + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 900, "a", "tool_call", tool="upload_file")]))
    assert "R1" not in ids(run(base + [raw(101, LATE + 20, "a", "tool_call", tool="upload_file")]))


def test_r2_tool_outside_declared_purpose():
    evs = baseline() + [raw(100, LATE, "a", "tool_call", tool="delete_all")]
    flags = run(evs, declared={"a": ["search", "http_post"]})
    f = [x for x in flags if x.rule_id == "R2"]
    assert len(f) == 1 and f[0].atlas[0]["id"] == "AML.T0053" and f[0].evidence[0].event_id == "ev100"
    assert "R2" not in ids(run(evs))                       # no declared purpose -> rule abstains
    assert "R2" not in ids(run(baseline(), declared={"a": ["search", "http_post"]}))


def test_r3_write_tool_to_new_external_destination():
    big = [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=HOST_NEW, payload_bytes=20000)]
    f = [x for x in run(baseline() + big) if x.rule_id == "R3"]
    assert len(f) == 1 and f[0].atlas[0]["id"] == "AML.T0086" and f[0].extra["new_hosts"] == [HOST_NEW]
    # negatives: known host, tiny payload, read-only tool, internal host, denied
    assert "R3" not in ids(run(baseline() + [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=HOST_OK, payload_bytes=20000)]))
    assert "R3" not in ids(run(baseline() + [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=HOST_NEW, payload_bytes=200)]))
    assert "R3" not in ids(run(baseline() + [raw(100, LATE, "a", "tool_call", tool="search", dest_host=HOST_NEW, payload_bytes=20000)]))
    assert "R3" not in ids(run(baseline() + [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host="x.corp.example", payload_bytes=20000)]))
    assert "R3" not in ids(run(baseline() + [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=HOST_NEW, payload_bytes=20000, status="denied")]))


def test_r4_immediate_external_call_after_untrusted_read():
    evs = baseline() + [raw(100, LATE, "a", "read", untrusted_content=True),
                        raw(101, LATE + 10, "a", "tool_call", tool="search", dest_host=HOST_NEW)]
    assert "R4" in ids(run(evs))
    # too slow, known host, or a plain READ of an external page (crawler-like) must not trigger
    assert "R4" not in ids(run(baseline() + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 200, "a", "tool_call", tool="search", dest_host=HOST_NEW)]))
    assert "R4" not in ids(run(baseline() + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 10, "a", "tool_call", tool="search", dest_host=HOST_OK)]))
    assert "R4" not in ids(run(baseline() + [raw(100, LATE, "a", "read", untrusted_content=True), raw(101, LATE + 10, "a", "read", dest_host=HOST_NEW, tool="fetch_url")]))


def test_r5_access_probing_needs_denials_ratio_and_sensitive_paths():
    probe = [raw(200 + i, LATE + i * 3, "a", "access", status="denied", resource=f"/secrets/k{i}") for i in range(14)]
    f = [x for x in run(baseline() + probe) if x.rule_id == "R5"]
    assert len(f) == 1 and f[0].atlas[0]["id"] == "AML.T0075"
    benign_denied = [raw(200 + i, LATE + i * 3, "a", "read", status="denied", resource=f"/finance/q{i}.xlsx") for i in range(14)]
    assert "R5" not in ids(run(baseline() + benign_denied))        # denied but not sensitive
    few = probe[:3]
    assert "R5" not in ids(run(baseline() + few))


def test_rules_abstain_without_baseline():
    evs = [raw(i, T + i * 5, "a", "tool_call", tool="http_post", dest_host=HOST_NEW, payload_bytes=9000) for i in range(6)]
    assert run(evs) == []


def test_every_flag_has_evidence_atlas_mapping_and_approximation_note():
    evs = (baseline() + [raw(100, LATE, "a", "read", untrusted_content=True),
                         raw(101, LATE + 10, "a", "tool_call", tool="upload_file", dest_host=HOST_NEW, payload_bytes=9000),
                         raw(102, LATE + 20, "a", "tool_call", tool="http_post", dest_host=HOST_NEW + ".x", payload_bytes=9000)]
           + [raw(300 + i, LATE + 100 + i, "a", "access", status="denied", resource=f"/admin/{i}") for i in range(14)])
    flags = run(evs, declared={"a": ["search", "http_post"]})
    # v6: the 14-request denied burst is also sequential probing evidence (R13 CUSUM / micro-windows), so R13 joins R5
    assert set(ids(flags)) == {"R1", "R2", "R3", "R4", "R5", "R13"}
    for f in flags:
        assert f.evidence and all(e.event_id and e.summary for e in f.evidence)
        assert f.atlas and all(a["id"] in ATLAS_TECHNIQUES and a["url"].startswith("https://atlas.mitre.org/") for a in f.atlas)
        assert "approximate" in f.mapping_note.lower() and f.mapping_note == ATLAS_MAPPING_NOTE
        assert [a["id"] for a in f.atlas] == RULE_ATLAS[f.rule_id]
        assert 0 < f.strength <= 1


def test_required_atlas_ids_present():
    assert {"AML.T0051", "AML.T0053", "AML.T0086"} <= set(ATLAS_TECHNIQUES)


def test_atlas_table_verifies_against_yaml_fixture(tmp_path):
    good = tmp_path / "atlas.yaml"
    good.write_text("".join(f"  {k}:\n    name: {v}\n    object-type: technique\n" for k, v in ATLAS_TECHNIQUES.items()))
    assert verify_against_yaml(good) == []
    bad = tmp_path / "bad.yaml"
    bad.write_text(good.read_text().replace("LLM Prompt Injection", "Something Else"))
    assert verify_against_yaml(bad)


def test_rules_are_deterministic():
    evs = baseline() + [raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=HOST_NEW, payload_bytes=20000)]
    a, b = run(evs), run(evs)
    assert [(f.rule_id, [e.event_id for e in f.evidence]) for f in a] == [(f.rule_id, [e.event_id for e in f.evidence]) for f in b]
