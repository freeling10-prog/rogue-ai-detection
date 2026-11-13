"""P3 log-only calibration replay. Not part of the E2 bound."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_gateway import p3_calibrate as C
from agent_gateway.cli import main
from agent_gateway.leakage_budget import LeakageLedger, MAX_BUDGET_QB, P3Config
from tests.p3_oracle import event_qb, qb_choice

MANIFEST = {
    "eligible": [["mcp:metrics", "report_metric"], ["mcp:metrics", "set_flag"]],
    "schemas": {"report_metric": {"v": {"enum": 256}}, "set_flag": {"on": "bool", "note": {"optional": "str"}}},
}


def _call(ts, session, tool, arguments=None, **extra):
    return {"ts_ms": ts, "session": session, "tool": tool, "arguments": arguments or {}, **extra}


def _run(objs, cfg=None, manifest=None):
    rows, rejected, _skipped = C.read_trace(json.dumps(o) for o in objs)
    assert rejected == []
    attachment = C.load_attachment(manifest) if manifest else None
    return C.calibrate(rows, cfg, attachment)


def _parts(doc):
    return {item["component"]: item["qb"] for item in doc["components"]}


def test_integer_helpers():
    assert C.nearest_rank([], 95) == 0
    assert C.nearest_rank([7], 95) == 7
    assert C.nearest_rank(list(range(1, 101)), 95) == 95
    assert C.nearest_rank(list(range(1, 21)), 95) == 19
    assert C.nearest_rank([5, 1, 9], 50) == 5
    assert C.with_margin(100, 25) == 125 and C.with_margin(101, 25) == 127 and C.with_margin(0, 25) == 0
    assert [C.qb_as_bits(q) for q in (128, 129, 130, 131)] == ["32", "32.25", "32.5", "32.75"]


def test_typed_events_split_into_the_five_components():
    """Two members, two eligible tools, typed fields: every figure is the oracle's."""
    doc = _run([
        {"link": ["a", "b"], "source": "delegation"},
        _call(0, "a", "report_metric", {"v": 3}, destination="mcp:metrics"),
        _call(0, "b", "report_metric", {"v": 4}, destination="mcp:metrics"),
        _call(5000, "a", "set_flag", {"on": True}, destination="mcp:metrics"),
    ], manifest=MANIFEST)
    enum = event_qb(gap=1, members=2, manifest_n=2, content_qb_value=qb_choice(256), charge_member=True)
    flag = event_qb(gap=4, members=2, manifest_n=2, content_qb_value=4 + 4, charge_member=True)
    assert _parts(doc) == {
        "continuation_qb": 12,
        "gap_qb": 2 * enum["gap_qb"] + flag["gap_qb"],
        "member_qb": 12,
        "selection_qb": 12,
        "content_typed_qb": 2 * 32 + 8,
        "content_raw_qb": 0,
    }
    total = 2 * enum["charge_qb"] + flag["charge_qb"]
    assert doc["total_qb"] == total == sum(_parts(doc).values())
    assert doc["content"] == {"qb": 72, "share_pct": C._share(72, total), "typed_qb": 72, "raw_qb": 0}
    assert doc["per_coalition"]["n"] == 1 and doc["per_coalition"]["peak_qb"] == total
    assert doc["per_session"]["n"] == 2
    assert doc["per_session"]["peak_qb"] == enum["charge_qb"] + flag["charge_qb"]
    assert doc["per_event"]["peak_qb"] == max(enum["charge_qb"], flag["charge_qb"])
    assert doc["rows"]["charged"] == 3 and doc["rows"]["links"] == 1


def test_untyped_content_is_reported_as_raw_deflate():
    doc = _run([_call(0, "s", "send_email", {"to": "a@b.c", "body": "hello"})])
    parts = _parts(doc)
    assert parts["content_typed_qb"] == 0 and parts["content_raw_qb"] > 0
    assert parts["selection_qb"] == 0 and parts["member_qb"] == 0
    # A value outside the typed schema falls back to the raw coder, as on the live ledger.
    doc = _run([_call(0, "s", "report_metric", {"v": "seven"}, destination="mcp:metrics")], manifest=MANIFEST)
    assert _parts(doc)["content_typed_qb"] == 0 and _parts(doc)["content_raw_qb"] > 0


def test_replay_equals_a_direct_log_only_ledger():
    calls = [(i * 700, "s", "send_email", {"to": "a@b.c", "body": "x" * i}) for i in range(6)]
    doc = _run([_call(*c) for c in calls])
    ledger = LeakageLedger()
    ledger.attach("s", P3Config(mode="log_only"))
    ledger.mark_charging("s", 0)
    for index, (ts, sid, tool, arguments) in enumerate(calls):
        ledger.reserve(sid, f"e{index}", "", tool, C._body(arguments), ts, False, arguments=arguments)
        ledger.commit(sid, f"e{index}")
    assert doc["total_qb"] == ledger.state("s")["spent_qb"]
    assert doc == _run([_call(*c) for c in calls])


def test_log_only_counts_over_budget_and_never_stops():
    doc = _run([_call(i * 1000, "s", "send_email", {"body": "report " + "z" * 40}) for i in range(5)],
               C.CalibrationConfig(budget_qb=128))
    assert doc["mode"] == "log_only"
    assert doc["rows"]["charged"] == 5
    assert doc["per_event"]["over_budget_at_candidate"] == 5
    assert doc["per_coalition"]["over_budget"] == 1 and doc["per_coalition"]["peak_qb"] > 128


def test_coalition_keys_and_link_rows_join_sessions():
    rows = [
        _call(0, "a", "send_email", {"body": "one"}, coalition="team"),
        _call(1000, "b", "send_email", {"body": "two"}, coalition="team"),
        _call(2000, "c", "send_email", {"body": "three"}),
        _call(3000, "d", "send_email", {"body": "four"}),
        {"link": ["c", "d"]},
    ]
    doc = _run(rows)
    assert doc["per_session"]["n"] == 4 and doc["per_coalition"]["n"] == 2
    assert doc["per_coalition"]["total_qb"] == doc["per_session"]["total_qb"] == doc["total_qb"]
    assert sorted(row["members"] for row in doc["top_coalitions"]) == [2, 2]
    # Member choice is charged only once a coalition has more than one member.
    assert _parts(doc)["member_qb"] == 4


def test_core_reads_are_local_and_non_core_reads_are_outbound():
    rows = [
        {"ts_ms": 0, "session": "s", "server": "core",
         "message": {"method": "resources/read", "params": {"uri": "file:///lab/readme.md"}}},
        {"ts_ms": 0, "session": "s", "server": "evil",
         "message": {"method": "resources/read", "params": {"uri": "notes://x/abcd"}}},
        {"ts_ms": 0, "session": "s", "server": "evil", "message": {"method": "prompts/get", "params": {"name": "p"}}},
        _call(0, "s", "lookup_order_status", {"order_id": 1}),
        _call(0, "s", "lookup_order_status", {"order_id": 1}, outbound=True),
    ]
    doc = _run(rows)
    assert doc["rows"]["local"] == 2 and doc["rows"]["outbound"] == 3
    custom = _run(rows[:2], C.CalibrationConfig(core_servers=frozenset({"evil"})))
    assert custom["rows"]["local"] == 1 and custom["rows"]["outbound"] == 1


def test_charge_trace_starts_at_taint_or_a_sensitive_read():
    cfg = C.CalibrationConfig(charge="trace")
    quiet = _run([_call(0, "s", "send_email", {"body": "hi"})], cfg)
    assert quiet["rows"]["uncharged_outbound"] == 1 and quiet["total_qb"] == 0
    after_read = _run([_call(0, "s", "read_internal_secrets"), _call(1000, "s", "send_email", {"body": "hi"})], cfg)
    assert after_read["rows"]["charged"] == 2
    marked = _run([_call(0, "s", "send_email", {"body": "hi"}, charging=True)], cfg)
    assert marked["rows"]["charged"] == 1
    assert _run([_call(0, "s", "send_email", {"body": "hi"})])["rows"]["charged"] == 1


def test_recommendation_uses_the_basis_and_margin():
    rows = []
    for index in range(20):
        # Text that does not compress away. The last session is the outlier.
        size = 400 if index == 19 else 10 + index
        body = "".join(format((j * 2654435761 + index) % 997, "x") for j in range(size))
        rows.append(_call(index * 1000, f"s{index}", "send_email", {"body": body}))
    peak = _run(rows, C.CalibrationConfig(margin_pct=25, basis="peak"))
    p95 = _run(rows, C.CalibrationConfig(margin_pct=10, basis="p95"))
    assert peak["recommendation"]["basis_qb"] == peak["per_coalition"]["peak_qb"]
    assert peak["recommendation"]["budget_qb"] == C.with_margin(peak["per_coalition"]["peak_qb"], 25)
    assert peak["recommendation"]["coalitions_over"] == 0 and peak["recommendation"]["events_over"] == 0
    assert p95["recommendation"]["basis_qb"] == p95["per_coalition"]["p95_qb"] < p95["per_coalition"]["peak_qb"]
    assert p95["recommendation"]["budget_qb"] == C.with_margin(p95["per_coalition"]["p95_qb"], 10)
    assert p95["recommendation"]["budget_bits"] == C.qb_as_bits(p95["recommendation"]["budget_qb"])
    assert p95["recommendation"]["coalitions_over"] >= 1
    big = _run([_call(i * 1000, "s", "send_email", {"body": str(i) * 400}) for i in range(40)])
    assert big["recommendation"]["budget_qb"] > MAX_BUDGET_QB
    assert big["recommendation"]["within_ledger_limit"] is False
    assert "cannot be configured" in C.render_text(big)


def test_the_replay_store_limit_is_reported_and_spend_keeps_counting():
    doc = _run([_call(i * 1000, "s", "report_metric", {"v": 1}, destination="mcp:metrics") for i in range(300)],
               manifest=MANIFEST)
    assert doc["rows"]["charged"] == 300
    assert doc["replay_capacity"] == [{"coalition": doc["top_coalitions"][0]["coalition"], "at_outbound_event": 257}]
    assert "replay store" in C.render_text(doc)


def test_ids_are_hashed_unless_asked_for():
    rows = [_call(0, "customer-session-1", "send_email", {"body": "hi"})]
    hidden = _run(rows)
    assert "customer-session-1" not in json.dumps(hidden)
    assert len(hidden["top_sessions"][0]["session"]) == 16
    assert _run(rows, C.CalibrationConfig(show_ids=True))["top_sessions"][0]["session"] == "customer-session-1"


def test_rejected_rows_are_listed_without_their_content():
    lines = [
        json.dumps(_call(0, "s", "send_email", {"body": "ok"})),
        "{not json SECRET-VALUE",
        json.dumps({"ts_ms": 1, "tool": "x", "arguments": {"k": "SECRET-VALUE"}}),
        json.dumps({"ts_ms": -1, "session": "s", "tool": "x"}),
        json.dumps({"link": ["s"], "source": "delegation"}),
        json.dumps({"link": ["s", "t"], "source": "telepathy"}),
        json.dumps({"session": "s", "tool": "x", "arguments": []}),
        json.dumps({"session": "s", "message": {"method": "tools/list"}}),
        "",
    ]
    rows, rejected, skipped = C.read_trace(lines)
    assert len(rows) == 1 and skipped == 1
    assert [item["line"] for item in rejected] == [2, 3, 4, 5, 6, 7]
    assert "SECRET-VALUE" not in json.dumps(rejected)


@pytest.mark.parametrize("doc", [
    [], {"zdict_hex": "zz"}, {"eligible": [["d"]]}, {"schemas": {"t": {}}},
    {"schemas": {"t": {"v": {"enum": 0}}}}, {"schemas": {"t": {"v": "float"}}},
    {"zdict_hex": "00" * 40000},
])
def test_a_bad_manifest_is_refused(doc):
    with pytest.raises(C.TraceError):
        C.load_attachment(doc)


@pytest.mark.parametrize("kwargs", [
    {"budget_qb": -1}, {"budget_qb": MAX_BUDGET_QB + 1}, {"slot_ms": 0}, {"margin_pct": -5},
    {"basis": "mean"}, {"charge": "never"}, {"margin_pct": True},
])
def test_a_bad_config_is_refused(kwargs):
    with pytest.raises(C.TraceError):
        C.CalibrationConfig(**kwargs)


def test_cli_prints_the_summary_and_json(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("AGENT_GATEWAY_HMAC_KEY", raising=False)
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(row) for row in [
        _call(0, "a", "report_metric", {"v": 3}, destination="mcp:metrics"),
        _call(1000, "a", "send_email", {"body": "hello"}),
    ]) + "\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
    assert main(["p3-calibrate", str(trace), "--manifest", str(manifest), "--margin-pct", "50"]) == 0
    text = capsys.readouterr().out
    assert "Recommended budget" in text and "50% margin" in text
    for label in C.COMPONENT_LABELS.values():
        assert label in text
    assert main(["p3-calibrate", str(trace), "--manifest", str(manifest), "--json", "--basis", "p95"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == C.SCHEMA and doc["recommendation"]["basis"] == "p95"
    assert [item["component"] for item in doc["components"]] == list(C.COMPONENTS)
    with trace.open("a", encoding="utf-8") as handle:
        handle.write("oops\n")
    assert main(["p3-calibrate", str(trace)]) == 1
    assert "line 3 rejected: not JSON" in capsys.readouterr().out
    assert main(["p3-calibrate", str(tmp_path / "missing.jsonl")]) == 2
    assert main(["p3-calibrate", str(trace), "--budget-qb", "-4"]) == 2
    manifest.write_text("{", encoding="utf-8")
    assert main(["p3-calibrate", str(trace), "--manifest", str(manifest)]) == 2


def test_the_module_states_the_timing_scope():
    assert ("Regular-rhythm timing beacons are flagged; irregular timing channels are not yet bounded."
            in " ".join((C.__doc__ or "").split()))
