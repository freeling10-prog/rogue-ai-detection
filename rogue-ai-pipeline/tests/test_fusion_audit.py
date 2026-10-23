"""Fusion guardrails (leads for human review only) and the hash-chained audit log."""
import ast
import json
import re
from pathlib import Path

import pytest

from rogue_pipeline.audit import GENESIS, AuditLog, verify_log
from rogue_pipeline.config import Config, FusionCfg
from rogue_pipeline.fusion import Lead, fuse
from rogue_pipeline.layer1_anomaly import AgentAnomaly
from rogue_pipeline.layer2_rules import EvidenceEvent, RuleFlag
from rogue_pipeline.layer3_graph import Cluster, EdgeInfo

PKG = Path(__file__).resolve().parents[1] / "rogue_pipeline"


def flag(agent="ag_x", strength=0.8):
    return RuleFlag("R3", "t", agent, [{"id": "AML.T0086", "name": "n", "url": "u"}], strength, "e", [EvidenceEvent("e1", 1.0, "s")])


def lead_kwargs(**over):
    kw = dict(lead_id="l", agent="ag_x", score=0.9, priority_band="review", components={}, anomaly_explanations=[],
              rule_flags=[flag()], cluster=None)
    kw.update(over)
    return kw


# ---- guardrails -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("field,value", [("severity", "high"), ("severity", "critical"), ("recommended_action", "block"),
                                         ("automatic_action", "block"), ("automatic_action", "throttle"), ("recommended_action", "terminate")])
def test_lead_cannot_be_constructed_with_automatic_or_high_severity(field, value):
    with pytest.raises(ValueError):
        Lead(**lead_kwargs(**{field: value}))


def test_lead_requires_corroboration_beyond_anomaly_score():
    with pytest.raises(ValueError):
        Lead(**lead_kwargs(rule_flags=[], cluster=None))


def test_lead_is_immutable():
    l = Lead(**lead_kwargs())
    with pytest.raises(Exception):
        l.severity = "high"


def test_anomaly_alone_never_creates_a_lead_even_at_maximum_score():
    an = {"ag_x": AgentAnomaly("ag_x", 0.9, 1.0, True)}
    assert fuse(FusionCfg(), an, [], []) == []
    # even with every weight maxed except the guardrail-bound anomaly weight
    assert fuse(FusionCfg(w_anomaly=0.54), an, [], []) == []


def test_config_rejects_anomaly_weight_that_could_create_leads_alone():
    with pytest.raises(ValueError):
        FusionCfg(w_anomaly=0.55, lead_threshold=0.55)
    with pytest.raises(ValueError):
        FusionCfg(w_anomaly=0.9)


def test_corroborated_agent_becomes_a_low_severity_human_review_lead():
    an = {"ag_x": AgentAnomaly("ag_x", 0.9, 0.9, True)}
    leads = fuse(FusionCfg(), an, [flag()], [])
    assert len(leads) == 1
    l = leads[0]
    assert (l.severity, l.recommended_action, l.automatic_action) == ("low", "human_review", "none")
    assert "human review" in l.disclaimer.lower() and "approximate" in l.disclaimer.lower()
    assert l.to_dict()["automatic_action"] == "none"


def test_suppressed_clusters_do_not_contribute():
    cl = Cluster(["ag_x", "ag_y"], 1.0, 1.0, [EdgeInfo("ag_x", "ag_y", 20, 10, 1.0, 1.0, 1.0)], suppressed=True)
    assert fuse(FusionCfg(), {}, [], [cl]) == []
    cl.suppressed = False
    assert {l.agent for l in fuse(FusionCfg(), {}, [], [cl])} == {"ag_x", "ag_y"}


def test_graph_density_alone_can_lead_and_scores_are_ordered():
    cl = Cluster(["ag_x", "ag_y"], 0.9, 0.9, [])
    leads = fuse(FusionCfg(), {}, [flag("ag_z", 0.8)], [cl])
    assert [l.score for l in leads] == sorted([l.score for l in leads], reverse=True)


def test_end_to_end_all_leads_are_low_severity_and_uncontrolled(pipeline_run):
    res, _ = pipeline_run
    assert res.leads
    assert {(l.severity, l.recommended_action, l.automatic_action) for l in res.leads} == {("low", "human_review", "none")}
    for l in res.leads:
        assert l.rule_flags or l.cluster


def test_ifonly_flagged_agents_exist_but_have_no_lead(pipeline_run):
    res, inv = pipeline_run
    only_if = res.anomaly.flagged - res.lead_agents()
    assert only_if, "the synthetic data contains benign anomalous agents (crawlers, scanners)"
    assert all(a not in res.lead_agents() for a in only_if)


def test_package_has_no_blocking_or_enforcement_code_path():
    """Static check: no function/class/attribute names that suggest enforcement against an agent."""
    forbidden = re.compile(r"(?i)\b(block|ban|terminate|kill|revoke|quarantine_agent|throttle|disable_agent|suspend)(_|\b)")
    allowed_context = {"write_quarantine", "QuarantineRecord", "quarantined", "quarantine_path"}
    offenders = []
    for path in PKG.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names.append(node.name)
            elif isinstance(node, ast.Attribute):
                names.append(node.attr)
            elif isinstance(node, ast.Name):
                names.append(node.id)
            for n in names:
                if forbidden.search(n) and n not in allowed_context:
                    offenders.append((path.name, n))
    assert offenders == []


def test_package_has_no_network_imports():
    banned = {"socket", "requests", "urllib", "http", "httpx", "aiohttp", "ftplib", "smtplib", "websocket", "websockets", "paramiko"}
    for path in list(PKG.glob("*.py")) + [PKG.parent / "run.py"]:
        for node in ast.walk(ast.parse(path.read_text())):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            for m in mods:
                assert m.split(".")[0] not in banned, f"{path.name} imports {m}"


# ---- audit log ------------------------------------------------------------------------------------------
@pytest.fixture
def log(tmp_path):
    lg = AuditLog(tmp_path / "audit.jsonl")
    for i in range(6):
        lg.append("lead", {"i": i, "note": "x" * i})
    return lg


def test_fresh_log_verifies_and_chain_links(log):
    r = verify_log(log.path)
    assert r.ok and r.records == 6 and r.head == log.head
    recs = [json.loads(l) for l in log.path.read_text().splitlines()]
    assert recs[0]["prev"] == GENESIS and all(recs[i]["prev"] == recs[i - 1]["hash"] for i in range(1, 6))


def test_modifying_a_record_is_detected_and_located(log):
    lines = log.path.read_text().splitlines()
    lines[3] = lines[3].replace('"i": 3', '"i": 99')
    log.path.write_text("\n".join(lines) + "\n")
    r = verify_log(log.path)
    assert not r.ok and "line 4" in r.message and "modified" in r.message


def test_deleting_inserting_and_reordering_are_detected(log):
    lines = log.path.read_text().splitlines()
    for mutated in (lines[:2] + lines[3:], lines[:3] + [lines[2]] + lines[3:], lines[:2] + [lines[3], lines[2]] + lines[4:]):
        log.path.write_text("\n".join(mutated) + "\n")
        assert not verify_log(log.path).ok
    log.path.write_text("\n".join(lines) + "\n")
    assert verify_log(log.path).ok


def test_rehashing_a_modified_record_still_breaks_the_next_link(log):
    import hashlib
    lines = [json.loads(l) for l in log.path.read_text().splitlines()]
    lines[2]["payload"]["i"] = 777
    body = {k: lines[2][k] for k in ("seq", "ts", "kind", "payload", "prev")}
    lines[2]["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    log.path.write_text("\n".join(json.dumps(l, sort_keys=True) for l in lines) + "\n")
    r = verify_log(log.path)
    assert not r.ok and "line 4" in r.message


def test_tail_truncation_detected_via_head_file_and_anchor(log):
    anchor = log.head
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:4]) + "\n")
    r = verify_log(log.path)
    assert not r.ok and "truncated" in r.message
    Path(str(log.path) + ".head").unlink()                     # attacker also removes the head file ...
    assert verify_log(log.path).ok                             # ... chain alone cannot tell (documented limitation)
    assert not verify_log(log.path, anchor=anchor).ok          # ... but an externally stored anchor does


def test_garbage_and_missing_files(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("not json\n")
    assert not verify_log(p).ok
    assert not verify_log(tmp_path / "missing.jsonl").ok


def test_appending_continues_the_chain_and_refuses_tampered_logs(log):
    lg2 = AuditLog(log.path)
    lg2.append("lead", {"i": 6})
    assert verify_log(log.path).records == 7
    lines = log.path.read_text().splitlines()
    lines[1] = lines[1].replace('"kind": "lead"', '"kind": "leaX"')
    log.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        AuditLog(log.path)


def test_pipeline_writes_verifiable_audit_log(tmp_path, sim, cfg, pseudo):
    from rogue_pipeline.pipeline import Pipeline
    lg = AuditLog(tmp_path / "a.jsonl")
    res = Pipeline(cfg, sim.policy, pseudo, lg).run(sim.all_items())
    r = verify_log(lg.path)
    recs = [json.loads(l) for l in lg.path.read_text().splitlines()]
    assert r.ok and recs[0]["kind"] == "run_start" and recs[-1]["kind"] == "run_end"
    assert sum(x["kind"] == "lead" for x in recs) == len(res.leads)
    assert any(x["kind"] == "suppressed_cluster" for x in recs)
    text = lg.path.read_text()
    assert not re.search(r"\b10\.\d+\.\d+\.\d+\b", text)                                   # no raw IPs in the log
    assert not any(a in text for a in ("assistant-0", "prober-1", "exfil-1", "ring1-m1"))   # no raw agent ids
