import json
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from rogue_detect.alerts import ATLAS, Alert, AlertLog
from rogue_detect.evaluate import evaluate
from rogue_detect.features import group_by_agent
from rogue_detect.intel import to_stix_bundle, validate_report
from rogue_detect.monitor import replay
from rogue_detect.pipeline import analyze
from rogue_detect.synthetic import ROGUE_ROLES, generate
from rogue_detect.web import make_server, serve_forever_in_thread


def test_end_to_end_planted_roles(analysis, dataset):
    _, roles = dataset
    ev = evaluate(analysis, roles)
    assert ev["fused_pipeline"]["recall"] >= 0.9, ev
    assert ev["fused_pipeline"]["precision"] >= 0.9, ev
    # fused pipeline should beat the unsupervised baseline on this synthetic data
    assert ev["fused_pipeline"]["f1"] > ev["isolation_forest_only"]["f1"]


def test_hard_negatives_are_not_escalated(analysis, dataset):
    _, roles = dataset
    hard = {a for a, r in roles.items() if r.startswith("benign_")}
    for al in analysis.alerts:
        if al.severity in ("medium", "high"):
            assert not (set(al.subjects) & hard), al.summary
    sched = [al for al in analysis.alerts if al.kind == "scheduled_sync"]
    assert sched and sched[0].severity == "info"


def test_isolation_forest_alone_is_capped_at_low(analysis):
    for al in analysis.alerts:
        if al.kind == "behavior_anomaly":
            assert al.severity == "low"


def test_alerts_have_explanations_and_valid_atlas_tags(analysis):
    for al in analysis.alerts:
        assert al.synthetic and al.summary
        for t in al.atlas:
            assert t["id"] in ATLAS and t["url"].endswith(t["id"])


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_other_seeds(seed):
    events, roles = generate(seed)
    ev = evaluate(analyze(events), roles)
    assert ev["fused_pipeline"]["recall"] >= 0.8 and ev["fused_pipeline"]["precision"] >= 0.8


def test_stealth_variant_runs_and_is_harder():
    events, roles = generate(7, stealth=True)
    std_events, _ = generate(7)
    stealth_ev = evaluate(analyze(events), roles)
    std_ev = evaluate(analyze(std_events), roles)
    assert stealth_ev["fused_pipeline"]["recall"] < std_ev["fused_pipeline"]["recall"]  # evasion works: documented
    assert stealth_ev["fused_pipeline"]["false_positives"] == 0


def test_alert_log_hash_chain_detects_tampering(tmp_path):
    log = AlertLog(str(tmp_path / "l.jsonl"))
    for i in range(3):
        log.append(Alert(f"AL-{i}", 1.0 + i, "access_probe", "high", [f"agent-{i}"], 0.5, "s"))
    assert log.verify() is None and len(log.read()) == 3
    lines = (tmp_path / "l.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["alert"]["severity"] = "low"
    lines[1] = json.dumps(rec)
    (tmp_path / "l.jsonl").write_text("\n".join(lines) + "\n")
    assert AlertLog(str(tmp_path / "l.jsonl")).verify() == 2
    # deletion of a record is also detected
    (tmp_path / "l.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert AlertLog(str(tmp_path / "l.jsonl")).verify() == 2


def test_alert_log_dedup_and_reload(tmp_path, analysis):
    p = str(tmp_path / "l.jsonl")
    log = AlertLog(p)
    for al in analysis.alerts:
        log.append(al)
    log2 = AlertLog(p)
    assert all(log2.has(al) for al in analysis.alerts) and log2.verify() is None


def test_monitor_replay_emits_and_dedups(tmp_path, dataset):
    events, _ = dataset
    log = AlertLog(str(tmp_path / "m.jsonl"))
    seen = []
    out = replay(events, log, window_s=3 * 3600, step_s=3600, min_severity="medium",
                 on_alert=lambda a, t: seen.append(a.key()))
    assert out and len(seen) == len(set(seen)) and log.verify() is None
    assert any(a.kind == "access_probe" for a in out)


def test_stix_bundle_shape(analysis):
    b = to_stix_bundle(analysis.alerts, "medium")
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    assert b["objects"][0]["type"] == "identity"
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    assert inds
    for o in inds:
        assert o["spec_version"] == "2.1" and o["pattern_type"] == "stix" and o["pattern"].startswith("[")
        assert o["x_synthetic"] is True and "synthetic-example" in o["labels"]
        assert o["id"].startswith("indicator--") and o["valid_from"].endswith("Z")


@pytest.mark.parametrize("form,msg", [
    ({"agent_ref": "", "description": "x" * 30, "category": "other"}, "required"),
    ({"agent_ref": "a", "description": "short", "category": "other"}, "Description"),
    ({"agent_ref": "a", "description": "y" * 30, "category": "bogus"}, "category"),
    ({"agent_ref": "a", "description": "y" * 30, "category": "other", "evidence_url": "javascript:alert(1)"}, "http"),
    ({"agent_ref": "a", "description": "my api_key=sk-12345 leaked in logs ok", "category": "other"}, "credential"),
    ({"agent_ref": "a", "description": "contact bob@example.com about this agent", "category": "other"}, "email"),
])
def test_report_validation_rejects(form, msg):
    with pytest.raises(ValueError) as e:
        validate_report(form)
    assert msg.lower() in str(e.value).lower()


@pytest.fixture()
def server(tmp_path, analysis, dataset):
    events, roles = dataset
    log = AlertLog(str(tmp_path / "a.jsonl"))
    for al in analysis.alerts:
        log.append(al)
    import os
    docs = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")
    state = {"analysis": analysis, "roles": roles, "by_agent": group_by_agent(events), "log": log,
             "reports_path": str(tmp_path / "reports.jsonl"), "docs_dir": docs}
    srv = make_server(state, "127.0.0.1", 0)
    serve_forever_in_thread(srv)
    yield f"http://127.0.0.1:{srv.server_address[1]}", state
    srv.shutdown()
    srv.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, r.read().decode(), r.headers


def test_web_dashboard_and_api(server):
    base, _ = server
    s, body, h = _get(base + "/")
    assert s == 200 and "SYNTHETIC DATA ONLY" in body and "<svg" in body and "collusion_cluster" in body
    assert "default-src 'none'" in h["Content-Security-Policy"]
    s, body, _ = _get(base + "/api/alerts")
    data = json.loads(body)
    assert s == 200 and data and all(a["synthetic"] for a in data)
    assert json.loads(_get(base + "/api/verify")[1]) == {"intact": True}
    assert json.loads(_get(base + "/api/cases")[1])
    s, body, _ = _get(base + "/resources")
    assert "ethics_and_compliance.md" in body
    s, body, _ = _get(base + "/resources/responsible_disclosure.md")
    assert s == 200 and "disclosure" in body.lower()


def test_web_blocks_path_traversal_and_unknown(server):
    base, _ = server
    for path in ("/resources/..%2fREADME.md", "/resources/../run.py", "/nope"):
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(base + path)
        assert e.value.code == 404


def _post(url, form):
    data = urllib.parse.urlencode(form).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_web_report_submission_and_escaping(server):
    base, state = server
    ok = {"agent_ref": "agent-054", "category": "unauthorized_access",
          "description": "Observed repeated denied requests to admin paths in a short burst.",
          "evidence_url": "https://example.invalid/e"}
    code, body = _post(base + "/report", ok)
    assert code == 200 and "Stored locally" in body
    saved = [json.loads(l) for l in open(state["reports_path"])]
    assert len(saved) == 1 and saved[0]["status"] == "unreviewed"
    xss = dict(ok, agent_ref="<script>alert(1)</script>", description="d" * 5)
    code, body = _post(base + "/report", xss)
    assert code == 400 and "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body
    code, _ = _post(base + "/report", dict(ok, description="z" * 30000))
    assert code in (400, 413)
