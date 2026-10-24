"""Hash-chained decision log, audit_manifest.json, and `verify`. Offline, no sockets."""
from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

from agent_gateway import audit_chain
from agent_gateway.audit_chain import GENESIS, MANIFEST_NAME, ChainWriter, verify_audit_dir, verify_chain_file
from agent_gateway.cli import main
from agent_gateway.pep import _AGW1_RE, PolicyEngine
from tests.conftest import KEY_A

FIX = Path(__file__).parent / "fixtures" / "audit" / "access-jsonl"


def _forbid_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args, **_kwargs):
        raise AssertionError("audit opened a socket")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


def _drive(engine: PolicyEngine) -> None:
    engine.evaluate_call(KEY_A, "c1", "read_internal_secrets", {})
    engine.evaluate_call(KEY_A, "c1", "read_external_url", {"url": "http://127.0.0.1/p"})
    engine.evaluate_call(KEY_A, "c1", "send_email", {"to": "a@b.c", "body": "x"})
    engine.evaluate_call(KEY_A, "c1", "search_external_kb", {"query": "secret_value_123"})


def _lines(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_pep_decision_log_is_hash_chained(engine: PolicyEngine):
    _drive(engine)
    entries = _lines(engine.alert_path)
    assert len(entries) >= 3
    assert [e["seq"] for e in entries] == list(range(len(entries)))
    assert entries[0]["prev_hash"] == GENESIS
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["entry_hash"]
    assert {e["kind"] for e in entries} >= {"policy_deny", "approval_webhook"}
    rep = verify_chain_file(engine.alert_path)
    assert rep.ok and rep.entries == len(entries) and rep.head_hash == entries[-1]["entry_hash"]
    text = engine.alert_path.read_text(encoding="utf-8")
    assert '"mac":' not in text  # live callback MACs are fingerprinted, not logged
    assert not _AGW1_RE.search(text)  # agw1. signatures are not logged


def test_chain_resumes_after_restart(tmp_path: Path):
    path = tmp_path / "alerts.jsonl"
    w = ChainWriter(path)
    w.append({"kind": "a"})
    w.append({"kind": "b"})
    w2 = ChainWriter(path)
    assert w2.seq == 2
    w2.append({"kind": "c"})
    rep = verify_chain_file(path)
    assert rep.ok and rep.entries == 3


@pytest.mark.parametrize("attack", ["edit", "drop_middle", "swap", "insert", "rehash_one"])
def test_chain_tamper_detected(tmp_path: Path, attack: str):
    path = tmp_path / "alerts.jsonl"
    w = ChainWriter(path)
    for i in range(5):
        w.append({"kind": "policy_deny", "step": i, "error": "post_taint_outbound_gated"})
    lines = path.read_text(encoding="utf-8").splitlines()
    if attack == "edit":
        e = json.loads(lines[2]); e["error"] = "allowed"; lines[2] = json.dumps(e)
    elif attack == "drop_middle":
        del lines[2]
    elif attack == "swap":
        lines[1], lines[2] = lines[2], lines[1]
    elif attack == "insert":
        lines.insert(2, json.dumps({"kind": "forged", "seq": 2, "prev_hash": GENESIS, "entry_hash": GENESIS}))
    else:
        # Recompute this entry's own hash: the next prev_hash still breaks.
        e = json.loads(lines[2]); e["error"] = "allowed"; lines[2] = json.dumps(audit_chain.link(e, 2, e["prev_hash"]))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_chain_file(path).ok is False


def _audit(tmp_path: Path, engine: PolicyEngine) -> Path:
    _drive(engine)
    src = tmp_path / "analyzer-out"
    shutil.copytree(FIX, src)
    out = tmp_path / "report"
    code = main(["audit", str(src), "--out-dir", str(out), "--decision-log", str(engine.alert_path)])
    assert code == 0
    return out


def test_audit_writes_manifest_and_verify_passes(tmp_path: Path, engine: PolicyEngine,
                                                 monkeypatch: pytest.MonkeyPatch, capsys):
    out = _audit(tmp_path, engine)
    _forbid_connect(monkeypatch)
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["schema"] == "agent-gateway.audit-manifest/1"
    for name in ("findings.json", "replay.html", "decision-log.jsonl", "audit-report.html",
                 "audit-report.json", "audit-report.pdf"):
        assert name in manifest["files"], name
    assert manifest["decision_log"]["ok"] is True
    assert manifest["decision_log"]["entries"] == len(_lines(engine.alert_path))
    assert "Not a certification" in manifest["note"]
    capsys.readouterr()
    assert main(["verify", str(out)]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["ok"] is True
    names = {c["check"] for c in res["checks"]}
    assert {"manifest_hmac", "decision_log_chain", "decision_log_head",
            "file:findings.json", "file:replay.html"} <= names


@pytest.mark.parametrize("target", ["findings.json", "replay.html", "decision-log.jsonl"])
def test_verify_detects_tampered_file(tmp_path: Path, engine: PolicyEngine, target: str, capsys):
    out = _audit(tmp_path, engine)
    path = out / target
    path.write_text(path.read_text(encoding="utf-8").replace("a", "b", 1) + " ", encoding="utf-8")
    capsys.readouterr()
    assert main(["verify", str(out)]) == 1
    res = json.loads(capsys.readouterr().out)
    failed = {c["check"] for c in res["checks"] if not c["ok"]}
    assert f"file:{target}" in failed


def test_verify_detects_truncated_log_and_forged_manifest(tmp_path: Path, engine: PolicyEngine):
    out = _audit(tmp_path, engine)
    log = out / "decision-log.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # chain still links, tail gone
    res = verify_audit_dir(out)
    failed = {c["check"] for c in res["checks"] if not c["ok"]}
    assert "decision_log_head" in failed and "decision_log_chain" not in failed

    # Re-digesting the files without the root key fails the manifest HMAC.
    out2 = _audit(tmp_path / "second", engine)
    (out2 / "findings.json").write_text("[]", encoding="utf-8")
    forged = audit_chain.build_manifest(out2, decision_log=out2 / "decision-log.jsonl", key=b"attacker-key")
    (out2 / MANIFEST_NAME).write_text(json.dumps(forged), encoding="utf-8")
    res2 = verify_audit_dir(out2)
    failed2 = {c["check"] for c in res2["checks"] if not c["ok"]}
    assert failed2 == {"manifest_hmac"}


def test_verify_flags_extra_and_missing_files(tmp_path: Path, engine: PolicyEngine):
    out = _audit(tmp_path, engine)
    (out / "injected.html").write_text("<p>new</p>", encoding="utf-8")
    (out / "replay.html").unlink()
    res = verify_audit_dir(out)
    failed = {c["check"]: c["detail"] for c in res["checks"] if not c["ok"]}
    assert failed["file:injected.html"] == "not listed in manifest"
    assert failed["file:replay.html"] == "missing"


def test_verify_without_manifest(tmp_path: Path, capsys):
    assert main(["verify", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["checks"][0]["check"] == "manifest"


def test_audit_without_decision_log_still_verifies(tmp_path: Path, capsys):
    out = tmp_path / "report"
    assert main(["audit", str(FIX), "--out-dir", str(out), "--no-pdf"]) == 0
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["decision_log"] is None
    capsys.readouterr()
    assert main(["verify", str(out)]) == 0
    assert main(["audit", str(FIX), "--out-dir", str(out), "--decision-log", str(tmp_path / "nope")]) == 2
