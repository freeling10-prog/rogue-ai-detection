"""Cross-session file labels and shell-redirect provenance.

These reproduce the loss where session 1 writes an UNTRUSTED file and a new
process, session 2, treats it as (PUBLIC, TRUSTED). They fail if labels stay
in session memory or if a redirection is not entered in the lineage ledger.
"""
from __future__ import annotations

import json

from agent_gateway.fs_label_store import TOP, FsLabelStore
from agent_gateway.pep import FS_LABEL_FLOW_DENIED, PepConfig, PolicyEngine
from agent_gateway.registry import Registry
from agent_gateway.symbolic_fs_transducer import FileLabel, FsTransducer, Integrity
from agent_gateway.taint import SharedState
from agent_gateway.workspace_path_validator import Node, Snapshot
from tests.conftest import KEY_A, REG


def filesystem() -> dict[str, Node]:
    return {"/ws": Node("dir"), "/ws/out": Node("dir"),
            "/ws/out/a": Node("file", (1, 1)), "/ws/out/b": Node("file", (1, 4)),
            "/ws/out/c": Node("file", (1, 5)), "/ws/.mcp.json": Node("file", (1, 2))}


def make_engine(state_dir) -> PolicyEngine:
    cfg = PepConfig(registry_path=REG, alert_log=state_dir / "alerts.jsonl")
    return PolicyEngine(Registry.load(REG), shared=SharedState(), cfg=cfg)


def test_untrusted_redirect_survives_a_new_process(state_dir):
    first = make_engine(state_dir)
    writer = first.attach_fs_transducer("s1", filesystem())
    writer.observe_untrusted()
    written = first.evaluate_call(KEY_A, "s1", "run_shell", {"command": "echo x > out/b"})
    assert written["allowed"] is True
    assert writer.label_at("out/b").integrity is Integrity.UNTRUSTED
    # A redirection-only command is a write, not an unmodeled shell.
    redirected = first.evaluate_call(KEY_A, "s1", "run_shell", {"command": ": > out/c"})
    assert redirected["allowed"] is True
    assert writer.label_at("out/c").integrity is Integrity.UNTRUSTED

    for path in ("/ws/out/b", "/ws/out/c"):
        lineage = first.provenance.evaluate_read(path, 0)
        assert lineage.effective_taint > 0
        assert lineage.verdict_code == "PROVENANCE_TAINT_INHERITED"
        assert lineage.writer_session_id == "s1"

    # New process: nothing in memory except what the sidecar and the ledger reload.
    second = make_engine(state_dir)
    reader = second.attach_fs_transducer("s2", filesystem())
    assert reader.label_at("/ws/out/b").integrity is Integrity.UNTRUSTED
    assert reader.label_at("out/c").integrity is Integrity.UNTRUSTED

    executed = second.evaluate_call(KEY_A, "s2", "run_script", {"path": "/ws/out/b"})
    assert executed["allowed"] is False
    assert executed["rule_code"] == FS_LABEL_FLOW_DENIED
    assert executed["fs_label"]["reason"] == "UNTRUSTED_SOURCE_TO_EXEC_SINK"

    looked = second.evaluate_call(KEY_A, "s2", "lookup_order_status", {"path": "/ws/out/c"})
    assert looked["allowed"] is True
    assert second.sessions["s2"].tainted is True

    egress = second.evaluate_call(KEY_A, "s2", "send_email",
                                  {"to": "ops@example.com", "body": "weekly", "path": "/ws/out/b"})
    assert egress["allowed"] is False
    assert egress["error"] == "post_taint_outbound_gated"


def test_post_epoch_file_with_no_record_is_untrusted(state_dir, tmp_path):
    real = tmp_path / "workspace"
    (real / "out").mkdir(parents=True)
    target = real / "out" / "b"
    engine = make_engine(state_dir)
    transducer = engine.attach_fs_transducer("s-disk", filesystem(), real_root=str(real))
    # Written after the store epoch, never committed by the gateway.
    target.write_text("planted by something else")
    assert transducer.label_at("/ws/out/b").integrity is Integrity.UNTRUSTED
    denied = engine.evaluate_call(KEY_A, "s-disk", "run_script", {"path": "/ws/out/b"})
    assert denied["allowed"] is False and denied["rule_code"] == FS_LABEL_FLOW_DENIED


def test_recorded_bytes_stay_trusted_until_they_change(tmp_path):
    real = tmp_path / "workspace"
    (real / "out").mkdir(parents=True)
    target = real / "out" / "b"
    target.write_text("version-one")
    store = FsLabelStore(tmp_path / "labels", "/ws", epoch_ns=1)
    store.bind_real_root(real)
    ident = store.content_identity("/ws/out/b")
    assert ident is not None and ident.sha256
    store.record(("path", "/ws/out/b"), FileLabel(), content=ident)
    transducer = FsTransducer(Snapshot(filesystem()), store=store)
    assert transducer.label_at("/ws/out/b").integrity is Integrity.TRUSTED
    target.write_text("version-two")
    assert transducer.label_at("/ws/out/b").integrity is Integrity.UNTRUSTED


def test_pre_epoch_file_keeps_the_model_default(tmp_path):
    real = tmp_path / "workspace"
    (real / "out").mkdir(parents=True)
    target = real / "out" / "b"
    target.write_text("already here")
    store = FsLabelStore(tmp_path / "labels", "/ws", epoch_ns=10**20)
    store.bind_real_root(real)
    assert store.content_label("/ws/out/b") is None
    assert store.verify() is True


def test_tampered_label_chain_fails_closed(tmp_path):
    store = FsLabelStore(tmp_path / "labels", "/ws", epoch_ns=1)
    chain = store.chain_path
    chain.write_text(chain.read_text(encoding="utf-8").replace('"kind":"epoch"', '"kind":"nope"', 1))
    reloaded = FsLabelStore(tmp_path / "labels", "/ws")
    assert reloaded.tampered is True
    assert reloaded.floor_label() == TOP
    assert reloaded.verify() is False
    index = json.loads((tmp_path / "labels" / "index.json").read_text(encoding="utf-8"))
    assert index["schema"] == "agent-gateway.fs-label-chain/1"
    assert "entry_hash" in chain.read_text(encoding="utf-8")
