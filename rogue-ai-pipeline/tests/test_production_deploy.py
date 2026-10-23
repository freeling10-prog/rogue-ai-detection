"""Production key enforcement, the --production / PIPELINE_ENV switch, and deploy/sync_and_score.sh.

What is NOT tested here (see README): a real remote host, a real rsync/ssh transfer, Docker. The script tests use
the real script with stub `rsync`/`ssh`/`agentwatch` programs on PATH."""
import base64
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import run as cli
from rogue_pipeline.config import Config
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import (KeyConfigError, MissingKeyError, ProductionKeyError, Pseudonymizer, check_production_secret,
                                         decode_secret, production_requested, resolve_key)
from rogue_pipeline.simulator import build

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "sync_and_score.sh"
STRONG = secrets.token_hex(32)
DEV = "ROGUE_PIPELINE_HMAC_KEY"


# ---- the key policy ---------------------------------------------------------------------------------------------
def test_strong_secrets_are_accepted_in_hex_base64_and_text_forms():
    assert len(check_production_secret(secrets.token_hex(32))) == 32                                   # 64 hex chars -> 32 bytes
    assert len(check_production_secret(base64.b64encode(secrets.token_bytes(32)).decode())) == 32      # base64 -> 32 bytes
    assert len(check_production_secret(secrets.token_urlsafe(40))) >= 32                               # >= 32 chars of text


@pytest.mark.parametrize("bad,why", [
    (None, "not set"), ("", "not set"), ("   ", "not set"),
    ("short", "too short"), ("a1b2c3d4e5f6" * 2, "too short"),                      # 24 chars
    ("a" * 64, "entropy"), ("ab" * 32, "entropy"), ("x" * 40, "default"),           # all-same text
    ("changeme" * 6, "default"), ("ChangeMe-" + secrets.token_hex(16), "default"),
    ("test-" + secrets.token_hex(16), "default"), ("password" + secrets.token_hex(16), "default"),
    ("demo-key-" + secrets.token_hex(16), "default"), ("ephemeral-" + secrets.token_hex(16), "default"),
    ("unit-test-key-0123456789abcdef", "default"),
    ("abcdefghijklmnopqrstuvwxyzABCDEF", "pattern"),                                 # sequential run
    ("0123456789abcdef" * 4, "entropy"),                                             # repeated block (hex form)
])
def test_weak_or_default_looking_secrets_are_refused_with_a_clear_reason(bad, why):
    with pytest.raises(ProductionKeyError) as ei:
        check_production_secret(bad)
    msg = str(ei.value)
    assert "PIPELINE_HMAC_SECRET" in msg
    assert why in msg
    if bad and len(bad.strip()) > 12:
        assert bad not in msg                                                       # never echoes the secret


def test_the_ephemeral_selftest_and_dev_keys_are_never_acceptable_in_production():
    assert "selftest" in "selftest-" + "x" * 32
    for k in ("selftest-" + "x" * 32, "cli-test-key-" + "k" * 24):
        with pytest.raises(ProductionKeyError):
            check_production_secret(k)
    with pytest.raises(ProductionKeyError):                                          # a real-looking value reused as the dev key
        check_production_secret(STRONG, other_dev_key=STRONG)


def test_resolve_key_production_has_no_fallbacks():
    with pytest.raises(ProductionKeyError, match="not set"):
        resolve_key(DEV, production=True, env={DEV: STRONG})                          # dev key present, secret missing: NO fallback
    with pytest.raises(ProductionKeyError, match="ephemeral"):
        resolve_key(DEV, production=True, allow_ephemeral=True, env={"PIPELINE_HMAC_SECRET": STRONG})
    key, eph, mode = resolve_key(DEV, production=True, env={"PIPELINE_HMAC_SECRET": STRONG})
    assert (len(key), eph, mode) == (32, False, "production")


def test_both_variables_set_production_uses_secret_dev_uses_dev_key():
    other = secrets.token_hex(32)
    env = {"PIPELINE_HMAC_SECRET": STRONG, DEV: other}
    assert resolve_key(DEV, production=True, env=env)[0] == bytes.fromhex(STRONG)     # production: secret wins, dev key IGNORED
    assert resolve_key(DEV, production=False, env=env)[0] == other.encode()           # dev: the dev key wins
    assert resolve_key(DEV, production=False, env={"PIPELINE_HMAC_SECRET": STRONG})[2] == "dev"   # dev convenience fallback
    with pytest.raises(ProductionKeyError, match="equals the development key"):
        resolve_key(DEV, production=True, env={"PIPELINE_HMAC_SECRET": STRONG, DEV: STRONG})


def test_dev_mode_is_unchanged():
    with pytest.raises(MissingKeyError):
        resolve_key(DEV, env={})
    key, eph, mode = resolve_key(DEV, allow_ephemeral=True, env={})
    assert eph and mode == "dev" and len(key) == 32
    assert resolve_key(DEV, env={DEV: "dev-key-0123456789abcdef"})[0] == b"dev-key-0123456789abcdef"
    with pytest.raises(KeyConfigError):
        resolve_key(DEV, env={DEV: "tiny"})


def test_production_requested_by_flag_or_environment():
    assert production_requested(True, {}) and production_requested(False, {"PIPELINE_ENV": "Production"})
    assert not production_requested(False, {"PIPELINE_ENV": "dev"}) and not production_requested(False, {})


def test_decode_secret_forms():
    assert decode_secret("ab" * 32)[1] == "hex" and decode_secret("plain text secret")[1] == "text"


# ---- the pipeline and CLI refuse / start ---------------------------------------------------------------------------
def test_pipeline_object_refuses_production_without_a_validated_pseudonymizer():
    d = build(0, n_assistants=5)
    with pytest.raises(ProductionKeyError):
        Pipeline(Config(), d.policy, Pseudonymizer(b"k" * 32), production=True)           # right length, but not validated
    key, _, _ = resolve_key(DEV, production=True, env={"PIPELINE_HMAC_SECRET": STRONG})
    p = Pipeline(Config(), d.policy, Pseudonymizer(key, production_validated=True), production=True)
    assert p.production


def _events(tmp_path):
    cli.main(["generate", "--out", str(tmp_path / "d")])
    return str(tmp_path / "d/events.jsonl"), str(tmp_path / "d/policy.json")


@pytest.fixture
def clean_env(monkeypatch):
    for k in (DEV, "PIPELINE_HMAC_SECRET", "PIPELINE_ENV"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


@pytest.fixture(scope="module")
def tiny_events(tmp_path_factory):
    d = tmp_path_factory.mktemp("prod")
    assert cli.main(["generate", "--out", str(d)]) == 0
    return str(d / "events.jsonl"), str(d / "policy.json")


@pytest.mark.parametrize("env,expect", [
    ({}, "not set"),
    ({"PIPELINE_HMAC_SECRET": "short"}, "too short"),
    ({"PIPELINE_HMAC_SECRET": "changeme" * 6}, "default"),
    ({"PIPELINE_HMAC_SECRET": "a" * 64}, "entropy"),
    ({DEV: STRONG}, "not set"),                                            # dev key alone is NOT enough in production
])
def test_cli_production_refuses_to_start_without_a_strong_secret(clean_env, tmp_path, tiny_events, capsys, env, expect):
    for k, v in env.items():
        clean_env.setenv(k, v)
    out = tmp_path / "o"
    rc = cli.main(["detect", "--production", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(out)])
    err = capsys.readouterr().err
    assert rc == 6 and "production mode refused to start" in err and expect in err
    assert not (out / "leads.json").exists()                               # fails BEFORE any processing


def test_cli_production_rejects_ephemeral_key_even_with_a_strong_secret(clean_env, tmp_path, tiny_events, capsys):
    clean_env.setenv("PIPELINE_HMAC_SECRET", STRONG)
    rc = cli.main(["detect", "--production", "--ephemeral-key", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(tmp_path / "o")])
    assert rc == 6 and "ephemeral" in capsys.readouterr().err


def test_cli_pipeline_env_production_has_the_same_effect_as_the_flag(clean_env, tmp_path, tiny_events, capsys):
    clean_env.setenv("PIPELINE_ENV", "production")
    clean_env.setenv(DEV, "dev-key-0123456789abcdef")                       # fine for dev, irrelevant in production
    rc = cli.main(["detect", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(tmp_path / "o")])
    assert rc == 6 and "PIPELINE_HMAC_SECRET" in capsys.readouterr().err


def test_cli_production_starts_with_a_strong_secret_and_ignores_the_dev_key(clean_env, tmp_path, tiny_events, capsys):
    clean_env.setenv("PIPELINE_HMAC_SECRET", STRONG)
    clean_env.setenv(DEV, "dev-key-0123456789abcdef")
    rc = cli.main(["detect", "--production", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 0 and "production mode" in out and "IGNORED" in out
    assert STRONG not in out and (tmp_path / "o/leads.json").exists()
    rec = json.loads((tmp_path / "o/audit.jsonl").read_text().splitlines()[0])
    assert rec["payload"]["production"] is True and rec["payload"]["ephemeral_key"] is False


def test_pseudonyms_differ_between_dev_and_production_keys(clean_env, tmp_path, tiny_events):
    clean_env.setenv(DEV, "dev-key-0123456789abcdef")
    cli.main(["detect", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(tmp_path / "dev")])
    clean_env.delenv(DEV)
    clean_env.setenv("PIPELINE_HMAC_SECRET", STRONG)
    cli.main(["detect", "--production", "--events", tiny_events[0], "--policy", tiny_events[1], "--out", str(tmp_path / "prod")])
    a = {l["agent"] for l in json.loads((tmp_path / "dev/leads.json").read_text())}
    b = {l["agent"] for l in json.loads((tmp_path / "prod/leads.json").read_text())}
    assert a and b and not (a & b)


def test_cli_dev_default_behaviour_unchanged_and_demo_flags_still_work(clean_env, tmp_path, capsys):
    clean_env.setenv(DEV, "dev-key-0123456789abcdef")
    assert cli.main(["demo", "--out", str(tmp_path)]) == 0
    assert "[key]" not in capsys.readouterr().out                           # dev mode prints nothing extra with a single dev key


def test_selftest_and_evaluate_refuse_production(clean_env, capsys):
    clean_env.setenv("PIPELINE_HMAC_SECRET", STRONG)
    assert cli.main(["selftest", "--production"]) == 6
    assert cli.main(["evaluate", "--production", "--seeds", "1"]) == 6


# ---- deploy/sync_and_score.sh ---------------------------------------------------------------------------------------
bash = shutil.which("bash")
pytestmark_script = pytest.mark.skipif(bash is None, reason="bash not available")


def _run_script(args, env, cwd=None, timeout=120):
    return subprocess.run([bash, str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=timeout, cwd=cwd)


@pytestmark_script
def test_script_dry_run_touches_nothing_and_needs_no_secrets(tmp_path):
    work = tmp_path / "work"
    env = {"PATH": "/usr/bin:/bin", "WORKDIR": str(work)}       # no ZONE_A_*, no secret, no rsync needed
    before = sorted(p.name for p in tmp_path.iterdir())
    r = _run_script(["--dry-run"], env, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "DRY RUN" in r.stdout and r.stdout.count("[dry-run] would run:") >= 4
    for needle in ("rsync", "--ignore-existing", "agentwatch analyze", "export-leads", "detect --production", "--baseline",
                   "verify-log", "export-stix", "--confirm", "history"[:0] + "anchor"):
        assert needle.replace(" ", "") in r.stdout.replace(" ", "").replace("\\", ""), needle
    assert not work.exists()                                      # nothing created
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert "--delete" not in r.stdout and "--remove-source-files" not in r.stdout


@pytestmark_script
def test_script_dry_run_does_not_print_the_secret_or_execute_anything(tmp_path):
    marker = tmp_path / "executed"
    stub = tmp_path / "bin"
    stub.mkdir()
    for name in ("rsync", "ssh", "python3"):
        f = stub / name
        f.write_text(f"#!/bin/sh\necho {name} >> {marker}\n")
        f.chmod(0o755)
    env = {"PATH": f"{stub}:/usr/bin:/bin", "WORKDIR": str(tmp_path / "w"), "PIPELINE_HMAC_SECRET": STRONG, "ZONE_A_HOST": "zone-a.invalid",
           "ZONE_A_USER": "pull", "ZONE_A_SSH_KEY": "/nonexistent", "ZONE_A_KNOWN_HOSTS": "/nonexistent", "ZONE_A_EXPORT_DIR": "/export",
           "PIPELINE_BASELINE": "/nonexistent", "ANCHOR_SSH_DEST": "anchor@anchor.invalid", "ANCHOR_SSH_KEY": "/nonexistent", "ANCHOR_REMOTE_FILE": "/a"}
    r = _run_script(["--dry-run"], env)
    assert r.returncode == 0 and not marker.exists()              # stubs never ran: dry run executes nothing
    assert STRONG not in r.stdout + r.stderr
    assert "zone-a.invalid" in r.stdout                           # hosts come from the environment, not the script


@pytestmark_script
def test_script_rejects_unknown_arguments_and_missing_required_env_in_real_mode(tmp_path):
    assert _run_script(["--wat"], {"PATH": "/usr/bin:/bin"}).returncode == 64
    r = _run_script([], {"PATH": "/usr/bin:/bin", "WORKDIR": str(tmp_path / "w")})
    assert r.returncode == 1 and "ZONE_A_HOST" in r.stderr and not (tmp_path / "w").exists()


@pytestmark_script
def test_script_has_strict_mode_pull_only_flags_and_no_hardcoded_hosts():
    text = SCRIPT.read_text()
    assert "set -euo pipefail" in text
    assert "--ignore-existing" in text and "--append-verify" in text and "-ro /var/lib" in text   # key restriction documented
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))      # comments may mention what is NOT used
    for forbidden in ("--delete", "--remove-source-files", "eval ", "StrictHostKeyChecking=no"):
        assert forbidden not in code, forbidden
    assert "StrictHostKeyChecking=yes" in code
    import re
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)                      # no literal IPs
    assert "--production" in text and "PIPELINE_ENV=production" in text


@pytestmark_script
@pytest.mark.skipif(shutil.which("shellcheck") is None and not (Path(sys.executable).parent / "shellcheck").exists(), reason="shellcheck not installed")
def test_script_passes_shellcheck():
    sc = shutil.which("shellcheck") or str(Path(sys.executable).parent / "shellcheck")
    r = subprocess.run([sc, "-x", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


@pytestmark_script
def test_script_end_to_end_with_stub_transfer_programs(tmp_path, monkeypatch):
    """The REAL script, real pipeline, STUB rsync/ssh/agentwatch (no remote host involved)."""
    from rogue_pipeline.baseline import save_baseline, train_baseline
    from rogue_pipeline.evaluation import _reference_by_agent
    cfg = Config()
    base = tmp_path / "baseline.npz"
    save_baseline(train_baseline(_reference_by_agent(cfg, (1000,), 60), cfg), base)

    zone_a = tmp_path / "zoneA"; (zone_a / "leads").mkdir(parents=True); (zone_a / "logs").mkdir()
    (zone_a / "leads" / "leads-1.jsonl").write_text('{"event_type":"honeytoken_hit"}\n')
    (zone_a / "logs" / "access.log").write_text("x\n")
    bindir = tmp_path / "bin"; bindir.mkdir()
    (bindir / "rsync").write_text('#!/bin/sh\nfor last; do :; done\ncp -rn "$STUB_ZONE_A"/. "$last"\necho "$@" >> "$STUB_LOG"\n')
    (bindir / "ssh").write_text('#!/bin/sh\ncat >> "$STUB_ANCHOR_FILE"\n')
    pkg = tmp_path / "fakepkg" / "agentwatch"; pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(
        "import sys, json\n"
        "a = sys.argv[1:]\n"
        "if a[0] == 'analyze': sys.exit(0)\n"
        "if a[0] == 'export-leads':\n"
        "    out = a[a.index('--out') + 1]; co = a[a.index('--coordination-out') + 1]\n"
        "    ev = lambda i, ts, ag, **k: {'event_id': f'x{i}', 'ts': ts, 'source': 'web_server', 'agent_id': ag, 'action': 'read', 'resource': '/api/v1/coordination-board', 'synthetic': True, **k}\n"
        "    open(out, 'w').write(json.dumps(ev(1, 1770000000.0, 'client:a')) + '\\n')\n"
        "    rec = lambda i, ts, typ, ref, s, ip, iss=None: {'schema': 'agentwatch.coordination-event/1', 'ts': ts, 'event_id': f'c{i}', 'type': typ, 'ref': ref,\n"
        "        'issuer': iss or {'session_id': s, 'ip': ip}, 'presenter': {'session_id': s, 'ip': ip}}\n"
        "    lines = [rec(1, '2026-03-02T10:00:00Z', 'handoff_token_issued', 'hf-aaaaaaaaaaaa', 'sA', '192.0.2.1'),\n"
        "             rec(2, '2026-03-02T10:05:00Z', 'handoff_token_presented', 'hf-aaaaaaaaaaaa', 'sB', '198.51.100.9', {'session_id': 'sA', 'ip': '192.0.2.1'})]\n"
        "    open(co, 'w').write('\\n'.join(json.dumps(l) for l in lines) + '\\n')\n"
        "    sys.exit(0)\n"
        "sys.exit(2)\n")
    key = tmp_path / "key"; key.write_text("k"); key.chmod(0o600)
    kh = tmp_path / "known_hosts"; kh.write_text("")
    work = tmp_path / "work"
    for n in ("rsync", "ssh"):
        (bindir / n).chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "STUB_ZONE_A": str(zone_a), "STUB_LOG": str(tmp_path / "stub.log"), "STUB_ANCHOR_FILE": str(tmp_path / "anchors.txt"),
           "ZONE_A_HOST": "zone-a.invalid", "ZONE_A_USER": "pull", "ZONE_A_SSH_KEY": str(key), "ZONE_A_KNOWN_HOSTS": str(kh), "ZONE_A_EXPORT_DIR": "/export",
           "WORKDIR": str(work), "PIPELINE_BASELINE": str(base), "PIPELINE_HMAC_SECRET": STRONG, "ANCHOR_SSH_DEST": "anchor@anchor.invalid",
           "ANCHOR_SSH_KEY": str(key), "ANCHOR_REMOTE_FILE": "/anchors/log", "PIPELINE_PYTHON": sys.executable, "AGENTWATCH_PYTHON": sys.executable,
           "PYTHONPATH": str(tmp_path / "fakepkg") + os.pathsep + str(ROOT), "SYNTHETIC_DATA": "1", "ROGUE_PIPELINE_HMAC_KEY": "should-be-unset-by-script-xxxxxxxx"}
    r = _run_script([], env, timeout=300)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert "production mode" in r.stdout and "IGNORED" not in r.stdout          # script unsets the dev key before the pipeline runs
    anchors = (tmp_path / "anchors.txt").read_text().split()
    assert len(anchors) == 2 and len(anchors[1]) == 64                          # <batch id> <head hash> stored "off-host" (stub)
    assert (work / "anchors" / "last_head").read_text().strip() == anchors[1]
    leads = json.loads(next((work / "batches").iterdir()).joinpath("leads.json").read_text())
    assert any(l["cluster"] and "cross_ip_token_handoff" in l["cluster"]["edge_kinds"] for l in leads)   # the stubbed handoff was caught
    assert not any((work / "batches").glob("*/confirmed.stix.json"))            # nothing confirmed -> nothing exported
    # second run: pre-run verification against the anchor passes, then tampering is caught
    r2 = _run_script([], env, timeout=300)
    assert r2.returncode == 0, r2.stdout[-1500:] + r2.stderr[-1500:]
    log = work / "state" / "audit.jsonl"
    lines = log.read_text().splitlines()
    lines[1] = lines[1].replace("lead", "leax", 1)
    log.write_text("\n".join(lines) + "\n")
    r3 = _run_script([], env, timeout=300)
    assert r3.returncode != 0 and "FAILED VERIFICATION" in r3.stderr + r3.stdout
