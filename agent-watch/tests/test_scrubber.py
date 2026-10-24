"""Secret/PII scrubber: nothing raw reaches disk, deterministic salted hashes, evasion resistance."""
import json
import os
import re
import stat
from pathlib import Path

import pytest

from agentwatch import scrubber as scrubber_mod
from agentwatch.config import load_config
from agentwatch.coordination import BOARD_PATH
from agentwatch.export import export_coordination_file, export_file
from agentwatch.honeypot import create_honeypot_app
from agentwatch.leads import LeadWriter, sanitize_text
from agentwatch.pipeline import run_pipeline
from agentwatch.report import build_report
from agentwatch.scrubber import MIN_SALT_CHARS, Scrubber, load_or_create_salt

ROOT = Path(__file__).resolve().parent.parent
TOKEN_FMT = r"\[REDACTED_{}_SHA256:[0-9a-f]{{10}}\]"

# Obviously synthetic secrets with the right *shape* (none is a real credential).
SK = "sk-ABCDEFGHIJKLMNOP0123456789abcdef"
SK_ANT = "sk-ant-api03-ZZZZYYYYXXXXWWWWVVVV_uuuu-tttt"
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3"
AWS = "AKIA" + "ABCDEFGH12345678"
JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl"
BEARER_TOKEN = "tok_Synthetic.Value-123456"
EMAIL = "jane.doe+x@Example-Corp.example"
ALL = [SK, SK_ANT, GH, AWS, JWT, BEARER_TOKEN, EMAIL, EMAIL.lower()]


@pytest.fixture
def scrub():
    return Scrubber("unit-test-salt-0123456789")


@pytest.mark.parametrize("raw,kind", [
    (SK, "OPENAI_ANTHROPIC_KEY"), (SK_ANT, "OPENAI_ANTHROPIC_KEY"), (GH, "GITHUB_TOKEN"), (AWS, "AWS_ACCESS_KEY"),
    (JWT, "JWT"), (f"Bearer {BEARER_TOKEN}", "BEARER"), (f"bearer {BEARER_TOKEN}", "BEARER"), (EMAIL, "EMAIL"),
    ("ghs_" + "x" * 25, "GITHUB_TOKEN"), ("gho_" + "y" * 25, "GITHUB_TOKEN"),
])
def test_each_pattern_is_replaced_with_typed_salted_hash_token(scrub, raw, kind):
    out = scrub.scrub_text(f"before {raw} after")
    assert re.fullmatch("before " + TOKEN_FMT.format(kind) + " after", out), out
    assert raw.split()[-1] not in out


def test_identical_secrets_identical_hashes_different_secrets_differ(scrub):
    a1, a2 = scrub.scrub_text(f"x {SK} y"), scrub.scrub_text(f"{{'k': '{SK}'}}")
    h = lambda s: re.search(r"SHA256:([0-9a-f]{10})", s).group(1)   # noqa: E731
    assert h(a1) == h(a2)
    assert h(scrub.scrub_text(SK)) != h(scrub.scrub_text(SK[:-1] + "Z"))
    assert h(scrub.scrub_text(EMAIL)) == h(scrub.scrub_text(EMAIL.upper().replace("EXAMPLE", "Example")))   # case-insensitive mailbox
    assert h(scrub.scrub_text(f"Bearer {BEARER_TOKEN}")) == h(scrub.scrub_text(f"BEARER   {BEARER_TOKEN}"))
    other = Scrubber("a-completely-different-salt-xyz")
    assert h(other.scrub_text(SK)) != h(scrub.scrub_text(SK))              # salt matters


def test_nested_json_lists_and_keys_are_scrubbed(scrub):
    doc = {"a": [{"b": (SK, [GH, {"c": EMAIL}])}], EMAIL: 1, "n": 5, "ok": True, "none": None,
           "deep": {"x": {"y": {"z": f"Authorization: Bearer {BEARER_TOKEN}"}}}}
    out = json.dumps(scrub.scrub(doc))
    for raw in (SK, GH, EMAIL, BEARER_TOKEN):
        assert raw not in out
    assert out.count("REDACTED_") >= 5 and '"n": 5' in out and '"ok": true' in out


def test_deeply_nested_input_is_bounded(scrub):
    x = {}
    for _ in range(200):
        x = {"k": x}
    assert "TRUNCATED_DEPTH" in json.dumps(scrub.scrub(x))


EVASIONS = {
    "zero_width": lambda s: "\u200b".join(s[i:i + 3] for i in range(0, len(s), 3)),
    "bidi_and_bom": lambda s: s[:5] + "\u202e\ufeff\u2066" + s[5:],
    "escape_and_nul": lambda s: s[:4] + "\x1b\x00\x07" + s[4:],
    "soft_hyphen": lambda s: s.replace("-", "-\u00ad", 1) if "-" in s else s[:6] + "\u00ad" + s[6:],
    "fullwidth": lambda s: "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s),
}


@pytest.mark.parametrize("name", sorted(EVASIONS))
@pytest.mark.parametrize("secret", [SK, GH, AWS, JWT, EMAIL, f"Bearer {BEARER_TOKEN}"])
def test_unicode_and_control_char_tricks_do_not_defeat_scrubbing_in_either_order(scrub, name, secret):
    tricky = EVASIONS[name](secret)
    plain = secret.split()[-1].lower()
    for result in (scrub.scrub_text(sanitize_text(tricky, 10_000)),      # sanitise, then scrub (the write path)
                   sanitize_text(scrub.scrub_text(tricky), 10_000)):      # scrub, then sanitise
        assert "REDACTED_" in result and plain not in result.lower() and re.sub(r"\W", "", plain)[:12] not in re.sub(r"\W", "", result.lower())


def test_newline_percent_and_unicode_escapes_do_not_hide_a_secret(scrub):
    """CR/LF/TAB (and sanitize_text's visible escapes), %XX and \\uXXXX must still redact."""
    h = lambda s: re.search(r"SHA256:([0-9a-f]{10})", s).group(1)   # noqa: E731
    split_nl = SK[:10] + "\n" + SK[10:]
    split_tab = SK[:8] + "\t" + SK[8:]
    escaped = sanitize_text(split_nl, 10_000)                       # "\\n" two-character escape
    encoded_email = EMAIL.replace("@", "%40")
    double_email = EMAIL.replace("@", "%2540")
    unicode_email = EMAIL.replace("@", "\\u0040")
    assert "\\n" in escaped and "\n" not in escaped
    for raw in (split_nl, split_tab, SK[:6] + "\r\n" + SK[6:], escaped,
                f"e={encoded_email}", f"e={double_email}", f"e={unicode_email}",
                f"Bearer%20{BEARER_TOKEN}", f"Bearer+{BEARER_TOKEN}",
                "note " + SK[:12] + "%0a" + SK[12:]):
        out = scrub.scrub_text(raw)
        assert "REDACTED_" in out, raw
        assert SK not in out and SK[:10] not in out
        assert EMAIL.lower() not in out.lower() and encoded_email not in out and BEARER_TOKEN not in out
    assert h(scrub.scrub_text(SK)) == h(scrub.scrub_text(split_nl)) == h(scrub.scrub_text(escaped))
    assert h(scrub.scrub_text(EMAIL)) == h(scrub.scrub_text(encoded_email)) == h(scrub.scrub_text(double_email))
    assert h(scrub.scrub_text(f"Bearer {BEARER_TOKEN}")) == h(scrub.scrub_text(f"Bearer%20{BEARER_TOKEN}"))
    # a newline that is not hiding a secret stays a visible escape (log injection stays neutralised)
    assert scrub.scrub_text(sanitize_text("hello\nworld", 100)) == "hello\\nworld"


def test_split_and_encoded_secrets_do_not_reach_the_lead_log(tmp_path):
    log = tmp_path / "leads.jsonl"
    app = create_honeypot_app(log, seed="t")
    c = app.test_client()
    body = f"k={SK[:10]}\n{SK[10:]}&e={EMAIL.replace('@', '%40')}&b=Bearer%20{BEARER_TOKEN}"
    assert c.post("/api/v1/admin", data=body, content_type="text/plain").status_code == 200
    c.get("/api/v1/admin", query_string="e=" + EMAIL.replace("@", "%2540") + "&k=" + SK[:12] + "%0a" + SK[12:])
    blob = log.read_text()
    for raw in (SK, SK[:10], EMAIL, EMAIL.replace("@", "%40"), EMAIL.replace("@", "%2540"), BEARER_TOKEN):
        assert raw not in blob, raw
    assert "REDACTED_OPENAI_ANTHROPIC_KEY" in blob and "REDACTED_EMAIL" in blob and "REDACTED_BEARER" in blob


def test_hash_is_same_for_plain_and_obfuscated_forms(scrub):
    h = lambda s: re.search(r"SHA256:([0-9a-f]{10})", s).group(1)   # noqa: E731
    assert h(scrub.scrub_text(SK)) == h(scrub.scrub_text(EVASIONS["zero_width"](SK))) == h(scrub.scrub_text(EVASIONS["fullwidth"](SK)))


# ---- salt handling -------------------------------------------------------------------------------------------------------------
def test_salt_file_is_random_0600_and_stable(tmp_path):
    p = tmp_path / "state" / "scrub.salt"
    s1 = load_or_create_salt(p)
    assert len(s1) >= 32 and stat.S_IMODE(p.stat().st_mode) == 0o600
    assert load_or_create_salt(p) == s1
    assert load_or_create_salt(tmp_path / "other.salt") != s1               # per-install randomness
    p.chmod(0o644)
    load_or_create_salt(p)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600                           # tightened again


def test_salt_is_never_hardcoded_in_the_package():
    salt = Path(os.environ["AGENT_WATCH_SALT_FILE"])
    scrubber_mod.reset_default_scrubber()
    scrubber_mod.get_default_scrubber()
    value = salt.read_text().strip()
    assert value and not any(value in f.read_text(errors="ignore") for f in (ROOT / "agentwatch").rglob("*.py"))
    assert not any(value in f.read_text(errors="ignore") for f in (ROOT / "deploy").rglob("*") if f.is_file() and f.suffix != ".pyc")


def test_env_salt_overrides_file_and_short_salt_is_rejected_without_echo(monkeypatch):
    monkeypatch.setenv("AGENT_WATCH_SCRUB_SALT", "x" * MIN_SALT_CHARS)
    assert Scrubber.from_env().scrub_text(SK).startswith("[REDACTED_")
    monkeypatch.setenv("AGENT_WATCH_SCRUB_SALT", "short-secret")
    with pytest.raises(ValueError) as exc:
        Scrubber.from_env()
    assert "short-secret" not in str(exc.value)


def test_scrub_failure_drops_the_record_instead_of_writing_it_raw(tmp_path):
    class Boom(Scrubber):
        def scrub(self, obj, _depth=0):
            raise RuntimeError(f"leaking {SK}")

    w = LeadWriter(tmp_path / "x.jsonl", scrubber=Boom("unit-test-salt-0123456789"))
    assert w.write({"k": SK}) is False and w.dropped == 1
    assert not (tmp_path / "x.jsonl").exists() or SK not in (tmp_path / "x.jsonl").read_text()


# ---- nothing raw on disk after hostile traffic -----------------------------------------------------------------------------------
def all_bytes_under(root: Path) -> bytes:
    return b"\n".join(p.read_bytes() for p in root.rglob("*") if p.is_file() and p.name != "scrub.salt")


def test_no_raw_secret_on_disk_after_posting_secrets_everywhere(tmp_path):
    log = tmp_path / "data" / "leads.jsonl"
    app = create_honeypot_app(log, seed="t", registry_path=tmp_path / "data" / "registry.json")
    c = app.test_client()
    hdr = {"Authorization": f"Bearer {BEARER_TOKEN}", "Cookie": f"session={SK}; gh={GH}", "X-API-Key": AWS,
           "X-Custom": f"contact {EMAIL}", "User-Agent": f"agent/1 {SK_ANT}", "Referer": f"http://x.invalid/?t={JWT}"}
    token = c.get(BOARD_PATH, headers=hdr, query_string={"api_key": SK}).get_json()["handoff_token"]
    body = {"handoff_token": token, "agent_id": f"agent-{EMAIL}", "message": f"my key is {SK} and {GH}",
            "system_prompt_summary": f"Use Bearer {BEARER_TOKEN} for {AWS}; token {JWT}",
            "current_objective": [f"mail {EMAIL}", {"deep": [SK_ANT]}], "declared_tools": [GH, {"k": AWS}],
            f"key_{EMAIL}": 1}
    assert c.post(BOARD_PATH, json=body, headers=hdr).status_code == 200
    c.post(BOARD_PATH, data=f"{{broken {SK} {EMAIL}", content_type="application/json", headers=hdr)           # malformed
    c.post(BOARD_PATH, data=f"x={GH}" + "A" * 17000, content_type="text/plain", headers=hdr)                  # oversize
    c.get(f"/api/v2/staging/records?token={SK}&e={EMAIL}", headers=hdr)                                        # error trap
    c.get(f"/diag/abcdef0123?ctx={GH}", headers=hdr)
    c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "query_staging_db", "arguments": {"sql": f"-- {SK} {EMAIL}"}}}, headers=hdr)
    c.post("/graphql", json={"query": f"{{ stagingRecords {{ records }} }} # {AWS}"}, headers=hdr)
    c.get(f"/canary/{SK}?x={EMAIL}", headers=hdr)
    blob = all_bytes_under(tmp_path)
    assert b"REDACTED_" in blob
    for raw in ALL + ["Bearer " + BEARER_TOKEN]:
        assert raw.encode() not in blob, raw
    # hashes allow correlation: the same key shows the same token everywhere it appeared
    hashes = set(re.findall(rb"REDACTED_OPENAI_ANTHROPIC_KEY_SHA256:([0-9a-f]{10})", blob))
    assert hashes and len(hashes) <= 2
    # obfuscated copies are caught too, on the same path
    c.post(BOARD_PATH, json={"handoff_token": token, "message": EVASIONS["zero_width"](SK) + EVASIONS["fullwidth"](GH)}, headers=hdr)
    assert SK.encode() not in all_bytes_under(tmp_path) and b"\xe2\x80\x8b" not in log.read_bytes()


def test_decoy_state_files_contain_no_visitor_text(tmp_path):
    log = tmp_path / "l.jsonl"
    app = create_honeypot_app(log, seed="t")
    c = app.test_client()
    token = c.get(BOARD_PATH).get_json()["handoff_token"]
    c.post(BOARD_PATH, json={"handoff_token": token, "message": "VISITOR-TEXT-MARKER " + SK})
    sqlite_bytes = (tmp_path / "l.jsonl.state.sqlite").read_bytes()
    assert b"VISITOR-TEXT-MARKER" not in sqlite_bytes and SK.encode() not in sqlite_bytes
    assert stat.S_IMODE((tmp_path / "l.jsonl.state.sqlite").stat().st_mode) == 0o600


def test_reports_and_exports_scrub_even_pre_existing_unscrubbed_input(tmp_path, capsys):
    from agentwatch.cli import main
    acc = tmp_path / "access.log"
    acc.write_text("\n".join(
        f'203.0.113.7 - - [22/Oct/2026:10:00:{i:02d} +0000] "GET /api/v1/search?q=a&api_key={SK}&e={EMAIL} HTTP/1.1" 200 10 "-" "curl/8 {GH}"'
        for i in range(40)) + "\n")
    out_json = tmp_path / "r.json"
    assert main(["analyze", str(acc), "--json-out", str(out_json), "--no-color", "--min-severity", "info"]) == 0
    text = out_json.read_text() + capsys.readouterr().out
    for raw in (SK, EMAIL, GH):
        assert raw not in text
    assert "REDACTED_" in text
    # an old lead file written before the scrubber existed: exports still scrub
    lead = {"event_type": "honeytoken_hit", "event_id": "e1", "timestamp": "2026-10-22T10:00:00Z", "source_ip": "192.0.2.1",
            "priority": "high", "token_id": "ht-1", "decoy": {"kind": "canary_follow"}, "tags": [SK],
            "request": {"path": f"/x/{GH}", "response_status": 200},
            "cognitive_capture": {"message": EMAIL, "untrusted": True}, "coordination": {"events": []}}
    src = tmp_path / "old.jsonl"
    src.write_text(json.dumps(lead) + "\n")
    export_file(src, tmp_path / "raw.jsonl")
    export_coordination_file(src, tmp_path / "coord.jsonl")
    data = (tmp_path / "raw.jsonl").read_text() + (tmp_path / "coord.jsonl").read_text()
    assert SK not in data and GH not in data and EMAIL not in data and "REDACTED_" in data
