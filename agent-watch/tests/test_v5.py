"""v5: harness fingerprint (cohort -> archetype) and the static HTML replay (XSS safety, secret scrubbing, CSP, causal timeline)."""
from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from agentwatch import cli
from agentwatch.fingerprint import ARCHETYPES, fingerprint_session
from agentwatch.fingerprint_eval import EXPECTED, collect
from agentwatch.replay import CSP, build_replay_html
from agentwatch.config import load_config
from agentwatch.pipeline import run_pipeline
from helpers import CFG, mk, sess

HOSTILE = "</script><script>alert(1)</script>"
SECRETS = ["sk-ABCDEFGHIJKLMNOPQRSTUV123456", "AKIAABCDEFGHIJKLMNOP", "Bearer abcDEF123456.secretTokenValue", "victim.person@example.com"]
KNOWN_WRONG = {"human_beacon_blocked", "mimic_browser_stealth", "mimic_header_forger"}


# ---------------------------------------------------------------------------------------------- fingerprint
@pytest.fixture(scope="module")
def rows():
    return collect([7])


def test_every_cohort_gets_its_expected_archetype(rows):
    seen = {c for _, c, _, _, _ in rows}
    assert seen == {c for c, _, _, _ in EXPECTED}, "every simulated cohort must be present"
    for _, cohort, expected, got, _conf in rows:
        if cohort in KNOWN_WRONG:
            continue
        assert got == expected, f"{cohort}: expected {expected}, got {got}"


def test_known_misses_are_documented_not_hidden(rows):
    got = {c: g for _, c, _, g, _ in rows if c in KNOWN_WRONG}
    assert got["mimic_browser_stealth"] == "unclassified"          # honest miss: nothing observable
    assert got["mimic_header_forger"] == "unclassified"            # honest miss: forged coherent headers are trusted
    assert got["human_beacon_blocked"] == "headless_or_http_mimic"  # honest false positive (the README says so)


def test_humans_are_never_labelled_with_a_harness_except_the_documented_fp(rows):
    for _, cohort, _, got, _ in rows:
        if cohort.startswith("human") and cohort != "human_beacon_blocked":
            assert got == "unclassified"


def test_mcp_runner_high_confidence_needs_the_whole_chain(rows):
    assert {c for _, c, _, g, conf in rows if g == "mcp_tool_runner"} == {"mcp tool runner"}
    assert all(conf == "high" for _, c, _, g, conf in rows if c == "mcp tool runner")


def test_empty_quiet_session_is_unclassified_with_no_reasons():
    fp = fingerprint_session(sess([mk(0, "/"), mk(5, "/about")]), [], CFG)
    assert fp.archetype == "unclassified" and fp.confidence == "low" and fp.also_matched == []
    assert all("no harness signature" in r for r in fp.reasons)


def test_fingerprint_is_deterministic():
    s = sess([mk(0, "/wp-login.php"), mk(1, "/.git/config"), mk(2, "/xmlrpc.php"), mk(3, "/phpmyadmin/"), mk(4, "/.env"), mk(5, "/wp-admin/")])
    a, b = fingerprint_session(s, [], CFG), fingerprint_session(s, [], CFG)
    assert a.as_dict() == b.as_dict()
    assert a.archetype == "commodity_or_static_scanner" and a.reasons


def test_payload_structure_profile_has_counts_and_buckets_only():
    s = sess([mk(0, "/")])
    d = fingerprint_session(s, [], CFG).as_dict()["payload_structure"]
    assert set(d) == {"json_key_count", "objective_length_bucket", "retry_latency_after_4xx_trap"}


def test_json_report_carries_harness_fields(tmp_path):
    from agentwatch.synthetic import generate_demo
    art = generate_demo(str(tmp_path), seed=3, extended=True)
    results, parsed = run_pipeline([art["access_log"], art["leads"], art["access_mirror"]], load_config())
    from agentwatch.report import build_report
    rep = build_report(results, ["x"], parsed, "defaults")
    assert all({"harness_archetype", "harness_confidence", "harness_reasons", "payload_structure"} <= set(s) for s in rep["sessions"])
    assert {s["harness_archetype"] for s in rep["sessions"]} & {"prompt_injected_crawler", "stateful_coordinator"}


def test_export_web_carries_harness_label(tmp_path):
    from agentwatch.synthetic import generate_demo
    from agentwatch.export import export_web_file
    art = generate_demo(str(tmp_path), seed=3, extended=True)
    out = tmp_path / "web.jsonl"
    export_web_file([art["leads"], art["access_mirror"]], str(out), load_config(), synthetic=True)
    web = [json.loads(l).get("web") or {} for l in out.read_text().splitlines()]
    labels = {w.get("harness_archetype") for w in web if w}
    assert labels - {None} and labels <= set(ARCHETYPES) | {"unclassified", None}


# ---------------------------------------------------------------------------------------------- replay
def _hostile_files(tmp_path: Path) -> tuple[Path, Path]:
    base = "2026-10-22T10:00:{:02d}.000000Z"
    acc, leads = [], []

    def access(t, path, links, status=200, ref="", hdr=None):
        acc.append({"schema": "agentwatch.access/1", "timestamp": base.format(t), "client_ip": "192.0.2.77", "method": "GET", "path": path,
                    "query": "", "status": status, "bytes": 10, "user_agent": "Mozilla/5.0 " + HOSTILE, "referer": ref,
                    "headers": hdr or {}, "content_type": "text/html", "links": links})
    access(0, "/", ["/about"], hdr={"x-evil": HOSTILE + " " + SECRETS[0], "authorization": SECRETS[2]})
    access(2, "/about", ["/"])
    access(4, "/hidden-" + HOSTILE.replace("/", "%2F"), [])
    access(6, "/api/v1/export", [], status=429)
    leads.append({"schema": "agentwatch.lead/1", "event_type": "honeytoken_hit", "event_id": "e1", "timestamp": base.format(8),
                  "source_ip": "192.0.2.77", "token_id": "cb-1", "decoy": {"name": "coordination_board", "kind": "coordination_register", "token_id": "cb-1"},
                  "request": {"method": "POST", "path": "/api/v1/coordination-board", "headers": {"user-agent": "Mozilla/5.0 " + HOSTILE},
                              "user_agent": "Mozilla/5.0 " + HOSTILE, "response_status": 200},
                  "method": "POST", "path": "/api/v1/coordination-board", "user_agent": "Mozilla/5.0 " + HOSTILE, "tags": ["registered"],
                  "detail": {"step": 0},
                  "coordination": {"events": [{"type": "handoff_token_issued", "ref": "hf-abc123", "cross_session": False, "cross_ip": False}]},
                  "cognitive_capture": {"agent_id": "a1", "system_prompt_summary": HOSTILE + " " + SECRETS[1],
                                        "declared_tools": [HOSTILE, SECRETS[3]], "current_objective": HOSTILE + " " + SECRETS[0] + "\u2028 " + SECRETS[3]}})
    leads.append({"schema": "agentwatch.lead/1", "event_type": "honeytoken_hit", "event_id": "e2", "timestamp": base.format(9),
                  "source_ip": "192.0.2.77", "token_id": "ht-2", "decoy": {"name": "mcp_tool:q", "kind": "mcp_decoy_tool_call", "token_id": "ht-2"},
                  "request": {"method": "POST", "path": "/mcp", "headers": {}, "user_agent": "Mozilla/5.0 " + HOSTILE, "response_status": 200},
                  "method": "POST", "path": "/mcp", "user_agent": "Mozilla/5.0 " + HOSTILE, "tags": ["mcp_tools_call"],
                  "detail": {"tool": HOSTILE, "arg_keys": "sql", "arguments": json.dumps({"sql": HOSTILE, "k": SECRETS[0]})}})
    a, l = tmp_path / "leads.access.jsonl", tmp_path / "leads.jsonl"
    a.write_text("\n".join(json.dumps(x) for x in acc) + "\n")
    l.write_text("\n".join(json.dumps(x) for x in leads) + "\n")
    return l, a


class _P(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.metas: list[dict] = []
        self.scripts = 0
        self.urls: list[str] = []
        self.stack: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "meta":
            self.metas.append(d)
        if tag == "script":
            self.scripts += 1
        for k in ("href", "src", "action", "poster", "srcset"):
            if k in d:
                self.urls.append(str(d[k]))
        if tag not in ("meta", "br", "input"):
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass


def _render(tmp_path):
    leads, access = _hostile_files(tmp_path)
    res, _ = run_pipeline([str(leads), str(access)], load_config())
    return build_replay_html(res, load_config(), include_humans=True)


def test_replay_is_valid_html_with_csp_and_no_external_refs(tmp_path):
    doc = _render(tmp_path)
    p = _P()
    p.feed(doc)
    p.close()
    csp = [m for m in p.metas if m.get("http-equiv") == "Content-Security-Policy"]
    assert len(csp) == 1 and csp[0]["content"] == "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" == CSP
    assert p.urls == [], "no href/src/action attributes at all"
    assert doc.startswith("<!DOCTYPE html>") and p.stack == []


def test_replay_escapes_hostile_payloads(tmp_path):
    doc = _render(tmp_path)
    assert "<script>alert(1)" not in doc and "</script><script>" not in doc
    assert doc.count("<script") == 1 and doc.count("</script>") == 1       # only our own inline script
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in doc    # shown as inert text
    assert "\u2028" not in doc and "\u2029" not in doc


def test_replay_leaks_no_raw_secrets(tmp_path):
    doc = _render(tmp_path)
    for s in SECRETS + ["secretTokenValue", "abcDEF123456", "victim.person"]:
        assert s not in doc, s
    assert "[REDACTED_" in doc


def test_replay_has_untrusted_box_triage_timeline_and_rules(tmp_path):
    doc = _render(tmp_path)
    assert "UNTRUSTED AGENT INPUT - SCRUBBED" in doc
    for label in ("Likely benign automation", "Accidental scraper", "Goal-directed agent - escalate", "NOT an automatic block"):
        assert label in doc
    assert "UNLINKED JUMP (never offered)" in doc and 'class="red"' in doc          # /hidden-... was never offered by any page
    assert "handoff_token_issued ref hf-abc123" in doc and "peer_hint" in doc
    assert "R10" in doc and "approximate" in doc.lower() and "AML.T0053" in doc and "mcp tool:" in doc.lower()


def test_replay_inline_script_never_evals_or_writes_html():
    from agentwatch import replay
    js = replay._JS
    for bad in ("eval(", "innerHTML", "document.write", "Function(", "JSON.parse", "outerHTML", "insertAdjacentHTML", "fetch(", "XMLHttpRequest"):
        assert bad not in js


def test_replay_cli_writes_file_and_rejects_missing(tmp_path, capsys):
    leads, access = _hostile_files(tmp_path)
    out = tmp_path / "r.html"
    assert cli.main(["replay", str(leads), "--access", str(access), "--out", str(out), "--include-humans"]) == 0
    assert out.read_text().startswith("<!DOCTYPE html>")
    assert cli.main(["replay", str(tmp_path / "nope.jsonl"), "--out", str(out)]) == 2


def test_replay_of_demo_marks_unlinked_jumps_and_archetypes(tmp_path):
    from agentwatch.synthetic import generate_demo
    art = generate_demo(str(tmp_path), seed=7, extended=True)
    out = tmp_path / "demo.html"
    assert cli.main(["replay", str(art["leads"]), "--access", str(art["access_mirror"]), "--out", str(out)]) == 0
    doc = out.read_text()
    assert "prompt_injected_crawler" in doc and "stateful_coordinator" in doc and "UNLINKED JUMP" in doc
    assert "AWFAKE-" not in doc.replace("AWFAKE-...", "")        # the literal descriptor is fine; no actual decoy credential value
