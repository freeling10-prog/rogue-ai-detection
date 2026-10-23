import json

from agentwatch.parser import (MAX_LINE_BYTES, parse_combined_line, parse_json_line, parse_lines,
                               parse_timestamp)
from helpers import CFG, UA, mk

COMBINED = '203.0.113.5 - - [22/Oct/2026:10:00:01 +0000] "GET /search?q=a%20b&page=2 HTTP/1.1" 200 512 "https://x.invalid/" "Mozilla/5.0 \\"q\\""'


def test_combined_line_fields():
    r = parse_combined_line(COMBINED)
    assert r and r.ip == "203.0.113.5" and r.method == "GET"
    assert r.path == "/search" and r.query == "q=a%20b&page=2" and r.params["page"] == ["2"]
    assert r.status == 200 and r.size == 512
    assert r.ua == 'Mozilla/5.0 "q"' and r.referer == "https://x.invalid/"
    assert r.ts.utcoffset().total_seconds() == 0


def test_combined_timezone_converted_to_utc():
    r = parse_combined_line('1.2.3.4 - - [22/Oct/2026:12:00:00 +0200] "GET / HTTP/1.1" 200 - "-" "-"')
    assert r and r.ts.hour == 10 and r.ua == "" and r.referer == "" and r.size == 0


def test_combined_without_referer_ua_fields():
    assert parse_combined_line('1.2.3.4 - - [22/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.0" 404 12').status == 404


def test_json_line_gateway_format():
    line = json.dumps({"timestamp": "2026-10-22T10:00:00Z", "client_ip": "1.2.3.4", "method": "post",
                       "path": "/api/v1/x?y=1", "status": 429, "headers": {"User-Agent": "u", "X-Forwarded-For": "9.9.9.9"},
                       "latency_ms": 5})
    r, ctx = parse_json_line(line)
    assert not ctx and r.method == "POST" and r.path == "/api/v1/x" and r.query == "y=1"
    assert r.status == 429 and r.ua == "u" and r.headers["x-forwarded-for"] == "9.9.9.9" and r.latency_ms == 5


def test_json_alternative_keys_and_epoch():
    r, _ = parse_json_line(json.dumps({"ts": 1792663200, "remote_addr": "1.1.1.1", "uri": "/a?b=2",
                                        "status_code": 200, "request_time": 0.25, "ua": "z"}))
    assert r.path == "/a" and r.query == "b=2" and r.latency_ms == 250 and r.ua == "z"
    assert parse_timestamp(1792663200000).year == 2026      # milliseconds


def test_malformed_and_long_lines_counted_not_fatal():
    res = parse_lines(["garbage", "{bad json", "", COMBINED, "A" * (MAX_LINE_BYTES + 10)])
    assert len(res.requests) == 1 and res.errors == 3


def test_mixed_formats_sorted_by_time():
    j = json.dumps({"timestamp": "2026-10-22T09:59:59Z", "client_ip": "1.1.1.1", "path": "/", "status": 200})
    res = parse_lines([COMBINED, j])
    assert [r.ip for r in res.requests] == ["1.1.1.1", "203.0.113.5"]


def test_honeypot_lead_becomes_tagged_request_and_context_skipped():
    lead = {"schema": "agentwatch.lead/1", "event_type": "honeytoken_hit", "timestamp": "2026-10-22T10:00:00Z",
            "source_ip": "192.0.2.9", "token_id": "ht-abc", "decoy": {"kind": "fake_admin_api", "token_id": "ht-abc"},
            "request": {"method": "GET", "path": "/api/v1/admin", "raw_query": "a=1", "user_agent": "UA1",
                        "headers": {"user-agent": "UA1"}, "response_status": 200}}
    ctx = dict(lead, event_type="decoy_context")
    res = parse_lines([json.dumps(lead), json.dumps(ctx)])
    assert len(res.requests) == 1 and res.context_events == 1
    r = res.requests[0]
    assert r.source == "honeypot" and r.token_id == "ht-abc" and r.decoy_kind == "fake_admin_api"
    assert r.ip == "192.0.2.9" and r.query == "a=1" and r.ua == "UA1"


# ---- sessions --------------------------------------------------------------
from agentwatch.sessions import build_sessions  # noqa: E402


def test_sessions_split_by_ip_and_ua():
    reqs = [mk(0), mk(1), mk(2, ua="other"), mk(3, ip="192.0.2.2")]
    assert len(build_sessions(reqs, CFG)) == 3


def test_sessions_idle_gap_splits():
    reqs = [mk(0), mk(10), mk(10 + CFG["session"]["idle_gap_s"] + 1)]
    sizes = sorted(len(s.requests) for s in build_sessions(reqs, CFG))
    assert sizes == [1, 2]


def test_ua_rotation_after_block_is_relinked():
    reqs = [mk(0, "/api/a"), mk(1, "/api/a", status=429), mk(3, "/api/a", ua="UA-2"), mk(4, "/api/b", ua="UA-2")]
    sessions = build_sessions(reqs, CFG)
    assert len(sessions) == 1 and len(sessions[0].user_agents) == 2


def test_ua_change_without_block_stays_separate():
    reqs = [mk(0), mk(1), mk(3, ua="UA-2"), mk(4, ua="UA-2")]
    assert len(build_sessions(reqs, CFG)) == 2


def test_relinking_can_be_disabled():
    cfg = json.loads(json.dumps(CFG))
    cfg["session"]["link_ua_rotation"] = False
    reqs = [mk(1, status=429), mk(3, ua="UA-2")]
    assert len(build_sessions(reqs, cfg)) == 2
