from agentwatch.detectors import (classify_role, detect_adaptation, detect_honeytokens, detect_param_evasion,
                                  detect_tool_chains)
from helpers import CFG, UA, mk, sess


def kinds(findings):
    return {f.kind for f in findings}


# ---- adaptation after blocks -----------------------------------------------
def base_run(n=6, gap=1.0):
    return [mk(i * gap, "/api/items", f"page={i}") for i in range(n)]


def test_ua_change_after_429():
    reqs = base_run() + [mk(6, "/api/items", "page=6", status=429), mk(7, "/api/items", "page=6", ua="Other/1.0")]
    f = detect_adaptation(sess(reqs), CFG)
    assert "ua_change" in kinds(f)
    assert any(x.data["succeeded"] for x in f if x.kind == "ua_change")


def test_param_change_cache_buster_after_403():
    reqs = base_run() + [mk(6, "/api/items", "page=6", status=403), mk(7, "/api/items", "page=6&_=12345")]
    assert "param_change" in kinds(detect_adaptation(sess(reqs), CFG))


def test_header_change_after_block():
    h1 = {"accept-language": "en", "x-forwarded-for": "1.1.1.1"}
    h2 = {"accept-language": "de", "x-forwarded-for": "2.2.2.2"}
    reqs = base_run()[:3] + [mk(3, "/api/items", status=429, headers=h1), mk(4, "/api/items", headers=h2)]
    assert "header_change" in kinds(detect_adaptation(sess(reqs), CFG))


def test_path_reorder_detected():
    reqs = [mk(0, "/api/a"), mk(1, "/api/a", status=429), mk(2, "/api/b"), mk(3, "/api/c"), mk(4, "/api/a")]
    assert "path_reorder" in kinds(detect_adaptation(sess(reqs), CFG))


def test_backoff_detected_but_unchanged_retry_is_not_adaptation():
    backoff = [mk(i, "/api/x", "p=1") for i in range(5)] + [mk(5, "/api/x", "p=1", status=429), mk(30, "/api/x", "p=1")]
    assert kinds(detect_adaptation(sess(backoff), CFG)) == {"backoff"}
    retry = [mk(i, "/api/x", "p=1") for i in range(5)] + [mk(5, "/api/x", "p=1", status=429), mk(6, "/api/x", "p=1", status=429)]
    f = detect_adaptation(sess(retry), CFG)
    assert kinds(f) == {"no_adaptation"}


def test_plain_pagination_after_429_is_not_param_change():
    # naive scraper keeps counting page=N whether or not it was blocked
    reqs = [mk(i * 0.5, "/api/items", f"page={i}&limit=100") for i in range(8)]
    reqs[5] = mk(2.5, "/api/items", "page=5&limit=100", status=429)
    assert "param_change" not in kinds(detect_adaptation(sess(reqs), CFG))


# ---- tool chaining -----------------------------------------------------------
def chain(t, q="a", ids=(1, 2), gap=1.0):
    out = [mk(t, "/api/v1/search", f"q={q}")]
    for k, i in enumerate(ids, 1):
        out.append(mk(t + k * gap, f"/api/v1/items/{i}"))
    out.append(mk(t + (len(ids) + 1) * gap, "/api/v1/export", "ids=1,2"))
    return out


def test_roles():
    assert classify_role(mk(0, "/api/v1/search"), CFG) == "search"
    assert classify_role(mk(0, "/products/42"), CFG) == "detail"
    assert classify_role(mk(0, "/api/v1/export"), CFG) == "export"
    assert classify_role(mk(0, "/about"), CFG) is None


def test_regular_tool_chains_flagged():
    reqs = chain(0, "a") + chain(10, "b") + chain(20, "c")
    f = detect_tool_chains(sess(reqs), CFG)
    assert len(f) == 1 and f[0].data["chains"] == 3 and f[0].data["signature"] == "S>D>D>E"


def test_single_chain_not_flagged():
    assert detect_tool_chains(sess(chain(0)), CFG) == []


def test_slow_human_paced_chains_not_flagged():
    reqs = chain(0, gap=9.0) + chain(120, gap=9.0)      # 9s per step -> over max_median_step_s
    cfg_reqs = sess(reqs)
    assert detect_tool_chains(cfg_reqs, CFG) == []


def test_irregular_chain_shapes_not_flagged():
    reqs = chain(0, ids=(1,)) + chain(10, ids=(1, 2)) + chain(20, ids=(1, 2, 3))
    assert detect_tool_chains(sess(reqs), CFG) == []


# ---- parameter / header evasion ----------------------------------------------
def test_enumeration_query_param():
    reqs = [mk(i * 0.5, "/api/items", f"page={i}") for i in range(1, 12)]
    assert "enumeration" in kinds(detect_param_evasion(sess(reqs), CFG))


def test_enumeration_path_ids():
    reqs = [mk(i * 0.4, f"/api/v1/items/{1000 + i}") for i in range(12)]
    f = detect_param_evasion(sess(reqs), CFG)
    assert any(x.kind == "enumeration" and x.data["key"] == "<path id>" for x in f)


def test_slow_human_paging_not_enumeration():
    reqs = [mk(i * 8.0, "/products", f"page={i}") for i in range(1, 8)]
    assert "enumeration" not in kinds(detect_param_evasion(sess(reqs), CFG))


def test_cache_busting_detected_by_name_and_by_shape():
    named = [mk(i, "/api/x", f"q=a&_={1700000000000 + i * 37}") for i in range(5)]
    assert "cache_busting" in kinds(detect_param_evasion(sess(named), CFG))
    shaped = [mk(i, "/api/x", f"zz={i * 7919:08x}") for i in range(5)]
    assert "cache_busting" in kinds(detect_param_evasion(sess(shaped), CFG))


def test_systematic_variation():
    cats = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
    reqs = [mk(i * 0.5, "/api/list", f"limit=50&category={c}") for i, c in enumerate(cats)]
    assert "systematic_variation" in kinds(detect_param_evasion(sess(reqs), CFG))


def test_header_rotation_and_ua_rotation():
    reqs = [mk(i, "/api/x", headers={"x-forwarded-for": f"10.0.0.{i}"}) for i in range(10)]
    f = detect_param_evasion(sess(reqs), CFG)
    assert any(x.kind == "header_rotation" and x.data["header"] == "x-forwarded-for" for x in f)
    uas = [mk(i, "/api/x", status=429 if i % 2 == 0 else 200, ua=f"UA-{i % 4}") for i in range(12)]
    f2 = detect_param_evasion(sess(uas), CFG)
    assert any(x.data.get("header") == "user-agent" for x in f2)


def test_stable_browsing_has_no_evasion_findings():
    reqs = [mk(i * 7, p) for i, p in enumerate(["/", "/about", "/products", "/products/3", "/support", "/", "/about", "/products/9"])]
    assert detect_param_evasion(sess(reqs), CFG) == []


# ---- honeytokens ---------------------------------------------------------------
def test_honeytoken_path_hits_in_access_logs_deduplicated():
    reqs = [mk(0, "/admin-backup/"), mk(1, "/admin-backup/"), mk(2, "/canary/abc123"), mk(3, "/index")]
    f = detect_honeytokens(sess(reqs), CFG)
    assert {x.kind for x in f} == {"robots_disallow", "canary_follow"} and len(f) == 2


def test_honeytoken_lead_requests():
    r = mk(0, "/api/v1/admin")
    r.source, r.token_id, r.decoy_kind = "honeypot", "ht-1", "fake_admin_api"
    f = detect_honeytokens(sess([r]), CFG)
    assert f[0].kind == "fake_admin_api" and f[0].data["token_id"] == "ht-1"
