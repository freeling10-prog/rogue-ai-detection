"""v6 pipeline ("Deep-Cover & Frontier Evasion"): scrubber PR #4 sync, the v6 web contract (6-boolean beacon, js_assets_fetched,
cursor_prov, signals, llmjacking), R11 tiers, R10 schema cursor / LLMjacking, advisory missing cursor, R12 routine-tool hijack,
R13 CUSUM / micro-windows / timing collapse, R14 parasitic fork, the AML.T0118 swarm edges, rule-family corroboration, STIX.

HONEST CAVEAT: the v6 simulator cohorts and the v6 rules were written by the same author.  These tests pin intended behaviour,
hard-negative suppression and documented misses - they are not evidence of real-world accuracy."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from pydantic import ValidationError

from rogue_pipeline.config import Config, Policy, ProbingCfg, SuppressionGroup
from rogue_pipeline.features import group_events
from rogue_pipeline.fusion import fuse, rules_strength
from rogue_pipeline.layer2_rules import RULE_ATLAS, RULE_FAMILY, RuleFlag, rule_families
from rogue_pipeline.layer3_graph import INHERITANCE, PARTITION
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.probing import calibrate, cusum, probe_vector, stats, timing_collapse, _order
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import V6_SIGNALS, RawEvent, WebMeta
from rogue_pipeline.scrub import Scrubber
from rogue_pipeline.simulator import INTERNAL, SENSITIVE_PATHS, T0, V6_SCENARIOS, build
from rogue_pipeline.web_simulator import V6_COUNTS, V6_GROUPS, build_web, to_v5_format

KEY = b"unit-test-key-0123456789abcdef"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
HUMAN6 = {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False,
          "challenge_proof_ok": True, "kinematic_dwell_ok": True, "inertial_scroll_ok": True}
LEGACY3 = {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False}


def scr() -> Scrubber:
    ps = Pseudonymizer(KEY)
    return Scrubber(lambda v: ps.token("scrub", v, ""))


class G:
    """v6 web RawEvent builder for one client (browser UA).  ``js`` is the session's js_assets_fetched (carried on every event)."""

    def __init__(self, ip: str = "192.0.2.60", ua: str = BROWSER, js: Optional[int] = 2) -> None:
        self.ip, self.ua, self.js, self.n, self.t = ip, ua, js, 0, 1000.0
        self.events: List[Dict[str, Any]] = []

    def req(self, path: str, dt: float = 3.0, *, kind: str = "html", status: str = "allowed", **web: Any) -> "G":
        self.n += 1
        self.t += dt
        w = {"user_agent": self.ua, "content_kind": kind, **{k: v for k, v in web.items() if v is not None}}
        if self.js is not None:
            w["js_assets_fetched"] = self.js
        self.events.append({"event_id": f"{self.ip}-{self.n}", "ts": T0 + self.t, "source": "web_server", "agent_id": f"client:{self.ip}",
                            "action": "access", "status": status, "resource": path, "ip": self.ip, "synthetic": True, "web": w})
        return self

    def pages(self, n: int, *, sec: str = "coherent", beacon: Optional[dict] = None, assets: bool = True, start: int = 0) -> "G":
        prev = None
        for i in range(start, start + n):
            self.req(f"/kb/article-{i}", beacon_offered=True, referer_present=prev is not None, referer_path=prev,
                     referer_valid=True if prev else None, linked_from_prev=True if prev else None,
                     sec_fetch_state=sec, sec_fetch_mismatch=sec != "coherent")
            if assets:
                self.req("/static/site.css", 0.05, kind="asset", asset_kind="css")
                self.req("/static/site.js", 0.05, kind="asset", asset_kind="js")
            if beacon is not None and prev is not None:
                self.req("/api/v1/telemetry/nav", 0.3, kind="beacon", beacon=beacon)
            prev = f"/kb/article-{i}"
        return self


def run(items: List[Dict[str, Any]], cfg: Optional[Config] = None, policy: Optional[Policy] = None):
    pseudo = Pseudonymizer(KEY)
    return Pipeline(cfg or Config(), policy or Policy(), pseudo).run(items), pseudo


def flags(res, pseudo, agent: str) -> Dict[str, RuleFlag]:
    a = pseudo.agent(agent)
    return {f.rule_id: f for f in res.flags if f.agent == a}


def lead(res, pseudo, agent: str):
    a = pseudo.agent(agent)
    return next((l for l in res.leads if l.agent == a), None)


# ======================================================================== Step 0: scrubber sync with PR #4
def test_unicode_escaped_percent_encoded_email_is_redacted():
    out = scr().scrub_text("contact bob\\u002540example.com now")
    assert "bob" not in out and "example.com" not in out and "REDACTED_EMAIL" in out


def test_decode_loop_is_capped_at_two_rounds():
    # three layers of encoding: only two are undone, and the remaining text is left as-is (deterministic, bounded)
    triple = "bob%25252540example.com"
    assert scr().scrub_text(triple) == scr().scrub_text(triple)


def test_dict_keys_are_scrubbed():
    s = scr()
    out = s.scrub({"alice@example.org": "v", "nested": {"token sk-abcdefghijklmnopqrstuvwx": 1}, 7: "x"})
    keys = list(out) + list(out["nested"])
    assert not any("alice@example.org" in str(k) for k in keys)
    assert not any("sk-abcdefghijklmnopqrstuvwx" in str(k) for k in keys)
    assert 7 in out


# ======================================================================== contract / schema strictness
def test_signal_names_match_the_contract_file():
    text = open("/workspace/v6-event-contract.md").read() if __import__("os").path.exists("/workspace/v6-event-contract.md") else ""
    for name in V6_SIGNALS:
        assert not text or f"`{name}`" in text
    assert set(V6_SIGNALS) == {"beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
                               "schema_provenance_cursor", "missing_required_cursor", "parasitic_session_fork", "llmjacking_probe"}


def test_web_schema_accepts_six_and_three_key_beacons_and_nulls():
    WebMeta(content_kind="beacon", beacon=HUMAN6)
    WebMeta(content_kind="beacon", beacon=LEGACY3)
    WebMeta(content_kind="beacon", beacon={**LEGACY3, "challenge_proof_ok": None, "kinematic_dwell_ok": None, "inertial_scroll_ok": None})
    WebMeta(signals=[], js_assets_fetched=0, cursor_prov=None)


@pytest.mark.parametrize("bad", [
    {"signals": ["made_up_signal"]},
    {"signals": ["beacon_forged", "beacon_forged"]},
    {"cursor_prov": "evil"},
    {"js_assets_fetched": -1},
    {"js_assets_fetched": "3"},
    {"beacon": {**HUMAN6, "client_id": "x"}},
    {"beacon": {**HUMAN6, "challenge_proof_ok": "yes"}},
    {"llmjacking": {"tool_count": 1, "system_prompt_len_bucket": "huge", "autonomous_loop_directive": False}},
    {"llmjacking": {"tool_count": 1, "system_prompt_len_bucket": "0", "autonomous_loop_directive": False, "messages": "x"}},
])
def test_web_schema_rejects_malformed_v6_fields(bad):
    with pytest.raises(ValidationError):
        WebMeta(**bad)


def test_arg_entropy_bounds():
    base = {"event_id": "e1", "ts": T0, "source": "api_gateway", "agent_id": "a", "action": "tool_call", "tool": "http_post",
            "synthetic": True}
    RawEvent(**{**base, "arg_entropy": 7.5})
    with pytest.raises(ValidationError):
        RawEvent(**{**base, "arg_entropy": 9.0})


def test_v6_web_cohorts_normalize_cleanly_and_v5_format_is_v5_valid():
    w = build_web(0, v6=True)
    cfg = Config()
    rep = Normalizer(cfg.normalization, Pseudonymizer(KEY), None, cfg.web).process(w.events)
    assert not rep.quarantined
    v5 = to_v5_format(w.events)
    for e in v5:
        wb = e.get("web") or {}
        assert not ({"js_assets_fetched", "cursor_prov", "signals", "llmjacking"} & set(wb))
        if wb.get("beacon"):
            assert set(wb["beacon"]) == {"webdriver_present", "pointer_trail_seen", "dom_automation_props"}


# ======================================================================== R11
def test_beacon_blocked_human_with_js_and_coherent_headers_is_exempt():
    g = G("192.0.2.61").pages(6, beacon=None)
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.61")
    assert "R11" not in f and lead(res, p, "client:192.0.2.61") is None


def test_js_off_human_without_js_fetch_is_exempt_even_with_bad_headers():
    g = G("192.0.2.62", js=0).pages(6, sec="absent", assets=False)
    res, p = run(g.events)
    assert "R11" not in flags(res, p, "client:192.0.2.62")


def test_script_fetched_but_unexecuted_fires_weak_with_incoherent_headers():
    g = G("192.0.2.63").pages(6, sec="absent")
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.63")["R11"]
    assert f.extra["tier"] == "weak" and "script_fetched_but_unexecuted" in f.extra["reasons"]


def test_forged_beacon_is_strong():
    canned = {**HUMAN6, "challenge_proof_ok": False}
    g = G("192.0.2.64").pages(5, beacon=canned)
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.64")["R11"]
    assert f.extra["tier"] == "strong" and "beacon_forged" in f.extra["reasons"]
    l = lead(res, p, "client:192.0.2.64")
    assert l is not None and l.severity == "low" and l.automatic_action == "none" and l.recommended_action == "human_review"


def test_legacy_proofless_beacon_counts_as_arrived_not_forged():
    g = G("192.0.2.65").pages(6, beacon=LEGACY3)
    res, p = run(g.events)
    assert "R11" not in flags(res, p, "client:192.0.2.65")


def test_vlm_quantized_interaction_needs_valid_proof_and_two_quantized_beacons():
    vlm = {**HUMAN6, "inertial_scroll_ok": False, "kinematic_dwell_ok": False}
    g = G("192.0.2.66").pages(5, beacon=vlm)
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.66")["R11"]
    assert "vlm_quantized_interaction" in f.extra["reasons"] and f.extra["tier"] == "strong"
    # one quantized beacon only (others human): no VLM verdict
    g2 = G("192.0.2.67").pages(2, beacon=vlm).pages(4, beacon=HUMAN6, start=10)
    res2, p2 = run(g2.events)
    assert "vlm_quantized_interaction" not in (flags(res2, p2, "client:192.0.2.67").get("R11") or RuleFlag("x", "", "", [], 0, "", [])).extra.get("reasons", [])


def test_inversion_hit_alone_is_advisory_corroborate_tier_no_lead():
    g = G("192.0.2.68").pages(4, beacon=HUMAN6)
    g.req("/kb/archive/diagnostic", decoy_kind="dom_visual_inversion_hit", signals=["dom_visual_inversion_hit"], referer_present=True,
          referer_path="/kb/article-3", referer_valid=True, linked_from_prev=True, sec_fetch_state="coherent")
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.68")
    assert "R10" not in f                                   # the inversion lead is context-only, never a decoy floor
    assert f["R11"].extra["tier"] == "corroborate" and f["R11"].extra["floor"] is None
    assert lead(res, p, "client:192.0.2.68") is None


def test_accessibility_user_keyboard_inversion_is_not_a_lead():
    kb = {**HUMAN6, "pointer_trail_seen": False, "kinematic_dwell_ok": None}   # keyboard activation: no pointer, dwell unknown
    g = G("192.0.2.69").pages(5, beacon=kb)
    g.req("/kb/archive/diagnostic", decoy_kind="dom_visual_inversion_hit", signals=["dom_visual_inversion_hit"], referer_present=True,
          referer_path="/kb/article-4", referer_valid=True, linked_from_prev=True, sec_fetch_state="coherent")
    res, p = run(g.events)
    assert lead(res, p, "client:192.0.2.69") is None


def test_inversion_plus_synthetic_click_on_script_fetching_client_is_strong():
    synth = {**HUMAN6, "pointer_trail_seen": False, "kinematic_dwell_ok": False}
    g = G("192.0.2.70").pages(4, beacon=synth)
    g.req("/kb/archive/diagnostic", decoy_kind="dom_visual_inversion_hit", signals=["dom_visual_inversion_hit"], referer_present=True,
          referer_path="/kb/article-3", referer_valid=True, linked_from_prev=True, sec_fetch_state="coherent")
    res, p = run(g.events)
    assert "dom_order_synthetic_click" in flags(res, p, "client:192.0.2.70")["R11"].extra["reasons"]
    # the same with js_assets_fetched == 0 (no script ran): stays advisory
    g0 = G("192.0.2.71", js=0).pages(4, beacon=synth, assets=False)
    g0.req("/kb/archive/diagnostic", decoy_kind="dom_visual_inversion_hit", signals=["dom_visual_inversion_hit"], referer_present=True,
           referer_path="/kb/article-3", referer_valid=True, linked_from_prev=True, sec_fetch_state="coherent")
    res0, p0 = run(g0.events)
    assert "dom_order_synthetic_click" not in flags(res0, p0, "client:192.0.2.71").get("R11", RuleFlag("x", "", "", [], 0, "", [])).extra.get("reasons", [])


# ======================================================================== R10 / R9 cursor rules
def test_schema_provenance_cursor_while_browsing_is_strong_r10():
    g = G("192.0.2.72").pages(3, beacon=HUMAN6)
    for i in range(2):
        g.req(f"/kb/article-{20 + i}?cursor=prov.schema.abc", cursor_prov="schema", signals=["schema_provenance_cursor"],
              linked_from_prev=False, referer_present=False)
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.72")["R10"]
    assert f.extra["tier"] == "strong" and "schema_provenance_cursor" in f.extra["signals"]


def test_llmjacking_probe_maps_to_t0051_t0053_and_keeps_only_buckets():
    g = G("192.0.2.73", ua="python-httpx/0.27", js=0)
    g.req("/v1/chat/completions", kind="api", decoy_kind="llmjacking_probe", signals=["llmjacking_probe"],
          llmjacking={"tool_count": 3, "system_prompt_len_bucket": "1001-4000", "autonomous_loop_directive": True})
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.73")["R10"]
    ids = [a["id"] for a in f.atlas]
    assert "AML.T0051" in ids and "AML.T0053" in ids and f.extra["tier"] == "strong"
    assert f.extra["llmjacking"]["tool_count"] == 3 and f.extra["llmjacking"]["system_prompt_len_bucket"] == "1001-4000"


def test_bare_missing_required_cursor_is_advisory():
    g = G("192.0.2.74").pages(3, beacon=HUMAN6)
    for i in range(4):
        g.req(f"/kb/page/{i + 2}", status="denied", signals=["missing_required_cursor"], referer_present=True, referer_path="/kb/article-2",
              referer_valid=True, linked_from_prev=True)
    res, p = run(g.events)
    assert "R9" not in flags(res, p, "client:192.0.2.74") and lead(res, p, "client:192.0.2.74") is None


# ======================================================================== R14
def _rider(ip: str, gap: float) -> G:
    g = G(ip).pages(1, beacon=HUMAN6)
    for i in range(1, 6):
        g.req(f"/kb/article-{i}", 4.0, referer_present=True, referer_path=f"/kb/article-{i - 1}", referer_valid=True, linked_from_prev=True,
              sec_fetch_state="coherent", beacon_offered=True)
        g.req("/api/v1/telemetry/nav", 0.1, kind="beacon", beacon=HUMAN6)
        g.req(f"/kb/vault/item-{i}", gap - 0.1, linked_from_prev=False, referer_present=False)
    return g


def test_r14_fires_on_concurrent_unlinked_subtree():
    g = _rider("192.0.2.75", 0.25)
    res, p = run(g.events)
    f = flags(res, p, "client:192.0.2.75")
    assert "R14" in f and f["R14"].extra["forks"] >= 2


def test_r14_respects_the_500ms_window():
    g = _rider("192.0.2.76", 2.0)
    res, p = run(g.events)
    assert "R14" not in flags(res, p, "client:192.0.2.76")


def test_two_tab_reader_is_not_a_fork():
    g = G("192.0.2.77").pages(4, beacon=HUMAN6)
    g.req("/kb/article-30", 0.2, referer_present=True, referer_path="/kb/article-1", referer_valid=True, linked_from_prev=False,
          offered_earlier=True, sec_fetch_state="coherent")
    res, p = run(g.events)
    assert "R14" not in flags(res, p, "client:192.0.2.77")


# ======================================================================== R12
def _r12_agent(a: str, *, chain: bool = False, jump: bool = False, untrusted: bool = True, extra_steps: int = 0) -> List[Dict[str, Any]]:
    ev: List[Dict[str, Any]] = []
    n = [0]

    def e(t: float, action: str, **kw: Any) -> None:
        n[0] += 1
        ev.append({"event_id": f"{a}-{n[0]}", "ts": T0 + t, "source": "api_gateway", "agent_id": a, "action": action, "synthetic": True,
                   "dest_host": INTERNAL, **kw})
    for i in range(30):
        e(i * 200.0, "read", resource=f"/docs/page-{i}.md")
    for i in range(6):
        e(300 + i * 900.0, "tool_call", tool="http_post", resource="/hooks/notify", dest_host="hooks.partner-1.example.net",
          payload_bytes=1200 + 100 * i, arg_entropy=4.2)
    t = 20000.0
    if untrusted:
        e(t, "read", resource="/inbox/msg-1", untrusted_content=True)
    if chain:
        e(t + 10, "read", resource="/secrets/db/1")
    for k in range(extra_steps):
        e(t + 15 + k, "read", resource=f"/docs/page-{100 + k}.md")
    e(t + 40, "tool_call", tool="http_post", resource="/hooks/notify", dest_host="hooks.partner-1.example.net",
      payload_bytes=15000 if jump else 1300, arg_entropy=7.6 if jump else 4.2)
    return ev


def _r12(events, a):
    res, p = run(events, policy=Policy(declared_tools={a: ["http_post"]}))
    return flags(res, p, a).get("R12")


def test_r12_argument_jump_after_untrusted_read():
    f = _r12(_r12_agent("hj1", jump=True), "hj1")
    assert f is not None and "argument_jump" in f.extra["kinds"]
    assert [x["id"] for x in f.atlas] == ["AML.T0080", "AML.T0086"] == RULE_ATLAS["R12"]


def test_r12_read_sensitive_send_chain_within_three_steps():
    f = _r12(_r12_agent("hj2", chain=True), "hj2")
    assert f is not None and "read_sensitive_send_chain" in f.extra["kinds"]


def test_r12_negatives_no_untrusted_read_or_padded_chain_or_normal_size():
    assert _r12(_r12_agent("hj3", jump=True, untrusted=False), "hj3") is None
    assert _r12(_r12_agent("hj4", chain=True, extra_steps=4), "hj4") is None       # documented evasion: padding beyond 3 steps
    assert _r12(_r12_agent("hj5"), "hj5") is None


# ======================================================================== R13
def _norm(events):
    cfg = Config()
    rep = Normalizer(cfg.normalization, Pseudonymizer(KEY), None, cfg.web).process(events)
    assert not rep.quarantined
    return rep.events


def _probe_session(a: str, n: int, every: int, gap=lambda k: 30.0, same_resource: bool = False, served_later: bool = False):
    ev = []
    t = 0.0
    for k in range(n):
        t += gap(k)
        if k % every == every - 1:
            r = "/admin/users/1" if same_resource else SENSITIVE_PATHS[k % len(SENSITIVE_PATHS)] + f"/{k}"
            ev.append({"event_id": f"{a}-{k}", "ts": T0 + t, "source": "api_gateway", "agent_id": a, "action": "access", "status": "denied",
                       "resource": r, "dest_host": INTERNAL, "synthetic": True})
        else:
            ev.append({"event_id": f"{a}-{k}", "ts": T0 + t, "source": "api_gateway", "agent_id": a, "action": "read",
                       "resource": f"/docs/page-{k}.md", "dest_host": INTERNAL, "synthetic": True})
    return ev


def test_cusum_accumulates_a_padded_trickle_but_not_benign_noise():
    pc = ProbingCfg()
    trickle = [1 if i % 5 == 0 else 0 for i in range(300)]          # 20 %: well above p1_low
    assert cusum(trickle, pc.p0, pc.p1)[0] >= pc.cusum_h
    benign = [1 if i % 60 == 0 else 0 for i in range(300)]          # ~1.7 %
    assert cusum(benign, pc.p0, pc.p1)[0] < pc.cusum_h


def test_r13_fires_on_cmdp_style_padded_prober_and_retries_count_once():
    ev = _probe_session("cm1", 240, 6)
    st = stats(_norm(ev), ProbingCfg())
    assert st.w3_max <= 1 and st.cusum_max >= ProbingCfg().cusum_h
    res, p = run(ev)
    assert "R13" in flags(res, p, "cm1")
    retry = _probe_session("cm2", 240, 6, same_resource=True)       # one refused resource retried 40 times: ONE distinct probe
    assert sum(probe_vector(_order(_norm(retry)))) == 1
    res2, p2 = run(retry)
    assert "R13" not in flags(res2, p2, "cm2")


def test_timing_collapse_flags_a_pacer_not_poisson_or_a_clock():
    import random
    rng = random.Random(3)
    pc = ProbingCfg()
    paced = [0.0]
    for _ in range(60):
        paced.append(paced[-1] + rng.lognormvariate(4.0, 0.2))
    assert timing_collapse(paced, pc)[0]
    poisson = [0.0]
    for _ in range(60):
        poisson.append(poisson[-1] + rng.expovariate(1 / 50))
    assert not timing_collapse(poisson, pc)[0]
    clock = [i * 60.0 + rng.uniform(-0.5, 0.5) for i in range(60)]   # a cron: CV below collapse_min_cv -> excluded
    assert not timing_collapse(clock, pc)[0]


def test_collapse_alone_never_fires_r13():
    import random
    rng = random.Random(5)
    t, ev = 0.0, []
    for k in range(80):
        t += rng.lognormvariate(4.0, 0.2)
        ev.append({"event_id": f"pc-{k}", "ts": T0 + t, "source": "api_gateway", "agent_id": "pacer", "action": "read",
                   "resource": f"/docs/page-{k}.md", "dest_host": INTERNAL, "synthetic": True})
    res, p = run(ev)
    assert "R13" not in flags(res, p, "pacer")


def test_r13_hard_negatives_in_the_simulators():
    w = build_web(1, v6=True)
    res, p = run(w.events)
    for a, (k, g) in w.labels.items():
        if g in ("slow_legit_crawler", "human_flaky_network", "human_accessibility", "human_two_tabs", "human_kb_reader"):
            assert "R13" not in flags(res, p, a), (g, a)
    d = build(1, 30, extended=True, v6=True, positives=False)
    res2, p2 = run(d.events, policy=d.policy)
    inv = {p2.agent(a): a for a in d.labels}
    hit = {d.labels[inv[f.agent]][1] for f in res2.flags if f.rule_id == "R13" and f.agent in inv}
    assert not hit & {"cron_declared", "cron_undeclared", "permission_drift", "crawler", "compliance_scanner", "orchestrator_pool"}


def test_calibration_reads_only_what_it_is_given_and_is_deterministic():
    d = build(1001, 20, extended=True, v6=True, positives=False)
    assert all(k == "benign" for k, _ in d.labels.values())
    by = group_events(_norm(d.events))
    c1, c2 = calibrate(by, source="t"), calibrate(by, source="t")
    assert c1.as_dict() == c2.as_dict() and c1.p0 >= 0.005 and c1.w3_min <= 4 and c1.w7_min <= 8 and c1.collapse_hits_benign == 0


def test_configured_r13_thresholds_cover_the_calibration_output():
    pc = ProbingCfg()
    # numbers printed by scripts/calibrate_r13.py (benign seeds 1000-1002), rounded up into the config
    assert pc.cusum_h >= 3.59 and pc.cusum_h_low >= 2.51 and pc.p0 >= 0.0476 and pc.w3_min >= 3 and pc.w7_min >= 3


# ======================================================================== graph edges (AML.T0118)
def _reader(a: str, paths: List[str], t0: float, gap: float = 20.0) -> List[Dict[str, Any]]:
    import random
    rng = random.Random(a)                    # irregular gaps: a strict clock would be (correctly) suppressed as a shared schedule
    out, t = [], t0
    for i, p in enumerate(paths):
        t += rng.uniform(0.3, 1.7) * gap
        out.append({"event_id": f"{a}-{i}", "ts": T0 + t, "source": "web_server", "agent_id": a, "action": "access", "status": "allowed",
                    "resource": p, "synthetic": True, "web": {"user_agent": BROWSER, "content_kind": "html"}})
    return out


def _partition_world(declared: bool = False):
    import random
    rng = random.Random(11)
    kb = [f"/kb/article-{i}" for i in range(70)]
    ev: List[Dict[str, Any]] = []
    sh = kb[:]
    rng.shuffle(sh)
    swarm = [f"sw-{j}" for j in range(3)]
    for j, a in enumerate(swarm):
        ev += _reader(a, sh[j * 22:(j + 1) * 22], j * 5000.0)
    for h in range(8):                                              # ordinary readers: random overlapping samples
        ev += _reader(f"rd-{h}", rng.sample(kb, 15), 1000.0 + h * 700, gap=33.0)
    pol = Policy(suppression_groups=[SuppressionGroup(kind="orchestrator_pool", name="shards", members=swarm)]) if declared else Policy()
    return ev, swarm, pol


def _edge_kinds(res, pseudo, agents, active: bool = True):
    ids = {pseudo.agent(a) for a in agents}
    cl = (res.graph.active if active else res.graph.clusters) if res.graph else []
    return {e.kind for c in cl for e in c.edges if e.a in ids or e.b in ids}


def test_disjoint_target_partition_links_a_three_agent_split():
    ev, swarm, pol = _partition_world()
    res, p = run(ev, policy=pol)
    assert PARTITION in _edge_kinds(res, p, swarm)
    assert PARTITION not in _edge_kinds(res, p, [f"rd-{h}" for h in range(8)])
    c = next(c for c in res.graph.active if PARTITION in c.kinds)
    assert "AML.T0118" in [a["id"] for a in c.atlas]


def test_declared_pool_partition_is_suppressed():
    ev, swarm, pol = _partition_world(declared=True)
    res, p = run(ev, policy=pol)
    assert PARTITION not in _edge_kinds(res, p, swarm, active=True)


def test_partition_abstains_without_enough_outside_coverage_evidence():
    import random
    rng = random.Random(2)
    ev: List[Dict[str, Any]] = []
    for j in range(3):                                              # crawlers over a huge space: disjoint by chance, coverage unknown
        ev += _reader(f"cr-{j}", [f"/kb/page-{rng.randint(1, 10 ** 6)}" for _ in range(25)], j * 3000.0)
    res, p = run(ev)
    assert PARTITION not in _edge_kinds(res, p, [f"cr-{j}" for j in range(3)], active=False)


def test_epistemic_discovery_inheritance_and_slow_crawler_negative():
    w = build_web(0, v6=True)
    res, p = run(w.events)
    sw = [a for a, (_, g) in w.labels.items() if g == "swarm_schelling_overlap"]
    assert INHERITANCE in _edge_kinds(res, p, sw)
    crawl = [a for a, (_, g) in w.labels.items() if g in ("slow_legit_crawler", "human_kb_reader")]
    assert not _edge_kinds(res, p, crawl)


# ======================================================================== gate / families
def _flag(rid: str, s: float, **extra: Any) -> RuleFlag:
    return RuleFlag(rid, "t", "a", [], s, "e", [], extra=dict(extra))


def test_rule_families_combine_by_noisy_or_only_across_families():
    cfg = Config().fusion
    assert rules_strength(cfg, [_flag("R12", 0.6), _flag("R13", 0.5)]) == pytest.approx(0.8)
    assert rules_strength(cfg, [_flag("R1", 0.6), _flag("R12", 0.6)]) == 0.6          # same family (tool_use): strongest only
    assert rule_families(_flag("R13", 0.5, families=["probing", "timing"])) == ["probing", "timing"]
    assert RULE_FAMILY["R14"] == "session_fork" and RULE_FAMILY["R12"] == "tool_use"


def test_two_rule_families_pass_the_gate_one_weak_rule_does_not():
    cfg = Config().fusion
    two = fuse(cfg, {}, [_flag("R12", 0.6), _flag("R13", 0.5)], [], "t")
    assert two and two[0].gate_reason.startswith("rule_families:")
    one: List[Dict[str, Any]] = []
    assert fuse(cfg, {}, [_flag("R12", 0.64)], [], "t", gated_out=one) == [] and one
    off = cfg.model_copy(update={"corroboration_gate": False})
    assert fuse(off, {}, [_flag("R12", 0.7), _flag("R13", 0.5)], [], "t")[0].components["rules"] == 0.7   # gate off = v3 fusion (max)


# ======================================================================== simulators / labelling
def test_v6_core_cohorts_are_appended_without_changing_earlier_data():
    a, b = build(2, 30, extended=True), build(2, 30, extended=True, v6=True)
    assert b.events[: 0] == [] and [e for e in b.events if e["agent_id"] in a.labels] == a.events
    groups = {g for _, g in b.labels.values()}
    assert set(V6_SCENARIOS) <= groups and {"permission_drift", "sharded_pool"} <= groups


def test_v6_cohorts_are_labelled_same_author_synthetic():
    import rogue_pipeline.simulator as S
    import rogue_pipeline.web_simulator as W
    assert "Same author" in (S._v6.__doc__ or "")
    assert all(e.get("synthetic") is True for e in build_web(0, v6=True).events)
    assert set(V6_GROUPS) == set(V6_COUNTS)
    assert "same author" in (W.__doc__ or "").lower() or "same-author" in (W.__doc__ or "").lower()


def test_v6_web_leads_are_low_severity_human_review_only():
    w = build_web(2, v6=True)
    res, _ = run(w.events)
    assert res.leads and all(l.severity == "low" and l.automatic_action == "none" and l.recommended_action == "human_review" for l in res.leads)


# ======================================================================== STIX
def test_stix_carries_v6_rules_techniques_and_validates():
    from rogue_pipeline.stix_export import build_bundle, validate_bundle
    w = build_web(0, v6=True)
    res, p = run(w.events)
    want = {"R11", "R14", "R10"}
    chosen = [l for l in res.leads if {f.rule_id for f in l.rule_flags} & want or (l.cluster and PARTITION in l.cluster["edge_kinds"])]
    assert chosen
    dicts = [l.to_dict() for l in chosen]
    bundle = build_bundle(dicts, [d["lead_id"] for d in dicts])
    js = bundle.serialize()
    v = validate_bundle(js)
    assert v.parsed_ok, v.parse_error
    if v.validator_available:
        assert v.validator_ok, v.validator_messages
    obj = json.loads(js)
    assert any("x_rogue_v6_detections" in o for o in obj["objects"] if o["type"] == "indicator")
    ext = {r["external_id"] for o in obj["objects"] if o["type"] == "attack-pattern" for r in o["external_references"]}
    assert "AML.T0118" in ext or "AML.T0075" in ext


def test_v6_scripts_compile_and_calibration_script_reads_benign_only():
    import py_compile
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "scripts"
    for f in ("eval_v6.py", "_run_core.py", "calibrate_r13.py", "eval_web.py"):
        py_compile.compile(str(root / f), doraise=True)
    src = (root / "calibrate_r13.py").read_text()
    assert 'kind == "benign"' in src and "positives=False" in src


def test_reference_baseline_excludes_declared_sharded_pool_but_test_data_keeps_it():
    from rogue_pipeline.evaluation import V6_REFERENCE_EXCLUDE
    assert V6_REFERENCE_EXCLUDE == ("sharded_pool",)
    assert any(g == "sharded_pool" for _, g in build(0, 20, extended=True, v6=True).labels.values())
