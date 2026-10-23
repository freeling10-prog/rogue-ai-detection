"""v4 pipeline: R8 revision (selective blocking is not starvation), R11 (beacon / ARIA / browser-agent inconsistency), the two-signal
corroboration gate, per-layer attribution, the empirical R9 link-graph fallback, the encoded-secret scrubber port, the v4 web
simulator cohorts.

HONEST CAVEAT: simulators and rules share an author.  These tests pin intended behaviour and documented misses, not accuracy."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from pydantic import ValidationError

from rogue_pipeline.attribution import attribute, candidate_of_lead
from rogue_pipeline.config import Config, FusionCfg, Policy
from rogue_pipeline.evaluation import Counts, RunEval, aggregate, format_markdown
from rogue_pipeline.features import group_events
from rogue_pipeline.fusion import classify_actor, fuse, gate_decision
from rogue_pipeline.layer1_anomaly import AgentAnomaly
from rogue_pipeline.layer2_rules import LinkGraph, RuleEngine, RuleFlag
from rogue_pipeline.layer3_graph import Cluster, EdgeInfo
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import REDACTION_RE, RawEvent, WebMeta
from rogue_pipeline.scrub import Scrubber
from rogue_pipeline.sequence_model import SequenceResult
from rogue_pipeline.simulator import T0
from rogue_pipeline.web_simulator import V4_COUNTS, V4_GROUPS, build_web, to_v3_format

KEY = b"unit-test-key-0123456789abcdef"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
HUMAN_B = {"webdriver_present": False, "pointer_trail_seen": True, "dom_automation_props": False}
BOT_B = {"webdriver_present": True, "pointer_trail_seen": False, "dom_automation_props": False}
DOM_B = {"webdriver_present": False, "pointer_trail_seen": False, "dom_automation_props": True}
QUIET_B = {"webdriver_present": False, "pointer_trail_seen": False, "dom_automation_props": False}


class G:
    """Builder of v4 web RawEvent dicts for one client (browser UA)."""

    def __init__(self, ip: str = "192.0.2.50", ua: str = BROWSER) -> None:
        self.ip, self.ua, self.n, self.t = ip, ua, 0, 1000.0
        self.events: List[Dict[str, Any]] = []

    def req(self, path: str, dt: float = 3.0, *, kind: str = "html", status: str = "allowed", **web: Any) -> "G":
        self.n += 1
        self.t += dt
        w = {"user_agent": self.ua, "content_kind": kind, **{k: v for k, v in web.items() if v is not None}}
        self.events.append({"event_id": f"{self.ip}-{self.n}", "ts": T0 + self.t, "source": "web_server", "agent_id": f"client:{self.ip}",
                            "action": "access", "status": status, "resource": path, "ip": self.ip, "synthetic": True, "web": w})
        return self

    def pages(self, n: int, *, sec: Optional[str] = None, offered: bool = True, assets: tuple = (), beacon: Optional[dict] = None,
              referer: bool = True) -> "G":
        prev = None
        for i in range(n):
            self.req(f"/p{i}", beacon_offered=True if offered else None, referer_present=(prev is not None) if referer else None,
                     referer_path=prev if referer else None, sec_fetch_state=sec,
                     sec_fetch_mismatch=None if sec is None else sec != "coherent")
            for a in assets:
                self.req(f"/static/{a}", 0.05, kind="asset", asset_kind=a.split(".")[-1] if "." in a else a)
            if beacon is not None and i >= 1:
                self.req("/api/v1/telemetry/nav", 0.05, kind="beacon", beacon=beacon)
            prev = f"/p{i}"
        return self


def run(items: List[Dict[str, Any]], cfg: Optional[Config] = None, **kw):
    pseudo = Pseudonymizer(KEY)
    return Pipeline(cfg or Config(), Policy(), pseudo, **kw).run(items), pseudo


def flags_of(res, pseudo, ip: str) -> Dict[str, RuleFlag]:
    a = pseudo.agent(f"client:{ip}")
    return {f.rule_id: f for f in res.flags if f.agent == a}


def lead_of(res, pseudo, ip: str):
    a = pseudo.agent(f"client:{ip}")
    return next((l for l in res.leads if l.agent == a), None)


def with_crowd(g: G, n: int = 6) -> List[Dict[str, Any]]:
    """The client under test plus a few quiet human-like clients (so there is a population)."""
    items = list(g.events)
    for k in range(n):
        items += G(f"192.0.2.{120 + k}").pages(6, sec="coherent", assets=("site.css", "site.js"), beacon=HUMAN_B).events
    return items


# ============================================================= schema / normalization
def test_v4_web_fields_are_strict():
    base = {"event_id": "e1", "ts": 1.0e9, "source": "web_server", "agent_id": "client:1.2.3.4", "action": "access", "synthetic": True}
    ok = RawEvent.model_validate({**base, "web": {"content_kind": "beacon", "beacon": HUMAN_B}})
    assert ok.web.beacon.pointer_trail_seen is True
    for bad in ({"content_kind": "beacon", "beacon": {**HUMAN_B, "client_id": "x"}},             # an identifier smuggled into the beacon
                {"content_kind": "beacon", "beacon": {"webdriver_present": True}},               # missing booleans
                {"content_kind": "beacon", "beacon": {**HUMAN_B, "webdriver_present": "yes"}},   # no coercion
                {"content_kind": "html", "referer_path": "https://evil.example/x"},
                {"content_kind": "html", "referer_path": "//evil.example/x"},
                {"content_kind": "html", "referer_path": "/a\x00b"},
                {"strong_signal": "aria_fastpath_typo"}):
        with pytest.raises(ValidationError):
            RawEvent.model_validate({**base, "web": bad})
    assert WebMeta.model_validate({"strong_signal": "aria_fastpath"}).strong_signal == "aria_fastpath"


def test_normalizer_keeps_pseudonyms_not_paths_or_beacon_identifiers():
    pseudo = Pseudonymizer(KEY)
    g = G().pages(3, sec="coherent", beacon=HUMAN_B)
    rep = Normalizer(Config().normalization, pseudo, None, Config().web).process(g.events)
    html = [e for e in rep.events if e.web.content_kind == "html"]
    assert html[0].web.is_entry is False and html[1].web.referer_key == pseudo.resource("/p0")
    assert html[1].web.path_key == pseudo.resource("/p1")
    assert "/p0" not in repr(rep.events) and "Mozilla" not in repr(rep.events)
    b = [e for e in rep.events if e.web.content_kind == "beacon"][0]
    assert b.web.beacon == (False, True, False)
    assert Normalizer(Config().normalization, pseudo, None, Config().web).process(
        [G().req("/robots.txt").events[0]]).events[0].web.is_entry is True


# ============================================================= R8: selective blocking is not starvation
def test_r8_does_not_fire_for_images_only_blocked_human():
    g = G().pages(8, sec="coherent", assets=("site.css", "site.js", "favicon.ico"), beacon=HUMAN_B)       # no image is ever requested
    res, p = run(with_crowd(g))
    assert "R8" not in flags_of(res, p, g.ip) and lead_of(res, p, g.ip) is None


def test_r8_abstains_on_coherent_sec_fetch_even_with_zero_assets():
    g = G().pages(8, sec="coherent", offered=False)
    res, p = run(with_crowd(g))
    assert "R8" not in flags_of(res, p, g.ip)


def test_r8_abstains_when_core_css_js_were_loaded_even_without_sec_fetch():
    g = G().pages(8, sec="absent", assets=("site.css",), offered=False)
    res, p = run(with_crowd(g))
    assert "R8" not in flags_of(res, p, g.ip)


def test_r8_fires_on_zero_core_assets_with_absent_sec_fetch_and_favicon_only_does_not_exempt():
    g = G().pages(8, sec="absent", assets=("favicon.ico",), offered=False)       # favicon / images are not core assets
    res, p = run(with_crowd(g))
    f = flags_of(res, p, g.ip)["R8"]
    assert f.extra["core_assets"] == 0 and f.strength == Config().web.strength_asset_starvation_sec_fetch


def test_r8_fires_on_contradictory_sec_fetch_even_when_assets_were_loaded():
    g = G().pages(6, sec="contradictory", assets=("site.css", "site.js"), offered=False)
    res, p = run(with_crowd(g))
    assert flags_of(res, p, g.ip)["R8"].extra["contradictory"] == 6


def test_r8_legacy_events_without_asset_kind_still_exempt():
    g = G()
    for i in range(7):
        g.req(f"/p{i}", sec_fetch_mismatch=True)
        g.req("/x.png", 0.05, kind="asset")                                       # v3 collector: no asset_kind
    res, p = run(with_crowd(g))
    assert "R8" not in flags_of(res, p, g.ip)


# ============================================================= R11
def test_r11_webdriver_beacon_is_strong_floor_and_goal_directed():
    g = G().pages(6, sec="coherent", assets=("site.css", "site.js"), beacon=BOT_B)
    res, p = run(with_crowd(g))
    f = flags_of(res, p, g.ip)["R11"]
    assert f.extra["tier"] == "strong" and "webdriver_present" in f.extra["reasons"] and f.extra["floor"] == Config().web.floor_strong
    ld = lead_of(res, p, g.ip)
    assert ld is not None and ld.actor_class == "goal_directed" and ld.priority_band == "review_first" and ld.gate_reason == "floor"
    assert ld.severity == "low" and ld.automatic_action == "none" and ld.recommended_action == "human_review"


def test_r11_dom_automation_property_is_strong():
    g = G().pages(5, sec="coherent", assets=("site.css", "site.js"), beacon=DOM_B)
    res, p = run(with_crowd(g))
    assert "dom_automation_props" in flags_of(res, p, g.ip)["R11"].extra["reasons"]


def test_r11_aria_canary_hit_by_browser_backed_client_is_strong():
    g = G().pages(5, sec="coherent", assets=("site.css", "site.js"), beacon=QUIET_B)
    g.req("/api/v1/kb-snapshot", kind="api", strong_signal="aria_fastpath", decoy_kind="aria_fastpath")
    res, p = run(with_crowd(g))
    f = flags_of(res, p, g.ip)
    assert f["R11"].extra["tier"] == "strong" and "aria_canary_hit" in f["R11"].extra["reasons"] and f["R10"].extra["tier"] == "strong"


def test_r11_no_beacon_after_script_fetch_is_weak_floor_possible_mimic_not_review_first():
    g = G().pages(7, sec="coherent", assets=("site.css", "site.js"))              # fetches script, never runs it
    res, p = run(with_crowd(g))
    f = flags_of(res, p, g.ip)["R11"]
    assert f.extra["tier"] == "weak" and f.extra["reasons"] == ["beacon_missing_after_script_fetch"]
    ld = lead_of(res, p, g.ip)
    assert ld is not None and ld.actor_class == "possible_mimic" and ld.priority_band == "review" and ld.floor_applied == Config().web.floor_weak


def test_r11_is_silent_for_js_disabled_human_with_css_only():
    g = G().pages(7, sec="coherent", assets=("site.css",))
    res, p = run(with_crowd(g))
    assert "R11" not in flags_of(res, p, g.ip) and lead_of(res, p, g.ip) is None


def test_r11_is_silent_when_site_never_offered_the_beacon_or_too_few_navigations():
    g = G().pages(7, sec="coherent", assets=("site.css", "site.js"), offered=False)
    res, p = run(with_crowd(g))
    assert "R11" not in flags_of(res, p, g.ip)
    g2 = G("192.0.2.60").pages(3, sec="coherent", assets=("site.css", "site.js"))           # only 2 click-throughs < beacon_min_navs
    res2, p2 = run(with_crowd(g2))
    assert "R11" not in flags_of(res2, p2, g2.ip)


def test_r11_no_render_no_beacon_needs_noncoherent_sec_fetch_and_documents_the_forger_miss():
    absent = G("192.0.2.61").pages(8, sec="absent")
    res, p = run(with_crowd(absent))
    assert flags_of(res, p, absent.ip)["R11"].extra["reasons"] == ["no_render_no_beacon"]
    forger = G("192.0.2.62").pages(8, sec="coherent")                                       # forged coherent headers, no assets, no beacon
    res2, p2 = run(with_crowd(forger))
    assert "R11" not in flags_of(res2, p2, forger.ip) and lead_of(res2, p2, forger.ip) is None   # documented miss


def test_r11_stealth_beacon_with_hidden_values_is_a_documented_miss():
    g = G().pages(8, sec="coherent", assets=("site.css", "site.js"), beacon=QUIET_B)
    res, p = run(with_crowd(g))
    assert lead_of(res, p, g.ip) is None


def test_r11_human_with_beacon_and_pointer_is_clean():
    g = G().pages(8, sec="coherent", assets=("site.css", "site.js"), beacon=HUMAN_B)
    res, p = run(with_crowd(g))
    assert lead_of(res, p, g.ip) is None


def test_r11_ignores_clients_that_do_not_claim_a_browser():
    g = G(ua="python-requests/2.31").pages(8, sec="absent")
    res, p = run(with_crowd(g))
    assert "R11" not in flags_of(res, p, g.ip)


def test_classify_actor_r11_tiers():
    mk = lambda tier: RuleFlag("R11", "t", "a", [], 0.6, "e", [], extra={"tier": tier})
    assert classify_actor([mk("strong")]) == "goal_directed" and classify_actor([mk("weak")]) == "possible_mimic"


# ============================================================= corroboration gate
def _an(score: float) -> Dict[str, AgentAnomaly]:
    return {"x": AgentAnomaly("x", score, score, True)}


def _seq(score: float) -> Dict[str, SequenceResult]:
    return {"x": SequenceResult("x", score, 9.0, 4.0, 40)}


def _flag(rule: str = "R3", strength: float = 0.8, **extra: Any) -> RuleFlag:
    return RuleFlag(rule, "t", "x", [], strength, "e", [], extra=extra)


def _cluster(density: float, kinds=("timing_content",)) -> Cluster:
    return Cluster(["x", "y"], density, density, [EdgeInfo("x", "y", 0.0, 0, 0.0, 0.0, density, kind=k) for k in kinds])


def test_gate_blocks_purely_statistical_candidate_but_records_it():
    blocked: List[Dict[str, Any]] = []
    assert fuse(FusionCfg(), _an(0.9), [], [], "t", _seq(1.0), 0.6, blocked) == []
    assert blocked and blocked[0]["families"] == ["statistical"] and blocked[0]["agent"] == "x"
    off = fuse(FusionCfg(corroboration_gate=False), _an(0.9), [], [], "t", _seq(1.0), 0.6)
    assert len(off) == 1 and off[0].gate_reason == "gate_off"


def test_gate_isolation_forest_plus_sequence_count_as_one_family():
    f = FusionCfg()
    assert gate_decision(f, ["statistical"], 0.0, None, None) == ""


def test_gate_two_families_pass_and_low_isolation_forest_does_not_count():
    f = FusionCfg()
    ld = fuse(f, _an(0.9), [_flag("R9", 0.62)], [], "t")                     # statistical + rules
    assert len(ld) == 1 and ld[0].gate_reason == "families:statistical+rules" and ld[0].families == ["statistical", "rules"]
    weak_if = fuse(f, _an(0.2), [_flag("R9", 0.62)], [], "t")                # IF below anomaly_min: not a family -> rule alone, below solo_min
    assert weak_if == []


def test_gate_single_weak_rule_blocked_strong_rule_and_floor_pass():
    f = FusionCfg()
    assert fuse(f, {}, [_flag("R9", 0.62)], [], "t") == []
    assert fuse(f, {}, [_flag("R3", 0.8)], [], "t")[0].gate_reason == "solo_rule"
    fl = fuse(f, {}, [_flag("R10", 0.58, floor=0.58, tier="weak")], [], "t")
    assert fl and fl[0].gate_reason == "floor"


def test_gate_solo_cluster_requires_density_and_edge_plus_anomaly_passes():
    f = FusionCfg()
    anoms = {"x": AgentAnomaly("x", 0.5, 0.5, True), "y": AgentAnomaly("y", 0.5, 0.5, True)}
    assert fuse(f, {}, [], [_cluster(0.9)], "t")[0].gate_reason == "solo_graph"
    assert fuse(f, {}, [], [_cluster(0.70)], "t") == []                                       # score .56 passes the threshold, gate blocks it
    both = fuse(f, anoms, [], [_cluster(0.70)], "t")
    assert both and both[0].gate_reason == "families:statistical+graph"


def test_gate_strict_setting_removes_solo_exceptions():
    strict = FusionCfg(rule_solo_min=1.01, graph_solo_min=1.01)
    assert fuse(strict, {}, [_flag("R3", 0.8)], [], "t") == []
    assert fuse(strict, {}, [_flag("R10", 0.8, floor=0.8, tier="strong")], [], "t")            # floors still pass


def test_gate_off_switch_restores_v3_fusion_exactly():
    f_off = FusionCfg(corroboration_gate=False)
    assert len(fuse(f_off, {}, [_flag("R9", 0.62)], [], "t")) == 1


def test_gated_out_candidates_surface_on_pipeline_result():
    g = G().pages(8, sec="coherent", assets=("site.css", "site.js"), beacon=HUMAN_B)
    res, _ = run(with_crowd(g))
    assert isinstance(res.gated_out, list)


# ============================================================= attribution
def _lead(cfg: FusionCfg, **kw: Any):
    return fuse(cfg, kw.get("an", {}), kw.get("flags", []), kw.get("clusters", []), "t", kw.get("seq"), 0.6)[0]


def test_attribution_layers():
    off = FusionCfg(corroboration_gate=False)
    seq_if = _lead(off, an=_an(0.9), seq=_seq(1.0))
    assert attribute(candidate_of_lead(seq_if), off)["detail"] == "isolation_forest+sequence_model"
    assert attribute(candidate_of_lead(_lead(off, flags=[_flag("R3", 0.8)])), off)["layer"] == "rule_gate"
    fl = _lead(off, flags=[_flag("R11", 0.58, floor=0.58, tier="weak")])
    a = attribute(candidate_of_lead(fl), off)
    assert a["layer"] == "floor" and a["detail"] == "floor:R11"
    g = attribute(candidate_of_lead(_lead(off, clusters=[_cluster(0.9, ("timing_content", "shared_redacted_token"))])), off)
    assert g["layer"] == "coordination_graph" and "timing_content" in g["detail"]


def test_attribution_table_appears_in_evaluation_markdown_and_counts_gate_effect():
    c = Counts(5, 2, 1, 40)
    run1 = RunEval(0, 0.0, {"fused_leads": {"overall": c}}, {"g": (1, 3)}, 10, 3, True, {},
                   [("benign", "compliance_scanner", "isolation_forest+sequence_model", True), ("benign", "tool_adopter", "rule:R2", False),
                    ("positive", "exfil", "isolation_forest+sequence_model", True)])
    agg = aggregate([run1])
    assert agg["attribution"]["benign"]["compliance_scanner | isolation_forest+sequence_model"] == {"leads_without_gate": 1, "blocked_by_gate": 1}
    md = format_markdown({"levels": {"0.0": agg}})
    assert "Per-layer attribution" in md and "| benign | compliance_scanner | isolation_forest+sequence_model | 1 | 1 |" in md


# ============================================================= R9 fallback: empirical link graph
def _plain(ip: str, path_chain: List[str], first_direct: bool = True) -> List[Dict[str, Any]]:
    """Ordinary access-log style events: NO offered-link fields, only same-site Referer paths."""
    g = G(ip)
    prev = None
    for p in path_chain:
        g.req(p, 5.0, referer_path=prev, referer_present=prev is not None)
        prev = p
    return g.events


SITE = ["/", "/a", "/b", "/c", "/d", "/e", "/f"]


def _crowd_plain(n: int = 8) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for k in range(n):
        out += _plain(f"192.0.2.{150 + k}", SITE)
    return out


def test_r9_fallback_flags_jumps_that_no_observed_navigation_supports():
    jumper = _plain("192.0.2.90", ["/", "/d", "/f", "/b", "/e", "/c"])         # lands deep, no referer, on pages benign users reach by click only
    for e in jumper[1:]:
        e["web"].pop("referer_path", None); e["web"]["referer_present"] = False
    res, p = run(_crowd_plain() + jumper)
    f = flags_of(res, p, "192.0.2.90")["R9"]
    assert f.extra["fallback"] is True and f.strength == Config().web.link_fallback_strength
    for k in range(8):
        assert "R9" not in flags_of(res, p, f"192.0.2.{150 + k}")                     # benign click-throughs are the graph


def test_r9_fallback_exempts_entry_points_and_popular_direct_landing_pages():
    out = _crowd_plain()
    for k in range(4):                                                              # four benign visitors land directly on /e (e.g. from search)
        v = _plain(f"192.0.2.{170 + k}", ["/e"]); out += v
    visitor = _plain("192.0.2.95", ["/", "/robots.txt", "/sitemap.xml", "/e", "/e", "/e"])
    for e in visitor:
        e["web"].pop("referer_path", None); e["web"]["referer_present"] = False
    res, p = run(out + visitor)
    assert "R9" not in flags_of(res, p, "192.0.2.95")


def test_r9_fallback_is_off_without_population_or_when_disabled():
    jumper = _plain("192.0.2.90", ["/", "/d", "/f", "/b", "/e", "/c"])
    for e in jumper[1:]:
        e["web"].pop("referer_path", None); e["web"]["referer_present"] = False
    res, p = run(_crowd_plain(1) + jumper)                                           # too few clients to infer a graph
    assert "R9" not in flags_of(res, p, "192.0.2.90")
    off = Config().model_copy(update={"web": Config().web.model_copy(update={"link_graph_fallback": False})})
    res2, p2 = run(_crowd_plain() + jumper, cfg=off)
    assert "R9" not in flags_of(res2, p2, "192.0.2.90")


def test_r9_exact_graph_takes_precedence_over_fallback():
    g = G("192.0.2.96")
    for i, pth in enumerate(["/", "/d", "/f", "/b", "/e", "/c"]):
        g.req(pth, 3.0, linked_from_prev=None if i == 0 else False, referer_valid=None if i == 0 else False, offered_earlier=None if i == 0 else False)
    res, p = run(_crowd_plain() + g.events)
    f = flags_of(res, p, "192.0.2.96")["R9"]
    assert "fallback" not in f.extra and f.extra["never_offered"] >= 2


def test_r9_client_cannot_support_its_own_moves_and_reference_graph_is_used_alone():
    own = _plain("192.0.2.97", ["/", "/d", "/f", "/b", "/e", "/c"])
    for e in own[1:]:
        e["web"].pop("referer_path", None); e["web"]["referer_present"] = False
    pseudo = Pseudonymizer(KEY)
    pipe = Pipeline(Config(), Policy(), pseudo)
    ref = pipe.learn_link_reference(_crowd_plain())
    assert isinstance(ref, LinkGraph) and len(ref.agents) == 8
    res = Pipeline(Config(), Policy(), pseudo, link_reference=ref).run(own + _plain("192.0.2.98", SITE))
    assert "R9" in {f.rule_id for f in res.flags if f.agent == pseudo.agent("client:192.0.2.97")}
    # leave-one-out: the engine never lets the agent's own edges count as support
    rep = Normalizer(Config().normalization, pseudo, None, Config().web).process(own)
    lg = LinkGraph.learn(group_events(rep.events))
    ev = rep.events[-1]
    assert lg.allowed(ev.agent, ev, Config().web) is False


# ============================================================= scrubber port
def _sc() -> Scrubber:
    p = Pseudonymizer(KEY)
    return Scrubber(lambda v: p.token("scrub", v, ""))


SECRET = "sk-abcdefghijklmnopqrstuvwxyz0123"


@pytest.mark.parametrize("text", [
    SECRET,
    "sk-abcdefghijklmnop\nqrstuvwxyz0123",                  # newline-split
    "sk-abcdefghijklmnop\r\nqrstuvwxyz0123",                # CR LF
    "sk-abcdefghijklmnop\tqrstuvwxyz0123",                  # TAB
    "sk-abcdefghijklmnop\\nqrstuvwxyz0123",                 # escaped \n
    "sk-abcdefghijklmnop%0Aqrstuvwxyz0123",                 # percent newline
    "sk%2Dabcdefghijklmnopqrstuvwxyz0123",                  # %2D = '-'
    "sk-abcdefghijklmnop\\u0071rstuvwxyz0123",              # \u0071 = 'q'
    "ｓｋ-abcdefghijklmnopqrstuvwxyz0123",                   # full-width
    "sk-abcdefghijklmnop\u200bqrstuvwxyz0123",              # zero-width space
])
def test_scrubber_collapses_encoded_and_split_secrets_to_the_same_marker(text):
    out = _sc().scrub_text(f"key={text} end")
    assert REDACTION_RE.search(out) and "abcdefghijklmnop" not in out and out.endswith(" end")
    assert REDACTION_RE.search(out).group(0) == REDACTION_RE.search(_sc().scrub_text(SECRET)).group(0)


def test_scrubber_email_encodings_and_double_encoding_and_marker_is_keyed():
    plain = _sc().scrub_text("bob@example.com")
    for enc in ("bob%40example.com", "bob%2540example.com", "bob\\u0040example.com", "bob\\u002540example.com", "BOB@Example.COM"):
        assert _sc().scrub_text(enc) == plain, enc
    nested = _sc().scrub({"bob@example.com": {"note": "bob@example.com"}})
    assert "bob@example.com" not in nested and "bob@example.com" not in next(iter(nested.values()))["note"]
    other = Scrubber(lambda v: Pseudonymizer(b"another-key-0123456789abcdef").token("scrub", v, ""))
    assert other.scrub_text("bob@example.com") != plain               # different key -> different marker (no cross-deployment correlation)
    assert _sc().scrub_text("a%20b") == "a%20b"                         # non-secrets are left exactly as they were


def test_scrubber_bearer_and_github_and_jwt_shapes():
    s = _sc()
    for t in ("Authorization: Bearer abc.DEF-123_xyz", "ghp_abcdefghijklmnopqrstuvwx", "AKIAABCDEFGHIJKLMNOP",
              "eyJhbGciOiJIUzI.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4"):
        assert REDACTION_RE.search(s.scrub_text(t)), t


def test_normalizer_scrubs_raw_fields_before_hashing_and_marks_them_as_redaction_tokens():
    pseudo = Pseudonymizer(KEY)
    norm = Normalizer(Config().normalization, pseudo)
    def ev(i: str, res: str, text: str, tok: Optional[str] = None) -> Dict[str, Any]:
        d = {"event_id": i, "ts": 1.0e9, "source": "api_gateway", "agent_id": f"a-{i}", "action": "message", "synthetic": True,
             "resource": "peer-" + res, "text": text}
        if tok:
            d["request_token"] = tok
        return d
    rep = norm.process([ev("e1", "x", f"use {SECRET} now"), ev("e2", "x", "use sk%2Dabcdefghijklmnopqrstuvwxyz0123 now"),
                        ev("e3", "x", "see bob%40example.com", tok=SECRET)])
    a, b, c = rep.events
    assert a.redactions == b.redactions and len(a.redactions) == 1          # encoded and plain secret: the SAME correlatable marker
    assert a.shingles == b.shingles
    assert c.presented is None and len(c.redactions) == 2                   # a secret-shaped request token became a marker, not a token
    assert SECRET not in repr(rep.events) and "abcdefghijklmnop" not in repr(rep.events)


def test_scrub_switch_off_keeps_v3_behaviour():
    pseudo = Pseudonymizer(KEY)
    cfg = Config().normalization.model_copy(update={"scrub_raw_fields": False})
    n = Normalizer(cfg, pseudo)
    assert n.scrubber is None
    rep = n.process([{"event_id": "e", "ts": 1.0e9, "source": "api_gateway", "agent_id": "a", "action": "message", "synthetic": True,
                      "resource": "peer", "text": f"use {SECRET}"}])
    assert not rep.events[0].redactions


def test_shared_encoded_secret_joins_two_agents_in_the_graph_via_the_marker():
    """End to end: the same secret leaked once in plain form and once percent-encoded is ONE shared redaction marker."""
    pseudo = Pseudonymizer(KEY)
    rep = Normalizer(Config().normalization, pseudo).process([
        {"event_id": "r1", "ts": 1.0e9, "source": "api_gateway", "agent_id": "p", "action": "message", "synthetic": True, "resource": "q", "text": f"k {SECRET}"},
        {"event_id": "r2", "ts": 1.0e9 + 5, "source": "api_gateway", "agent_id": "q", "action": "message", "synthetic": True, "resource": "p",
         "text": "k sk%2Dabcdefghijklmnopqrstuvwxyz0123"}])
    assert rep.events[0].redactions == rep.events[1].redactions


# ============================================================= simulator cohorts (v4)
@pytest.fixture(scope="module")
def v4_run():
    web = build_web(0, v4=True)
    pseudo = Pseudonymizer(KEY)
    res = Pipeline(Config(), Policy(), pseudo).run(web.events)
    leads = {l.agent: l for l in res.leads}
    by_group: Dict[str, List[Any]] = {}
    for agent, (_, grp) in web.labels.items():
        by_group.setdefault(grp, []).append(leads.get(pseudo.agent(agent)))
    return res, by_group, web


def test_v4_simulator_keeps_v3_groups_identical_and_v3_format_is_strippable():
    v3, v4 = build_web(1), build_web(1, v4=True)
    stripped = [e for e in to_v3_format(v4.events) if v4.labels[e["agent_id"]][1] in {g for _, g in v3.labels.values()}]
    assert len(stripped) == len(v3.events) and all("beacon" not in e["web"] and "asset_kind" not in e["web"] for e in stripped)
    assert {v4.labels[a][1] for a in v4.labels} >= set(V4_GROUPS) and all(V4_COUNTS[g] > 0 for g in V4_GROUPS)
    assert not [e for e in to_v3_format(v4.events) if e["web"].get("content_kind") == "beacon"]


def test_v4_cohorts_events_validate_with_nothing_quarantined(v4_run):
    res, _, web = v4_run
    assert not res.normalization.quarantined and len(res.normalization.events) == len(web.events)


@pytest.mark.parametrize("group", ["web_human", "web_human_no_assets", "human_images_blocked", "human_js_off"])
def test_v4_ordinary_humans_get_no_lead(v4_run, group):
    assert all(l is None for l in v4_run[1][group]), group


@pytest.mark.parametrize("group", ["human_beacon_blocked", "human_no_assets_nosec"])
def test_v4_hard_negative_humans_get_a_weak_queue_lead_by_design(v4_run, group):
    leads = v4_run[1][group]
    assert all(l is not None and l.actor_class == "possible_mimic" and l.priority_band == "review" for l in leads), group


@pytest.mark.parametrize("group", ["mimic_assets", "mimic_linked", "mimic_linked_nosec", "mimic_browser_webdriver", "mimic_aria", "mimic_basic"])
def test_v4_mimics_produce_leads(v4_run, group):
    assert all(l is not None for l in v4_run[1][group]), group


def test_v4_strong_cohorts_are_goal_directed_review_first(v4_run):
    for group in ("mimic_browser_webdriver", "mimic_aria"):
        assert all(l.actor_class == "goal_directed" and l.priority_band == "review_first" for l in v4_run[1][group]), group


@pytest.mark.parametrize("group", ["mimic_browser_stealth", "mimic_header_forger"])
def test_v4_documented_evaders_still_evade(v4_run, group):
    assert all(l is None for l in v4_run[1][group]), group


def test_v4_scanner_prefilter_and_accidental_scraper_unchanged(v4_run):
    _, g, _ = v4_run
    assert all(l is None for l in g["commodity_scanner"]) and all(l is not None and l.actor_class == "accidental_scraper" for l in g["accidental_scraper"])


def test_v4_leads_never_carry_user_agent_or_beacon_payload(v4_run):
    res, _, _ = v4_run
    blob = json.dumps([l.to_dict() for l in res.leads], default=str)
    assert "Mozilla" not in blob and "Firefox" not in blob and '"pointer_trail_seen"' not in blob and '"beacon"' not in blob


def test_v4_scripts_compile():
    import py_compile
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "scripts"
    for f in ("eval_web.py", "_run_events.py"):
        py_compile.compile(str(root / f), doraise=True)
