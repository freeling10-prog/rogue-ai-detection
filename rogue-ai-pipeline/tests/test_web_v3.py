"""v3: web-collector evidence (R8 asset starvation, R9 unlinked jump, R10 strong-signal floor), the commodity-scanner
pre-filter, accidental-scraper vs goal-directed classification, baseline hygiene and the synthetic web clients.

HONEST CAVEAT: the simulated web clients were written by the same author as the rules.  These tests pin intended behaviour
(including documented misses); they are not accuracy measurements."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pytest
from pydantic import ValidationError

from rogue_pipeline.audit import AuditLog
from rogue_pipeline.baseline import train_baseline
from rogue_pipeline.config import Config, Policy
from rogue_pipeline.features import group_events
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.prefilter import classify_scanner, prefilter_by_agent
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import RawEvent, WebMeta
from rogue_pipeline.simulator import T0, build
from rogue_pipeline.web_simulator import COUNTS, GROUPS, build_web

KEY = b"unit-test-key-0123456789abcdef"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
ROOT = Path(__file__).resolve().parent.parent


class Gen:
    """Tiny builder of web RawEvent dicts for one client."""

    def __init__(self, ip: str = "192.0.2.50", ua: str = BROWSER) -> None:
        self.ip, self.ua, self.n, self.t = ip, ua, 0, 1000.0
        self.events: List[Dict[str, Any]] = []

    def req(self, path: str, dt: float = 3.0, *, kind: str = "html", status: str = "allowed", ua: Optional[str] = None, **web: Any) -> "Gen":
        self.n += 1
        self.t += dt
        w = {"user_agent": ua or self.ua, "content_kind": kind, **{k: v for k, v in web.items() if v is not None}}
        self.events.append({"event_id": f"{self.ip}-{self.n}", "ts": T0 + self.t, "source": "web_server", "agent_id": f"client:{self.ip}",
                            "action": "access", "status": status, "resource": path, "ip": self.ip, "synthetic": True, "web": w})
        return self

    def pages(self, n: int, *, sec: Optional[bool] = None, linked: bool = True) -> "Gen":
        for i in range(n):
            self.req(f"/p{i}", linked_from_prev=None if i == 0 else linked, referer_valid=None if i == 0 else linked, sec_fetch_mismatch=sec)
        return self


def run(items: List[Dict[str, Any]], cfg: Optional[Config] = None, audit: Optional[AuditLog] = None):
    pseudo = Pseudonymizer(KEY)
    return Pipeline(cfg or Config(), Policy(), pseudo, audit=audit).run(items), pseudo


def lead_for(res, pseudo, agent_raw: str):
    a = pseudo.agent(agent_raw)
    return next((l for l in res.leads if l.agent == a), None)


def rules_of(res, pseudo, raw):
    a = pseudo.agent(raw)
    return {f.rule_id: f for f in res.flags if f.agent == a}


# ------------------------------------------------------------------------------------------ schema / normalization
def test_web_block_is_strict():
    ok = {"event_id": "e1", "ts": 1.0e9, "source": "web_server", "agent_id": "client:1.2.3.4", "action": "access", "synthetic": True,
          "web": {"content_kind": "html", "linked_from_prev": True}}
    assert RawEvent.model_validate(ok).web.content_kind == "html"
    for bad in ({"nope": 1}, {"content_kind": "video"}, {"strong_signal": "made_up"}, {"mcp": "resources_read"}, {"linked_from_prev": "yes"},
                {"decoy_kind": "Has Spaces"}, {"user_agent": "bad\x00ua"}, {"ja4": "not-a-ja4"}, {"user_agent": "x" * 301}):
        with pytest.raises(ValidationError):
            RawEvent.model_validate({**ok, "web": bad})


def test_malformed_web_block_goes_to_quarantine_not_silently_dropped():
    g = Gen().req("/")
    g.events[0]["web"]["surprise"] = 1
    res, _ = run(g.events)
    assert len(res.normalization.quarantined) == 1 and "unknown_field" in res.normalization.quarantined[0].reasons[0]


def test_user_agent_is_reduced_to_flags_and_discarded():
    pseudo = Pseudonymizer(KEY)
    rep = Normalizer(Config().normalization, pseudo, None, Config().web).process(
        [Gen(ua="zgrab/0.x").req("/.env").events[0], Gen("192.0.2.51").req("/").events[0], Gen("192.0.2.52", ua="Googlebot/2.1 bot").req("/").events[0]])
    kinds = [e.web.ua_class for e in rep.events]
    assert kinds == ["scanner", "browser", "declared_bot"]
    for e in rep.events:
        assert "zgrab" not in repr(e) and "Mozilla" not in repr(e) and "/.env" not in repr(e)       # nothing raw survives
        assert not hasattr(e.web, "user_agent")


def test_events_without_a_web_block_are_unchanged():
    pseudo = Pseudonymizer(KEY)
    rep = Normalizer(Config().normalization, pseudo).process([{"event_id": "x", "ts": 1.0e9, "source": "api_gateway", "agent_id": "a1",
                                                              "action": "read", "synthetic": True, "resource": "/config/.env"}])
    assert rep.events[0].web is None


# ------------------------------------------------------------------------------------------ pre-filter
SCANNER_PATHS = ["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin/index.php", "/wp-admin/", "/index.php", "/.git/config"]


def scanner(ip="192.0.2.60", ua=BROWSER, paths=SCANNER_PATHS):
    g = Gen(ip, ua)
    for p in paths:
        g.req(p, 0.4, kind="other", status="denied")
    return g


@pytest.mark.parametrize("ua", ["zgrab/0.x", "masscan/1.3", "CensysInspect/1.1", "Mozilla/5.0 (compatible; Shodan)", "Nmap Scripting Engine", "nikto/2.5"])
def test_known_scanner_user_agents_are_filtered_even_on_innocuous_paths(ua):
    g = Gen(ua=ua).req("/").req("/about")
    res, _ = run(g.events + Gen("192.0.2.99").pages(3).events)
    assert res.prefiltered.agents == 1 and res.prefiltered.by_reason == {"scanner_ua": 1}


@pytest.mark.parametrize("paths", [["/wp-login.php"] * 3, ["/.env", "/.env.bak"], ["/phpmyadmin/"] * 2, ["/shell.php", "/a/b/c.php"], ["/wp-admin/x"]])
def test_php_wordpress_env_phpmyadmin_only_clients_are_filtered(paths):
    res, _ = run(scanner(paths=paths).events + Gen("192.0.2.99").pages(3).events)
    assert res.prefiltered.by_reason == {"scanner_path": 1} and res.prefiltered.events == len(paths)


def test_filtered_clients_are_counted_in_result_notes_and_audit_log(tmp_path):
    items = scanner("192.0.2.61").events + scanner("192.0.2.62", "zgrab/0.x").events + Gen("192.0.2.99").pages(6).events
    res, _ = run(items, audit=AuditLog(tmp_path / "audit.jsonl"))
    assert res.prefiltered.agents == 2 and res.prefiltered.events == 14 and res.prefiltered.by_reason == {"scanner_path": 1, "scanner_ua": 1}
    assert any("pre-filter set aside 2 commodity-scanner" in n for n in res.notes)
    log = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    pf = [r for r in log if r.get("type", r.get("event")) == "prefilter" or "agents_filtered" in json.dumps(r)]
    assert pf and "agents_filtered" in json.dumps(pf[0])


def test_filtered_scanner_never_becomes_a_lead_but_would_without_the_filter():
    # 14 denied requests on sensitive-looking paths: R5 (access probing) fires when the filter is off
    heavy = Gen("192.0.2.70")
    for i in range(14):
        heavy.req(["/.env", "/admin/config.php", "/config/.env", "/admin/xmlrpc.php", "/secrets/x.php"][i % 5], 0.3, kind="other", status="denied")
    benign = [e for i in range(12) for e in Gen(f"192.0.2.{100 + i}").pages(8).events]
    on, p1 = run(heavy.events + benign)
    off, p2 = run(heavy.events + benign, Config(web={"prefilter": False}))
    assert lead_for(on, p1, "client:192.0.2.70") is None and on.prefiltered.agents == 1
    assert lead_for(off, p2, "client:192.0.2.70") is not None and "R5" in rules_of(off, p2, "client:192.0.2.70")


def test_scanner_user_agent_is_not_a_hiding_place_for_goal_directed_clients():
    g = Gen(ua="zgrab/0.x").req("/.env", kind="other", status="denied").req("/mcp", kind="api", mcp="tools_list")
    g.req("/mcp", kind="api", mcp="tools_call", strong_signal="mcp_list_then_call", decoy_kind="mcp_decoy_tool_call")
    res, p = run(g.events + Gen("192.0.2.99").pages(4).events)
    assert res.prefiltered.agents == 0 and res.prefiltered.kept_scanner_like_with_goal_evidence == 1
    assert lead_for(res, p, "client:192.0.2.50").actor_class == "goal_directed"


@pytest.mark.parametrize("signal", ["schema_param", "session_canary", "error_hint_follow", "mcp_tools_call", "fake_credential_use"])
def test_using_what_a_decoy_offered_exempts_a_scanner_looking_client(signal):
    g = scanner(paths=["/wp-login.php", "/.env", "/xmlrpc.php"]).req("/api/v1/status", kind="api", strong_signal=signal)
    res, _ = run(g.events + Gen("192.0.2.99").pages(3).events)
    assert res.prefiltered.agents == 0


def test_a_bare_decoy_touch_does_not_exempt_a_scanner():
    """Scanners hit the /.env and /wp-login decoys constantly; touching a decoy is not goal-directed evidence."""
    g = scanner(paths=["/wp-login.php", "/.env", "/xmlrpc.php"]).req("/.env", kind="other", strong_signal="decoy_hit", decoy_kind="fake_credentials_file")
    res, _ = run(g.events + Gen("192.0.2.99").pages(3).events)
    assert res.prefiltered.agents == 1


def test_mixed_client_below_the_scanner_path_share_is_not_filtered():
    g = scanner(paths=["/wp-login.php", "/.env"])
    g.pages(6)                                                      # 2 of 8 requests are scanner paths = 25% < 80%
    res, _ = run(g.events)
    assert res.prefiltered.agents == 0


def test_non_web_traffic_is_never_prefiltered():
    items = [{"event_id": f"e{i}", "ts": 1.0e9 + i, "source": "api_gateway", "agent_id": "probe-1", "action": "access", "status": "denied",
              "resource": "/wp-login.php", "synthetic": True} for i in range(30)]
    res, _ = run(items)
    assert res.prefiltered.agents == 0 and res.prefiltered.events == 0


def test_prefilter_switch_and_config_validation():
    assert Config(web={"enabled": False}).web.enabled is False
    with pytest.raises(ValidationError):
        Config(web={"scanner_path_min_share": 0.4})
    with pytest.raises(ValidationError):
        Config(web={"unknown": 1})
    by = group_events(Normalizer(Config().normalization, Pseudonymizer(KEY), None, Config().web).process(scanner().events).events)
    kept, rep = prefilter_by_agent(by, Config(web={"prefilter": False}).web)
    assert kept == by and rep.agents == 0
    assert all(classify_scanner(v, Config().web) == "scanner_path" for v in by.values())


def test_scanners_are_kept_out_of_the_frozen_baseline():
    cfg = Config()
    pseudo = Pseudonymizer(KEY)
    ref: Dict[str, Any] = {}
    items = []
    for k in (1000, 1001, 1002):
        d = build(k, 60, extended=True, positives=False)
        items += [{**e, "agent_id": f"r{k}-{e['agent_id']}", "event_id": f"r{k}-{e['event_id']}"} for e in d.events]
    scans = [e for i in range(6) for e in scanner(f"192.0.2.{150 + i}", paths=SCANNER_PATHS * 3).events]
    norm = Normalizer(cfg.normalization, pseudo, None, cfg.web)
    clean = group_events(norm.process(items).events)
    dirty = group_events(norm.process(items + scans).events)
    assert len(dirty) == len(clean) + 6
    b_clean, b_dirty = train_baseline(clean, cfg, created_at="2026-01-01T00:00:00+00:00"), train_baseline(dirty, cfg, created_at="2026-01-01T00:00:00+00:00")
    assert b_dirty.meta["n_prefiltered_scanner_agents"] == 6 and b_clean.meta["n_prefiltered_scanner_agents"] == 0
    assert b_dirty.meta["n_reference_agents"] == b_clean.meta["n_reference_agents"]
    same = lambda a, b: (np.array_equal(a.scaler_center, b.scaler_center) and np.array_equal(a.ref_median, b.ref_median)
                         and a.lo == b.lo and a.hi == b.hi)
    assert same(b_dirty, b_clean)                                       # identical model: the scanners left no trace in the baseline
    # control: with the filter OFF the scanners are learned as 'normal'
    b_off = train_baseline(dirty, Config(web={"prefilter": False}), created_at="2026-01-01T00:00:00+00:00")
    assert b_off.meta["n_reference_agents"] == b_clean.meta["n_reference_agents"] + 6 and not same(b_off, b_clean)


# ------------------------------------------------------------------------------------------ R8
def test_r8_fires_at_five_pages_without_assets():
    res, p = run(Gen().pages(5).events)
    f = rules_of(res, p, "client:192.0.2.50")["R8"]
    assert f.extra["pages"] == 5 and "Sec-Fetch" in f.explanation and "not checked" in f.explanation


def test_r8_needs_five_pages_zero_assets_and_a_browser_claim():
    assert "R8" not in rules_of(*run(Gen().pages(4).events), "client:192.0.2.50")
    g = Gen().pages(8).req("/favicon.ico", kind="asset")
    assert "R8" not in rules_of(*run(g.events), "client:192.0.2.50")
    assert "R8" not in rules_of(*run(Gen(ua="python-requests/2.31").pages(8).events), "client:192.0.2.50")
    denied = Gen()
    for i in range(8):
        denied.req(f"/x{i}", status="denied")
    assert "R8" not in rules_of(*run(denied.events), "client:192.0.2.50")        # error pages are not page loads


def test_r8_sec_fetch_mismatch_raises_strength_and_is_reported():
    plain = rules_of(*run(Gen().pages(6, sec=False).events), "client:192.0.2.50")["R8"]
    mism = rules_of(*run(Gen().pages(6, sec=True).events), "client:192.0.2.50")["R8"]
    assert mism.strength > plain.strength and mism.extra["sec_fetch_mismatch"] == 6 and "also lack the Sec-Fetch" in mism.explanation


def test_r8_alone_without_sec_fetch_headers_is_not_enough_for_a_lead_but_with_mismatch_it_is():
    """Text-mode browsers look like this; R8 by itself must stay below the lead threshold unless the headers also disagree."""
    r1, p1 = run(Gen().pages(8, sec=False).events + Gen("192.0.2.98").pages(3).events)
    assert lead_for(r1, p1, "client:192.0.2.50") is None
    r2, p2 = run(Gen().pages(8, sec=True).events + Gen("192.0.2.98").pages(3).events)
    l = lead_for(r2, p2, "client:192.0.2.50")
    assert l is not None and l.actor_class == "possible_mimic" and l.severity == "low"


# ------------------------------------------------------------------------------------------ R9
def jumps(n_never: int, n_early: int = 0, valid_ref: int = 0) -> Gen:
    g = Gen().req("/")
    for i in range(n_never):
        g.req(f"/guess{i}", linked_from_prev=False, referer_valid=False, offered_earlier=False)
    for i in range(n_early):
        g.req(f"/queued{i}", linked_from_prev=False, referer_valid=False, offered_earlier=True)
    for i in range(valid_ref):
        g.req(f"/back{i}", linked_from_prev=False, referer_valid=True, offered_earlier=True)
    return g


def test_r9_needs_two_never_offered_jumps():
    assert "R9" not in rules_of(*run(jumps(1).events), "client:192.0.2.50")
    f = rules_of(*run(jumps(2).events), "client:192.0.2.50")["R9"]
    assert f.extra["never_offered"] == 2


def test_r9_does_not_count_breadth_first_queue_moves_or_valid_referers():
    assert "R9" not in rules_of(*run(jumps(0, n_early=9, valid_ref=5).events), "client:192.0.2.50")
    f = rules_of(*run(jumps(2, n_early=6).events), "client:192.0.2.50")["R9"]
    assert f.extra == {"never_offered": 2, "offered_earlier": 6}


def test_r9_strength_grows_and_is_capped():
    s = [rules_of(*run(jumps(n).events), "client:192.0.2.50")["R9"].strength for n in (2, 4, 30)]
    assert s[0] < s[1] <= s[2] == Config().web.strength_unlinked_jump_cap


def test_r9_abstains_when_the_collector_has_no_link_graph():
    g = Gen().req("/")
    for i in range(10):
        g.req(f"/g{i}")                                              # no linked_from_prev at all
    assert "R9" not in rules_of(*run(g.events), "client:192.0.2.50")


# ------------------------------------------------------------------------------------------ R10 + floors
@pytest.mark.parametrize("sig", ["session_canary", "schema_param", "error_hint_follow", "mcp_tools_call", "mcp_list_then_call"])
def test_single_strong_event_sets_the_strong_floor(sig):
    g = Gen().pages(3).req("/x", kind="api", strong_signal=sig, decoy_kind="d")
    res, p = run(g.events + Gen("192.0.2.98").pages(3).events)
    l = lead_for(res, p, "client:192.0.2.50")
    assert l.score >= Config().web.floor_strong and l.floor_applied == Config().web.floor_strong and l.actor_class == "goal_directed"
    assert l.priority_band == "review_first"


@pytest.mark.parametrize("padding", [0, 50, 500])
def test_floor_cannot_be_diluted_by_benign_padding(padding):
    g = Gen().req("/internal/ops-links", strong_signal="decoy_hit", decoy_kind="fake_backup")
    for i in range(padding):
        g.req(f"/p{i}", 5.0, linked_from_prev=True, referer_valid=True, sec_fetch_mismatch=False)
        g.req("/static/site.css", 0.1, kind="asset")
    res, p = run(g.events + [e for k in range(5) for e in Gen(f"192.0.2.{110 + k}").pages(6).events])
    l = lead_for(res, p, "client:192.0.2.50")
    assert l is not None and l.score >= Config().web.floor_weak


def test_floors_can_be_switched_off():
    cfg = Config(web={"floors_enabled": False})
    g = Gen().req("/x", kind="api", strong_signal="schema_param")
    res, p = run(g.events + Gen("192.0.2.98").pages(3).events, cfg)
    l = lead_for(res, p, "client:192.0.2.50")
    # R10 is still evidence, but without a floor its noisy-or contribution alone (0.8 * 0.9 = 0.72) applies
    assert l is None or l.floor_applied is None


def test_three_distinct_decoy_kinds_make_a_weak_signal_goal_directed():
    g = Gen().req("/a", strong_signal="hidden_link", decoy_kind="hidden_link").req("/b", strong_signal="decoy_hit", decoy_kind="fake_backup")
    one = rules_of(*run(g.events), "client:192.0.2.50")["R10"]
    assert one.extra["tier"] == "weak"
    g.req("/c", strong_signal="decoy_hit", decoy_kind="fake_credentials_file")
    three = rules_of(*run(g.events), "client:192.0.2.50")["R10"]
    assert three.extra["tier"] == "strong" and three.extra["distinct_decoys"] == 3


# ------------------------------------------------------------------------------------------ accidental vs goal-directed
def test_lone_hidden_link_hit_is_an_accidental_scraper_in_the_normal_queue():
    g = Gen(ua="NaiveScraper/1.0")
    for i in range(6):
        g.req(f"/p{i}", 0.5, linked_from_prev=None if i == 0 else True, referer_valid=False if i else None)
    g.req("/internal/ops-links", 0.5, linked_from_prev=False, referer_valid=False, offered_earlier=True, strong_signal="hidden_link", decoy_kind="hidden_link")
    res, p = run(g.events + [e for k in range(5) for e in Gen(f"192.0.2.{110 + k}").pages(6).events])
    l = lead_for(res, p, "client:192.0.2.50")
    assert l.actor_class == "accidental_scraper" and l.priority_band == "review" and l.severity == "low"
    assert l.score < Config().fusion.band_review_first and l.floor_applied == Config().web.floor_weak


def test_scraper_vs_agent_labelling_matrix():
    cases = {
        "accidental_scraper": Gen("192.0.2.71").req("/h", strong_signal="hidden_link", decoy_kind="hidden_link"),
        "goal_directed": Gen("192.0.2.72").req("/m", kind="api", mcp="tools_call", strong_signal="mcp_tools_call", decoy_kind="mcp_decoy_tool_call"),
        "possible_mimic": Gen("192.0.2.73").pages(7, sec=True),
    }
    items = [e for g in cases.values() for e in g.events] + [e for k in range(5) for e in Gen(f"192.0.2.{110 + k}").pages(6).events]
    res, p = run(items)
    got = {k: lead_for(res, p, f"client:{g.ip}").actor_class for k, g in cases.items()}
    assert got == {k: k for k in cases}


def test_non_web_leads_are_unclassified_and_leads_stay_low_severity():
    d = build(0, 40)
    res = Pipeline(Config(), d.policy, Pseudonymizer(KEY)).run(d.events)
    assert res.leads and all(l.actor_class == "unclassified" and l.severity == "low" and l.automatic_action == "none" for l in res.leads)
    assert all("actor_class" in l.to_dict() for l in res.leads)


def test_every_web_lead_keeps_the_safety_invariants():
    d = build_web(0)
    res = Pipeline(Config(), d.policy, Pseudonymizer(KEY)).run(d.events)
    assert res.leads
    assert all(l.severity == "low" and l.recommended_action == "human_review" and l.automatic_action == "none" for l in res.leads)


# ------------------------------------------------------------------------------------------ synthetic web clients / mini evaluation
def test_web_simulator_is_deterministic_and_labelled():
    a, b = build_web(3), build_web(3)
    assert a.events == b.events and a.labels == b.labels
    assert sum(1 for v in a.labels.values()) == sum(COUNTS.values())
    assert all(RawEvent.model_validate(e) for e in a.events[:200])
    assert {g for _, g in a.labels.values()} == set(GROUPS)
    assert build_web(4).events != a.events


@pytest.fixture(scope="module")
def web_run():
    d = build_web(0)
    bg = build(0, 40, positives=False)
    pseudo = Pseudonymizer(KEY)
    res = Pipeline(Config(), Policy(), pseudo).run(bg.events + d.events)
    inv = {pseudo.agent(a): a for a in d.labels}
    by_group: Dict[str, List[Any]] = {}
    for a, (_, g) in d.labels.items():
        by_group.setdefault(g, []).append(next((l for l in res.leads if l.agent == pseudo.agent(a)), None))
    return res, by_group


def test_web_run_scanners_filtered_and_humans_quiet(web_run):
    res, g = web_run
    assert res.prefiltered.agents == COUNTS["commodity_scanner"] and res.prefiltered.kept_scanner_like_with_goal_evidence == 1
    assert all(l is None for l in g["commodity_scanner"]) and all(l is None for l in g["web_human"]) and all(l is None for l in g["web_human_no_assets"])


def test_web_run_detects_what_it_should_and_misses_what_it_should(web_run):
    _, g = web_run
    for name in ("mimic_basic", "mimic_linked", "mimic_schema", "mcp_agent", "decoy_explorer", "scanner_ua_spoof", "accidental_scraper"):
        assert all(l is not None for l in g[name]), name
    assert all(l is None for l in g["mimic_assets"])                       # documented evader
    assert {l.actor_class for l in g["accidental_scraper"]} == {"accidental_scraper"}
    assert {l.actor_class for l in g["mimic_linked"]} == {"possible_mimic"}
    for name in ("mimic_schema", "mcp_agent", "decoy_explorer", "scanner_ua_spoof", "mimic_basic"):
        assert {l.actor_class for l in g[name]} == {"goal_directed"}, name


def test_agent_watch_export_sample_is_accepted_and_classified():
    """A real export from agent-watch's `export-web` (checked in as a fixture) validates against the strict schema."""
    items = [json.loads(x) for x in (ROOT / "tests" / "data" / "agentwatch_web_export_sample.jsonl").read_text().splitlines()]
    res, p = run(items)
    assert res.normalization.counts["quarantined"] == 0 and len(res.normalization.events) == len(items)
    classes = {l.actor_class for l in res.leads}
    assert classes <= {"goal_directed", "accidental_scraper", "possible_mimic"} and res.leads


def test_cli_demo_web_runs_end_to_end(tmp_path):
    env = {"ROGUE_PIPELINE_HMAC_KEY": "cli-test-key-0123456789abcdef", "PATH": "/usr/bin:/bin"}
    out = subprocess.run([sys.executable, str(ROOT / "run.py"), "demo", "--web", "--out", str(tmp_path), "--ephemeral-key"], env=env, cwd=ROOT,
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    assert "[prefilter] set aside 8 commodity-scanner client(s)" in out.stdout and "actor=goal_directed" in out.stdout
    md = (tmp_path / "leads.md").read_text()
    assert "Commodity-scanner pre-filter" in md and "Web actor class" in md
    leads = json.loads((tmp_path / "leads.json").read_text())
    assert all(l["severity"] == "low" and l["automatic_action"] == "none" for l in leads)
