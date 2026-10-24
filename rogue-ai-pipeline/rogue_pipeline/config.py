"""Typed, validated configuration (thresholds in TOML) and environment policy (declared purposes, schedules).

Two separate inputs:

* ``Config``  - detector thresholds and weights, loaded from TOML (``config/default.toml``).
* ``Policy``  - knowledge about the monitored environment keyed by RAW agent id: declared tool allow-lists,
  known cron schedules, declared orchestrator pools. It is resolved to pseudonyms at pipeline start, so
  raw identifiers never reach the detection layers.

The HMAC key is never stored in either file; only the NAME of the environment variable is.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PseudonymizationCfg(_Strict):
    key_env: str = "ROGUE_PIPELINE_HMAC_KEY"
    min_key_bytes: int = Field(16, ge=16)
    digest_hex_len: int = Field(16, ge=8, le=64)


class NormalizationCfg(_Strict):
    scrub_raw_fields: bool = True        # v4: keyed encoded-secret scrubber on resource/text/tokens at ingest (%40, %2540, \uXXXX, split tokens)
    require_synthetic: bool = True
    keep_capture: bool = True      # keep sanitized honeypot capture metadata on events (False: drop it at normalization)
    max_text_len: int = Field(2000, ge=1)
    internal_domain_suffixes: List[str] = [".corp.example", ".internal"]
    sensitive_patterns: List[str] = [
        r"/(admin|secrets?|internal|credentials?|config)(/|$)",
        r"\.env\b",
        r"/\.ssh",
        r"id_rsa",
    ]
    shingle_size: int = Field(3, ge=1, le=6)
    max_shingles_per_event: int = Field(32, ge=1)
    # coarse tool classes for the sequence model; unknown tools become "other" (keeps the vocabulary small and
    # lets agents with different tool subsets share one benign model)
    tool_classes: Dict[str, str] = {
        "search_docs": "retrieve", "read_file": "retrieve", "fetch_url": "retrieve",
        "summarize": "transform", "translate": "transform", "process_batch": "transform",
        "calendar": "productivity", "create_ticket": "productivity", "report_status": "productivity",
        "http_post": "egress", "send_email": "egress", "upload_file": "egress", "write_file": "egress",
        "post_webhook": "egress",
    }


class ToolsCfg(_Strict):
    write_tools: List[str] = ["send_email", "http_post", "upload_file", "write_file", "post_webhook"]


class Layer1Cfg(_Strict):
    n_estimators: int = Field(300, ge=50)
    random_state: int = 0
    min_events: int = Field(8, ge=2)
    score_lo: float = 0.45      # raw isolation score mapped to 0.0 at/below this value
    score_hi: float = 0.70      # ... and to 1.0 at/above this value
    flag_threshold: float = Field(0.5, ge=0.0, le=1.0)
    top_k_explanations: int = Field(3, ge=1, le=8)

    @model_validator(mode="after")
    def _lo_hi(self) -> "Layer1Cfg":
        if self.score_hi <= self.score_lo:
            raise ValueError("score_hi must be greater than score_lo")
        return self


class Layer2Cfg(_Strict):
    baseline_min_events: int = Field(20, ge=1)
    baseline_min_seconds: float = 3600.0
    untrusted_window_s: float = 300.0     # R1: tool shift must follow an untrusted read within this window
    immediate_window_s: float = 60.0      # R4: outbound call this soon after untrusted read
    min_exfil_bytes: int = 1000           # R3: ignore tiny writes
    access_min_denied: int = 10
    access_min_denied_ratio: float = 0.2
    access_min_sensitive: int = 5
    max_evidence: int = Field(8, ge=1)
    apply_allowlist: bool = True          # honour per-event exemptions from verified identity / IP / ASN allowlists
    # --- v6 R12 routine_tool_hijack (AML.T0080 / AML.T0086, approximate) -----------------------------------------------------------
    r12_enabled: bool = True
    r12_jump_ratio: float = Field(2.5, gt=1.0)      # post-ingestion outbound argument size (x entropy when measured) vs the tool's clean median
    r12_min_clean_calls: int = Field(4, ge=1)       # calls of the SAME routine tool outside post-ingestion windows needed for a median
    r12_min_post_bytes: int = Field(1000, ge=0)     # ignore tiny posts even if the ratio is large
    r12_over_clean_max: float = Field(1.25, ge=1.0) # ... and the post must also exceed every clean call to that destination by this factor
    r12_post_steps: int = Field(5, ge=1)            # a call is "post-ingestion" if it is within this many events after an untrusted read ...
    r12_post_window_s: float = Field(900.0, gt=0)   # ... and within this many seconds
    r12_chain_steps: int = Field(3, ge=2)           # untrusted_read -> sensitive_internal_read -> routine_outbound_send within this many steps
    r12_strength_jump: float = Field(0.55, ge=0, le=1)
    r12_strength_chain: float = Field(0.6, ge=0, le=1)
    r12_strength_both: float = Field(0.75, ge=0, le=1)    # one episode that shows BOTH the chain and the size/entropy jump
    r12_strength_cap: float = Field(0.8, ge=0, le=1)


class ProbingCfg(_Strict):
    """v6 R13 slow_or_shielded_probing.  THRESHOLDS ARE CALIBRATED ON BENIGN REFERENCE DATA ONLY (``scripts/calibrate_r13.py``: the
    benign-only simulator reference seeds 1000-1002 used for the frozen baseline, plus benign web cohorts; no attack cohort is read).
    The defaults below are the numbers that script printed, rounded up (see the README section "R13 calibration"):
    p0 0.0476 -> 0.05, h 3.59 -> 4.0 (benign max CUSUM 2.87 x 1.25), W3 benign max 2 -> 3, W7 benign max 2 -> 3,
    collapse log-std threshold 0.6 (half the benign 1% quantile 1.20 of per-session max sub-window log-std; 0 benign hits)."""

    enabled: bool = True
    min_events: int = Field(12, ge=4)
    min_probes: int = Field(3, ge=1)                # fewer boundary-probing actions than this: R13 abstains (a person mistypes twice)
    p0: float = Field(0.05, gt=0, lt=1)             # H0 per-event probe rate (benign upper quantile, calibrated)
    p1: float = Field(0.15, gt=0, lt=1)             # H1 per-event probe rate (what a padded prober must still sustain to make progress)
    cusum_h: float = Field(4.0, gt=0)              # alarm when max CUSUM statistic >= h (benign reference max x margin, calibrated)
    p1_low: float = Field(0.1, gt=0, lt=1)          # a second CUSUM tuned to a SMALL shift (a padded prober just above the benign tail)
    cusum_h_low: float = Field(2.6, gt=0)           # its alarm: benign max 2.01 x 1.25 = 2.51, rounded up (calibrated)
    cusum_h_strong: float = Field(2.0, ge=1.0)      # x h: sustained evidence far beyond any benign session -> solo-strength flag
    w3_min: int = Field(3, ge=1, le=4)              # probes among any 3 consecutive events (calibrated: benign max + 1; 4 = disabled)
    w7_min: int = Field(3, ge=1, le=8)              # probes among any 7 consecutive events (8 = disabled)
    paced_rate_min: float = Field(0.05, ge=0, le=1) # with a timing collapse: distinct-probe share above the benign 99th percentile -> reason
    session_density_min: float = Field(0.5, ge=0, le=1)   # full-session probe share that counts as a density reason (R5-like, but no min count)
    collapse_window: int = Field(8, ge=3)           # inter-request gaps per timing sub-window
    collapse_min_windows: int = Field(4, ge=4)
    collapse_max_logstd: float = Field(0.6, gt=0)  # every sub-window's std of log-gaps below this (benign low quantile x margin, calibrated) ...
    collapse_max_mean_spread: float = Field(0.35, gt=0)   # ... and the sub-window mean log-gaps differ by less than this ...
    collapse_min_cv: float = Field(0.15, ge=0)      # ... but the session is NOT a clock (CV of gaps >= periodic_cv): crons are excluded
    strength_one: float = Field(0.5, ge=0, le=1)
    strength_two: float = Field(0.6, ge=0, le=1)
    strength_strong: float = Field(0.68, ge=0, le=1)


class Layer3Cfg(_Strict):
    window_s: float = Field(15.0, gt=0)
    min_neg_log10_p: float = 8.0          # timing edge only if the overlap is this surprising (-log10 p)
    timing_cap: float = 12.0              # -log10 p value that maps to timing strength 1.0
    min_shared_windows: int = Field(4, ge=1)
    max_df_frac: float = Field(0.15, gt=0, le=1)   # drop traces shared by more than this fraction of agents
    min_cosine: float = Field(0.5, ge=0, le=1)
    min_events: int = Field(8, ge=1)
    weight_timing: float = Field(0.5, ge=0, le=1)
    weight_content: float = Field(0.5, ge=0, le=1)
    edge_threshold: float = Field(0.55, ge=0, le=1)   # > max single-signal weight => both signals required
    min_cluster_size: int = Field(2, ge=2)
    split_below_density: float = Field(0.7, ge=0, le=1)   # split loosely-knit components into communities
    periodic_cv: float = 0.15             # strict periodicity => suspected shared schedule
    periodic_min_events: int = 8
    fanout_min_distinct_targets: int = 8  # same template across this many distinct targets => fan-out
    fanout_min_diversity: float = 0.6
    suppress_declared_groups: bool = True
    suppress_periodic: bool = True
    suppress_fanout: bool = True
    # --- cross-IP / cross-session stitching by shared semantic state -------------------------------------
    use_state_edges: bool = True
    weight_state: float = Field(0.6, ge=0, le=1)       # > edge_threshold: >= min_state_tokens distinct tokens suffice
    min_state_tokens: int = Field(3, ge=1)             # distinct handed-over tokens for full state strength
    weight_redacted: float = Field(0.6, ge=0, le=0.9)  # moderate confidence: same redacted secret marker in two sessions
    redacted_max_sessions: int = Field(6, ge=2)        # markers shared by more sessions than this are 'popular' and ignored
    state_min_events: int = Field(3, ge=1)             # stitched sessions may be short; timing/content still need min_events
    # --- v6: lag-invariant swarm edges (AML.T0118, approximate) ------------------------------------------------------
    partition_enabled: bool = True
    partition_min_agents: int = Field(3, ge=3)         # disjoint_target_partition: group size
    partition_min_targets: int = Field(6, ge=2)        # distinct targets each member touched in the resource family
    partition_max_p: float = Field(1e-3, gt=0, lt=1)   # every pair's overlap at or below this hypergeometric LOWER-tail p (improbably small)
    partition_min_coverage: float = Field(0.6, gt=0, le=1)   # union of the group covers this share of the targets OTHER agents touched
    partition_min_outside_targets: int = Field(5, ge=1)      # ... and other agents touched at least this many (else: abstain)
    partition_max_candidates: int = Field(300, ge=3)   # per family (cost bound; the most active agents are kept)
    partition_weight: float = Field(0.7, ge=0, le=1)   # base edge weight (+0.05 per extra decade of surprise, capped)
    partition_weight_cap: float = Field(0.9, ge=0, le=1)
    inheritance_enabled: bool = True
    inheritance_min_404: int = Field(2, ge=1)          # A's failed probes before its rare unlinked 200 counts as a "discovery"
    inheritance_rare_max_agents: int = Field(3, ge=2)  # the discovered path was requested by at most this many agents in the batch
    inheritance_max_sibling_share: float = Field(0.25, ge=0, le=1)   # B repeated at most this share of A's failed probes
    inheritance_weight: float = Field(0.75, ge=0, le=1)
    inheritance_weight_step: float = Field(0.1, ge=0, le=1)   # per additional inherited discovery
    inheritance_weight_cap: float = Field(0.95, ge=0, le=1)


class FusionCfg(_Strict):
    w_anomaly: float = Field(0.5, ge=0, le=1)
    w_rules: float = Field(0.9, ge=0, le=1)
    w_graph: float = Field(0.8, ge=0, le=1)
    w_sequence: float = Field(0.5, ge=0, le=1)      # applies only when the sequence GATE passes; like w_anomaly it must stay below lead_threshold
    lead_threshold: float = Field(0.55, gt=0, le=1)
    band_review_first: float = 0.75
    band_review: float = 0.60
    # --- v4: two-signal corroboration gate -------------------------------------------------------------------------
    # A lead needs (a) a floor from a strong single-event rule (R10 decoy contact / R11 browser-agent inconsistency), or
    # (b) >= 2 INDEPENDENT signal families among {statistical (Isolation Forest / sequence surprise: both compare against
    # benign reference behaviour and share inputs, so they count as ONE family), rule gate, coordination graph}, or
    # (c) one deterministic family that is strong on its own: a rule of strength >= rule_solo_min (0.65: two-fact rules such as R8 "no CSS/JS AND wrong Sec-Fetch"), or a cluster of density
    # >= graph_solo_min.  Setting both *_solo_min to 1.01 gives the strictest reading (every non-floor lead needs two families).
    corroboration_gate: bool = True
    anomaly_min: float = Field(0.3, ge=0, le=1)         # an Isolation Forest score below this does not count as a family at all
    rule_solo_min: float = Field(0.65, ge=0)            # >1 disables the solo-rule exception
    graph_solo_min: float = Field(0.8, ge=0)            # >1 disables the solo-cluster exception
    # v6: rules are split into independent FAMILIES (tool_use / probing / timing / navigation / web_interaction / session_fork / honeypot).
    # With the gate on, two different rule families corroborate each other like two signal families do, and their strengths combine by
    # noisy-or (capped) instead of max.  A single rule family (however many rules in it fire) still needs strength >= rule_solo_min.
    rule_family_corroboration: bool = True
    rule_family_cap: float = Field(0.95, ge=0, le=1)

    @model_validator(mode="after")
    def _anomaly_alone_cannot_lead(self) -> "FusionCfg":
        # Guardrail: unsupervised evidence alone must never be enough to raise a lead.
        if self.w_anomaly >= self.lead_threshold:
            raise ValueError("w_anomaly must be below lead_threshold: anomaly score alone cannot create a lead")
        if self.w_sequence >= self.lead_threshold:
            raise ValueError("w_sequence must be below lead_threshold: a sequence-surprise score alone cannot create a lead "
                             "(it can only reinforce another detector, e.g. Isolation Forest + sequence together)")
        return self


class FrozenCfg(_Strict):
    """Frozen-baseline (train once, score online) settings for Layer 1."""

    n_folds: int = Field(5, ge=2)                  # cross-fitting folds used to calibrate on UNSEEN reference agents
    lo_quantile: float = Field(0.5, ge=0, le=1)    # held-out reference score mapped to 0.0
    hi_quantile: float = Field(0.99, ge=0, le=1)   # ... and to 1.0
    min_reference_agents: int = Field(30, ge=10)
    min_session_events: int = Field(8, ge=2)       # fewer events => "insufficient evidence", never a guess
    entropy_min_span_s: float = 10800.0            # hour-of-day entropy is meaningless for shorter sessions: imputed

    @model_validator(mode="after")
    def _q(self) -> "FrozenCfg":
        if self.hi_quantile <= self.lo_quantile:
            raise ValueError("hi_quantile must exceed lo_quantile")
        return self


class SequenceCfg(_Strict):
    """Markov action-sequence model (timing-independent) and its fusion gate."""

    enabled: bool = True
    alpha: float = Field(0.5, gt=0)                # additive smoothing for unseen transitions
    window: int = Field(30, ge=5)                  # transitions per scoring window
    step: int = Field(10, ge=1)
    min_transitions: int = Field(20, ge=5)         # fewer => "insufficient evidence"
    n_folds: int = Field(5, ge=2)                  # cross-fit calibration on held-out reference agents
    lo_quantile: float = Field(0.5, ge=0, le=1)
    hi_quantile: float = Field(0.99, ge=0, le=1)
    gate: float = Field(0.6, ge=0, le=1)           # sequence score below this contributes nothing to fusion
    top_k: int = Field(3, ge=1, le=8)


class IpAllow(_Strict):
    cidr: str
    label: str
    exempt_rules: List[str] = ["R3", "R4"]
    allow_dest_suffixes: List[str] = []


class AsnAllow(_Strict):
    asn: int
    label: str
    exempt_rules: List[str] = ["R3", "R4"]
    allow_dest_suffixes: List[str] = []


class IdentityCfg(_Strict):
    """Optional verified-identity and network allowlists, applied BEFORE rule scoring (per event)."""

    enabled: bool = True
    max_skew_s: float = Field(300.0, gt=0)         # freshness window for signature `created`
    ip_allowlist: List[IpAllow] = []
    asn_allowlist: List[AsnAllow] = []


class WebCfg(_Strict):
    """v3: web-collector evidence (mimic detection), commodity-scanner pre-filter and score floors.  Applies only to events
    that carry a ``web`` block; events without one are never filtered or scored by these rules (so non-web traffic is unchanged)."""

    enabled: bool = True
    prefilter: bool = True                    # drop commodity-scanner clients before scoring and before baseline training
    scanner_ua_patterns: List[str] = [r"zgrab", r"masscan", r"censys", r"shodan", r"nmap", r"nikto", r"sqlmap", r"nuclei",
                                      r"gobuster", r"dirbuster", r"wpscan", r"expanse", r"netcraft", r"internet-measurement"]
    scanner_path_patterns: List[str] = [r"\.php\d?(\?|$|/)", r"/wp-(admin|login|content|includes|json)", r"/xmlrpc", r"/\.env\b",
                                        r"/\.git(/|$)", r"/phpmyadmin", r"/pma(/|$)", r"/cgi-bin/", r"/vendor/phpunit", r"/actuator",
                                        r"/boaform", r"/\.aws/", r"/server-status"]
    declared_bot_ua_patterns: List[str] = [r"bot\b", r"crawler", r"spider", r"slurp", r"scrapy", r"python-requests", r"curl/", r"wget/",
                                           r"go-http-client", r"httpclient"]
    browser_ua_patterns: List[str] = [r"Mozilla/5\.0", r"Chrome/", r"Safari/", r"Firefox/", r"Edg/"]
    prefilter_min_events: int = Field(1, ge=1)
    scanner_path_min_share: float = Field(0.8, gt=0.5, le=1)   # share of a client's requests that must be scanner paths (tolerates a stray /admin/)
    asset_starvation_min_pages: int = Field(5, ge=2)
    unlinked_min_never_offered: int = Field(2, ge=1)
    strength_asset_starvation: float = Field(0.5, ge=0, le=1)
    strength_asset_starvation_sec_fetch: float = Field(0.65, ge=0, le=1)
    strength_unlinked_jump: float = Field(0.55, ge=0, le=1)
    strength_unlinked_jump_cap: float = Field(0.8, ge=0, le=1)
    strong_distinct_decoys: int = Field(3, ge=2)       # this many different decoy kinds touched => adaptive, not accidental
    # --- v4 ---------------------------------------------------------------------------------------------------------
    core_asset_kinds: List[str] = ["css", "js"]        # R8: a client that loaded any of these is a rendering client
    beacon_min_navs: int = Field(3, ge=1)              # R11: click-through page loads (Referer present) before "no beacon" means anything
    strength_browser_inconsistency: float = Field(0.55, ge=0, le=1)
    link_graph_fallback: bool = True                   # R9: learn the allowed link graph from Referer transitions when offered links are absent
    link_min_support: int = Field(2, ge=1)             # distinct clients that must have taken a Referer transition for it to be "allowed"
    link_fallback_min_jumps: int = Field(4, ge=2)      # unsupported transitions before the fallback R9 fires (noisier than the exact graph)
    link_fallback_strength: float = Field(0.5, ge=0, le=1)
    link_entry_paths: List[str] = ["/", "/robots.txt", "/sitemap.xml"]
    floors_enabled: bool = True
    floor_weak: float = Field(0.58, ge=0, le=1)        # single hidden-link/decoy contact: reaches the queue, below review_first
    floor_strong: float = Field(0.8, ge=0, le=1)       # decoy-protocol use that needs reading/parsing (schema, MCP call, canary)
    # --- v6 ---------------------------------------------------------------------------------------------------------
    nav_coherent_share: float = Field(0.8, gt=0, le=1)  # R11: share of page loads with coherent Sec-Fetch-* that exempts a missing beacon
    vlm_min_beacons: int = Field(2, ge=1)               # R11: beacons showing the quantized-interaction pattern before it counts
    synthetic_click_min_beacons: int = Field(2, ge=1)   # R11: zero-dwell clicks with no pointer movement before it counts (weak)
    strength_corroborate: float = Field(0.45, ge=0, le=1)   # R11 weak reasons WITHOUT a floor (need another family)
    missing_cursor_min: int = Field(2, ge=1)            # R9: requests that dropped a load-bearing cursor (400 Missing Required Cursor)
    strength_missing_cursor: float = Field(0.55, ge=0, le=1)
    r14_enabled: bool = True
    r14_window_s: float = Field(0.5, gt=0)              # R14: a suspicious request within this many seconds of a human-branch page load
    r14_min_forks: int = Field(2, ge=1)
    r14_strength: float = Field(0.6, ge=0, le=1)
    r14_strength_cap: float = Field(0.75, ge=0, le=1)


class Config(_Strict):
    pseudonymization: PseudonymizationCfg = Field(default_factory=PseudonymizationCfg)
    normalization: NormalizationCfg = Field(default_factory=NormalizationCfg)
    tools: ToolsCfg = Field(default_factory=ToolsCfg)
    layer1: Layer1Cfg = Field(default_factory=Layer1Cfg)
    layer2: Layer2Cfg = Field(default_factory=Layer2Cfg)
    layer3: Layer3Cfg = Field(default_factory=Layer3Cfg)
    fusion: FusionCfg = Field(default_factory=FusionCfg)
    frozen: FrozenCfg = Field(default_factory=FrozenCfg)
    sequence: SequenceCfg = Field(default_factory=SequenceCfg)
    identity: IdentityCfg = Field(default_factory=IdentityCfg)
    web: WebCfg = Field(default_factory=WebCfg)
    probing: ProbingCfg = Field(default_factory=ProbingCfg)


def load_config(path: Optional[str | Path] = None) -> Config:
    """Load thresholds from TOML. ``None`` returns the built-in defaults."""
    if path is None:
        return Config()
    with open(path, "rb") as fh:
        return Config(**tomllib.load(fh))


class SuppressionGroup(_Strict):
    """A declared benign group whose members are expected to act in lockstep."""

    kind: Literal["schedule", "orchestrator_pool"]
    name: str
    members: List[str]            # RAW agent ids
    orchestrator: Optional[str] = None   # RAW id of the declared orchestrator (token holder) of an orchestrator_pool


class Policy(_Strict):
    """Environment knowledge keyed by RAW agent id (resolved to pseudonyms inside the pipeline)."""

    declared_tools: Dict[str, List[str]] = {}
    suppression_groups: List[SuppressionGroup] = []


def load_policy(path: Optional[str | Path] = None) -> Policy:
    if path is None:
        return Policy()
    return Policy(**json.loads(Path(path).read_text(encoding="utf-8")))


class ResolvedPolicy(_Strict):
    """Policy after pseudonymization. Only this form is visible to detection layers."""

    declared_tools: Dict[str, frozenset] = {}
    groups: Dict[str, frozenset] = {}          # "<kind>:<name>" -> frozenset of agent pseudonyms
    orchestrators: frozenset = frozenset()     # pseudonyms of declared orchestrators (may legitimately hand tokens to workers)


class IdentityKeyCfg(_Strict):
    """One entry of an identity-registry JSON file. The key itself is read from the environment variable
    ``key_env`` - never stored in the file."""

    keyid: str
    key_env: str
    operator: str
    agents: List[str] = []                         # raw agent ids bound to this key (empty = any)
    allow_dest_suffixes: List[str] = []            # destinations the exemption covers (empty = any)
    exempt_rules: List[str] = ["R3", "R4"]


class IdentityRegistryFile(_Strict):
    keys: List[IdentityKeyCfg]
