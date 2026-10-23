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


class FusionCfg(_Strict):
    w_anomaly: float = Field(0.5, ge=0, le=1)
    w_rules: float = Field(0.9, ge=0, le=1)
    w_graph: float = Field(0.8, ge=0, le=1)
    w_sequence: float = Field(0.5, ge=0, le=1)      # applies only when the sequence GATE passes; like w_anomaly it must stay below lead_threshold
    lead_threshold: float = Field(0.55, gt=0, le=1)
    band_review_first: float = 0.75
    band_review: float = 0.60

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
    floors_enabled: bool = True
    floor_weak: float = Field(0.58, ge=0, le=1)        # single hidden-link/decoy contact: reaches the queue, below review_first
    floor_strong: float = Field(0.8, ge=0, le=1)       # decoy-protocol use that needs reading/parsing (schema, MCP call, canary)


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
