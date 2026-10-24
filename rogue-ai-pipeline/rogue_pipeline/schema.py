"""Standardized telemetry event schema with strict validation.

``RawEvent``        - what collectors (API gateway, web server, simulator) hand to the pipeline. Unknown
                      fields are forbidden and types are strict; anything that fails goes to quarantine.
``NormalizedEvent`` - what the detection layers see: pseudonymized identifiers only, raw text discarded
                      (replaced by keyed shingle hashes). Feature extraction accepts nothing else.
"""
from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, FrozenSet, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from .sanitize import sanitize_untrusted

Source = Literal["api_gateway", "web_server", "simulator"]
Action = Literal["read", "write", "tool_call", "message", "access"]
Status = Literal["allowed", "denied"]

_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
_TOOL = re.compile(r"^[a-z0-9_.-]{1,64}$")
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
REDACTION_RE = re.compile(r"\[REDACTED_([A-Z0-9_]{1,32})_SHA256:([0-9a-f]{10})\]")
_TOKEN = re.compile(r"^(?:\[REDACTED_[A-Z0-9_]{1,32}_SHA256:[0-9a-f]{10}\]|[A-Za-z0-9._~/:+=-]{4,128})$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TS_MIN = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()
TS_MAX = datetime(2100, 1, 1, tzinfo=timezone.utc).timestamp()


# soft limits truncate (flagged); hard limits reject the event (quarantine)
CAPTURE_LIMITS = {"system_prompt_summary": 500, "current_objective": 300, "message": 500}
CAPTURE_HARD_CHARS = 20_000
CAPTURE_MAX_TOOLS, CAPTURE_HARD_TOOLS, CAPTURE_TOOL_LEN = 20, 100, 64
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$")


class CapturedAgentMeta(BaseModel):
    """What a cognitive-capture decoy recorded about the visiting agent. ATTACKER-CONTROLLED and UNTRUSTED.

    Construction sanitizes and truncates (see ``sanitize.py``); ``truncated`` and ``sanitized_chars_removed`` are
    computed here and any caller-supplied values are overwritten, so a collector cannot understate them."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    system_prompt_summary: StrictStr = ""
    declared_tools: List[StrictStr] = Field(default_factory=list)
    current_objective: StrictStr = ""
    message: StrictStr = ""
    truncated: StrictBool = False
    sanitized_chars_removed: StrictInt = 0
    untrusted: Literal[True] = True              # constant marker: never trust, never obey

    @model_validator(mode="before")
    @classmethod
    def _clean(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            raise ValueError("capture must be an object")
        allowed = {"system_prompt_summary", "declared_tools", "current_objective", "message", "truncated",
                   "sanitized_chars_removed", "untrusted"}
        extra = set(data) - allowed
        if extra:
            raise ValueError(f"unknown capture field(s): {sorted(extra)}")
        out: dict = {}
        trunc, removed = False, 0
        for k, soft in CAPTURE_LIMITS.items():
            v = data.get(k, "")
            if not isinstance(v, str):
                raise ValueError(f"capture.{k} must be a string")
            if len(v) > CAPTURE_HARD_CHARS:
                raise ValueError(f"capture.{k} is oversize ({len(v)} > {CAPTURE_HARD_CHARS} characters): rejected")
            clean, t, r = sanitize_untrusted(v, soft)
            out[k], trunc, removed = clean, trunc or t, removed + r
        tools = data.get("declared_tools", [])
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ValueError("capture.declared_tools must be a list of strings")
        if len(tools) > CAPTURE_HARD_TOOLS:
            raise ValueError(f"capture.declared_tools is oversize ({len(tools)} > {CAPTURE_HARD_TOOLS} entries): rejected")
        kept: List[str] = []
        for t in tools:
            if len(t) > CAPTURE_HARD_CHARS:
                raise ValueError("capture.declared_tools entry is oversize: rejected")
            clean, tr, r = sanitize_untrusted(t, CAPTURE_TOOL_LEN)
            removed += r
            if tr or not _TOOL_NAME.match(clean):
                trunc = True                       # dropped: not a plausible tool identifier
                continue
            if len(kept) >= CAPTURE_MAX_TOOLS:
                trunc = True
                continue
            kept.append(clean)
        out["declared_tools"] = kept
        out["truncated"], out["sanitized_chars_removed"] = trunc, removed
        return out

    def to_untrusted_dict(self) -> dict:
        """JSON-safe view that always carries the untrusted / attacker-controlled markers."""
        return {"untrusted": True, "attacker_controlled": True, "system_prompt_summary": self.system_prompt_summary,
                "declared_tools": list(self.declared_tools), "current_objective": self.current_objective,
                "message": self.message, "truncated": self.truncated, "sanitized_chars_removed": self.sanitized_chars_removed}


class MessageSignature(BaseModel):
    """Simulated HTTP Message Signature (RFC 9421 style, Web Bot Auth flavoured) carried with an event.

    ``value`` is a hex HMAC-SHA256 over the signature base built from the event itself (see ``identity.py``).
    Verification is offline against a locally configured key registry - no key directory is ever fetched."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    keyid: StrictStr = Field(min_length=1, max_length=64)
    created: StrictInt = Field(ge=0, le=4_102_444_800)
    value: StrictStr = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


WEB_STRONG_SIGNALS = ("hidden_link", "decoy_hit", "session_canary", "schema_param", "error_hint_follow", "mcp_tools_call",
                      "mcp_list_then_call", "fake_credential_use")
_DECOY_KIND = re.compile(r"^[a-z0-9_]{1,40}$")
_JA4 = re.compile(r"^[tqd][0-9]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")


class BeaconMeta(BaseModel):
    """The client-interaction beacon: booleans only, nothing else is accepted (extra fields are rejected).

    v4/v5: the three required booleans.  v6 (``/workspace/v6-event-contract.md``): three more, OPTIONAL so v4/v5 records stay valid
    (missing = unknown, never "false"): ``challenge_proof_ok`` (the per-page challenge was solved by the page's own JS),
    ``kinematic_dwell_ok`` (mouseup - mousedown >= 12 ms and a non-collinear pointer path), ``inertial_scroll_ok`` (scroll shows momentum
    decay, or there was no scroll)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    webdriver_present: StrictBool
    pointer_trail_seen: StrictBool
    dom_automation_props: StrictBool
    challenge_proof_ok: Optional[StrictBool] = None
    kinematic_dwell_ok: Optional[StrictBool] = None
    inertial_scroll_ok: Optional[StrictBool] = None


# v6 signal names (exact strings from the agent-watch -> pipeline contract).  Anything else in ``web.signals`` is rejected.
V6_SIGNALS = ("beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
              "schema_provenance_cursor", "missing_required_cursor", "parasitic_session_fork", "llmjacking_probe")
V6Signal = Literal["beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit", "vlm_quantized_interaction",
                   "schema_provenance_cursor", "missing_required_cursor", "parasitic_session_fork", "llmjacking_probe"]


class LlmjackingMeta(BaseModel):
    """v6: what the decoy ``POST /v1/chat/completions`` endpoint recorded - counts and buckets only, never the messages themselves."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_count: StrictInt = Field(ge=0, le=10_000)
    system_prompt_len_bucket: Literal["0", "1-200", "201-1000", "1001-4000", ">4000"]
    autonomous_loop_directive: StrictBool


class WebMeta(BaseModel):
    """Optional per-request facts from a web collector (the agent-watch honeypot's mirrored access stream).

    ``user_agent`` is accepted raw but is reduced to a handful of boolean/enum flags during normalization and then
    DISCARDED (``NormalizedEvent`` never carries it).  Everything else is already a derived fact.  ``None`` means
    "the collector could not tell" and makes the rules that need it abstain, never fire."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_agent: Optional[StrictStr] = Field(default=None, max_length=300)
    content_kind: Literal["html", "asset", "api", "beacon", "other"] = "other"
    asset_kind: Optional[Literal["css", "js", "font", "favicon", "image", "other"]] = None   # v4: sub-resource type (content_kind == asset)
    beacon: Optional[BeaconMeta] = None                 # v4: the three booleans of an interaction-beacon POST
    beacon_offered: Optional[StrictBool] = None         # v4: this page embedded the interaction beacon (one is expected on a click)
    harness_archetype: Optional[Literal["mcp_tool_runner", "schema_driven_api_agent", "stateful_coordinator", "prompt_injected_crawler",
                                        "headless_or_http_mimic", "commodity_or_static_scanner", "unclassified"]] = None   # v5: agent-watch harness label
    harness_confidence: Optional[Literal["low", "medium", "high"]] = None
    referer_present: Optional[StrictBool] = None        # v4: a Referer header was present on this page load (click-through)
    referer_path: Optional[StrictStr] = Field(default=None, max_length=300)   # v4: path of a same-site Referer (for the empirical link graph)
    sec_fetch_state: Optional[Literal["coherent", "contradictory", "absent"]] = None    # v4: Sec-Fetch-Mode/Dest on this page load
    referer_valid: Optional[StrictBool] = None          # Referer present AND names a page this client was served
    linked_from_prev: Optional[StrictBool] = None       # target was linked from the previous page (None: entry page / unknown)
    offered_earlier: Optional[StrictBool] = None        # not linked from the previous page, but some earlier page offered it
    sec_fetch_mismatch: Optional[StrictBool] = None     # page load without browser-style Sec-Fetch-* (None: not logged)
    strong_signal: Optional[Literal["hidden_link", "decoy_hit", "session_canary", "schema_param", "error_hint_follow",
                                    "mcp_tools_call", "mcp_list_then_call", "fake_credential_use", "aria_fastpath"]] = None
    decoy_kind: Optional[StrictStr] = None
    mcp: Optional[Literal["initialize", "tools_list", "tools_call"]] = None
    ja4: Optional[StrictStr] = None                     # optional TLS fingerprint supplied by an edge proxy (NOT produced here)
    # --- v6 (agent-watch v6 event contract) ------------------------------------------------------------------------------------------
    js_assets_fetched: Optional[StrictInt] = Field(default=None, ge=0, le=1_000_000)   # successful .js fetches by this SESSION (on every event)
    cursor_prov: Optional[Literal["schema", "html"]] = None   # provenance of the cursor/page_ref this request presented (None: none / invalid)
    signals: List[V6Signal] = Field(default_factory=list, max_length=8)   # per-event collector signals (enumerated; unknown names rejected)
    llmjacking: Optional[LlmjackingMeta] = None         # only on a POST /v1/chat/completions decoy request

    @field_validator("signals")
    @classmethod
    def _sig(cls, v: List[str]) -> List[str]:
        if len(set(v)) != len(v):
            raise ValueError("signals must not repeat")
        return v

    @field_validator("user_agent")
    @classmethod
    def _ua(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and _CTRL.search(v):
            raise ValueError("control characters are not allowed")
        return v

    @field_validator("referer_path")
    @classmethod
    def _rp(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and (not v.startswith("/") or v.startswith("//") or _CTRL.search(v)):
            raise ValueError("referer_path must be a site-relative path without control characters")
        return v

    @field_validator("decoy_kind")
    @classmethod
    def _dk(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _DECOY_KIND.match(v):
            raise ValueError("decoy_kind must match [a-z0-9_]{1,40}")
        return v

    @field_validator("ja4")
    @classmethod
    def _ja4(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _JA4.match(v):
            raise ValueError("ja4 is not a well-formed JA4 fingerprint")
        return v


class RawEvent(BaseModel):
    """One telemetry record as received from a collector. Strict: no extras, no silent type coercion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: StrictStr = Field(min_length=1, max_length=64)
    ts: float                                    # unix seconds (float/int) or tz-aware ISO-8601 string on input
    source: Source
    agent_id: StrictStr
    action: Action
    status: Status = "allowed"
    resource: StrictStr = Field(default="", max_length=512)
    tool: Optional[StrictStr] = None
    ip: Optional[StrictStr] = None
    user_id: Optional[StrictStr] = None
    dest_host: Optional[StrictStr] = None
    untrusted_content: StrictBool = False        # event ingested retrieved / untrusted text
    payload_bytes: StrictInt = Field(default=0, ge=0, le=10**10)
    arg_entropy: Optional[float] = Field(default=None, ge=0.0, le=8.0)   # v6: Shannon entropy (bits/byte) of the tool-call arguments, computed by
                                                                         # the collector before discarding them (R12); None = not measured
    text: Optional[StrictStr] = Field(default=None, max_length=10_000)
    synthetic: StrictBool = False                # collectors must label synthetic data explicitly
    # --- optional enrichment ------------------------------------------------------------------------------
    response_tokens: List[StrictStr] = Field(default_factory=list, max_length=16)  # state returned to the agent
    request_token: Optional[StrictStr] = None    # token / hidden path / canary the agent presented
    asn: Optional[StrictInt] = Field(default=None, ge=0, le=4_294_967_295)   # supplied by collector enrichment
    signature: Optional[MessageSignature] = None
    # --- honeypot (coordination board / cognitive capture) ------------------------------------------------
    honeypot: Optional[Literal["coordination_board", "cognitive_capture", "claim_shard"]] = None
    token_class: Optional[Literal["handoff_token", "verification_nonce", "claim_shard"]] = None   # class of the tokens above
    capture: Optional[CapturedAgentMeta] = None
    # --- web collector facts (v3) ---------------------------------------------------------------------------
    web: Optional[WebMeta] = None

    @field_validator("ts", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> float:
        if isinstance(v, bool):
            raise ValueError("ts must be a number or ISO-8601 string")
        if isinstance(v, (int, float)):
            ts = float(v)
        elif isinstance(v, str):
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("ts is not a valid ISO-8601 timestamp") from exc
            if dt.tzinfo is None:
                raise ValueError("ts string must include a timezone (e.g. 'Z')")
            ts = dt.timestamp()
        else:
            raise ValueError("ts must be a number or ISO-8601 string")
        if not math.isfinite(ts) or not (TS_MIN <= ts <= TS_MAX):
            raise ValueError("ts outside 2000-2100")
        return ts

    @field_validator("agent_id", "user_id")
    @classmethod
    def _ident(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _ID.match(v):
            raise ValueError("identifier must match [A-Za-z0-9._:@-]{1,64}")
        return v

    @field_validator("tool")
    @classmethod
    def _tool_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _TOOL.match(v):
            raise ValueError("tool must match [a-z0-9_.-]{1,64}")
        return v

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError("ip is not a valid IPv4/IPv6 address") from exc
        return v

    @field_validator("dest_host")
    @classmethod
    def _host(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip().lower().rstrip(".")
            if not _HOST.match(v):
                raise ValueError("dest_host is not a valid hostname")
        return v

    @field_validator("response_tokens")
    @classmethod
    def _tokens(cls, v: List[str]) -> List[str]:
        for t in v:
            if not _TOKEN.match(t):
                raise ValueError("response token must match [A-Za-z0-9._~/:+=-]{4,128}")
        return v

    @field_validator("request_token")
    @classmethod
    def _req_token(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _TOKEN.match(v):
            raise ValueError("request_token must match [A-Za-z0-9._~/:+=-]{4,128}")
        return v

    @field_validator("resource", "text")
    @classmethod
    def _no_ctrl(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and _CTRL.search(v):
            raise ValueError("control characters are not allowed")
        return v

    @model_validator(mode="after")
    def _cross(self) -> "RawEvent":
        if self.action == "tool_call" and not self.tool:
            raise ValueError("tool is required when action is tool_call")
        if self.action == "message" and not self.resource:
            raise ValueError("resource (recipient) is required when action is message")
        if self.capture is not None and self.honeypot != "cognitive_capture":
            raise ValueError("capture is only valid on honeypot=cognitive_capture events")
        if self.token_class is not None and not (self.response_tokens or self.request_token):
            raise ValueError("token_class requires response_tokens or request_token")
        return self


@dataclass(frozen=True, slots=True)
class WebFlags:
    """Derived web facts on a normalized event.  No User-Agent string, no path: only flags."""

    content_kind: str = "other"
    ua_class: str = "none"                  # browser | scanner | declared_bot | other | none
    scanner_path: bool = False              # resource matched a commodity-scanner path (php, wp-*, .env, phpmyadmin ...)
    referer_valid: Optional[bool] = None
    linked_from_prev: Optional[bool] = None
    offered_earlier: Optional[bool] = None
    sec_fetch_mismatch: Optional[bool] = None
    strong_signal: Optional[str] = None
    decoy_kind: Optional[str] = None
    mcp: Optional[str] = None
    has_ja4: bool = False
    # v4
    asset_kind: Optional[str] = None
    beacon: Optional[Tuple[bool, bool, bool]] = None    # (webdriver_present, pointer_trail_seen, dom_automation_props)
    beacon_offered: Optional[bool] = None
    referer_present: Optional[bool] = None
    sec_fetch_state: Optional[str] = None
    harness_archetype: Optional[str] = None             # v5: descriptive label from the collector (never scored by the pipeline)
    harness_confidence: Optional[str] = None
    referer_key: Optional[str] = None                   # pseudonym of the same-site Referer path (never the path itself)
    path_key: Optional[str] = None                      # pseudonym of the requested path without its query string
    is_entry: bool = False                              # the requested path is a static entry point (/, /robots.txt, /sitemap.xml)
    # v6
    beacon_ext: Optional[Tuple[Optional[bool], Optional[bool], Optional[bool]]] = None   # (challenge_proof_ok, kinematic_dwell_ok, inertial_scroll_ok)
    js_assets_fetched: Optional[int] = None
    cursor_prov: Optional[str] = None
    signals: FrozenSet[str] = frozenset()
    llmjacking: Optional[Tuple[int, str, bool]] = None   # (tool_count, system_prompt_len_bucket, autonomous_loop_directive)
    prefix_keys: Tuple[str, ...] = ()                    # pseudonyms of every path prefix (/a, /a/b, ...) - for "sub-path of" tests, no paths
    parent_key: Optional[str] = None                     # pseudonym of the parent directory of the requested path


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Detection-layer view of an event. Contains pseudonyms and derived flags only - no raw identifiers,
    no resource paths, no free text."""

    event_id: str
    ts: float
    source: str
    agent: str                      # pseudonym
    action: str
    status: str
    tool: Optional[str]
    resource_key: str               # pseudonym of the resource / recipient (recipient = agent pseudonym)
    sensitive: bool                 # resource matched a sensitive-path pattern
    dest_host: Optional[str]
    dest_external: bool
    untrusted: bool
    payload_bytes: int
    shingles: frozenset             # keyed hashes of normalized content shingles
    ip: Optional[str] = None        # pseudonym
    user: Optional[str] = None      # pseudonym
    category: str = "other"         # coarse action category for the sequence model (no raw paths)
    issued: frozenset = frozenset()          # keyed hashes of tokens returned to this agent in the response
    presented: Optional[str] = None          # keyed hash of the token the agent presented
    identity: str = "absent"        # "verified" | "failed" | "absent" (signature check result)
    exempt_rules: frozenset = frozenset()    # rule ids this event may not trigger (verified identity / allowlist)
    honeypot: Optional[str] = None           # decoy kind this event touched (coordination_board / cognitive_capture / claim_shard)
    token_class: Optional[str] = None        # class of issued tokens: handoff_token / verification_nonce / claim_shard
    redactions: frozenset = frozenset()      # keyed hashes of scrubber markers [REDACTED_<TYPE>_SHA256:<10hex>] seen in the event
    capture: Optional[CapturedAgentMeta] = None   # UNTRUSTED attacker-controlled metadata (sanitized); never used for scoring
    web: Optional[WebFlags] = None                # derived web-collector flags (None for non-web events)
    arg_entropy: Optional[float] = None           # v6: entropy (bits/byte) of tool-call arguments as measured by the collector
    family_key: Optional[str] = None              # v6: pseudonym of the resource FAMILY (first path segment), for disjoint-partition tests

    @property
    def denied(self) -> bool:
        return self.status == "denied"

    @property
    def outbound(self) -> bool:
        """Write-like action that sends data to an external destination."""
        return self.dest_external and self.action in ("write", "tool_call", "message")
