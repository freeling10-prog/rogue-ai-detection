"""Threshold configuration: built-in defaults, optionally overridden by JSON.

Only keys that exist in DEFAULTS may be overridden, so typos fail loudly
instead of silently doing nothing.  `config/thresholds.json` mirrors DEFAULTS.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Optional

DEFAULTS: dict[str, Any] = {
    "session": {
        "idle_gap_s": 1800,            # new session after this much silence
        "link_ua_rotation": True,      # re-join same-IP sessions split by a UA change after a block
        "rotation_link_gap_s": 120,    # max gap between a block and the rotated client
        "block_statuses": [403, 429],
    },
    "timing": {
        "min_requests": 8,             # page-level requests needed to judge timing
        "cv_static_max": 0.15,         # coefficient of variation <= this => fixed interval
        "cv_human_min": 0.8,           # CV >= this => human-like variability
        "entropy_bin_edges_s": [0.05, 0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 300],
        "entropy_static_max": 0.25,    # normalised entropy <= this => near-constant intervals
        "entropy_human_min": 0.55,
        "fast_median_s": 1.0,          # median gap <= this => faster than reading
    },
    "adaptation": {
        "window_s": 60,                # a reaction must follow a block within this long
        "backoff_factor": 2.0,
        "backoff_min_s": 2.0,
        "reorder_lookahead": 15,       # requests to look ahead for a resumed blocked path
    },
    "tool_chain": {
        "step_gap_s": 10,              # max gap between consecutive chain steps
        "min_chains": 2,
        "min_signature_share": 0.6,    # share of chains with the dominant shape
        "max_median_step_s": 8,
        "roles": {                     # first match wins (ordered)
            "export": [r"/(export|download|dump)\b", r"\.(csv|xlsx|ndjson)$", r"/api/v\d+/(bulk|batch)"],
            "search": [r"/search\b", r"/api/v\d+/search"],
            "detail": [r"/(items?|products?|records?|details?|view)/[\w-]+$"],
        },
    },
    "param_evasion": {
        "enum_min_run": 6,             # monotonic run length counted as enumeration
        "enum_max_median_gap_s": 3.0,
        "enum_step_consistency": 0.8,
        "cache_bust_names": ["_", "ts", "t", "cb", "cachebust", "cache", "nocache", "rand", "r", "nonce", "bust", "_t"],
        "cache_bust_min": 3,
        "systematic_min_distinct": 8,
        "systematic_share": 0.7,
        "rotating_headers": ["x-forwarded-for", "x-real-ip", "accept-language", "accept-encoding", "x-client-id", "sec-ch-ua"],
        "header_rotation_min_distinct": 4,
        "header_rotation_min_requests": 8,
        "ua_rotation_min_distinct": 3,
    },
    "honeytoken": {
        # path prefix -> decoy kind (used for plain access logs; honeypot leads carry their own kind)
        "paths": {
            "/admin-backup": "robots_disallow",
            "/staff-portal-": "hidden_link",
            "/api/v1/admin": "fake_admin_api",
            "/internal/export": "fake_export",
            "/canary/": "canary_follow",
            "/.env": "fake_credentials_file",
            "/api/v2/staging": "openapi_decoy",
            "/api/v2/legacy": "swagger_decoy",
            "/internal/agent-notes": "llms_txt_decoy",
            "/api/plugin/admin-actions": "ai_plugin_decoy",
            "/diag/": "error_hint_follow",
            "/api/v2/dump/begin": "stateful_dump_start",
            "/api/v2/dump/page/": "stateful_dump_step",
            "/api/v2/bulk/": "openapi_decoy",
            "/api/v1/coordination-board/claim-shard": "coordination_claim_step",
            "/api/v1/coordination-board": "coordination_board_read",
            "/api/v1/kb-snapshot": "aria_fastpath",
            "/kb/archive/diagnostic": "dom_visual_inversion_hit",     # v6: DOM-first / rendered-last footer link
            "/v1/chat/completions": "llmjacking_probe",               # v6: decoy chat-completions endpoint
        },
        "dump_chain_min_steps": 3,     # distinct server-issued dump pages followed => multi-turn evidence
    },
    "coordination": {
        # Agent Coordination Bus (honeypot).  Used for plain access logs; leads carry their own detail.
        "board_path": "/api/v1/coordination-board",
        "claim_path": "/api/v1/coordination-board/claim-shard",
        "claim_loop_min_steps": 2,     # distinct valid claim-shard turns => loop evidence
        "trap_paths": ["/openapi.json", "/swagger.yaml", "/graphql", "/mcp", "/llms.txt",
                       "/.well-known/ai-plugin.json", "/internal/agent-notes"],
        "trap_statuses": [400, 403, 429, 500],
    },
    "ttna": {
        # Time-to-Next-Action vs previous response size.  HEURISTIC and EVADABLE; unvalidated on real agents.
        "enabled": True,
        "min_pairs": 12,               # (previous response size, gap) pairs needed
        "max_gap_s": 60.0,             # ignore longer pauses (idle, not "thinking")
        "band_lo_s": 1.5,              # assumed LLM think-time band, lower edge
        "band_hi_s": 8.0,              # ... upper edge
        "min_band_fraction": 0.6,      # share of gaps that must fall in the band
        "min_spearman": 0.5,           # rank correlation between previous size and gap
        "min_size_cv": 0.3,            # response sizes must actually vary
        "bytes_per_token": 4.0,        # rough bytes->tokens conversion (reporting only)
        "max_asset_ratio": 0.2,        # browsers fetch assets; skip the check for asset-loading clients
    },
    "web": {
        # v3 passive detectors that do not need a decoy touch (they need the mirrored request stream: every request,
        # with content type, the links each page offered, and the browser header family)
        "enabled": True,
        "asset_starvation": {
            # v4: starvation means ZERO core page resources (stylesheets/scripts) over >= min_pages HTML documents, or
            # contradictory Sec-Fetch-* on page loads.  Omitting only images (or fonts/favicon) is how people with
            # images blocked / data-saver modes browse and is NOT starvation.
            "min_pages": 5,                       # HTML pages with ZERO .css/.js fetches
            "contradictory_min_pages": 3,         # page loads with header-logged Sec-Fetch needed to call them contradictory
            "contradictory_share": 0.5,
            "coherent_weakens": True,             # coherent Sec-Fetch navigate/document on the starved pages -> weak (advisory) only
            "browser_ua_patterns": [r"mozilla/5\.0"],   # only a client that CLAIMS to be a browser is expected to load assets
            "sec_fetch_check": True,              # when the log carries headers: browser-claiming page loads lacking Sec-Fetch-*
            "sec_fetch_min_share": 0.5,
        },
        "unlinked_jump": {
            # transitions to these paths are never "unlinked" (every client may probe them)
            "entry_paths": ["/", "/robots.txt", "/favicon.ico", "/sitemap.xml"],
            "max_findings": 20,
        },
        "asset_types": {                          # v4: sub-resource type by extension (core = what a browser needs to render)
            "css": [".css"], "js": [".js", ".mjs"], "font": [".woff", ".woff2", ".ttf", ".otf"], "favicon": ["favicon.ico"],
            "image": [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".bmp", ".ico"], "other": [".map"],
        },
        "headless": {
            # v4: signals for a browser-backed client (it loads assets, so asset starvation cannot fire)
            "beacon_path": "/api/v1/telemetry/nav",
            "aria_path": "/api/v1/kb-snapshot",
            "min_navs": 3,                        # click-through navigations (internal Referer) before "no beacon" means anything
            "min_pointerless_beacons": 4,         # weak advisory only (keyboard / screen-reader users never move a pointer)
            "inversion_path": "/kb/archive/diagnostic",   # v6: DOM-visual order inversion link
            "vlm_min_beacons": 2,                 # v6: valid-proof beacons with quantized scroll (+ instant click / inversion) needed
            "fork_window_s": 0.5,                 # v6 R14: parasitic request within this many seconds of a human page load
        },
        "schema_param": {"name": "client_schema_rev"},
        "session_canary_pattern": r"\bsc-[0-9a-f]{10}\b",
    },
    "contact": {
        # decoy classes for severity / labelling.  A lone hit on a PASSIVE decoy (invisible link, robots Disallow, the
        # guessable /.env) is what scanners, crawlers and curious humans produce: contact, not intent.
        "passive_kinds": ["hidden_link", "robots_disallow", "fake_credentials_file", "robots_fetch", "aria_fastpath",
                          "dom_visual_inversion_hit"],
        # a person can type these URLs (v6: or click a small, visible footer link)
        "human_plausible_kinds": ["robots_disallow", "fake_credentials_file", "robots_fetch", "dom_visual_inversion_hit"],
        "accidental_max_distinct_decoys": 2,
        # v6: decoy contacts that are CONTEXT only for the agent score / accidental-vs-goal-directed logic (every DOM-order crawler
        # meets the inversion link first; only the browser-backed web finding of the same name carries weight)
        "context_only_kinds": ["dom_visual_inversion_hit"],
        "strong_kinds": ["canary_follow", "canary_phrase_echo", "error_hint_follow", "mcp_decoy_tool_call",
                         "fake_credential_use", "schema_param_use", "session_canary_param", "llmjacking_probe"],
    },
    "floors": {
        # max-pooling: ONE high-signal event sets a floor on the scores; benign padding (assets, human-like timing,
        # extra quiet requests) can add points on top but can never pull the score below it.
        "enabled": True,
        "automation_any_decoy": 40,           # any decoy contact: at least a static bot, never "human"
        "agent": {"canary_follow": 60, "canary_phrase_echo": 60, "error_hint_follow": 60, "mcp_decoy_tool_call": 60,
                  "fake_credential_use": 60, "schema_param": 60, "session_canary_param": 60, "mcp_list_then_call": 70,
                  "headless_automation_signal": 65,
                  # v6 (web findings; strong R11 members only, the bare inversion decoy contact never sets a floor)
                  "beacon_forged": 65, "script_fetched_but_unexecuted": 65, "dom_visual_inversion_hit": 65,
                  "vlm_quantized_interaction": 65, "parasitic_session_fork": 65, "schema_provenance_cursor": 60,
                  "llmjacking_probe": 60},   # v4: ARIA fast-path / webdriver / automation globals seen from a browser-backed client
    },
    "navigation": {"deep_depth": 4, "flat_depth_max": 2},
    "assets": {"extensions": [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".webp"]},
    "ua": {
        "bot_patterns": [r"bot\b", r"crawler", r"spider", r"slurp", r"scrapy"],
        "scripted_patterns": [r"python-requests", r"python-urllib", r"curl/", r"wget/", r"httpx", r"aiohttp", r"go-http-client", r"node-fetch", r"axios/", r"okhttp"],
        "benign_patterns": [r"synthbot", r"googlebot", r"bingbot", r"uptimerobot", r"pingdom", r"kube-probe", r"synthmonitor"],
    },
    "benign_paths": ["/healthz", "/health", "/ping", "/status", "/robots.txt"],
    "weights": {
        "automation": {
            "fixed_interval": 40,
            "low_entropy": 15,
            "fast_requests": 25,
            "no_assets_no_referer": 10,
            "bot_ua": 25,
            "scripted_ua": 25,
            "honeytoken": 30,
            "human_assets": -20,       # loads CSS/JS/images like a browser
            "human_timing": -20,       # high CV and high entropy
        },
        "agent": {
            "ua_change": 25,
            "param_change": 20,
            "header_change": 20,
            "path_reorder": 10,
            "backoff": 5,
            "adaptation_cap": 55,
            "evasion_success": 10,     # request succeeded right after a strategy change
            "tool_chain": 20,
            "tool_chain_regular": 10,
            "enumeration": 10,
            "cache_busting": 20,
            "systematic_variation": 15,
            "header_rotation": 15,
            "evasion_after_block": 10,
            "deep_navigation": 10,
            "llm_timing": 10,          # weak by design; can never decide alone
            "multi_step_chain": 15,    # followed server-issued tokens across several turns
            # v3 passive web signals (need the mirrored request stream)
            "asset_starvation": 35,         # >= min_pages HTML pages, a browser-claiming UA, zero CSS/JS/image/favicon fetches
            "asset_starvation_sec_fetch": 10,   # ... and the Sec-Fetch-* headers a real browser sends are missing/mismatched
            "unlinked_jump": 15,            # per transition to a URL the previous page did not link and no valid Referer
            "unlinked_jump_cap": 45,
            "unlinked_jump_earlier": 5,     # weak variant: the URL WAS offered on an earlier page (queue / tab behaviour)
            "unlinked_jump_earlier_cap": 15,
            "schema_param": 50,             # sent the camouflaged client_schema_rev parameter from the decoy openapi.json
            "session_canary_param": 55,     # replayed the per-session canary served only inside machine-readable docs
            "mcp_list_then_call": 40,       # MCP tools/list followed by a valid tools/call (goal-directed tool use)
            "headless_automation_signal": 55,   # v4: browser-backed client + ARIA fast-path / webdriver / automation globals
            "headless_beacon_missing": 35,      # v4/v6: moderate R11 (v6: script_fetched_but_unexecuted without a forged beacon)
            "schema_provenance_cursor": 50,     # v6: schema-only cursor used inside a browsing session
            "parasitic_session_fork": 50,       # v6 R14 (also an R11-family member for the floor / actor logic)
            # coordination bus (distinct signals, each with its own plain-language reason)
            "coord_board_after_trap": 25,   # read the board after an error/schema trap (followed a breadcrumb)
            "coord_capture_post": 35,       # volunteered a registration (objective/tools/system prompt summary)
            "coord_claim_loop": 30,         # completed 2+ turns of the claim-shard nonce loop
            "coord_cross_identity": 20,     # a token issued to one session/IP was presented by another
            "honeytoken": {
                "default": 25,
                "aria_fastpath": 30,       # v4: followed the ARIA "AI Assistant Fast-Path" element (any DOM/anchor parser can)
                "llmjacking_probe": 45,    # v6: POSTed a chat-completions request to the decoy inference endpoint
                "beacon_forged": 30,       # v6: posted a beacon without a valid challenge proof
                "dom_visual_inversion_hit": 20,   # v6: passive, human-plausible on its own
                "canary_follow": 60,       # obeying an instruction embedded in retrieved text
                "canary_phrase_echo": 60,
                "fake_credential_use": 40,
                "error_hint_follow": 55,   # read an error body and followed its debug hint
                "mcp_decoy_tool_call": 45,
                "openapi_decoy": 30,
                "swagger_decoy": 30,
                "graphql_decoy": 30,
                "llms_txt_decoy": 30,
                "ai_plugin_decoy": 30,
                "stateful_dump_start": 30,
                "stateful_dump_step": 30,
                "coordination_board_read": 10,   # the specific coordination signals below carry the weight
                "coordination_register": 10,
                "coordination_claim_step": 10,
                "coordination_claim_rejected": 10,
                "coordination_post_rejected": 10,
                "per_additional_distinct": 10,
                "additional_cap": 20,
            },
        },
    },
    "thresholds": {"automation": 40, "agent": 60, "critical": 85, "medium": 30},
}


class ConfigError(ValueError):
    """Raised for malformed or unknown configuration keys."""


def _merge(base: dict[str, Any], override: dict[str, Any], path: str = "") -> None:
    for key, value in override.items():
        where = f"{path}.{key}" if path else key
        if key not in base:
            raise ConfigError(f"unknown config key: {where}")
        if isinstance(base[key], dict) and key not in ("roles", "paths"):
            if not isinstance(value, dict):
                raise ConfigError(f"config key {where} must be an object")
            _merge(base[key], value, where)
        else:
            base[key] = value


def load_config(path: Optional[str | Path] = None) -> dict[str, Any]:
    """Return DEFAULTS, overridden by the JSON file at *path* if given."""
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        try:
            override = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        if not isinstance(override, dict):
            raise ConfigError("config root must be a JSON object")
        _merge(cfg, override)
    return cfg
