"""Policy Enforcement Point (PEP) — loopback JSON-RPC / tools/call interceptor.

Lab-only insider gateway for *registered* internal agent API keys.
Implements ATLAS mitigation AML.M0030 (Restrict Tool Invocation on Untrusted Data).

Safety:
- Bind 127.0.0.1 by default.
- freeze/block apply ONLY to keys in config/agents.json.
- Web honeypot / public visitors: never auto-blocked (out of scope here).
- No outbound network from the gateway except an explicit approval-webhook opt-in (default OFF).
- Session capabilities are chained HMAC tokens. Untrusted ingest appends
  ``allow_egress=false``; that caveat cannot be stripped without the root key.
- Every decision-log line is SHA-256 hash-chained (``audit_chain.py``).
- Outbound arguments are checked against fingerprints of sensitive reads and
  canaries across steps and encodings (``deobfuscate.py``, approximate AML.T0086).
- URI / host arguments are canonicalized and checked for SSRF and cloud
  metadata targets (``egress_uri_guard.py``, approximate AML.T0053).
- Untrusted tool output is scanned for invisible-Unicode smuggling, delimiter
  spoofing, and cross-tool name shadowing (``tool_output_scanner.py``,
  approximate AML.T0051).
- Post-trifecta oracle and timing beacons are held (``side_channel_guard.py``,
  approximate AML.T0086).
- ``tools/list`` inventories are analyzed for multi-hop toxic combinations
  (``toxic_combinations.py``).
- Tool arguments pass a lexical firewall for path / command / header / SQL
  escalation (``arg_ast_guard.py``, approximate AML.T0051 / AML.T0053).
- Delegation across agents is attenuated monotonically; a delegated agent
  cannot egress what its parent was barred from (``delegation_guard.py``).
- Sensitive reads are watermarked and credential-tracked; a watermark or
  credential in an outbound call is denied and frozen (``canary_watermark.py``).
- MCP tool schemas are digest-pinned per server; drift without a signed
  manifest and cross-server tool-name collisions are denied
  (``schema_integrity_guard.py``, approximate AML.T0051).
- Computer-use pointer and keyboard actions are checked against reserved
  screen regions and a shortcut deny-list (``gui_action_guard.py``,
  approximate AML.T0053).
- Resource writes and reads are recorded in an HMAC-signed lineage ledger
  shared across sessions; a reader inherits the writer's taint and a
  modified record is denied (``memory_provenance_guard.py``, approximate
  AML.T0080.000).
- Released outbound arguments accumulate in a per-(session, destination)
  window that is checked for protected values split across calls and for
  cumulative invisible watermark characters (``temporal_accumulator_guard.py``,
  approximate AML.T0086).
- v12: tool definitions with hidden instruction markers are not served and
  calls to them are denied (``mcp_rugpull_guard.py``); writes to agent
  instruction, MCP / IDE configuration, and execution-hook files are denied
  (``workspace_config_guard.py``); a session with a pinned
  ``UserCapabilityManifest`` cannot reach an ungranted privileged sink or
  target after an untrusted read (``control_flow_integrity_guard.py``); and
  sensitive values reshaped into branch names, package names, DNS labels,
  URL parts, or other identifier arguments are denied on outbound calls
  (``stego_exfil_guard.py``; free-text bodies stay with ``deobfuscate.py``).
- v12.1: inline interpreter payloads (``python -c``, ``node -e``, heredocs,
  decoded pipes) are statically analysed for protected writes, obfuscated
  execution, and process / network primitives (``interpreter_exec_guard.py``);
  every MCP listing, the first included, is checked against the server's
  capability profile (``mcp_capability_manifest_guard.py``); and taint that
  crosses between agent sessions through notes, files, the bus, or
  delegation is tracked in a provenance graph so a peer cannot complete a
  split toxic chain (``cross_agent_collusion_guard.py``).
- v12.2: four reference middleware validators stay inert until a trusted
  adapter attaches state. Descriptor pins, a filesystem snapshot, a workflow
  manifest, and a similarity matcher then deny with their own rule codes
  (``registry_pin_validator.py``, ``workspace_path_validator.py``,
  ``lattice_flow_validator.py``, ``shingle_similarity_validator.py``).
- v12.3: a fifth reference validator, a bounded 16-place Petri net with
  weighted token conservation, gates workflow transitions once a trusted
  adapter attaches a manifest; an outbound step cannot fire while resource
  cleanup state is unsettled (``linear_obligation_validator.py``).
- v12.4: a sixth reference validator carries (confidentiality, integrity)
  labels across file effects in a copy-on-write overlay over the workspace
  model. A protected file copied into an ordinary one cannot be attached to an
  outbound call, and a file written while the session is untrusted cannot
  feed an execution sink (``symbolic_fs_transducer.py``).
- v12.5: a seventh reference validator canonicalizes a pinned tool's argument
  object to one byte string (key order, number spelling, set order, defaults)
  and compiles typed file commands to a fixed argv with ``--`` before every
  positional, refusing operands that start with ``-``
  (``canonical_argument_confinement.py``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from . import approve, capability
from .approval_webhook import build_approval_payload, consume_approve_once, deliver_webhook
from .audit_chain import ChainWriter
from .deobfuscate import DeobfuscationGuard, iter_strings, secret_candidates
from .egress_uri_guard import DEFAULT_LAB_ALLOW, inspect_arguments
from .side_channel_guard import SideChannelGuard, SideChannelPolicy
from . import tool_output_scanner, toxic_combinations
from .arg_ast_guard import inspect_call as inspect_arg_call
from .canary_watermark import CanaryRegistry
from .delegation_guard import DelegationLedger, attenuate_for_handoff, profile_from_token
from .gui_action_guard import KEY_ACTIONS, POINTER_ACTIONS, TEXT_ACTIONS, GuiActionGuard
from .memory_provenance_guard import ALL_CAPABILITIES_MASK, MemoryProvenanceGuard
from .schema_integrity_guard import SchemaIntegrityGuard
from .temporal_accumulator_guard import TemporalAccumulatorGuard
from .control_flow_integrity_guard import ControlFlowIntegrityGuard, UserCapabilityManifest
from .mcp_rugpull_guard import POISONING, scan_definition
from .stego_exfil_guard import StegoExfilGuard
from .workspace_config_guard import WorkspaceConfigGuard
from .cross_agent_collusion_guard import EXTERNAL_SINK, PRIVILEGED_EXEC, CrossAgentCollusionGuard, artifact_id
from .interpreter_exec_guard import InterpreterExecGuard
from .mcp_capability_manifest_guard import McpCapabilityManifestGuard
# v12.2 reference middleware validators (deterministic, standard-library only).
from . import common as reference_json
from .common import Denied as ReferenceDenied
from .canonical_argument_confinement import (
    Policy as ArgumentPolicy, command_from_arguments, confine, encode_arguments,
)
from .linear_obligation_validator import (
    ObligationManifest, ObligationNet,
)
from .lattice_flow_validator import (
    Call as FlowCall, Gate as ManifestGate, Label as FlowLabel,
    MethodPolicy as FlowMethodPolicy, Step as FlowStep,
)
from .registry_pin_validator import Registry as PinRegistry, lint_description as pin_lint_description
from .shingle_similarity_validator import Matcher as ShingleMatcher
from .symbolic_fs_transducer import FsTransducer, LabelDenied, PendingLabels, path_intents
from .workspace_path_validator import (
    Node as FsNode, Snapshot as FsSnapshot, analyze_shell, command_intents,
)
from .paths import default_registry_path
from .registry import Registry
from .scrub import scrub_obj
from .taint import (
    BLOCKED_EGRESS_WHILE_TAINTED,
    CORE_MCP_SERVERS,
    EGRESS_BUS,
    EGRESS_CREDS,
    EGRESS_EXTERNAL_READ,
    EGRESS_INTERNAL_READ,
    EGRESS_META,
    EGRESS_SEND,
    EGRESS_SPAWN,
    EGRESS_WRITE,
    SENSITIVE_READ_TOOLS,
    SharedState,
    ScratchpadEntry,
    SessionState,
    TOOL_EGRESS,
    UNTRUSTED_INGEST_TOOLS,
    egress_class,
    places_params_on_external_boundary,
)

log = logging.getLogger("agent_gateway.pep")

# Allowlisted constrained sinks: update_ticket_status with int/enum/exact ID only (no free-text)
TICKET_STATUS_ENUM = frozenset({"shipped", "pending", "cancelled", "processing", "delivered"})
HIGH_ENTROPY_THRESHOLD = 4.2  # bits/char; free-text / packed secrets sit above this

# Tainted tool call held for a person. Not a hard deny (quota, unknown key, bad capability).
_AWAITING_APPROVAL = frozenset({
    "lethal_trifecta_external_egress",
    "oob_required_while_tainted",
    "post_taint_outbound_gated",
    "oob_required_creds_while_tainted",
    "mcp_rug_pull_hold",
    "session_review_hold",
    "ssrf_internal_target_hold",
})
# Default sink names for cross-tool shadowing when a session has no tools/list.
_GUI_ACTIONS = POINTER_ACTIONS | KEY_ACTIONS | TEXT_ACTIONS
# Computer-use tool action names -> gui_action_guard action names.
_COMPUTER_ACTIONS = {
    "left_click": "click", "right_click": "right_click", "middle_click": "click", "double_click": "double_click",
    "triple_click": "click", "mouse_move": "mouse_move", "left_click_drag": "drag",
    "key": "key_combo", "type": "type_text",
}
# Lineage ledger encoding of a session: taint level 1 = tainted; capability bit 0 = may egress.
_PROV_TAINTED = 1
_PROV_CAP_EGRESS = 1
_PROV_KEY_LABEL = b"agent-gateway.memory-provenance/1"
_RESOURCE_ARGS = ("uri", "resource_uri", "resource", "path")
# v12 rule code -> JSON-RPC error code.
_V12_CODES = {
    "WORKSPACE_CONFIG_WRITE": -32045, "WORKSPACE_HOOK_TAMPER": -32046, "WORKSPACE_SYMLINK_ESCAPE": -32047,
    "CFI_TAINTED_PRIVILEGED_SINK": -32048, "CFI_UNENDORSED_TARGET": -32049,
    "STEGO_SECRET_SHINGLE_LEAK": -32052, "STEGO_SUBSEQUENCE_EXFIL": -32053, POISONING: -32054,
    # v12.1 (-32060 / -32061 are the sampling errors, so the block skips them)
    "INTERPRETER_PROTECTED_WRITE": -32055, "INTERPRETER_OBFUSCATED_PIPE": -32056,
    "INTERPRETER_DANGEROUS_PRIMITIVE": -32057, "MCP_FIRST_SEEN_OVERPRIVILEGED": -32058,
    "MCP_SCHEMA_PURPOSE_MISMATCH": -32059, "MCP_TOOL_NAMESPACE_FLOOD": -32062,
    "COLLUSION_CROSS_AGENT_LAUNDERING": -32063, "COLLUSION_SPLIT_TOXIC_CHAIN": -32064,
    "COLLUSION_CYCLIC_AMPLIFICATION": -32065,
}
_V12_ATLAS = {"WORKSPACE_CONFIG_WRITE": "AML.T0051", "WORKSPACE_HOOK_TAMPER": "AML.T0053",
              "WORKSPACE_SYMLINK_ESCAPE": "AML.T0053", "CFI_TAINTED_PRIVILEGED_SINK": "AML.T0051",
              "CFI_UNENDORSED_TARGET": "AML.T0051", "STEGO_SECRET_SHINGLE_LEAK": "AML.T0086",
              "STEGO_SUBSEQUENCE_EXFIL": "AML.T0086", POISONING: "AML.T0051",
              "INTERPRETER_PROTECTED_WRITE": "AML.T0053", "INTERPRETER_OBFUSCATED_PIPE": "AML.T0053",
              "INTERPRETER_DANGEROUS_PRIMITIVE": "AML.T0053", "MCP_FIRST_SEEN_OVERPRIVILEGED": "AML.T0051",
              "MCP_SCHEMA_PURPOSE_MISMATCH": "AML.T0051", "MCP_TOOL_NAMESPACE_FLOOD": "AML.T0051",
              "COLLUSION_CROSS_AGENT_LAUNDERING": "AML.T0086", "COLLUSION_SPLIT_TOXIC_CHAIN": "AML.T0086",
              "COLLUSION_CYCLIC_AMPLIFICATION": "AML.T0086"}
# v12.2 reference middleware validators. Rule codes ride the same decision path,
# findings list, alert chain and SARIF export as the v11 / v12 / v12.1 guards.
# -32055..-32059 and -32062..-32065 belong to v12.1; -32060 / -32061 are the
# sampling errors, so these five take the next free codes.
REGISTRY_PIN_DRIFT = "REGISTRY_PIN_DRIFT"
REGISTRY_ALIAS_AMBIGUOUS = "REGISTRY_ALIAS_AMBIGUOUS"
WORKSPACE_EFFECT_DENIED = "WORKSPACE_EFFECT_DENIED"
FLOW_MANIFEST_DENIED = "FLOW_MANIFEST_DENIED"
SIMILARITY_LEAK_DENIED = "SIMILARITY_LEAK_DENIED"
# v12.3: the Petri-net transition gate takes the next free code after -32070.
OBLIGATION_PROTOCOL_DENIED = "OBLIGATION_PROTOCOL_DENIED"
# v12.4: the file label transducer takes the next free code after -32071.
FS_LABEL_FLOW_DENIED = "FS_LABEL_FLOW_DENIED"
# v12.5: argument canonicalization and command confinement take -32073.
ARGUMENT_CONFINEMENT_DENIED = "ARGUMENT_CONFINEMENT_DENIED"
# Descriptor fields the reference profile hashes for a pin (annotations included:
# annotation-only drift is drift under this policy).
_REFERENCE_PIN_FIELDS = ("description", "inputSchema", "outputSchema", "annotations", "title")
_V12_CODES.update({
    REGISTRY_PIN_DRIFT: -32066, REGISTRY_ALIAS_AMBIGUOUS: -32067,
    WORKSPACE_EFFECT_DENIED: -32068, FLOW_MANIFEST_DENIED: -32069,
    SIMILARITY_LEAK_DENIED: -32070, OBLIGATION_PROTOCOL_DENIED: -32071,
    FS_LABEL_FLOW_DENIED: -32072, ARGUMENT_CONFINEMENT_DENIED: -32073,
})
_V12_ATLAS.update({REGISTRY_PIN_DRIFT: "AML.T0051", REGISTRY_ALIAS_AMBIGUOUS: "AML.T0051",
                   WORKSPACE_EFFECT_DENIED: "AML.T0053", FLOW_MANIFEST_DENIED: "AML.T0051",
                   SIMILARITY_LEAK_DENIED: "AML.T0086", OBLIGATION_PROTOCOL_DENIED: "AML.T0051",
                   FS_LABEL_FLOW_DENIED: "AML.T0086", ARGUMENT_CONFINEMENT_DENIED: "AML.T0053"})
_EXEC_TOOL_RE = re.compile(r"(?:^|[._\-])(?:shell|bash|exec|terminal|run_command|run_script)(?:$|[._\-])")
_DEFAULT_SINK_TOOLS = tuple(sorted(
    name for name, ec in TOOL_EGRESS.items() if ec in (EGRESS_WRITE, EGRESS_SEND, EGRESS_CREDS)
    and name not in SENSITIVE_READ_TOOLS
))


@dataclass
class PepConfig:
    host: str = "127.0.0.1"
    port: int = 9100
    registry_path: Path = field(default_factory=default_registry_path)
    allow_nonlocal: bool = False
    webhook_url: Optional[str] = None  # default OFF
    webhook_deliver: bool = False  # explicit opt-in; formatter never sends by itself
    webhook_sender: Optional[Any] = None  # test hook; production uses deliver_webhook
    freeze_seconds: float = 900.0
    max_delegation_depth: int = 1
    max_children_per_parent: int = 3
    alert_log: Optional[Path] = None
    # Literal loopback hosts lab fixtures may use. Any other spelling of them is denied.
    ssrf_lab_allow: frozenset = DEFAULT_LAB_ALLOW
    side_channel: SideChannelPolicy = field(default_factory=SideChannelPolicy)
    # Lab-only: simulated result body for a tool name (tests feed untrusted output here).
    lab_fixture_outputs: dict = field(default_factory=dict)
    # Resource limits on the HTTP path. In-process callers of PolicyEngine are not limited.
    max_body_bytes: int = 262_144  # whole request body
    max_arg_bytes: int = 65_536  # serialized tools/call arguments
    max_sessions: int = 1000  # live sessions held in memory
    max_id_len: int = 128  # session_id length
    # Computer-use viewport and reserved rectangles [x_min, y_min, x_max, y_max, label]. None = defaults.
    gui_viewport: tuple = (1440, 900)
    gui_regions: Optional[list] = None
    # Opt in to agent config ("config") and / or execution-hook ("hook") writes. Symlink escapes stay denied.
    workspace_allow: tuple = ()
    # MCP server -> capability profile (PURE_TRANSFORM ... PRIVILEGED). Core servers are PRIVILEGED.
    mcp_server_profiles: dict = field(default_factory=dict)
    max_tools_per_server: int = 32
    max_handoff_depth: int = 8


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_constrained_ticket_status(arguments: dict) -> bool:
    """Usability DoS fix: int/enum/exact ID from trusted record, no free-text from tainted context."""
    if not isinstance(arguments, dict):
        return False
    allowed_keys = {"order_id", "status", "ticket_id", "id"}
    if set(arguments.keys()) - allowed_keys:
        return False
    status = arguments.get("status")
    if status is not None and str(status) not in TICKET_STATUS_ENUM:
        return False
    for k in ("order_id", "ticket_id", "id"):
        if k in arguments and arguments[k] is not None:
            v = arguments[k]
            if isinstance(v, bool) or not isinstance(v, (int, str)):
                return False
            if isinstance(v, str) and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", v):
                return False
    # no free-text fields present
    for k, v in arguments.items():
        if isinstance(v, str) and k == "status":
            continue
        if isinstance(v, str) and shannon_entropy(v) >= HIGH_ENTROPY_THRESHOLD and len(v) > 16:
            return False
    return "status" in arguments


def _gui_action(tool_name: str, args: dict) -> Optional[tuple[str, dict]]:
    """``(action, args)`` for gui_action_guard when ``tool_name`` is a GUI action, else None.

    Accepts bare action names (``click``), ``computer.<action>``, and a
    ``computer`` tool whose ``action`` / ``coordinate`` / ``text`` arguments
    follow the common computer-use shape.
    """
    if tool_name in _GUI_ACTIONS:
        return tool_name, args
    if tool_name.startswith("computer.") and tool_name[len("computer."):] in _GUI_ACTIONS:
        return tool_name[len("computer."):], args
    if tool_name not in ("computer", "computer_use"):
        return None
    action = _COMPUTER_ACTIONS.get(str(args.get("action") or ""))
    if action is None:
        return None
    out = dict(args)
    coord = args.get("coordinate")
    if isinstance(coord, (list, tuple)) and len(coord) == 2:
        if action == "drag":
            start = args.get("start_coordinate")
            if isinstance(start, (list, tuple)) and len(start) == 2:
                out["start_x"], out["start_y"] = start
            out["end_x"], out["end_y"] = coord
        else:
            out["x"], out["y"] = coord
    if action == "key_combo":
        out["keys"] = args.get("text", args.get("keys"))
    return action, out


def _resource_uri(tool_name: str, args: dict) -> Optional[str]:
    """Ledger key for a tool call that reads or writes a named resource, else None."""
    if tool_name in ("save_session_note", "read_session_note"):
        note_id = str(args.get("note_id") or "")
        return f"scratchpad:{note_id}" if note_id else None
    for key in _RESOURCE_ARGS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def _has_free_text_sink(arguments: dict) -> bool:
    if not isinstance(arguments, dict):
        return True
    for key in ("body", "text", "memo", "message", "content", "note", "summary", "html"):
        if key in arguments and arguments[key] not in (None, ""):
            return True
    return False


_AGW1_RE = re.compile(r"agw1\.[A-Za-z0-9_-]{8,}\.[0-9a-f]{64}")


def _log_safe(obj: Any) -> Any:
    """Decision-log copy of an approval payload.

    The log can ship inside an audit directory, so live callback MACs become a
    SHA-256 fingerprint and ``agw1.`` tokens lose their signature.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "mac" and isinstance(v, str):
                out["mac_sha256"] = hashlib.sha256(v.encode("utf-8")).hexdigest()
            else:
                out[k] = _log_safe(v)
        return out
    if isinstance(obj, list):
        return [_log_safe(v) for v in obj]
    if isinstance(obj, str):
        return _AGW1_RE.sub("agw1.[redacted]", obj)
    return obj


class PolicyEngine:
    """In-process policy gate evaluated on every tools/call and tools/list."""

    def __init__(self, registry: Registry, shared: Optional[SharedState] = None, cfg: Optional[PepConfig] = None):
        self.registry = registry
        self.shared = shared or SharedState()
        self.cfg = cfg or PepConfig()
        self.sessions: dict[str, SessionState] = {}
        self.alert_path = self.cfg.alert_log or (approve.state_dir() / "alerts.jsonl")
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
        self.chain = ChainWriter(self.alert_path)
        self.deob = DeobfuscationGuard()
        self.side_channel = SideChannelGuard(self.cfg.side_channel)
        self.delegation = DelegationLedger()
        self.canary = CanaryRegistry()
        self.schema_guard = SchemaIntegrityGuard()
        self.gui_guard = GuiActionGuard(regions=self.cfg.gui_regions, viewport=self.cfg.gui_viewport)
        self.accumulator = TemporalAccumulatorGuard()
        self.workspace = WorkspaceConfigGuard(allow=self.cfg.workspace_allow)
        self.cfi = ControlFlowIntegrityGuard()
        self.stego = StegoExfilGuard()
        # v12.2 reference middleware validators. Each is inert until a trusted
        # adapter supplies its state, so a session with no pins, snapshot,
        # manifest, or matcher is unchanged by them.
        self.pin_registries: dict[str, PinRegistry] = {}
        self.pin_enrolled: set[tuple[str, str]] = set()
        self.pin_owners: dict[str, set[str]] = {}
        self.pin_findings: list[dict] = []
        self.path_snapshots: dict[str, FsSnapshot] = {}
        self.flow_gates: dict[str, ManifestGate] = {}
        self.similarity: Optional[ShingleMatcher] = None
        self.obligation_nets: dict[str, ObligationNet] = {}
        self.fs_transducers: dict[str, FsTransducer] = {}
        self.argument_policies: dict[str, ArgumentPolicy] = {}
        self.command_tools: set[str] = set()
        # Per-session result of the last admitted confinement, read by _allow().
        self._confined: dict[str, dict] = {}
        self.poisoned_tools: dict[tuple[str, str], dict] = {}
        self.interpreter = InterpreterExecGuard(allow=self.cfg.workspace_allow)
        core = set(CORE_MCP_SERVERS)
        if self.cfg.registry_path.is_file():
            try:
                core |= set(json.loads(self.cfg.registry_path.read_text()).get("core_mcp_servers") or [])
            except (ValueError, OSError):
                pass
        self.capability = McpCapabilityManifestGuard(
            profiles={**{c: "PRIVILEGED" for c in core}, **dict(self.cfg.mcp_server_profiles)},
            max_tools_per_server=self.cfg.max_tools_per_server)
        self.collusion = CrossAgentCollusionGuard(max_handoff_depth=self.cfg.max_handoff_depth)
        self._provenance: Optional[MemoryProvenanceGuard] = None
        self.inventories: dict[str, dict[str, dict]] = {}
        self.toxic: dict[str, dict] = {}
        self.findings: list[dict] = []
        self._clock = time.time

    def now(self) -> float:
        return self._clock()

    @property
    def provenance(self) -> MemoryProvenanceGuard:
        """Lineage ledger, keyed from the gateway HMAC key on first use (fails closed without one)."""
        if self._provenance is None:
            key = hmac.new(capability.hmac_key(), _PROV_KEY_LABEL, hashlib.sha256).digest()
            self._provenance = MemoryProvenanceGuard(hmac_key=key)
        return self._provenance

    def get_session(self, session_id: str, agent_key: str) -> SessionState:
        s = self.sessions.get(session_id)
        if s is None:
            rec = self.registry.get(agent_key)
            root = (rec.principal_key if rec else agent_key) or agent_key
            s = SessionState(session_id=session_id, agent_key=agent_key, root_parent_key=root)
            self.sessions[session_id] = s
        if not s.capability_token:
            self._install_fresh_capability(s)
        return s

    def _install_fresh_capability(self, sess: SessionState) -> None:
        mac = capability.mint(sess.session_id, sess.agent_key)
        sess.capability_token = capability.serialize(mac)
        sess.allow_egress = mac.allows_egress

    def _taint(self, sess: SessionState, reason: str, source_id: str = "") -> None:
        """Mark TAINTED and attenuate the session capability in place."""
        safe = capability.sanitize_source(source_id) if source_id else ""
        sess.mark_tainted(reason, source_id=safe)
        self._attenuate_session(sess)

    def _attenuate_session(self, sess: SessionState) -> None:
        """Append deny-egress caveats. The previous tag cannot strip them."""
        mac = capability.verify(sess.capability_token) if sess.capability_token else None
        if mac is None:
            mac = capability.mint(sess.session_id, sess.agent_key)
            if sess.tainted or not sess.allow_egress:
                mac = capability.attenuate(mac, capability.CAVEAT_DENY_EGRESS)
        elif mac.allows_egress:
            mac = capability.attenuate(mac, capability.CAVEAT_DENY_EGRESS)
        source = sess.taint_source_id or ""
        if source:
            caveat = capability.taint_source_caveat(source)
            if caveat not in mac.caveats:
                mac = capability.attenuate(mac, caveat)
        sess.capability_token = capability.serialize(mac)
        sess.allow_egress = mac.allows_egress

    def _adopt_presented_capability(
        self, sess: SessionState, presented: Optional[str], agent_key: str,
    ) -> Optional[str]:
        """Verify a client-presented chain. Return an error code, or None.

        A stateless worker needs only the HMAC secret. An attenuated chain
        cannot be upgraded: dropping ``allow_egress=false`` fails verification,
        and replaying an earlier allowing discharge is rejected while this
        worker still holds the attenuated session copy.
        """
        if not presented:
            return None
        mac = capability.verify(presented)
        if mac is None or mac.session_id != sess.session_id:
            return "capability_rejected"
        if not capability.agent_matches(mac, agent_key):
            return "capability_agent_mismatch"
        current = capability.verify(sess.capability_token) if sess.capability_token else None
        if current is None:
            return "capability_rejected"
        if not current.allows_egress and mac.allows_egress:
            return "capability_upgrade_rejected"
        if capability.extends(current.caveats, mac.caveats):
            sess.capability_token = capability.serialize(mac)
            sess.allow_egress = mac.allows_egress
            if not mac.allows_egress:
                self._taint(sess, "capability_attenuated", source_id=mac.taint_source or "capability")
            return None
        # Older prefix of the in-place chain that already denies egress: keep ours.
        if not mac.allows_egress and capability.extends(mac.caveats, current.caveats):
            return None
        return "capability_rejected"

    def _attach_capability(self, session_id: str, out: dict) -> dict:
        if not isinstance(out, dict):
            return out
        if out.get("error") in ("unregistered_agent", "agent_frozen"):
            return out
        sess = self.sessions.get(session_id)
        if sess is None or not sess.capability_token:
            return out
        out["capability_token"] = sess.capability_token
        out["allow_egress"] = bool(sess.allow_egress)
        return out

    def _alert(self, kind: str, detail: dict) -> None:
        rec = {"ts": self.now(), "kind": kind, **scrub_obj(detail)}
        self.chain.append(rec)
        # webhook stub: only if explicitly configured (still not used for public web)
        if self.cfg.webhook_url:
            log.warning("webhook stub configured but lab default is OFF-path; not sending: %s", kind)

    def _freeze_root(self, agent_key: str, reason: str) -> list[str]:
        ids = self.registry.freeze_root(agent_key, seconds=self.cfg.freeze_seconds, now=self.now())
        if ids:
            self._alert("r12_freeze", {"agent_key_prefix": agent_key[:12], "frozen_agents": ids, "reason": reason,
                                       "seconds": self.cfg.freeze_seconds})
        return ids

    def evaluate_tools_list(
        self, agent_key: str, session_id: str, server_name: str, descriptions: list[dict],
        capability_token: Optional[str] = None,
    ) -> dict:
        out = self._evaluate_tools_list(
            agent_key, session_id, server_name, descriptions, capability_token=capability_token,
        )
        return self._attach_capability(session_id, out)

    def _evaluate_tools_list(
        self, agent_key: str, session_id: str, server_name: str, descriptions: list[dict],
        capability_token: Optional[str] = None,
    ) -> dict:
        """Ingesting tools/list from non-allowlisted MCP servers sets TAINTED (AML.T0051.001)."""
        self.registry.lift_expired(self.now())
        if not self.registry.get(agent_key):
            return {"ok": False, "error": "unregistered_agent", "code": -32001}
        if self.registry.is_frozen_key(agent_key, self.now()):
            return {"ok": False, "error": "agent_frozen", "code": -32002}
        sess = self.get_session(session_id, agent_key)
        rejected = self._adopt_presented_capability(sess, capability_token, agent_key)
        if rejected:
            return self._deny(sess, sess.step_index, "tools/list", {}, rejected, -32040, atlas="AML.M0030")
        sess.step_index += 1
        core = CORE_MCP_SERVERS | set(
            json.loads(self.cfg.registry_path.read_text()).get("core_mcp_servers") or []
            if self.cfg.registry_path.is_file() else []
        )
        if (server_name or "").lower() not in {c.lower() for c in core}:
            # capability pinning: non-core description ingest = untrusted
            src = f"tools.list:{server_name or 'unknown'}"
            self._taint(sess, f"untrusted_tools_list:{server_name}", source_id=src)
            self._alert("taint_tools_list", {"session_id": session_id, "server": server_name,
                                            "n_descriptions": len(descriptions or [])})
        toxic = self.record_inventory(session_id, descriptions or [])
        return {
            "ok": True,
            "tainted": sess.tainted,
            "toxic_combinations": toxic,
            "tools": descriptions or [],
            "scrubbed_log": scrub_obj({"method": "tools/list", "server": server_name}),
        }

    def evaluate_call(
        self,
        agent_key: str,
        session_id: str,
        tool_name: str,
        arguments: Optional[dict] = None,
        approval_token: Optional[str] = None,
        delegation_depth: int = 0,
        parent_key: Optional[str] = None,
        bound_step_index: Optional[int] = None,
        capability_token: Optional[str] = None,
        destination: Optional[str] = None,
    ) -> dict:
        """Evaluate one tools/call.

        ``destination`` names the outbound channel for the temporal
        accumulator window (the MCP proxy passes ``mcp:<server>``); it
        defaults to the tool's egress class.
        """
        out = self._evaluate_call(
            agent_key, session_id, tool_name, arguments,
            approval_token=approval_token, delegation_depth=delegation_depth,
            parent_key=parent_key, bound_step_index=bound_step_index,
            capability_token=capability_token, destination=destination,
        )
        return self._attach_capability(session_id, out)

    def _evaluate_call(
        self,
        agent_key: str,
        session_id: str,
        tool_name: str,
        arguments: Optional[dict] = None,
        approval_token: Optional[str] = None,
        delegation_depth: int = 0,
        parent_key: Optional[str] = None,
        bound_step_index: Optional[int] = None,
        capability_token: Optional[str] = None,
        destination: Optional[str] = None,
    ) -> dict:
        self.registry.lift_expired(self.now())
        rec = self.registry.get(agent_key)
        if not rec:
            return {"ok": False, "error": "unregistered_agent", "code": -32001,
                    "message": "policy gate: key not in registry (web visitors are never acted on here)"}
        if self.registry.is_frozen_key(agent_key, self.now()):
            return {"ok": False, "error": "agent_frozen", "code": -32002,
                    "message": "Root Parent Principal frozen (R12); auto-lift when timer expires"}

        sess = self.get_session(session_id, agent_key)
        rejected = self._adopt_presented_capability(sess, capability_token, agent_key)
        if rejected:
            return self._deny(
                sess, sess.step_index, tool_name, dict(arguments or {}), rejected, -32040, atlas="AML.M0030",
            )
        if parent_key:
            pref = self.registry.get(parent_key)
            if pref:
                sess.root_parent_key = pref.principal_key
                sess.delegation_depth = max(sess.delegation_depth, 1)
        sess.delegation_depth = max(sess.delegation_depth, int(delegation_depth or 0))
        # Retries with a bound OOB token reuse the denied step_index (no re-increment)
        if approval_token and bound_step_index is not None:
            step = int(bound_step_index)
            sess.step_index = max(sess.step_index, step)
        else:
            sess.step_index += 1
            step = sess.step_index
        args = dict(arguments or {})
        eclass = egress_class(tool_name)
        oob_memo: dict[str, bool] = {}

        def oob() -> bool:
            # One-time token: consume at most once even when several gates ask.
            if "ok" not in oob_memo:
                oob_memo["ok"] = self._try_oob(sess, step, tool_name, args, approval_token)
            return oob_memo["ok"]

        principal = sess.root_parent_key or agent_key
        profile = profile_from_token(sess.capability_token, sensitive_read=sess.sensitive_read)
        if profile is not None:
            self.delegation.observe(principal, profile)

        # --- Inline interpreter payloads: protected writes, decoded execution, primitives (v12.1) ---
        interp = self.interpreter.inspect_tool_call(tool_name, args, session_id=sess.session_id)
        if not interp.allowed:
            return self._v12_deny(sess, step, tool_name, args, interp.rule_code, {"interpreter": interp.as_dict()})

        # --- Lexical / canonical argument firewall (approximate AML.T0051 / AML.T0053) ---
        arg_hit = inspect_arg_call(tool_name, args, self._tool_class(tool_name))
        if arg_hit is not None:
            finding = {**arg_hit, "kind": "arg_firewall_violation", "violation": arg_hit["kind"],
                       "session_id": sess.session_id, "step": step}
            self.findings.append(finding)
            self._alert("arg_firewall_violation", finding)
            out = self._deny(sess, step, tool_name, args, "arg_firewall_violation", -32035,
                             atlas=arg_hit.get("atlas", "AML.T0051"))
            out["arg_violation"] = arg_hit
            return out

        # --- Computer-use reserved regions and shortcut deny-list (approximate AML.T0053) ---
        gui = _gui_action(tool_name, args)
        if gui is not None:
            verdict = self.gui_guard.check(*gui)
            if not verdict.ok:
                kind = verdict.code.lower()
                finding = {"kind": kind, "session_id": sess.session_id, "step": step, "tool": tool_name,
                           "atlas": "AML.T0053", "atlas_approximate": True, "gui": verdict.as_dict()}
                self.findings.append(finding)
                self._alert(kind, finding)
                code = -32038 if kind == "gui_region_denied" else -32039
                out = self._deny(sess, step, tool_name, args, kind, code, atlas="AML.T0053")
                out["gui"] = verdict.as_dict()
                return out

        # --- Agent config, skill, and execution-hook persistence (v12) ---
        ws = self.workspace.inspect_tool_call(tool_name, args, session_id=sess.session_id)
        if not ws.allowed:
            return self._v12_deny(sess, step, tool_name, args, ws.rule_code, {"workspace": ws.as_dict()})

        # --- Control-flow integrity for sessions with a pinned capability manifest (v12) ---
        label = self.cfi.sessions.get(sess.session_id)
        if label is not None and label.manifest is not None:
            if sess.tainted:
                self.cfi.mark_untrusted(sess.session_id, sess.taint_source_id or "pep_taint")
            cfi = self.cfi.evaluate(sess.session_id, tool_name, args)
            if not cfi.allowed:
                return self._v12_deny(sess, step, tool_name, args, cfi.rule_code, {"cfi": cfi.as_dict()})

        # --- Reference middleware validators (v12.2) ---------------------------------
        ref = self._reference_middleware(sess, step, tool_name, args, eclass)
        if ref is not None:
            return ref

        # --- Review hold (MCP rug pull, side channel): every call waits for a person ---
        if sess.review_hold and not oob():
            if sess.review_hold == "mcp_rug_pull_detected":
                return self._deny(sess, step, tool_name, args, "mcp_rug_pull_hold", -32050, atlas="AML.T0051")
            return self._deny(sess, step, tool_name, args, "session_review_hold", -32051, atlas="AML.T0086")

        # --- SSRF / cloud metadata in any URI or host argument (approximate AML.T0053) ---
        uri = inspect_arguments(args, self.cfg.ssrf_lab_allow)
        if uri is not None:
            finding = {"kind": "ssrf_boundary_violation", "session_id": sess.session_id, "step": step,
                       "tool": tool_name, **uri.as_dict()}
            released = uri.verdict == "hold" and oob()
            finding["released_by_oob"] = released
            self.findings.append(finding)
            self._alert("ssrf_boundary_violation", finding)
            if uri.verdict == "deny":
                out = self._deny(sess, step, tool_name, args, "ssrf_boundary_violation", -32032, atlas="AML.T0053")
                out["uri"] = uri.as_dict()
                return out
            if not released:
                out = self._deny(sess, step, tool_name, args, "ssrf_internal_target_hold", -32034, atlas="AML.T0053")
                out["uri"] = uri.as_dict()
                return out

        # --- Cross-session resource lineage on reads (approximate AML.T0080.000) ---
        if eclass in (EGRESS_INTERNAL_READ, EGRESS_EXTERNAL_READ) and tool_name != "read_session_note":
            uri = _resource_uri(tool_name, args)
            if uri is not None:
                denied = self._provenance_read(sess, step, tool_name, args, uri)
                if denied is not None:
                    return denied

        # --- Multi-agent delegation hand-off (monotonic attenuation) ---
        if tool_name == "delegate_task":
            child_key = str(args.get("child_api_key") or args.get("to_agent_key") or "")
            child_session = str(args.get("child_session_id") or args.get("to_session_id") or f"{session_id}:child")
            merged = self.delegate(agent_key, session_id, child_key, child_session)
            return self._allow(sess, step, tool_name, args, eclass, delegation=merged.as_dict())

        # --- spawn quotas (AML.T0118) ---
        if tool_name == "spawn_subagent" or eclass == EGRESS_SPAWN:
            if sess.delegation_depth >= self.cfg.max_delegation_depth or rec.max_delegation_depth < 1:
                return {"ok": False, "error": "max_delegation_depth", "code": -32010,
                        "message": "max_delegation_depth=1; child cannot delegate further"}
            root = sess.root_parent_key or agent_key
            n = self.shared.children_by_parent.get(root, 0)
            limit = rec.max_children_per_parent or self.cfg.max_children_per_parent
            if n >= limit:
                return {"ok": False, "error": "max_children_per_parent", "code": -32011,
                        "message": f"fan-out refused: max_children_per_parent={limit}"}
            col = self._collusion_sink(sess, PRIVILEGED_EXEC)
            if col is not None:
                return self._v12_deny(sess, step, tool_name, args, col.rule_code, {"collusion": col.as_dict()})
            # reserve slot
            self.shared.children_by_parent[root] = n + 1
            sess.children_spawned += 1
            child_key = str(args.get("child_api_key") or "")
            child_session = str(args.get("child_session_id") or f"{session_id}:child")
            if child_key:
                self.delegate(agent_key, session_id, child_key, child_session)
            # propagate taint intent into result for caller
            result = {
                "ok": True,
                "allowed": True,
                "tool": tool_name,
                "egress_class": eclass,
                "child_inherits_taint": sess.tainted,
                "root_parent_key": root,
                "children_count": self.shared.children_by_parent[root],
                "result": {"spawned": True, "delegation_depth": sess.delegation_depth + 1},
                "scrubbed_args": scrub_obj(args),
            }
            sess.history.append({"step": step, "tool": tool_name, "ok": True})
            return result

        # --- bus post: propagate TAINTED (AML.T0118) ---
        if tool_name == "post_internal_bus":
            if sess.tainted and eclass in BLOCKED_EGRESS_WHILE_TAINTED:
                # bus post while tainted still allowed as *internal laundering vector we track*,
                # but we stamp taint on the message; outbound from peers will gate.
                pass
            col = self._collusion_write(sess, artifact_id("msg", "internal_bus"))
            if col is not None:
                return self._v12_deny(sess, step, tool_name, args, col.rule_code, {"collusion": col.as_dict()})
            msg = {
                "from_key": agent_key,
                "session_id": session_id,
                "payload": args.get("payload"),
                "tainted": bool(sess.tainted),
                "taint_source_id": sess.taint_source_id,
                "ts": self.now(),
            }
            self.shared.bus.append(msg)
            sess.history.append({"step": step, "tool": tool_name, "ok": True, "bus_tainted": msg["tainted"]})
            return {"ok": True, "allowed": True, "tool": tool_name, "egress_class": eclass,
                    "result": {"posted": True, "tainted": msg["tainted"]}, "scrubbed_args": scrub_obj(args)}

        if tool_name == "poll_internal_bus":
            # reading tainted bus messages taints this session
            self.collusion.record_read(self._agent_node(sess), artifact_id("msg", "internal_bus"))
            out = []
            for m in self.shared.bus:
                out.append(m)
                if m.get("tainted"):
                    self._taint(sess, "bus_taint_propagation", source_id=str(m.get("taint_source_id") or "bus"))
            return {"ok": True, "allowed": True, "tool": tool_name, "egress_class": eclass,
                    "tainted": sess.tainted, "result": {"messages": out}, "scrubbed_args": scrub_obj(args)}

        # --- scratchpad write/read with taint_inherited (AML.T0080.000) ---
        if tool_name == "save_session_note":
            # Provenance-tagged state (AML.T0080.000): writes while TAINTED are permitted but
            # always persist taint_inherited=True so a later clean session re-taints on read.
            note_id = str(args.get("note_id") or f"note-{session_id}-{step}")
            body = str(args.get("text") or args.get("body") or args.get("note") or "")
            col = self._collusion_write(sess, artifact_id("mem", note_id))
            if col is not None:
                return self._v12_deny(sess, step, tool_name, args, col.rule_code, {"collusion": col.as_dict()})
            entry = ScratchpadEntry(
                note_id=note_id, body=body, taint_inherited=bool(sess.tainted),
                source_session=session_id, created_at=self.now(),
            )
            self.shared.scratchpad[note_id] = entry
            self._provenance_write(sess, f"scratchpad:{note_id}")
            return {"ok": True, "allowed": True, "tool": tool_name, "egress_class": eclass,
                    "result": {"note_id": note_id, "taint_inherited": entry.taint_inherited},
                    "scrubbed_args": scrub_obj(args)}

        if tool_name == "read_session_note":
            note_id = str(args.get("note_id") or "")
            entry = self.shared.scratchpad.get(note_id)
            if entry is None:
                # default: most recent from any session if note_id empty
                if not note_id and self.shared.scratchpad:
                    entry = list(self.shared.scratchpad.values())[-1]
            if entry is not None:
                denied = self._provenance_read(sess, step, tool_name, args, f"scratchpad:{entry.note_id}")
                if denied is not None:
                    return denied
            if entry is not None:
                self.collusion.record_read(self._agent_node(sess), artifact_id("mem", entry.note_id))
            if entry and entry.taint_inherited:
                self._taint(sess, "scratchpad_taint_inherited", source_id=f"scratchpad:{entry.note_id}")
            return {"ok": True, "allowed": True, "tool": tool_name, "egress_class": eclass,
                    "tainted": sess.tainted,
                    "result": None if entry is None else {
                        "note_id": entry.note_id, "body": entry.body,
                        "taint_inherited": entry.taint_inherited,
                    },
                    "scrubbed_args": scrub_obj(args)}

        # --- mark untrusted ingest / sensitive ---
        if tool_name in UNTRUSTED_INGEST_TOOLS or eclass == EGRESS_EXTERNAL_READ:
            # file.read of allowlisted internal paths could be internal — treat file.read as untrusted for lab safety
            src = f"{tool_name}:{step}"
            self._taint(sess, f"untrusted_ingest:{tool_name}", source_id=sess.taint_source_id or src)
        if tool_name in SENSITIVE_READ_TOOLS or eclass == EGRESS_CREDS:
            # reading creds is both sensitive and blocked while tainted without OOB
            sess.mark_sensitive()

        # --- Lethal trifecta gate (AML.T0086): TAINTED + SENSITIVE_READ + external param egress ---
        # allow_egress is the capability-chain view of the same gate (monotonic caveat).
        egress_closed = bool(sess.tainted or not sess.allow_egress)
        if egress_closed and sess.sensitive_read and places_params_on_external_boundary(tool_name, args):
            if not oob():
                return self._deny(sess, step, tool_name, args, "lethal_trifecta_external_egress", -32030,
                                  atlas="AML.T0086")

        # --- Allowlisted constrained sink (falsification test 7 / usability DoS fix) ---
        if egress_closed and tool_name == "update_ticket_status" and _is_constrained_ticket_status(args) and not _has_free_text_sink(args):
            return self._release(sess, step, tool_name, args, eclass, constrained=True,
                                 approved=oob_memo.get("ok", False), destination=destination)

        # --- Confused-deputy: a clean-looking session whose principal was barred upstream ---
        if not egress_closed and eclass in BLOCKED_EGRESS_WHILE_TAINTED:
            dep = self.delegation.check_egress(principal, tool_name)
            if dep is not None and not oob():
                dep = {"session_id": sess.session_id, "step": step, **dep}
                self.findings.append(dep)
                self._alert("confused_deputy_delegation_blocked", dep)
                out = self._deny(sess, step, tool_name, args, "confused_deputy_delegation_blocked", -32036,
                                 atlas="AML.T0086")
                out["delegation"] = dep["profile"]
                return out

        # --- Block write/send/creds/bus while tainted unless bound OOB (spacers never clear taint) ---
        if egress_closed and eclass in BLOCKED_EGRESS_WHILE_TAINTED:
            if not oob():
                err = "oob_required_while_tainted"
                atlas = "AML.T0053"
                if eclass in (EGRESS_WRITE, EGRESS_SEND):
                    err = "post_taint_outbound_gated"
                    atlas = "AML.T0086"
                if eclass == EGRESS_CREDS:
                    err = "oob_required_creds_while_tainted"
                return self._deny(sess, step, tool_name, args, err, -32020, atlas=atlas)

        if tool_name == "credentials.pass_through":
            return self._deny(sess, step, tool_name, args, "credentials_pass_through_refused", -32012)

        return self._release(sess, step, tool_name, args, eclass, approved=oob_memo.get("ok", False),
                             destination=destination)

    def _release(self, sess: SessionState, step: int, tool_name: str, args: dict, eclass: str,
                 constrained: bool = False, approved: bool = False, destination: Optional[str] = None) -> dict:
        """Last gate before an allowed call leaves: cross-step / encoded exfil (approximate AML.T0086).

        Arguments are appended to the session window only when the call is
        released, so the window holds what actually left the gateway.
        """
        outbound = eclass != EGRESS_INTERNAL_READ
        if outbound and self.canary.has_canaries(sess.session_id):
            prov = self.canary.scan_outbound(sess.session_id, args)
            if prov is not None:
                finding = {"kind": "canary_watermark_exfil", "session_id": sess.session_id, "step": step,
                           "tool": tool_name, **prov.as_dict()}
                self.findings.append(finding)
                self._alert("canary_watermark_exfil", finding)
                self._taint(sess, "canary_exfil", source_id=f"canary:{prov.origin_tool_name}")
                frozen = self._freeze_root(sess.agent_key, "canary_watermark_exfil")
                out = self._deny(sess, step, tool_name, args, "canary_watermark_exfil", -32037, atlas="AML.T0086")
                out["provenance"] = prov.as_dict()
                out["frozen_agents"] = frozen
                return out
        if outbound and self.deob.has_secrets(sess.session_id):
            leak = self.deob.scan(sess.session_id, tool_name, args)
            if leak is not None:
                finding = {"kind": "deobfuscated_exfil_detected", "session_id": sess.session_id, "step": step,
                           "tool": tool_name, **leak.as_dict()}
                self.findings.append(finding)
                self._alert("deobfuscated_exfil_detected", finding)
                self._taint(sess, "deobfuscated_exfil", source_id=f"deobfuscate:{leak.form}")
                frozen = self._freeze_root(sess.agent_key, "deobfuscated_exfil_detected")
                out = self._deny(sess, step, tool_name, args, "deobfuscated_exfil_detected", -32031,
                                 atlas="AML.T0086")
                out["leak"] = leak.as_dict()
                out["frozen_agents"] = frozen
                return out
            self.deob.commit(sess.session_id, tool_name, args)
        if outbound:
            acc = self.accumulator.evaluate_call(sess.session_id, destination or eclass, args)
            if not acc.allowed:
                detail = {"rule": acc.matched_rule, "destination": destination or eclass,
                          "window_length": acc.window_length}
                finding = {"kind": "sharded_exfil_denied", "session_id": sess.session_id, "step": step,
                           "tool": tool_name, "atlas": "AML.T0086", "atlas_approximate": True, **detail}
                self.findings.append(finding)
                self._alert("sharded_exfil_denied", finding)
                self._taint(sess, "sharded_exfil", source_id=f"accumulator:{acc.matched_rule}")
                out = self._deny(sess, step, tool_name, args, "sharded_exfil_denied", -32043, atlas="AML.T0086")
                out["accumulator"] = detail
                return out
        if outbound and self.stego.secret_count(sess.session_id):
            sd = self.stego.inspect_outbound(tool_name, args, session_id=sess.session_id, identifiers_only=True)
            if not sd.allowed:
                self._taint(sess, "stego_exfil", source_id=f"stego:{sd.rule_code}")
                return self._v12_deny(sess, step, tool_name, args, sd.rule_code, {"stego": sd.as_dict()})
        # A call a person released with a bound OOB token is not oracle traffic.
        if outbound and sess.tainted and sess.sensitive_read and not approved:
            now = self.now()
            sig = self.side_channel.check(sess.session_id, tool_name, args, now)
            if sig is not None:
                finding = {"kind": "covert_side_channel_suspected", "session_id": sess.session_id,
                           "step": step, "tool": tool_name, **sig.as_dict()}
                self.findings.append(finding)
                self._alert("covert_side_channel_suspected", finding)
                sess.review_hold = "covert_side_channel_suspected"
                frozen = self._freeze_root(sess.agent_key, "covert_side_channel_suspected")
                out = self._deny(sess, step, tool_name, args, "covert_side_channel_suspected", -32033,
                                 atlas="AML.T0086")
                out["side_channel"] = sig.as_dict()
                out["frozen_agents"] = frozen
                return out
            self.side_channel.commit(sess.session_id, tool_name, args, now)
        # Cross-agent provenance (v12.1). A call a person released with a bound OOB token is not re-judged.
        if not approved:
            sink = self._sink_stage(tool_name, eclass, args)
            col = self._collusion_sink(sess, sink) if sink else None
            if col is None and eclass == EGRESS_WRITE and (uri := _resource_uri(tool_name, args)) is not None:
                col = self._collusion_write(sess, artifact_id("file", uri))
            if col is not None:
                return self._v12_deny(sess, step, tool_name, args, col.rule_code, {"collusion": col.as_dict()})
        return self._allow(sess, step, tool_name, args, eclass, constrained=constrained)

    # --- Multi-agent delegation, argument class -----------------------------------

    def _tool_class(self, tool_name: str) -> str:
        return toxic_combinations.tool_class({"name": tool_name})

    def delegate(self, sender_key: str, sender_session: str, recipient_key: str, recipient_session: str):
        """Hand off sender -> recipient with monotonic attenuation.

        The recipient's session capability is re-minted carrying the sender's
        deny caveats, and both principals' ledger entries fold together so a
        clean peer cannot launder the sender's taint. Returns the recipient's
        merged :class:`CapProfile`.
        """
        from .delegation_guard import CapProfile

        sender = self.sessions.get(sender_session)
        sender_principal = (sender.root_parent_key or sender_key) if sender else sender_key
        sender_profile = CapProfile()
        if sender is not None and sender.capability_token:
            p = profile_from_token(sender.capability_token, sensitive_read=sender.sensitive_read)
            if p is not None:
                sender_profile = p
        self.delegation.observe(sender_principal, sender_profile)

        recipient = self.get_session(recipient_session, recipient_key) if recipient_key else None
        recipient_principal = (recipient.root_parent_key or recipient_key) if recipient else recipient_key
        if recipient is not None and sender is not None and sender.capability_token and recipient.capability_token:
            handed = attenuate_for_handoff(sender.capability_token, recipient.capability_token)
            if handed is not None:
                recipient.capability_token = handed
                recipient.allow_egress = profile_from_token(handed).allow_egress
                if not recipient.allow_egress:
                    recipient.mark_tainted("delegation_attenuated", source_id=f"delegation:{sender_principal[:12]}")
        merged = self.delegation.delegate(sender_principal, recipient_principal, at_step=sender.step_index if sender else 0)
        if sender is not None and recipient is not None:
            self._collusion_sync(sender)
            self.collusion.record_delegation(self._agent_node(sender), self._agent_node(recipient))
        if recipient is not None:
            self.delegation.observe(recipient_principal,
                                    profile_from_token(recipient.capability_token,
                                                       sensitive_read=recipient.sensitive_read) or merged)
        return self.delegation.profile(recipient_principal)

    # --- Inventory, output scanning ------------------------------------------------

    def record_inventory(self, session_id: str, tools: list[dict]) -> dict:
        """Merge a tools/list into the session inventory and re-run the toxic-flow analysis."""
        inv = self.inventories.setdefault(session_id, {})
        for tool in tools:
            if isinstance(tool, dict) and tool.get("name"):
                inv[str(tool["name"])] = tool
        report = toxic_combinations.analyze(list(inv.values())).as_dict()
        self.toxic[session_id] = report
        totals = report["totals"]
        if totals["toxic"]:
            self._alert("toxic_combinations", {"session_id": session_id, "totals": totals,
                                               "atlas": "AML.T0086", "atlas_approximate": True})
        return totals

    def sink_tools(self, session_id: str) -> list[str]:
        inv = self.inventories.get(session_id)
        if inv:
            return tool_output_scanner.sink_tools_from(inv.values())
        return list(_DEFAULT_SINK_TOOLS)

    def scan_tool_output(self, agent_key: str, session_id: str, tool_name: str, result: Any) -> dict:
        """Scan untrusted output before it reaches the agent loop (approximate AML.T0051).

        Any finding taints the session and attenuates its ``agw1.`` capability.
        Returns ``{"findings": [...], "result": <invisible characters removed>}``.
        """
        found = [f.as_dict() for f in tool_output_scanner.scan_output(result, self.sink_tools(session_id))]
        if found:
            sess = self.get_session(session_id, agent_key)
            self._taint(sess, f"tool_output_injection:{tool_name}", source_id=f"tool_output:{tool_name}")
            finding = {"kind": "tool_output_injection", "session_id": session_id, "tool": tool_name,
                       "signals": found, "atlas": "AML.T0051", "atlas_approximate": True,
                       "allow_egress": bool(sess.allow_egress)}
            self.findings.append(finding)
            self._alert("tool_output_injection", finding)
        return {"findings": found, "result": tool_output_scanner.sanitize_output(result) if found else result}

    # --- MCP wire-proxy hooks (mcp_proxy.py) -------------------------------------

    def register_canary(self, value: str, label: str = "canary", session_id: Optional[str] = None) -> bool:
        """Fingerprint a canary secret. ``session_id=None`` watches every session."""
        self.accumulator.register_protected_token(value, session_id=session_id)
        self.stego.register_secret(value, label=label, session_id=session_id)
        return self.deob.register(value, label=label, session_id=session_id)

    def ingest_tool_result(self, agent_key: str, session_id: str, tool_name: str, result: Any) -> int:
        """Fingerprint data returned by a sensitive read. Returns secrets registered."""
        if tool_name not in SENSITIVE_READ_TOOLS and egress_class(tool_name) != EGRESS_CREDS:
            return 0
        sess = self.get_session(session_id, agent_key)
        sess.mark_sensitive()
        for _key, value in iter_strings(result):
            for candidate in secret_candidates(value):
                self.accumulator.register_protected_token(candidate, session_id=session_id)
                self.stego.register_secret(candidate, label=tool_name, session_id=session_id)
        return self.deob.register_output(result, label=tool_name, session_id=session_id)

    def mark_untrusted_ingest(self, agent_key: str, session_id: str, source: str) -> None:
        sess = self.get_session(session_id, agent_key)
        self._taint(sess, f"untrusted_ingest:{source}", source_id=sess.taint_source_id or source)

    def flag_rug_pull(self, agent_key: str, session_id: str, server_name: str, changes: list[dict]) -> dict:
        """A pinned MCP tool definition changed mid-session (approximate AML.T0051).

        Taints the session, appends ``allow_egress=false``, and holds every
        later tools/call for a bound one-time OOB approval.
        """
        sess = self.get_session(session_id, agent_key)
        self._taint(sess, f"mcp_rug_pull:{server_name}", source_id=f"mcp.rug_pull:{server_name or 'unknown'}")
        sess.review_hold = "mcp_rug_pull_detected"
        finding = {
            "kind": "mcp_rug_pull_detected", "atlas": "AML.T0051", "atlas_approximate": True,
            "session_id": session_id, "server": server_name, "changes": changes,
            "allow_egress": bool(sess.allow_egress),
        }
        self.findings.append(finding)
        self._alert("mcp_rug_pull_detected", finding)
        return finding

    # --- Cross-session resource lineage (memory_provenance_guard.py) -------------

    def _lineage(self, sess: SessionState) -> tuple[int, int]:
        closed = bool(sess.tainted or not sess.allow_egress)
        mask = ALL_CAPABILITIES_MASK & ~_PROV_CAP_EGRESS if closed else ALL_CAPABILITIES_MASK
        return (_PROV_TAINTED if sess.tainted else 0), mask

    def _provenance_write(self, sess: SessionState, uri: str) -> None:
        taint, mask = self._lineage(sess)
        try:
            self.provenance.record_write(uri, sess.session_id, taint, mask)
        except ValueError:
            # The stored record failed its HMAC; the next read of this resource is denied.
            self._alert("provenance_tamper_on_write", {"session_id": sess.session_id,
                                                       "atlas": "AML.T0080.000", "atlas_approximate": True})

    def _provenance_read(self, sess: SessionState, step: int, tool_name: str, args: dict,
                         uri: str) -> Optional[dict]:
        """Deny a read of a tampered record, else carry the writer's taint into ``sess``."""
        res = self.provenance.evaluate_read(uri, *self._lineage(sess))
        detail = {"verdict": res.verdict_code, "resource_hash": (res.resource_hash or "")[:16],
                  "writer_session_id": res.writer_session_id}
        if not res.allowed:
            finding = {"kind": "provenance_tamper_denied", "session_id": sess.session_id, "step": step,
                       "tool": tool_name, "atlas": "AML.T0080.000", "atlas_approximate": True, **detail}
            self.findings.append(finding)
            self._alert("provenance_tamper_denied", finding)
            self._taint(sess, "provenance_tamper", source_id=f"provenance:{detail['resource_hash']}")
            out = self._deny(sess, step, tool_name, args, "provenance_tamper_denied", -32042,
                             atlas="AML.T0080.000")
            out["provenance"] = detail
            return out
        if res.effective_taint > 0 or not res.effective_capability_mask & _PROV_CAP_EGRESS:
            if not sess.tainted:
                self._alert("provenance_taint_inherited", {"session_id": sess.session_id, "step": step,
                                                           "tool": tool_name, **detail})
            self._taint(sess, "provenance_taint_inherited",
                        source_id=f"provenance:{res.writer_session_id or detail['resource_hash']}")
        return None

    def export_provenance_ledger(self) -> dict:
        """HMAC-tagged lineage ledger, for persisting across gateway restarts."""
        return self.provenance.export_ledger()

    def load_provenance_ledger(self, data: dict) -> None:
        """Replace the lineage ledger; any record that fails its HMAC refuses the whole load."""
        self.provenance.load_ledger(data)

    # --- v12 guards -----------------------------------------------------------------

    def pin_capability_manifest(self, manifest: UserCapabilityManifest) -> None:
        """Pin the user's pre-taint grants for a session (control_flow_integrity_guard.py).

        Must happen before the session reads untrusted data. The manifest only
        narrows: calls it allows still pass every other gate.
        """
        sess = self.sessions.get(manifest.session_id)
        if sess is not None and sess.tainted:
            raise ValueError("capability manifest must be pinned before the session reads untrusted data")
        self.cfi.pin_manifest(manifest)

    # --- v12.2 reference middleware validators ---------------------------------------

    def pin_tool_descriptors(self, server_name: str, tools: list[dict]) -> list[dict]:
        """Enroll ``(server, tool)`` descriptors in the reference pin registry.

        One :class:`PinRegistry` per provider: the first listing of a server pins
        every descriptor it advertises and seals that server; a later listing can
        only confirm, never grow. Drift is sticky - a changed, invalid or removed
        descriptor revokes the key for the rest of the session (``REVOKED`` never
        heals), and a bare tool name claimed by two servers is recorded as an
        ambiguous alias rather than resolved by arrival order.

        Only failures are returned, each already carrying the rule code the
        caller records as a finding. Enrollment also lints display metadata with
        the reference linter, so a poisoned description is refused before it is
        ever served to a model.
        """
        verdicts: list[dict] = []
        for tool in tools or []:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "")
            if not name:
                continue
            descriptor = {k: tool[k] for k in _REFERENCE_PIN_FIELDS if k in tool}
            registry = self.pin_registries.setdefault(server_name, PinRegistry())
            try:
                raw = json.dumps(descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                registry.register(server_name, name, raw)
            except ReferenceDenied as exc:
                # Membership is sticky: a key that was ever enrolled stays
                # enrolled, so a revoked pin is still gated at call time.
                verdicts.append({
                    "ok": False, "code": REGISTRY_PIN_DRIFT, "tool": name, "server_id": server_name,
                    "reason": str(exc),
                    "lint": list(pin_lint_description(str(descriptor.get("description") or ""))),
                })
                continue
            registry.seal()
            self.pin_enrolled.add((server_name, name))
            owners = self.pin_owners.setdefault(name, set())
            owners.add(server_name)
            if len(owners) > 1:
                verdicts.append({
                    "ok": False, "code": REGISTRY_ALIAS_AMBIGUOUS, "tool": name,
                    "server_id": server_name, "owners": sorted(owners),
                    "reason": "bare alias claimed by several providers",
                })
        return verdicts

    def pin_state(self, server_name: str, tool_name: str) -> str:
        """``PINNED`` / ``REVOKED`` / ``UNPINNED`` for one qualified method."""
        registry = self.pin_registries.get(server_name)
        if registry is None or (server_name, tool_name) not in self.pin_enrolled:
            return "UNPINNED"
        try:
            registry.lookup(tool_name, server_name)
        except ReferenceDenied as exc:
            return "REVOKED" if str(exc) in {"REVOKED_OR_UNKNOWN", "REGISTRY_NOT_SEALED"} else str(exc)
        return "PINNED"

    def attach_workspace_snapshot(self, session_id: str, nodes: dict[str, FsNode],
                                  generation: int = 0, root: str = "/ws") -> FsSnapshot:
        """Make shell-effect analysis live for one session.

        ``nodes`` is a trusted, complete filesystem model built by the broker -
        never caller-supplied JSON. Once attached, every shell command the
        session submits is parsed into a conservative effect union and checked
        against the model; unmodeled syntax, a protected path, a shared inode or
        a stale generation is a denial.
        """
        snapshot = FsSnapshot(nodes, generation, root)
        self.path_snapshots[session_id] = snapshot
        return snapshot

    def pin_workflow_manifest(self, session_id: str, job_id: str, steps: tuple[FlowStep, ...],
                              policies: dict[tuple[str, str], FlowMethodPolicy]) -> ManifestGate:
        """Gate a session's calls with a precommitted, single-use-step manifest.

        Once pinned, every call must match one unused step on provider, method,
        pin, resource roles, path patterns and argument digest. Failed and
        unknown outcomes never restore spent authority.
        """
        gate = ManifestGate(job_id, tuple(steps), dict(policies))
        self.flow_gates[session_id] = gate
        return gate

    def configure_similarity_matcher(self, key: bytes, protected: tuple[str, ...],
                                     **kwargs) -> ShingleMatcher:
        """Match outbound identifiers against protected strings (shingle + LCS).

        Audit records carry keyed identifier hashes only, never the raw query or
        the protected string.
        """
        self.similarity = ShingleMatcher(key, tuple(protected), **kwargs)
        return self.similarity

    def attach_obligation_net(self, session_id: str, manifest: ObligationManifest) -> ObligationNet:
        """Gate a session's calls with a bounded Petri-net workflow manifest.

        The manifest is compiled (bounds plus the weighted non-minting rule)
        before it is attached. Once attached, every call must be an enabled
        transition: enough tokens in each input place, no place above 15, and
        for an outbound step, every resource cleanup place settled to zero.
        The marking advances only after all other reference validators pass.
        """
        net = ObligationNet(manifest)
        self.obligation_nets[session_id] = net
        return net

    def attach_fs_transducer(self, session_id: str, nodes: dict[str, FsNode],
                             generation: int = 0, root: str = "/ws") -> FsTransducer:
        """Carry (confidentiality, integrity) labels across a session's file effects.

        ``nodes`` is the same trusted broker model ``attach_workspace_snapshot``
        takes. Protected paths and inodes start PROTECTED; everything else starts
        PUBLIC / TRUSTED. Shell commands and workspace path arguments are checked
        by the workspace model first, then labels flow from read sources to write
        targets. An outbound call may not read a non-PUBLIC file and an execution
        sink may not read an UNTRUSTED one. Labels are committed only after every
        other reference validator passes. The broker publishes namespace changes
        with ``FsTransducer.rebase``.
        """
        transducer = FsTransducer(FsSnapshot(nodes, generation, root))
        self.fs_transducers[session_id] = transducer
        return transducer

    def pin_argument_policy(self, tool_name: str, policy: ArgumentPolicy) -> ArgumentPolicy:
        """Canonicalize ``tool_name``'s argument object under a pinned field policy.

        Unknown fields, duplicate keys, non-finite or oversized numbers, nested
        values beyond one array level and duplicate set elements are denied.
        An admitted call's allow result carries the canonical bytes, which are
        what a dispatcher forwards.
        """
        if type(policy) is not ArgumentPolicy:
            raise TypeError("policy must be a canonical_argument_confinement.Policy")
        if tool_name in self.command_tools:
            raise ValueError("tool is already pinned as a typed command")
        self.argument_policies[tool_name] = policy
        return policy

    def pin_command_tool(self, tool_name: str) -> None:
        """Treat ``tool_name``'s arguments as a typed file command.

        The arguments must be exactly {utility, operands, mode, script, append}.
        The command is compiled to a fixed argv with ``--`` before every
        positional; an operand starting with ``-`` is denied. The compiled
        effects also go through the workspace model and the label transducer
        when those are attached.
        """
        if tool_name in self.argument_policies:
            raise ValueError("tool is already pinned to an argument policy")
        self.command_tools.add(tool_name)

    def _confinement(self, sess: SessionState, step: int, tool_name: str,
                     args: dict) -> tuple[Optional[dict], Optional[tuple]]:
        """(denial, compiled argv). Both None when no confinement is pinned."""
        self._confined.pop(sess.session_id, None)
        policy = self.argument_policies.get(tool_name)
        if policy is not None:
            try:
                canonical = policy.canonicalize(encode_arguments(args))
            except ReferenceDenied as exc:
                return self._confinement_deny(sess, step, tool_name, args, "arguments", exc,
                                              policy.commitment), None
            self._confined[sess.session_id] = {
                "kind": "arguments", "policy": policy.commitment,
                "canonical_arguments": canonical.decode("utf-8")}
            return None, None
        if tool_name in self.command_tools:
            try:
                argv = confine(command_from_arguments(args))
            except ReferenceDenied as exc:
                return self._confinement_deny(sess, step, tool_name, args, "command", exc), None
            self._confined[sess.session_id] = {"kind": "command", "argv": list(argv)}
            return None, argv
        return None, None

    def _confinement_deny(self, sess: SessionState, step: int, tool_name: str, args: dict,
                          kind: str, exc: ReferenceDenied, policy: Optional[str] = None) -> dict:
        detail = {"reason": str(exc), "kind": kind}
        if policy is not None:
            detail["policy"] = policy
        return self._v12_deny(sess, step, tool_name, args, ARGUMENT_CONFINEMENT_DENIED,
                              {"confinement": detail})

    def _shell_effects(self, args: dict, argv: Optional[tuple]):
        """Effect union for a typed command's argv or a literal shell command, or None.

        A typed command never falls back to shell text: its ``script`` field is
        a sed expression, not a command line.
        """
        if argv is not None:
            return command_intents(list(argv))
        command = args.get("command") or args.get("cmd") or args.get("script")
        if isinstance(command, str) and command.strip():
            return analyze_shell(command)
        return None

    def _fs_label_plan(self, transducer: FsTransducer, tool_name: str, args: dict,
                       eclass: str, argv: Optional[tuple] = None) -> Optional[tuple]:
        """Typed adapter: (intents, cwd, is_egress, is_config_or_exec_sink), or None.

        A literal shell command is analyzed into its effect union. Its fixed
        command set (cat, tee, cp, mv, ln, chmod, sed, echo) never interprets
        file content, and its output returns to the agent, so it is neither an
        egress nor an execution sink; ``chmod`` targets are still checked as
        execution sinks inside the transducer. Any other call is applicable only
        when a resource argument names a path inside the workspace root: a write
        tool's paths are write targets, every other tool's paths are read
        sources, checked against the call's sink stage.
        """
        cwd = args.get("cwd") if isinstance(args.get("cwd"), str) else None
        effects = self._shell_effects(args, argv)
        if effects is not None:
            return effects, cwd, False, False
        root = transducer.state.base.root
        paths = tuple(dict.fromkeys(
            args[k] for k in _RESOURCE_ARGS
            if isinstance(args.get(k), str) and (args[k] == root or args[k].startswith(root + "/"))))
        if not paths:
            return None
        stage = self._sink_stage(tool_name, eclass, args)
        if eclass == EGRESS_WRITE and stage is None:
            return path_intents(writes=paths), cwd, False, False
        is_egress = stage == EXTERNAL_SINK or eclass in (EGRESS_SEND, EGRESS_CREDS)
        return path_intents(reads=paths), cwd, is_egress, stage == PRIVILEGED_EXEC

    def _flow_call(self, gate: ManifestGate, tool_name: str, args: dict) -> FlowCall:
        """Typed adapter: discover the step, its roles and the canonical digest."""
        try:
            args_digest = reference_json.digest("flow-args-v1", args)
        except ReferenceDenied:
            return FlowCall("", "", "", tool_name, "", (), "")
        pending = sorted(sid for sid, s in gate.steps.items() if s.method == tool_name
                         and gate.status(sid) == "NEW")
        if not pending:
            # A spent step is still addressable so that an identical request key
            # resolves to its prior receipt (idempotent replay) instead of a
            # silent new dispatch.
            pending = sorted(sid for sid, s in gate.steps.items() if s.method == tool_name)
        if not pending:
            return FlowCall("", "", "", tool_name, "", (), args_digest)
        step = gate.steps[pending[0]]
        resources = tuple((role, str(args[role])) for role, _ in step.resources
                          if isinstance(args.get(role), str))
        request_key = reference_json.digest("flow-request-v1",
                                            {"step": step.step_id, "args": args})
        return FlowCall(request_key, step.step_id, step.provider, tool_name, step.pin,
                        resources, args_digest)

    def _reference_middleware(self, sess: SessionState, step: int, tool_name: str, args: dict,
                              eclass: str) -> Optional[dict]:
        """Shell effects, manifest admission and outbound identifier matching.

        Returns a denial dict, or None when every applicable validator passed.
        A validator with no trusted state attached is not applicable and
        contributes nothing - the v11 / v12 gates above already ran.
        """
        denial, argv = self._confinement(sess, step, tool_name, args)
        if denial is not None:
            return denial

        snapshot = self.path_snapshots.get(sess.session_id)
        if snapshot is not None:
            try:
                effects = self._shell_effects(args, argv)
            except ReferenceDenied as exc:
                return self._v12_deny(sess, step, tool_name, args, WORKSPACE_EFFECT_DENIED,
                                      {"shell": {"reason": str(exc), "modeled": False,
                                                 "generation": snapshot.generation}})
        if snapshot is not None and effects is not None:
            cwd = args.get("cwd") if isinstance(args.get("cwd"), str) else None
            try:
                snapshot.check_all(effects, cwd)
            except ReferenceDenied as exc:
                return self._v12_deny(sess, step, tool_name, args, WORKSPACE_EFFECT_DENIED,
                                      {"shell": {"reason": str(exc), "modeled": True,
                                                 "effects": len(effects),
                                                 "generation": snapshot.generation}})

        transducer = self.fs_transducers.get(sess.session_id)
        labels: Optional[PendingLabels] = None
        if transducer is not None:
            if sess.tainted:
                transducer.observe_untrusted()
            try:
                plan = self._fs_label_plan(transducer, tool_name, args, eclass, argv)
                if plan is not None:
                    intents, cwd, is_egress, is_sink = plan
                    labels = transducer.check(intents, cwd, is_egress=is_egress,
                                              is_config_or_exec_sink=is_sink)
            except LabelDenied as exc:
                return self._fs_label_deny(sess, step, tool_name, args, transducer, exc)
            except ReferenceDenied as exc:
                # The workspace model itself refused the effect (Predicate W).
                return self._v12_deny(sess, step, tool_name, args, WORKSPACE_EFFECT_DENIED,
                                      {"shell": {"reason": str(exc), "modeled": True,
                                                 "generation": transducer.state.base.generation,
                                                 "via": "fs_transducer"}})

        gate = self.flow_gates.get(sess.session_id)
        if gate is not None:
            if sess.tainted:
                gate.ingest(FlowLabel.EXTERNAL)
            ticket = self._flow_call(gate, tool_name, args)
            try:
                receipt = gate.begin(ticket)
            except ReferenceDenied as exc:
                return self._v12_deny(sess, step, tool_name, args, FLOW_MANIFEST_DENIED,
                                      {"flow": {"reason": str(exc), "label": gate.label.name,
                                                "step": ticket.step_id or None}})
            # The lab gateway simulates the tool result, so the dispatch completes
            # here. A real dispatcher takes from the outbox and records the
            # downstream outcome (DONE / FAILED / UNKNOWN) instead. An idempotent
            # replay returns the prior receipt and is not completed again.
            if gate.status(receipt.call.step_id) == "QUEUED":
                gate.take()
                gate.complete(receipt, "DONE")

        net = self.obligation_nets.get(sess.session_id)
        transition = None
        if net is not None:
            sequence = net.sequence
            try:
                transition = net.resolve(tool_name)
                net.check(*transition)
            except ReferenceDenied as exc:
                return self._obligation_deny(sess, step, tool_name, args, net, exc)

        matcher = self.similarity
        if matcher is not None and eclass in (EGRESS_WRITE, EGRESS_SEND, EGRESS_CREDS):
            for _, text in iter_strings(args):
                if not isinstance(text, str) or not text:
                    continue
                try:
                    decision = matcher.check(text)
                except ReferenceDenied as exc:
                    return self._v12_deny(sess, step, tool_name, args, SIMILARITY_LEAK_DENIED,
                                          {"similarity": {"reason": str(exc), "blocked": True}})
                if decision.blocked:
                    return self._v12_deny(sess, step, tool_name, args, SIMILARITY_LEAK_DENIED,
                                          {"similarity": {"reason": decision.reason,
                                                          "identifier_hash": decision.identifier_hash,
                                                          "protected_hash": decision.protected_hash}})
        if labels is not None:
            # Labels only rise, so committing before the Petri-net fire can
            # overstate a file's label if that fire then fails, never understate it.
            try:
                transducer.commit(labels)
            except LabelDenied as exc:
                return self._fs_label_deny(sess, step, tool_name, args, transducer, exc)
        if net is not None and transition is not None:
            # Commit point: fenced on the sequence read before the other checks.
            try:
                net.fire(*transition, expected_sequence=sequence)
            except ReferenceDenied as exc:
                return self._obligation_deny(sess, step, tool_name, args, net, exc)
        return None

    def _obligation_deny(self, sess: SessionState, step: int, tool_name: str, args: dict,
                         net: ObligationNet, exc: ReferenceDenied) -> dict:
        return self._v12_deny(sess, step, tool_name, args, OBLIGATION_PROTOCOL_DENIED,
                              {"obligation": {"reason": str(exc), "marking": net.marking_hex,
                                              "sequence": net.sequence}})

    def _fs_label_deny(self, sess: SessionState, step: int, tool_name: str, args: dict,
                       transducer: FsTransducer, exc: LabelDenied) -> dict:
        # Reason codes and labels only: no path or file content in the finding.
        return self._v12_deny(sess, step, tool_name, args, FS_LABEL_FLOW_DENIED,
                              {"fs_label": {"reason": str(exc), "axis": exc.axis,
                                            "generation": transducer.generation,
                                            "session_integrity": transducer.session_integrity.name}})

    def _agent_node(self, sess: SessionState) -> str:
        """Collusion-graph node for one session of one registered agent."""
        rec = self.registry.get(sess.agent_key)
        return f"{rec.agent_id if rec else sess.agent_key[:12]}/{sess.session_id}"

    def _collusion_sync(self, sess: SessionState) -> None:
        node = self._agent_node(sess)
        if sess.sensitive_read:
            self.collusion.record_source(node, "sensitive")
        if sess.tainted:
            self.collusion.record_source(node, "untrusted")

    def _collusion_write(self, sess: SessionState, artifact: str):
        self._collusion_sync(sess)
        d = self.collusion.record_write(self._agent_node(sess), artifact)
        return None if d.allowed else d

    def _collusion_sink(self, sess: SessionState, sink: str):
        self._collusion_sync(sess)
        d = self.collusion.check_sink(self._agent_node(sess), sink)
        return None if d.allowed else d

    @staticmethod
    def _sink_stage(tool_name: str, eclass: str, args: dict) -> Optional[str]:
        if eclass == EGRESS_SPAWN or _EXEC_TOOL_RE.search(tool_name.casefold()):
            return PRIVILEGED_EXEC
        if eclass == EGRESS_SEND or places_params_on_external_boundary(tool_name, args):
            return EXTERNAL_SINK
        return None

    def _v12_deny(self, sess: SessionState, step: int, tool_name: str, args: dict, rule_code: str,
                  extra: dict) -> dict:
        atlas = _V12_ATLAS.get(rule_code, "")
        finding = {"kind": rule_code, "session_id": sess.session_id, "step": step, "tool": tool_name,
                   "atlas": atlas, "atlas_approximate": True,
                   **{k: v for d in extra.values() for k, v in d.items() if k not in ("allowed", "kind")}}
        self.findings.append(finding)
        self._alert(rule_code, finding)
        out = self._deny(sess, step, tool_name, args, rule_code.lower(), _V12_CODES[rule_code], atlas=atlas)
        out.update(extra)
        out["rule_code"] = rule_code
        return out

    def register_tool_schemas(
        self, agent_key: str, session_id: str, server_name: str, tools: list[dict],
        manifest: Optional[dict] = None,
    ) -> list[dict]:
        """Pin tool schema digests for ``server_name`` (approximate AML.T0051).

        Returns one verdict dict per tool. Drift and cross-server name
        collisions are recorded as findings and decision-log entries.
        """
        verdicts = [v.as_dict() for v in self.schema_guard.register_listing(server_name, tools, manifest)]
        for tool in tools:
            hit = scan_definition(tool) if isinstance(tool, dict) and tool.get("name") else None
            if hit is not None:
                name = str(tool["name"])
                self.poisoned_tools[(server_name, name)] = hit
                verdicts.append({"ok": False, "code": POISONING, "tool": name, "server_id": server_name,
                                 "marker": hit["marker"], "field": hit["field"]})
        for cv in self.capability.register_listing(server_name, tools, session_id=session_id):
            if not cv.ok:
                verdicts.append({"ok": False, "code": cv.code, "tool": cv.tool, "server_id": server_name,
                                 "detail": cv.detail, "first_seen": cv.first_seen})
        # Reference pin registry: sticky descriptor pins, alias ambiguity, metadata lint.
        for verdict in self.pin_tool_descriptors(server_name, tools):
            kind = verdict["code"]
            finding = {"kind": kind, "session_id": session_id, "server": server_name,
                       "tool": verdict.get("tool"), "atlas": _V12_ATLAS.get(kind, ""),
                       "atlas_approximate": True,
                       **{k: v for k, v in verdict.items() if k not in ("ok", "code")}}
            self.findings.append(finding)
            self.pin_findings.append(finding)
            self._alert(kind, finding)
        for v in verdicts:
            if v["ok"]:
                continue
            kind = v["code"] if v["code"] in _V12_CODES else v["code"].lower()
            finding = {"kind": kind, "session_id": session_id, "server": server_name, "tool": v.get("tool"),
                       **{k: val for k, val in v.items() if k not in ("ok", "tool")}}
            self.findings.append(finding)
            self._alert(kind, finding)
        return verdicts

    def check_schema_call(
        self, agent_key: str, session_id: str, server_name: str, tool_name: str, arguments: Optional[dict] = None,
    ) -> Optional[dict]:
        """Deny a call to a tool whose pinned schema drifted, whose capability profile refused it, or whose definition is poisoned, or return None."""
        cap = self.capability.check_call(server_name, tool_name)
        if not cap.ok and self.registry.get(agent_key):
            sess = self.get_session(session_id, agent_key)
            sess.step_index += 1
            out = self._v12_deny(sess, sess.step_index, tool_name, dict(arguments or {}), cap.code,
                                 {"mcp": cap.as_dict()})
            return self._attach_capability(session_id, out)
        if (server_name, tool_name) in self.pin_enrolled and self.pin_state(server_name, tool_name) == "REVOKED":
            if self.registry.get(agent_key):
                sess = self.get_session(session_id, agent_key)
                sess.step_index += 1
                out = self._v12_deny(sess, sess.step_index, tool_name, dict(arguments or {}),
                                     REGISTRY_PIN_DRIFT,
                                     {"pin": {"server_id": server_name, "state": "REVOKED"}})
                return self._attach_capability(session_id, out)
        poison = self.poisoned_tools.get((server_name, tool_name))
        if poison is not None and self.registry.get(agent_key):
            sess = self.get_session(session_id, agent_key)
            sess.step_index += 1
            out = self._v12_deny(sess, sess.step_index, tool_name, dict(arguments or {}), POISONING,
                                 {"mcp": {"server_id": server_name, **poison}})
            return self._attach_capability(session_id, out)
        verdict = self.schema_guard.check_call(server_name, tool_name)
        if verdict.ok or not self.registry.get(agent_key):
            return None
        sess = self.get_session(session_id, agent_key)
        sess.step_index += 1
        out = self._deny(sess, sess.step_index, tool_name, dict(arguments or {}), "schema_drift_denied", -32041,
                         atlas="AML.T0051")
        out["schema"] = verdict.as_dict()
        return self._attach_capability(session_id, out)

    def evaluate_sampling(
        self, agent_key: str, session_id: str, params: Optional[dict] = None,
        capability_token: Optional[str] = None,
    ) -> dict:
        out = self._evaluate_sampling(agent_key, session_id, params, capability_token)
        return self._attach_capability(session_id, out)

    def _evaluate_sampling(
        self, agent_key: str, session_id: str, params: Optional[dict], capability_token: Optional[str],
    ) -> dict:
        """Server-initiated sampling/createMessage: needs a clean session and a root-keyed grant."""
        self.registry.lift_expired(self.now())
        if not self.registry.get(agent_key):
            return {"ok": False, "error": "unregistered_agent", "code": -32001}
        if self.registry.is_frozen_key(agent_key, self.now()):
            return {"ok": False, "error": "agent_frozen", "code": -32002}
        sess = self.get_session(session_id, agent_key)
        tool = "sampling/createMessage"
        summary = {"max_tokens": (params or {}).get("maxTokens"),
                   "n_messages": len((params or {}).get("messages") or [])}
        rejected = self._adopt_presented_capability(sess, capability_token, agent_key)
        sess.step_index += 1
        step = sess.step_index
        if rejected:
            return self._deny(sess, step, tool, summary, rejected, -32040, atlas="AML.M0030")
        if sess.tainted or not sess.allow_egress or sess.review_hold:
            return self._deny(sess, step, tool, summary, "sampling_rejected_while_tainted", -32060,
                              atlas="AML.T0051")
        mac = capability.verify(sess.capability_token) if sess.capability_token else None
        if mac is None or not capability.allows_sampling(mac):
            return self._deny(sess, step, tool, summary, "sampling_not_granted", -32061, atlas="AML.M0030")
        sess.history.append({"step": step, "tool": tool, "ok": True})
        return {"ok": True, "allowed": True, "tool": tool, "step_index": step, "tainted": False}

    def _try_oob(self, sess: SessionState, step: int, tool_name: str, args: dict, token: Optional[str]) -> bool:
        if not token:
            return False
        ok = approve.verify_and_consume(
            sess.session_id, step, tool_name, args, token,
            taint_source_id=sess.taint_source_id or "",
            now=self.now(),
        )
        if not ok:
            ok = consume_approve_once(
                token,
                session_id=sess.session_id,
                step_index=step,
                tool_name=tool_name,
                arguments=args,
                taint_source_id=sess.taint_source_id or "",
                now=self.now(),
            )
        if ok:
            self._alert("oob_consumed", {"session_id": sess.session_id, "step": step, "tool": tool_name})
        return ok

    def _emit_approval_webhook(self, sess: SessionState, step: int, tool_name: str, args: dict, atlas: str) -> dict:
        """Format a held call for a human. HTTP only when webhook_deliver is set."""
        rec = self.registry.get(sess.agent_key)
        payload = build_approval_payload(
            principal_key=(rec.principal_key if rec else sess.root_parent_key or ""),
            agent_id=(rec.agent_id if rec else ""),
            agent_key=sess.agent_key,
            session_id=sess.session_id,
            capability_token=sess.capability_token,
            allow_egress=bool(sess.allow_egress),
            taint_source_id=sess.taint_source_id or "",
            taint_reasons=list(sess.taint_reasons),
            gate_atlas=atlas,
            tool_name=tool_name,
            arguments=args,
            step_index=step,
            now=self.now(),
            freeze_seconds=self.cfg.freeze_seconds,
        )
        if self.cfg.webhook_deliver and self.cfg.webhook_url:
            sender = self.cfg.webhook_sender or deliver_webhook
            try:
                outgoing = dict(payload)
                outgoing["delivered"] = True
                sender(self.cfg.webhook_url, outgoing)
            except Exception as exc:  # noqa: BLE001 - delivery must not change the policy decision
                log.warning("approval webhook deliver failed: %s", type(exc).__name__)
            else:
                payload["delivered"] = True
        self.chain.append({"ts": self.now(), "kind": "approval_webhook", "payload": _log_safe(payload)})
        return payload

    def _deny(self, sess: SessionState, step: int, tool_name: str, args: dict, error: str, code: int,
              atlas: str = "") -> dict:
        sess.history.append({"step": step, "tool": tool_name, "ok": False, "error": error})
        self._alert("policy_deny", {"session_id": sess.session_id, "step": step, "tool": tool_name,
                                    "error": error, "atlas": atlas, "args": scrub_obj(args)})
        out = {
            "ok": False, "allowed": False, "error": error, "code": code,
            "tool": tool_name, "step_index": step, "tainted": sess.tainted,
            "sensitive_read": sess.sensitive_read, "atlas": atlas,
            "scrubbed_args": scrub_obj(args),
            "message": f"policy gate denied {tool_name}: {error}",
        }
        if error in _AWAITING_APPROVAL and (sess.tainted or not sess.allow_egress):
            out["approval_webhook"] = self._emit_approval_webhook(sess, step, tool_name, args, atlas)
        return out

    def _allow(self, sess: SessionState, step: int, tool_name: str, args: dict, eclass: str,
               constrained: bool = False, delegation: Optional[dict] = None) -> dict:
        sess.history.append({"step": step, "tool": tool_name, "ok": True, "constrained": constrained})
        if eclass in (EGRESS_INTERNAL_READ, EGRESS_EXTERNAL_READ) and (uri := _resource_uri(tool_name, args)):
            self.collusion.record_read(self._agent_node(sess), artifact_id("file", uri))
        # Simulated tool results for lab (no real egress)
        result: dict[str, Any] = {"echo": True, "tool": tool_name}
        if tool_name in ("read_internal_secrets", "credentials.get", "secrets.get"):
            result["secret"] = "secret_value_123"
            sess.mark_sensitive()
            self.deob.register(result["secret"], label=tool_name, session_id=sess.session_id)
            self.accumulator.register_protected_token(result["secret"], session_id=sess.session_id)
            self.stego.register_secret(result["secret"], label=tool_name, session_id=sess.session_id)
            # Forensic watermark + credential tracking on the returned secret (approximate AML.T0086).
            result["secret"] = self.canary.watermark_output(sess.session_id, step, tool_name, result["secret"])
        if tool_name in ("read_external_url", "web.fetch", "fetch_url"):
            result["body"] = "untrusted content from lab fixture"
        if tool_name in self.cfg.lab_fixture_outputs:
            result["body"] = self.cfg.lab_fixture_outputs[tool_name]
            if tool_name in SENSITIVE_READ_TOOLS or eclass == EGRESS_CREDS:
                result["body"] = self.canary.watermark_output(sess.session_id, step, tool_name, result["body"])
        if eclass == EGRESS_WRITE:
            uri = _resource_uri(tool_name, args)
            if uri is not None:
                self._provenance_write(sess, uri)
        if tool_name == "lookup_order_status":
            result["order_id"] = args.get("order_id", 123)
            result["status"] = "shipped"
        output_findings: list[dict] = []
        if tool_name in UNTRUSTED_INGEST_TOOLS or eclass == EGRESS_EXTERNAL_READ:
            scanned = self.scan_tool_output(sess.agent_key, sess.session_id, tool_name, result)
            output_findings, result = scanned["findings"], scanned["result"]
        out = {
            "ok": True, "allowed": True, "tool": tool_name, "egress_class": eclass,
            "step_index": step, "tainted": sess.tainted, "sensitive_read": sess.sensitive_read,
            "constrained_sink": constrained, "result": result, "scrubbed_args": scrub_obj(args),
        }
        if output_findings:
            out["output_findings"] = output_findings
        if delegation is not None:
            out["delegation"] = delegation
        confined = self._confined.pop(sess.session_id, None)
        if confined is not None:
            out["confinement"] = confined
        return out


def create_app(cfg: Optional[PepConfig] = None, engine: Optional[PolicyEngine] = None) -> Flask:
    cfg = cfg or PepConfig()
    registry = Registry.load(cfg.registry_path)
    cfg.freeze_seconds = registry.freeze_seconds
    cfg.max_children_per_parent = registry.max_children_per_parent
    eng = engine or PolicyEngine(registry, cfg=cfg)

    app = Flask("agent_gateway")
    app.config["POLICY_ENGINE"] = eng
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_body_bytes

    def _limit_error(code: int, reason: str):
        return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": reason}}), code

    def _check_limits(session_id: str, arguments: Any):
        """Return an error response when a request exceeds a configured limit, else None."""
        if len(session_id) > cfg.max_id_len:
            return _limit_error(400, "session_id too long")
        if session_id not in eng.sessions and len(eng.sessions) >= cfg.max_sessions:
            return _limit_error(429, "session limit reached")
        if arguments is not None and len(json.dumps(arguments, default=str)) > cfg.max_arg_bytes:
            return _limit_error(413, "arguments too large")
        return None

    @app.errorhandler(413)
    def _too_large(_exc):
        return _limit_error(413, "request body too large")

    @app.before_request
    def _loopback_only():
        if cfg.allow_nonlocal:
            return None
        # Reject non-loopback Host / remote
        ra = request.remote_addr or ""
        if ra not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "loopback_only", "message": "PEP binds to 127.0.0.1; pass --allow-nonlocal only in isolated lab"}), 403
        return None

    @app.get("/health")
    def health():
        eng.registry.lift_expired(eng.now())
        return jsonify({"ok": True, "service": "agent-gateway", "bind": "loopback", "version": "0.3.0"})

    def _agent_key_from_request(body: dict) -> str:
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        params = body.get("params") or {}
        return str(params.get("agent_key") or body.get("agent_key") or "")

    @app.post("/mcp")
    def mcp_rpc():
        try:
            body = request.get_json(force=True, silent=False)
        except RequestEntityTooLarge:
            raise
        except Exception:
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), 400
        if not isinstance(body, dict):
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}), 400
        rid = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}
        agent_key = _agent_key_from_request(body)
        session_id = str(params.get("session_id") or request.headers.get("X-Session-Id") or "sess-default")

        bad = _check_limits(session_id, params.get("arguments") if method == "tools/call" else None)
        if bad is not None:
            return bad

        cap_tok = params.get("capability_token") or request.headers.get("X-Capability-Token") or None
        if method == "tools/list":
            out = eng.evaluate_tools_list(
                agent_key, session_id,
                server_name=str(params.get("server") or params.get("server_name") or ""),
                descriptions=list(params.get("tools") or params.get("descriptions") or []),
                capability_token=str(cap_tok) if cap_tok else None,
            )
            if not out.get("ok"):
                return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": out.get("code", -32000), "message": out.get("error")}})
            return jsonify({"jsonrpc": "2.0", "id": rid, "result": out})

        if method == "tools/call":
            name = str(params.get("name") or params.get("tool") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            token = params.get("approval_token") or request.headers.get("X-Approval-Token")
            depth = int(params.get("delegation_depth") or 0)
            parent = params.get("parent_key")
            bound = params.get("bound_step_index")
            out = eng.evaluate_call(
                agent_key, session_id, name, arguments,
                approval_token=token, delegation_depth=depth, parent_key=parent,
                bound_step_index=int(bound) if bound is not None else None,
                capability_token=str(cap_tok) if cap_tok else None,
            )
            if not out.get("ok"):
                return jsonify({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": out.get("code", -32000), "message": out.get("message") or out.get("error"),
                    "data": {k: out[k] for k in (
                        "error", "tainted", "sensitive_read", "atlas", "step_index",
                        "allow_egress", "capability_token",
                    ) if k in out},
                }})
            return jsonify({"jsonrpc": "2.0", "id": rid, "result": out})

        return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}})

    # Convenience non-JSON-RPC helpers for unit tests
    @app.post("/v1/call")
    def v1_call():
        body = request.get_json(force=True, silent=True) or {}
        agent_key = _agent_key_from_request(body) or str(body.get("agent_key") or "")
        bound = body.get("bound_step_index")
        cap_tok = body.get("capability_token") or request.headers.get("X-Capability-Token") or None
        bad = _check_limits(str(body.get("session_id") or "sess"), body.get("arguments"))
        if bad is not None:
            return bad
        out = eng.evaluate_call(
            agent_key,
            str(body.get("session_id") or "sess"),
            str(body.get("tool") or body.get("name") or ""),
            body.get("arguments") if isinstance(body.get("arguments"), dict) else {},
            approval_token=body.get("approval_token"),
            delegation_depth=int(body.get("delegation_depth") or 0),
            parent_key=body.get("parent_key"),
            bound_step_index=int(bound) if bound is not None else None,
            capability_token=str(cap_tok) if cap_tok else None,
        )
        return jsonify(out), (200 if out.get("ok") else 403)

    return app


def run_server(cfg: PepConfig) -> None:
    if not cfg.allow_nonlocal and cfg.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Refusing non-loopback bind without --allow-nonlocal")
    app = create_app(cfg)
    app.run(host=cfg.host, port=cfg.port, threaded=True)
