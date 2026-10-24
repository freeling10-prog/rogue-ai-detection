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
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request

from . import approve, capability
from .approval_webhook import build_approval_payload, consume_approve_once, deliver_webhook
from .audit_chain import ChainWriter
from .deobfuscate import DeobfuscationGuard
from .egress_uri_guard import DEFAULT_LAB_ALLOW, inspect_arguments
from .side_channel_guard import SideChannelGuard, SideChannelPolicy
from . import tool_output_scanner, toxic_combinations
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
        self.inventories: dict[str, dict[str, dict]] = {}
        self.toxic: dict[str, dict] = {}
        self.findings: list[dict] = []
        self._clock = time.time

    def now(self) -> float:
        return self._clock()

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
    ) -> dict:
        out = self._evaluate_call(
            agent_key, session_id, tool_name, arguments,
            approval_token=approval_token, delegation_depth=delegation_depth,
            parent_key=parent_key, bound_step_index=bound_step_index,
            capability_token=capability_token,
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
            # reserve slot
            self.shared.children_by_parent[root] = n + 1
            sess.children_spawned += 1
            child_key = str(args.get("child_api_key") or "")
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
            entry = ScratchpadEntry(
                note_id=note_id, body=body, taint_inherited=bool(sess.tainted),
                source_session=session_id, created_at=self.now(),
            )
            self.shared.scratchpad[note_id] = entry
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
                                 approved=oob_memo.get("ok", False))

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

        return self._release(sess, step, tool_name, args, eclass, approved=oob_memo.get("ok", False))

    def _release(self, sess: SessionState, step: int, tool_name: str, args: dict, eclass: str,
                 constrained: bool = False, approved: bool = False) -> dict:
        """Last gate before an allowed call leaves: cross-step / encoded exfil (approximate AML.T0086).

        Arguments are appended to the session window only when the call is
        released, so the window holds what actually left the gateway.
        """
        outbound = eclass != EGRESS_INTERNAL_READ
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
        return self._allow(sess, step, tool_name, args, eclass, constrained=constrained)

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
        return self.deob.register(value, label=label, session_id=session_id)

    def ingest_tool_result(self, agent_key: str, session_id: str, tool_name: str, result: Any) -> int:
        """Fingerprint data returned by a sensitive read. Returns secrets registered."""
        if tool_name not in SENSITIVE_READ_TOOLS and egress_class(tool_name) != EGRESS_CREDS:
            return 0
        sess = self.get_session(session_id, agent_key)
        sess.mark_sensitive()
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
               constrained: bool = False) -> dict:
        sess.history.append({"step": step, "tool": tool_name, "ok": True, "constrained": constrained})
        # Simulated tool results for lab (no real egress)
        result: dict[str, Any] = {"echo": True, "tool": tool_name}
        if tool_name in ("read_internal_secrets", "credentials.get", "secrets.get"):
            result["secret"] = "secret_value_123"
            sess.mark_sensitive()
            self.deob.register(result["secret"], label=tool_name, session_id=sess.session_id)
        if tool_name in ("read_external_url", "web.fetch", "fetch_url"):
            result["body"] = "untrusted content from lab fixture"
        if tool_name in self.cfg.lab_fixture_outputs:
            result["body"] = self.cfg.lab_fixture_outputs[tool_name]
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
        return out


def create_app(cfg: Optional[PepConfig] = None, engine: Optional[PolicyEngine] = None) -> Flask:
    cfg = cfg or PepConfig()
    registry = Registry.load(cfg.registry_path)
    cfg.freeze_seconds = registry.freeze_seconds
    cfg.max_children_per_parent = registry.max_children_per_parent
    eng = engine or PolicyEngine(registry, cfg=cfg)

    app = Flask("agent_gateway")
    app.config["POLICY_ENGINE"] = eng

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
        except Exception:
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), 400
        if not isinstance(body, dict):
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}), 400
        rid = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}
        agent_key = _agent_key_from_request(body)
        session_id = str(params.get("session_id") or request.headers.get("X-Session-Id") or "sess-default")

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
