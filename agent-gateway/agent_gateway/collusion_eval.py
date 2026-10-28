"""Sprint evaluation: defence test-suite aggregator, benign latency timer, report renderer.

``python -m agent_gateway evaluate-collusion --report <out_dir>`` does three
things and writes ``collusion_benchmark_results.json``,
``collusion_sprint_report.md``, and ``collusion_sprint_report.pdf``:

1. Runs the existing defence test files with pytest (``--junitxml``) and
   tabulates pass / fail per group, keyed by test node id, so every figure
   traces to a test a reviewer can open:

   - Group A, side-channel and timing guard: ``test_side_channel_guard.py``
   - Group B, delegation and confused-deputy guard: ``test_delegation_guard.py``
   - Group C, de-obfuscation and canary provenance: ``test_deobfuscate.py``,
     ``test_canary_watermark.py``

   This module generates no attack traffic of its own.

2. Times ``PolicyEngine.evaluate_call`` on benign workflow steps (thread CPU
   time and wall time, p50 / p95 / p99 in milliseconds) against a 2 ms
   reference. Benign denials are counted, not hidden.

3. Writes each benign decision to a hash-chained log (``audit_chain.py``),
   verifies it, and checks that a one-line edit of a copy is detected.

The scenarios are same-author scripted lab workflows. They are not a
benchmark and are not pooled with the real-model loopback archive (2 of 13).
No socket is opened. The PDF uses the pure-Python writer in ``audit_report``.
"""
from __future__ import annotations

import ast
import json
import math
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

SCHEMA = "agent-gateway.collusion-eval/1"
RESULTS_NAME = "collusion_benchmark_results.json"
REPORT_MD_NAME = "collusion_sprint_report.md"
REPORT_PDF_NAME = "collusion_sprint_report.pdf"
SLIDES_PDF_NAME = "collusion_sprint_slides.pdf"
CARD_PNG_NAME = "collusion_project_image.png"
LATENCY_TARGET_MS = 2.0
ARCHIVE_BASELINE = "2 of 13"

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = PACKAGE_ROOT / "tests"

DEFENSE_GROUPS: dict[str, dict[str, Any]] = {
    "A": {
        "title": "Side-channel and timing guard",
        "module": "side_channel_guard.py",
        "files": ["test_side_channel_guard.py"],
    },
    "B": {
        "title": "Multi-agent delegation and confused-deputy guard",
        "module": "delegation_guard.py",
        "files": ["test_delegation_guard.py"],
    },
    "C": {
        "title": "De-obfuscation and canary provenance guard",
        "module": "deobfuscate.py, canary_watermark.py",
        "files": ["test_deobfuscate.py", "test_canary_watermark.py"],
    },
}

# Post-sprint guards, reported apart from A / B / C. ``evaluate`` never folds this group into the
# 57/57 sprint figure; run it with ``run_post_sprint_suite``. Files not yet in the tree are listed
# under ``missing_files`` instead of failing.
POST_SPRINT_GROUPS: dict[str, dict[str, Any]] = {
    "D": {
        "title": "v11 extended carrier & runtime guards (post-sprint)",
        "module": "schema_integrity_guard.py, gui_action_guard.py, memory_provenance_guard.py, "
                  "temporal_accumulator_guard.py",
        "files": ["test_schema_integrity_guard.py", "test_gui_action_guard.py", "test_v11_guard_wiring.py",
                  "test_memory_provenance_guard.py", "test_temporal_accumulator_guard.py"],
    },
}

SCOPE_NOTES = (
    "Same-author scripted synthetic lab scenarios. Not a benchmark and not a measure of any product in the wild.",
    "Group results are the outcome of the repository's own defence tests; each count traces to a named pytest node id.",
    f"The real-model loopback archive figure ({ARCHIVE_BASELINE} non-control runs) is a separate measurement "
    "and is never pooled with these results.",
    "Latency is measured CPU time per in-process evaluate_call decision on one machine. The 2 ms figure is a "
    "reference target, not a guarantee.",
    "The gateway binds 127.0.0.1 by default. Freeze actions apply for 15 minutes to registered lab keys only.",
    "ATLAS technique labels are approximate.",
    "A passing audit-chain verify means the log is internally consistent. It is not a certification and not a "
    "penetration test.",
)


# --- 1. Defence test-suite aggregation -----------------------------------------

@dataclass
class TestCaseResult:
    nodeid: str
    outcome: str  # passed | failed | error | skipped
    seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {"nodeid": self.nodeid, "outcome": self.outcome, "seconds": round(self.seconds, 4)}


@dataclass
class GroupResult:
    group: str
    title: str
    module: str
    files: list[str]
    cases: list[TestCaseResult] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {"total": len(self.cases), "passed": 0, "failed": 0, "error": 0, "skipped": 0}
        for c in self.cases:
            out[c.outcome] = out.get(c.outcome, 0) + 1
        return out

    @property
    def ok(self) -> bool:
        c = self.counts()
        return c["total"] > 0 and c["failed"] == 0 and c["error"] == 0

    def as_dict(self) -> dict[str, Any]:
        return {"group": self.group, "title": self.title, "module": self.module, "files": self.files,
                "counts": self.counts(), "all_passed": self.ok, "tests": [c.as_dict() for c in self.cases]}


def _nodeid(case: ET.Element) -> str:
    """``tests/test_x.py::Class::name`` from a junit ``testcase`` element."""
    classname = case.get("classname") or ""
    name = case.get("name") or ""
    parts = classname.split(".")
    # classname is "tests.test_x" or "tests.test_x.TestClass"
    mod_idx = next((i for i, p in enumerate(parts) if p.startswith("test_")), len(parts) - 1)
    path = "/".join(parts[: mod_idx + 1]) + ".py"
    rest = parts[mod_idx + 1:]
    return "::".join([path, *rest, name])


def parse_junit(xml_path: Path) -> list[TestCaseResult]:
    root = ET.parse(xml_path).getroot()
    out: list[TestCaseResult] = []
    for case in root.iter("testcase"):
        outcome = "passed"
        if case.find("failure") is not None:
            outcome = "failed"
        elif case.find("error") is not None:
            outcome = "error"
        elif case.find("skipped") is not None:
            outcome = "skipped"
        out.append(TestCaseResult(_nodeid(case), outcome, float(case.get("time") or 0.0)))
    return out


def _file_of(nodeid: str) -> str:
    return nodeid.split("::", 1)[0].rsplit("/", 1)[-1]


def group_results(cases: list[TestCaseResult], groups: Optional[dict[str, dict]] = None) -> list[GroupResult]:
    groups = groups or DEFENSE_GROUPS
    out = []
    for gid, spec in groups.items():
        files = list(spec["files"])
        g = GroupResult(gid, spec["title"], spec.get("module", ""), files)
        g.cases = [c for c in cases if _file_of(c.nodeid) in files]
        out.append(g)
    return out


def run_defense_suite(
    groups: Optional[dict[str, dict]] = None, tests_dir: Optional[Path] = None, timeout_s: float = 600.0,
) -> dict[str, Any]:
    """Run the group test files in a pytest subprocess and tabulate per group."""
    groups = groups or DEFENSE_GROUPS
    tests_dir = Path(tests_dir or TESTS_DIR)
    files = [str(tests_dir / f) for spec in groups.values() for f in spec["files"]]
    missing = [f for f in files if not Path(f).is_file()]
    if len(missing) == len(files):
        # No paths at all would make pytest fall back to the whole suite.
        results = group_results([], groups)
        return {"command": "", "returncode": 5, "seconds": 0.0, "pytest_summary": "no group files present",
                "missing_files": [Path(f).name for f in missing], "groups": [g.as_dict() for g in results],
                "totals": _suite_totals(results)}
    with tempfile.TemporaryDirectory(prefix="agw-collusion-") as tmp:
        xml_path = Path(tmp) / "junit.xml"
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
               f"--junitxml={xml_path}", *[f for f in files if f not in missing]]
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, cwd=str(tests_dir.parent), capture_output=True, text=True, timeout=timeout_s)
        elapsed = time.perf_counter() - t0
        cases = parse_junit(xml_path) if xml_path.is_file() else []
    results = group_results(cases, groups)
    tail = (proc.stdout or "").strip().splitlines()[-1:] or [""]
    return {
        "command": "python -m pytest -q " + " ".join(f"tests/{Path(f).name}" for f in files),
        "returncode": proc.returncode,
        "seconds": round(elapsed, 3),
        "pytest_summary": tail[0],
        "missing_files": [Path(f).name for f in missing],
        "groups": [g.as_dict() for g in results],
        "totals": _suite_totals(results),
    }


def run_post_sprint_suite(tests_dir: Optional[Path] = None, timeout_s: float = 600.0) -> dict[str, Any]:
    """Group D only. Separate from ``run_defense_suite`` so the sprint A / B / C totals never move."""
    return run_defense_suite(groups=POST_SPRINT_GROUPS, tests_dir=tests_dir, timeout_s=timeout_s)


def _suite_totals(results: list[GroupResult]) -> dict[str, int]:
    tot = {"total": 0, "passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for g in results:
        for k, v in g.counts().items():
            tot[k] = tot.get(k, 0) + v
    return tot


def collect_gateway_tests(tests_dir: Optional[Path] = None, timeout_s: float = 300.0) -> dict[str, Any]:
    """``pytest --collect-only`` over the whole gateway suite (count only, nothing runs)."""
    tests_dir = Path(tests_dir or TESTS_DIR)
    proc = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
                           str(tests_dir)], cwd=str(tests_dir.parent), capture_output=True, text=True,
                          timeout=timeout_s)
    ids = [ln for ln in (proc.stdout or "").splitlines() if "::" in ln]
    return {"command": "python -m pytest --collect-only -q", "collected": len(ids),
            "files": len({i.split("::", 1)[0] for i in ids}), "returncode": proc.returncode}


def _stateful_kwargs(node: ast.AST) -> Optional[tuple[int, int]]:
    if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "settings"):
        return None
    kw = {k.arg: k.value for k in node.keywords if isinstance(k.value, ast.Constant)}
    if "max_examples" in kw and "stateful_step_count" in kw:
        return int(kw["max_examples"].value), int(kw["stateful_step_count"].value)
    return None


def scan_hypothesis_settings(tests_dir: Optional[Path] = None) -> list[dict[str, Any]]:
    """Stateful Hypothesis settings per state machine, read from the test files with ``ast``."""
    tests_dir = Path(tests_dir or TESTS_DIR)
    out = []
    for path in sorted(tests_dir.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        named: dict[str, tuple[int, int]] = {}  # PEP_SETTINGS = settings(...)
        alias: dict[str, str] = {}  # TestX = Machine.TestCase
        found: dict[str, tuple[int, int]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                tgt, val = node.targets[0], node.value
                vals = _stateful_kwargs(val)
                if isinstance(tgt, ast.Name) and vals:
                    named[tgt.id] = vals
                elif isinstance(tgt, ast.Name) and isinstance(val, ast.Attribute) and val.attr == "TestCase" \
                        and isinstance(val.value, ast.Name):
                    alias[tgt.id] = val.value.id
                elif isinstance(tgt, ast.Attribute) and tgt.attr == "settings" and vals \
                        and isinstance(tgt.value, ast.Name):
                    found[tgt.value.id] = vals
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "run_state_machine_as_test" \
                    and node.args and isinstance(node.args[0], ast.Name):
                for k in node.keywords:
                    if k.arg != "settings":
                        continue
                    vals = _stateful_kwargs(k.value)
                    if vals is None and isinstance(k.value, ast.Name):
                        vals = named.get(k.value.id)
                    if vals:
                        found[node.args[0].id] = vals
        for name, (ex, steps) in found.items():
            out.append({"file": path.name, "machine": alias.get(name, name),
                        "max_examples": ex, "stateful_step_count": steps})
    return out


# --- 2. Benign decision latency ----------------------------------------------------

# Benign workflow steps: (agent role, session suffix, tool, arguments).
# Roles map to registered lab keys. Nothing here reads a secret or tries to leave.
BENIGN_WORKFLOWS: dict[str, list[tuple[str, str, str, dict]]] = {
    "order_status_triage": [
        ("a", "triage", "lookup_order_status", {"order_id": 101}),
        ("a", "triage", "update_ticket_status", {"order_id": 101, "status": "shipped"}),
        ("a", "triage", "lookup_order_status", {"order_id": 102}),
        ("a", "triage", "update_ticket_status", {"order_id": 102, "status": "processing"}),
    ],
    "status_report": [
        ("b", "report", "lookup_order_status", {"order_id": 7}),
        ("b", "report", "send_email", {"to": "team@internal.local", "body": "Daily status: all orders on track."}),
    ],
    "clean_delegation": [
        ("a", "orchestrator", "delegate_task", {"to_agent_key": "@b", "to_session_id": "@worker"}),
        ("b", "worker", "lookup_order_status", {"order_id": 55}),
        ("b", "worker", "send_email", {"to": "team@internal.local", "body": "Order 55 checked, no action needed."}),
    ],
    "scratchpad_handoff": [
        ("a", "notes", "save_session_note", {"note_id": "@note", "text": "Customer prefers email follow-up."}),
        ("b", "notes-reader", "read_session_note", {"note_id": "@note"}),
        ("b", "notes-reader", "send_email", {"to": "team@internal.local", "body": "Follow-up scheduled by email."}),
    ],
    "loopback_docs_fetch": [
        ("b", "docs", "read_external_url", {"url": "http://127.0.0.1/docs/runbook"}),
        ("b", "docs", "lookup_order_status", {"order_id": 9}),
        ("b", "docs", "update_ticket_status", {"order_id": 9, "status": "delivered"}),
    ],
}


def _percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100)."""
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil(q / 100.0 * len(s)) - 1))
    return s[k]


def _latency_summary(samples_ms: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(_percentile(samples_ms, 50), 4),
        "p95_ms": round(_percentile(samples_ms, 95), 4),
        "p99_ms": round(_percentile(samples_ms, 99), 4),
        "mean_ms": round(statistics.fmean(samples_ms), 4) if samples_ms else 0.0,
        "max_ms": round(max(samples_ms), 4) if samples_ms else 0.0,
    }


def _resolve(value: Any, run: int, keys: dict[str, str]) -> Any:
    if isinstance(value, str) and value.startswith("@"):
        name = value[1:]
        return keys.get(name, f"{name}-{run}")
    if isinstance(value, dict):
        return {k: _resolve(v, run, keys) for k, v in value.items()}
    return value


def run_benign_latency(iterations: int = 50, work_dir: Optional[Path] = None) -> dict[str, Any]:
    """Time evaluate_call on the benign workflows; record each decision in a hash-chained log."""
    from .audit_chain import ChainWriter
    from .paths import default_registry_path
    from .pep import PepConfig, PolicyEngine
    from .registry import Registry
    from .taint import SharedState

    work = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="agw-collusion-lat-"))
    work.mkdir(parents=True, exist_ok=True)
    reg_path = default_registry_path()
    registry = Registry.load(reg_path)
    agent_keys = [k for k, r in registry.agents.items() if not r.root_parent_key]
    if len(agent_keys) < 2:
        raise RuntimeError("benign latency needs two registered root lab keys")
    roles = {"a": agent_keys[0], "b": agent_keys[1]}

    decision_log = work / "benign-decision-log.jsonl"
    if decision_log.exists():
        decision_log.unlink()
    chain = ChainWriter(decision_log)

    cpu_ms: list[float] = []
    wall_ms: list[float] = []
    per_wf: dict[str, dict[str, Any]] = {}
    denials: list[dict[str, Any]] = []
    steps = 0
    for run in range(iterations):
        # Fresh engine per iteration so quotas and history do not carry over.
        cfg = PepConfig(registry_path=reg_path, alert_log=work / f"pep-alerts-{run % 2}.jsonl")
        engine = PolicyEngine(Registry.load(reg_path), shared=SharedState(), cfg=cfg)
        for wf, wf_steps in BENIGN_WORKFLOWS.items():
            stat = per_wf.setdefault(wf, {"steps": 0, "denied": 0, "cpu_ms": []})
            keys = {"a": roles["a"], "b": roles["b"],
                    "worker": f"{wf}-worker-{run}", "note": f"{wf}-note-{run}"}
            for role, sess, tool, args in wf_steps:
                key = roles[role]
                sid = f"{wf}-{sess}-{run}" if sess != "worker" else keys["worker"]
                call_args = _resolve(args, run, keys)
                c0 = time.thread_time_ns()
                w0 = time.perf_counter_ns()
                out = engine.evaluate_call(key, sid, tool, call_args)
                w1 = time.perf_counter_ns()
                c1 = time.thread_time_ns()
                c_ms = (c1 - c0) / 1e6
                w_ms = (w1 - w0) / 1e6
                cpu_ms.append(c_ms)
                wall_ms.append(w_ms)
                stat["steps"] += 1
                stat["cpu_ms"].append(c_ms)
                steps += 1
                ok = bool(out.get("ok"))
                if not ok:
                    stat["denied"] += 1
                    denials.append({"workflow": wf, "tool": tool, "error": out.get("error")})
                chain.append({"kind": "benign_decision", "workflow": wf, "run": run, "tool": tool,
                              "allowed": ok, "error": out.get("error"), "cpu_ms": round(c_ms, 4)})

    workflows = {
        wf: {"steps": s["steps"], "denied": s["denied"], **_latency_summary(s["cpu_ms"])}
        for wf, s in per_wf.items()
    }
    cpu = _latency_summary(cpu_ms)
    return {
        "iterations": iterations,
        "decisions": steps,
        "workflows": workflows,
        "cpu": cpu,
        "wall": _latency_summary(wall_ms),
        "target_ms": LATENCY_TARGET_MS,
        "p99_cpu_within_target": cpu["p99_ms"] <= LATENCY_TARGET_MS,
        "benign_denials": len(denials),
        "benign_denial_rate": round(len(denials) / steps, 6) if steps else 0.0,
        "benign_denial_examples": denials[:10],
        "llm_calls": 0,
        "clock": "time.thread_time_ns (CPU) and time.perf_counter_ns (wall), in-process, includes decision-log I/O",
        "decision_log": decision_log,
    }


# --- 3. Audit-chain verification ---------------------------------------------------

def verify_decision_log(decision_log: Path) -> dict[str, Any]:
    """Verify the benign chain, then confirm a one-line edit of a copy is caught."""
    from .audit_chain import verify_chain_file, verify_chain_lines

    rep = verify_chain_file(decision_log)
    lines = Path(decision_log).read_text(encoding="utf-8").splitlines()
    tamper_detected = None
    if lines:
        idx = len(lines) // 2
        entry = json.loads(lines[idx])
        entry["allowed"] = not entry.get("allowed")
        edited = [*lines[:idx], json.dumps(entry), *lines[idx + 1:]]
        dropped = [*lines[:idx], *lines[idx + 1:]]
        tamper_detected = {
            "edited_line": not verify_chain_lines(edited).ok,
            "dropped_line": not verify_chain_lines(dropped).ok,
        }
    return {"file": Path(decision_log).name, "chain_ok": rep.ok, "entries": rep.entries,
            "head_hash": rep.head_hash, "errors": rep.errors[:5], "tamper_checks": tamper_detected}


# --- Orchestration and rendering ---------------------------------------------------

def evaluate(iterations: int = 50, suite: Optional[dict[str, Any]] = None,
             work_dir: Optional[Path] = None, collection: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Run all three parts. ``suite`` / ``collection`` may be passed in to reuse earlier pytest runs."""
    t0 = time.perf_counter()
    suite = suite if suite is not None else run_defense_suite()
    collection = collection if collection is not None else collect_gateway_tests()
    latency = run_benign_latency(iterations=iterations, work_dir=work_dir)
    chain = verify_decision_log(latency.pop("decision_log"))
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "machine": platform.machine()},
        "defense_suite": suite,
        "gateway_suite": {**collection, "hypothesis_stateful": scan_hypothesis_settings()},
        "benign_latency": latency,
        "audit_chain": chain,
        "archive_baseline": {"value": ARCHIVE_BASELINE, "pooled": False,
                             "note": "Real-model loopback archive, non-control runs. Separate measurement."},
        "scope_notes": list(SCOPE_NOTES),
        "seconds": round(time.perf_counter() - t0, 3),
    }


def _md_table(header: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def render_markdown(doc: dict[str, Any]) -> str:
    suite, lat, chain = doc["defense_suite"], doc["benign_latency"], doc["audit_chain"]
    tot = suite["totals"]
    cpu = lat["cpu"]
    L: list[str] = [
        "# AgentGate: Deterministic Guardrails Against Multi-Agent Collusion Carriers",
        "",
        "Apart Research AI Collusion Research Sprint. Track 3 (Collusion Carriers and Countermeasures) / "
        "Track 2 (Detection and Audit of Collusion).",
        "",
        f"Generated {doc['generated_at']} by `python -m agent_gateway evaluate-collusion --report`. "
        "Same-author scripted synthetic lab scenarios; not a benchmark.",
        "",
        "## Abstract",
        "",
        "Autonomous agents that share tools can coordinate covertly: one agent can leak information through "
        "which tool or argument it picks and when it calls, launder a restricted capability by handing work to "
        "a cleaner peer, or move data in small or re-encoded pieces across steps. AgentGate is a loopback "
        "Policy Enforcement Point that addresses these carriers with deterministic checks and no model calls: "
        "a post-taint side-channel guard, monotonic capability attenuation across delegation, and n-gram "
        "fingerprinting across encodings with canary watermarks for provenance. "
        f"In this run the repository's defence tests for the three carrier groups passed {tot['passed']} of "
        f"{tot['total']}. Benign policy decisions took a p50 of {cpu['p50_ms']} ms and a p99 of {cpu['p99_ms']} ms "
        f"of CPU time (reference target {lat['target_ms']} ms). The hash-chained decision log verified "
        f"{'clean' if chain['chain_ok'] else 'with errors'} over {chain['entries']} entries.",
        "",
        "## Problem Statement",
        "",
        "Content filters look for a secret in what an agent sends. Collusion carriers avoid that in three ways:",
        "",
        "- **Group A, side channels.** Information moves through the choice among a few argument variants, or "
        "through call timing, so no fragment of the protected value appears in any argument.",
        "- **Group B, delegation laundering.** A restricted agent hands its task or state to a peer whose own "
        "capability looks clean (a confused deputy).",
        "- **Group C, split and encoded smuggling.** A protected value leaves in pieces across steps, or after "
        "Base64, hex, URL, or whitespace transformation.",
        "",
        "## Methodology: Zero-Compute Deterministic Guardrails",
        "",
        "Every check is arithmetic, hashing, or HMAC on the call path. No LLM is consulted "
        f"(LLM calls in this run: {lat['llm_calls']}).",
        "",
        "- `side_channel_guard.py`: after a session is both TAINTED and SENSITIVE_READ, released outbound "
        "calls are counted for distinct argument variants, total calls, and regular inter-call rhythm "
        "(coefficient of variation). A signal denies the call, holds the session for review, and freezes the "
        "registered root key for 15 minutes.",
        "- `delegation_guard.py`: a hand-off re-mints the recipient's `agw1.` capability with the sender's deny "
        "caveats (lattice meet). Caveats are chained HMACs, so they cannot be stripped without the root key, "
        "and a delegated principal that was barred upstream is held at egress.",
        "- `deobfuscate.py`: protected values are stored only as salted SHA-256 digests of 8-character n-grams "
        "of the raw value and its encoded forms, matched against a per-session sliding window of released "
        "arguments.",
        "- `canary_watermark.py`: sensitive reads carry a zero-width HMAC watermark bound to "
        "(session, step, tool), plus credential-format digests, so a hit names the originating step.",
        "- `audit_chain.py`: each decision-log line carries `seq`, `prev_hash`, and `entry_hash`.",
        "",
        "Evaluation procedure, all offline and reproducible:",
        "",
        f"1. Run the existing defence test files with pytest: `{suite['command']}`. Counts come from the "
        "JUnit XML, keyed by node id.",
        f"2. Run {len(BENIGN_WORKFLOWS)} benign multi-agent workflows {lat['iterations']} times through an "
        "in-process `PolicyEngine` and time each `evaluate_call` with thread CPU time.",
        "3. Write each benign decision to a hash-chained log, verify it, and check that editing or dropping a "
        "line in a copy is detected.",
        "",
        "## Results",
        "",
        "### Reproducible test-suite results by group",
        "",
    ]
    rows = []
    for g in suite["groups"]:
        c = g["counts"]
        rows.append([f"{g['group']}: {g['title']}", ", ".join(f"`{f}`" for f in g["files"]),
                     c["total"], c["passed"], c["failed"] + c["error"], c["skipped"]])
    rows.append(["**Total**", "", tot["total"], tot["passed"], tot["failed"] + tot["error"], tot["skipped"]])
    L += _md_table(["Group", "Test files", "Tests", "Passed", "Failed", "Skipped"], rows)
    L += ["", f"pytest: `{suite['pytest_summary']}` (exit {suite['returncode']}, {suite['seconds']} s). "
          "The full per-test list is in "
          f"`{RESULTS_NAME}` under `defense_suite.groups[].tests`.", ""]
    if suite.get("missing_files"):
        L += [f"Missing test files: {', '.join(suite['missing_files'])}", ""]
    for g in suite["groups"]:
        bad = [t for t in g["tests"] if t["outcome"] in ("failed", "error")]
        if bad:
            L.append(f"Failing in group {g['group']}: " + ", ".join(f"`{t['nodeid']}`" for t in bad))
    gw = doc.get("gateway_suite")
    if gw:
        L += ["### Whole gateway suite and stateful property fuzzing", "",
              f"`{gw['command']}` collects {gw['collected']} tests in {gw['files']} files. "
              "The CI job runs all of them. Stateful Hypothesis machines, with settings read from the test files:",
              ""]
        L += _md_table(["State machine", "File", "max_examples", "stateful_step_count"],
                       [[h["machine"], f"`{h['file']}`", h["max_examples"], h["stateful_step_count"]]
                        for h in gw["hypothesis_stateful"]])
        L.append("")
    L += ["### Benign decision latency (CPU time per `evaluate_call`)", ""]
    L += _md_table(
        ["Measure", "p50 ms", "p95 ms", "p99 ms", "mean ms", "max ms"],
        [["CPU", cpu["p50_ms"], cpu["p95_ms"], cpu["p99_ms"], cpu["mean_ms"], cpu["max_ms"]],
         ["Wall", lat["wall"]["p50_ms"], lat["wall"]["p95_ms"], lat["wall"]["p99_ms"],
          lat["wall"]["mean_ms"], lat["wall"]["max_ms"]]],
    )
    L += ["", f"{lat['decisions']} decisions. Reference target {lat['target_ms']} ms: p99 CPU "
          f"{'within' if lat['p99_cpu_within_target'] else 'above'} target. Timing includes decision-log I/O.",
          ""]
    L += _md_table(
        ["Benign workflow", "Steps", "Denied", "p50 CPU ms", "p99 CPU ms"],
        [[wf, s["steps"], s["denied"], s["p50_ms"], s["p99_ms"]] for wf, s in lat["workflows"].items()],
    )
    L += ["", f"Benign denials: {lat['benign_denials']} of {lat['decisions']} decisions "
          f"(rate {lat['benign_denial_rate']}).", ""]
    if lat["benign_denial_examples"]:
        L.append("Denied benign steps: " + ", ".join(
            f"{d['workflow']}/{d['tool']} ({d['error']})" for d in lat["benign_denial_examples"]))
        L.append("")
    tc = chain["tamper_checks"] or {}
    L += ["### Audit-chain verification", ""]
    L += _md_table(
        ["Check", "Result"],
        [["Benign decision log chain", "verified" if chain["chain_ok"] else "FAILED"],
         ["Entries", chain["entries"]],
         ["Head hash", f"`{chain['head_hash'][:16]}...`"],
         ["Edited line in a copy detected", "yes" if tc.get("edited_line") else "no"],
         ["Dropped line in a copy detected", "yes" if tc.get("dropped_line") else "no"]],
    )
    L += [
        "",
        "## Defence Analysis: Why the Carriers Fail Here",
        "",
        "- **Side channels (Group A).** The guard does not try to read the content. It bounds the channel: "
        "the number of distinct variants, the number of calls after the taint point, and how regular the timing "
        "is. Crossing any bound holds the session for a person, so leakage is capped by policy rather than by "
        "spotting a pattern.",
        "- **Delegation laundering (Group B).** Restrictions travel with the hand-off as HMAC caveats and are "
        "folded with a lattice meet, which only moves down. A peer cannot hold more egress than the agent that "
        "delegated to it, and a fresh session of a delegated principal is still held.",
        "- **Split and encoded smuggling (Group C).** Matching runs on a sliding window across steps and over "
        "decoded forms, so splitting or encoding does not remove the n-gram overlap. Watermarks and credential "
        "digests give step-level provenance in the hash-chained log.",
        "- **Containment.** On a signal the registered root key and its children are frozen for 15 minutes. "
        "Unregistered callers are never acted on.",
        "",
        "## Scope and Limitations",
        "",
    ]
    L += [f"- {n}" for n in doc["scope_notes"]]
    L += [
        "- Group counts show that the guards behave as their own tests specify. They are not an estimate of "
        "recall against an unknown adversary.",
        "- Benign workflows were written by the same author and are few; the denial rate is a smoke check, "
        "not a false-positive rate for real deployments.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "pip install -e './agent-gateway[test]'",
        "cd agent-gateway",
        "export AGENT_GATEWAY_HMAC_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')",
        "python -m agent_gateway evaluate-collusion --report ../sprint_submission",
        "```",
        "",
        f"Environment: Python {doc['environment']['python']} on {doc['environment']['platform']}. "
        f"Total evaluation time {doc['seconds']} s.",
        "",
    ]
    return "\n".join(L)


def _md_to_lines(md: str) -> list[str]:
    """Plain text lines for the Helvetica PDF writer (markup stripped)."""
    out: list[str] = []
    in_code = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not in_code and line.startswith("|"):
            if set(line.replace("|", "").strip()) <= {"-"}:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            line = " | ".join(cells)
        if not in_code:
            if line.startswith("#"):
                title = line.lstrip("#").strip()
                if out and out[-1] != "":
                    out.append("")
                line = title.upper() if raw.startswith("## ") else title
            line = line.replace("**", "").replace("`", "")
        out.append(line)
    return out


def render_pdf_bytes(md: str) -> bytes:
    from .audit_report import render_pdf

    return render_pdf(_md_to_lines(md))


def _json_safe(doc: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(doc, default=str))


def write_report(out_dir: Path, doc: dict[str, Any]) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md = render_markdown(doc)
    from .sprint_artifacts import render_card_png, render_slides_pdf

    paths = {"json": out_dir / RESULTS_NAME, "markdown": out_dir / REPORT_MD_NAME, "pdf": out_dir / REPORT_PDF_NAME,
             "slides": out_dir / SLIDES_PDF_NAME, "image": out_dir / CARD_PNG_NAME}
    paths["json"].write_text(json.dumps(_json_safe(doc), indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(md, encoding="utf-8")
    paths["pdf"].write_bytes(render_pdf_bytes(md))
    paths["slides"].write_bytes(render_slides_pdf(doc))
    paths["image"].write_bytes(render_card_png(doc))
    return paths


def summary_line(doc: dict[str, Any]) -> dict[str, Any]:
    tot = doc["defense_suite"]["totals"]
    lat = doc["benign_latency"]
    return {
        "defense_tests_passed": f"{tot['passed']} of {tot['total']}",
        "groups_all_passed": {g["group"]: g["all_passed"] for g in doc["defense_suite"]["groups"]},
        "benign_cpu_ms": {k: lat["cpu"][k] for k in ("p50_ms", "p95_ms", "p99_ms")},
        "target_ms": lat["target_ms"],
        "benign_denials": lat["benign_denials"],
        "audit_chain_ok": doc["audit_chain"]["chain_ok"],
        "gateway_tests_collected": (doc.get("gateway_suite") or {}).get("collected"),
        "archive_baseline": f"{ARCHIVE_BASELINE} (separate, not pooled)",
    }


def ok(doc: dict[str, Any]) -> bool:
    suite = doc["defense_suite"]
    return (suite["returncode"] == 0 and all(g["all_passed"] for g in suite["groups"])
            and doc["audit_chain"]["chain_ok"])

