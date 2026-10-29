"""Claude Code ``PreToolUse`` policy adapter (standard library only).

Wire it into Claude Code once::

    python -m agent_gateway.claude_code_hook --install

``--install`` loads or creates ``~/.claude/settings.json`` (``--settings``
for another path) and adds one ``PreToolUse`` command hook that runs this
module. Running it again does not add a second entry.

Hook contract: Claude Code writes ``{"session_id", "tool_name",
"tool_input", ...}`` to stdin before each tool call. The adapter evaluates
three workspace policy rules, appends one SHA-256 hash-chained JSONL entry
to ``~/.claude/agentgate_audit.jsonl`` (``--audit-log`` for another path),
and, when a rule denies the call, writes the Claude Code block response to
stdout. An allowed call writes nothing. Exit status is 0 either way.

Rules (first match wins):

- ``METADATA_URI_DENIED``: any argument references the link-local cloud
  metadata address ``169.254.169.254`` (also as hex, decimal, or
  IPv4-mapped IPv6), ``metadata.google.internal``, or a ``file://`` URI.
- ``CREDENTIAL_PATH_DENIED``: ``Read`` / ``Write`` / ``Edit`` /
  ``MultiEdit`` on, or a ``Bash`` command that references, a ``.env`` file
  (``.env.example``, ``.env.sample`` and ``.env.template`` are allowed),
  anything under ``.ssh/`` or ``.aws/``, ``.npmrc``, or ``.pypirc``.
- ``SHELL_POLICY_DENIED``: a ``Bash`` command with a recursive ``rm`` of
  ``/`` or the home directory, a force push to ``main`` / ``master``, or a
  remote download piped straight into a shell or interpreter.
- ``WORKSPACE_CONFIG_WRITE`` / ``WORKSPACE_HOOK_TAMPER`` /
  ``WORKSPACE_SYMLINK_ESCAPE`` (``workspace_config_guard.py``): a
  ``Write`` / ``Edit`` / ``MultiEdit`` / ``NotebookEdit`` on, or a ``Bash``
  redirection, ``tee``, ``cp``, ``mv``, ``ln -s``, ``chmod``, ``sed -i``, or
  ``git config`` touching, an agent instruction or configuration file
  (``CLAUDE.md``, ``.claude/``, ``.mcp.json``, ``.cursor/`` ...) or an
  execution hook (``.git/hooks/``, ``.git/config``, CI workflows, shell rc
  files). ``--allow-workspace-writes config,hook`` (or the
  ``AGENTGATE_ALLOW_WORKSPACE_WRITES`` environment variable) opts in;
  symlink escapes are never allowed.
- ``INTERPRETER_PROTECTED_WRITE`` / ``INTERPRETER_OBFUSCATED_PIPE`` /
  ``INTERPRETER_DANGEROUS_PRIMITIVE`` (``interpreter_exec_guard.py``): a
  ``Bash`` command whose inline interpreter payload (``python -c``,
  ``node -e``, ``ruby -e``, ``perl -e``, ``php -r``, ``bash -c``, a heredoc)
  writes a protected path, or that pipes decoded base64 / hex into a shell,
  or whose payload calls a process, network, or dynamic-code primitive. The
  workspace opt-in applies to protected writes; credential paths never.
- ``WORKSPACE_HIDDEN_DIRECTIVE``: a ``Read`` of an instruction file
  (``CLAUDE.md``, ``AGENTS.md``, ``SKILL.md``, ``.cursor/rules/*``) whose
  current content on disk has an HTML comment or invisible characters.

Input that is not a JSON object is denied (``HOOK_INPUT_INVALID``): the
adapter fails closed. The rules are lexical configuration checks, not a
sandbox; a determined local user can always run commands outside Claude
Code. ``--self-test`` runs four fixed validation checks and prints the
measured CPU time of each decision.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import GENESIS, link, verify_chain_file
from .interpreter_exec_guard import InterpreterExecGuard
from .workspace_config_guard import (
    WorkspaceConfigGuard,
    is_instruction_file,
    scan_workspace_instruction_file,
)

HOOK_MODULE = "agent_gateway.claude_code_hook"
DEFAULT_SETTINGS = Path.home() / ".claude" / "settings.json"
DEFAULT_AUDIT_LOG = Path.home() / ".claude" / "agentgate_audit.jsonl"

PATH_TOOLS = frozenset({"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"})
PATH_KEYS = ("file_path", "path", "notebook_path")
ENV_TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template"})

ALLOW = "ALLOW"
DENY = "DENY"

# --- link-local / private metadata targets ------------------------------------------

_METADATA_RE = re.compile(
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|\b0x0*a9fea9fe\b"
    r"|\b2852039166\b"
    r"|::ffff:(?:169\.254\.169\.254|a9fe:a9fe)"
    r"|fd00:ec2::254"
    r"|\bfile://",
    re.IGNORECASE,
)

# --- protected credential paths ---------------------------------------------------

_ENV_NAME_RE = re.compile(r"^\.env(?:\.([A-Za-z0-9_.-]+))?$")
_CRED_DIRS = frozenset({".ssh", ".aws"})
_CRED_FILES = frozenset({".npmrc", ".pypirc"})
_TOKEN_STRIP = "\"'`;|&()<>{}[],"
_SPLIT_RE = re.compile(r"[\s=:]+")

# --- shell command policy ---------------------------------------------------------

_SEGMENT_RE = re.compile(r"\|\||&&|;|\n|\|&|\||&")
_HOME_TARGETS = frozenset({"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*",
                           "${HOME}", "${HOME}/", "${HOME}/*"})
_DOWNLOADERS = frozenset({"curl", "wget"})
_INTERPRETERS = re.compile(r"^(?:ba|z|da|k|c|tc|fi)?sh$|^python[0-9.]*$|^perl$|^ruby$|^node$|^php$")
_SUBST_DOWNLOAD_RE = re.compile(
    r"\b(?:ba|z|da|k)?sh\b[^|;&\n]*(?:<\(|\$\(|`)\s*(?:curl|wget)\b", re.IGNORECASE)
_PROTECTED_BRANCHES = frozenset({"main", "master"})


@dataclass(frozen=True)
class HookDecision:
    allowed: bool
    rule_code: str
    reason: str

    @property
    def verdict(self) -> str:
        return ALLOW if self.allowed else DENY


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k in sorted(obj, key=str):
            yield from _strings(obj[k])
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _strings(item)


def protected_path(path: str) -> Optional[str]:
    """The protected component of ``path``, or None when the path is not protected."""
    norm = path.strip().strip(_TOKEN_STRIP).replace("\\", "/")
    if not norm:
        return None
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return None
    for part in parts[:-1]:
        if part in _CRED_DIRS:
            return part + "/"
    name = parts[-1]
    if name in _CRED_DIRS:
        return name + "/"
    if name in _CRED_FILES:
        return name
    m = _ENV_NAME_RE.match(name)
    if m and (m.group(1) or "").lower() not in ENV_TEMPLATE_SUFFIXES:
        return name
    return None


def _command_paths(command: str) -> Iterable[str]:
    for token in _SPLIT_RE.split(command):
        token = token.strip(_TOKEN_STRIP)
        if token:
            yield token


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _strip_prefix(words: list[str]) -> list[str]:
    """Drop ``sudo`` / ``env`` / ``VAR=value`` prefixes so the command word comes first."""
    i = 0
    while i < len(words) and (words[i] in ("sudo", "env", "command", "exec", "nohup", "time")
                              or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i])):
        i += 1
    return words[i:]


def _recursive_home_rm(words: list[str]) -> bool:
    if not words or Path(words[0]).name != "rm":
        return False
    recursive = False
    targets = []
    for w in words[1:]:
        if w in ("--recursive", "--no-preserve-root"):
            recursive = True
        elif w.startswith("-") and not w.startswith("--"):
            recursive = recursive or "r" in w or "R" in w
        elif not w.startswith("-"):
            targets.append(w)
    home = os.path.expanduser("~")
    return recursive and any(t in _HOME_TARGETS or t.rstrip("/") == home or t in (home + "/*",)
                             for t in targets)


def _force_push_protected(words: list[str]) -> bool:
    if len(words) < 2 or Path(words[0]).name != "git" or "push" not in words[1:3]:
        return False
    rest = words[words.index("push") + 1:]
    force = any(w in ("-f", "--force") or w.startswith("--force-with-lease") or w.startswith("--force-if-includes")
                or (w.startswith("-") and not w.startswith("--") and "f" in w) for w in rest)
    refs = [w for w in rest if not w.startswith("-")]
    forced_ref = any(r.startswith("+") and r.lstrip("+").split(":")[-1] in _PROTECTED_BRANCHES for r in refs)
    targets = any(r.split(":")[-1].removeprefix("refs/heads/") in _PROTECTED_BRANCHES for r in refs)
    return (force and targets) or forced_ref


def shell_policy_violation(command: str) -> Optional[str]:
    """Short description of the first command-policy violation, or None."""
    if _SUBST_DOWNLOAD_RE.search(command):
        return "remote download executed through process or command substitution"
    segments = [s for s in _SEGMENT_RE.split(command)]
    pipes = re.split(r"(?<!\|)\|(?![|&])", command)
    for seg in segments:
        words = _strip_prefix(_words(seg))
        if _recursive_home_rm(words):
            return "recursive deletion of the root or home directory"
        if _force_push_protected(words):
            return "force push to a protected branch (main / master)"
    for left, right in zip(pipes, pipes[1:]):
        lw = _strip_prefix(_words(_SEGMENT_RE.split(left)[-1]))
        rw = _strip_prefix(_words(_SEGMENT_RE.split(right)[0]))
        if lw and Path(lw[0]).name in _DOWNLOADERS and rw and _INTERPRETERS.match(Path(rw[0]).name):
            return "remote download piped to a shell interpreter"
    return None


WORKSPACE_ENV = "AGENTGATE_ALLOW_WORKSPACE_WRITES"
MAX_INSTRUCTION_BYTES = 262_144


def _workspace_checks(tool_name: str, tool_input: dict, allow: Iterable[str], cwd: str) -> Optional[HookDecision]:
    guard = WorkspaceConfigGuard(allow=allow)
    if tool_name in PATH_TOOLS or tool_name == "Bash":
        ws = guard.inspect_tool_call(tool_name, tool_input)
        if not ws.allowed:
            return HookDecision(False, ws.rule_code, f"{tool_name} {ws.operation} on {ws.path}: {ws.detail}")
    if tool_name == "Read":
        path = tool_input.get("file_path") or tool_input.get("path")
        if isinstance(path, str) and is_instruction_file(path):
            full = Path(path).expanduser()
            if not full.is_absolute() and cwd:
                full = Path(cwd) / full
            try:
                with full.open("rb") as f:
                    content = f.read(MAX_INSTRUCTION_BYTES).decode("utf-8", "replace")
            except OSError:
                return None
            hit = scan_workspace_instruction_file(path, content)
            if hit is not None:
                return HookDecision(False, hit.rule_code, f"Read of {path}: {hit.detail}")
    return None


def evaluate(tool_name: str, tool_input: Any, *, workspace_allow: Iterable[str] = (), cwd: str = "") -> HookDecision:
    """Evaluate one ``PreToolUse`` call against the workspace policy rules.

    ``workspace_allow`` opts in to ``"config"`` / ``"hook"`` writes; ``cwd``
    resolves a relative ``Read`` path for the instruction-file scan.
    """
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}
    for text in _strings(tool_input):
        m = _METADATA_RE.search(text)
        if m:
            return HookDecision(False, "METADATA_URI_DENIED",
                                f"{tool_name} argument references a link-local metadata or file:// target "
                                f"({m.group(0)})")
    if tool_name in PATH_TOOLS:
        for key in PATH_KEYS:
            val = tool_input.get(key)
            hit = protected_path(val) if isinstance(val, str) else None
            if hit:
                return HookDecision(False, "CREDENTIAL_PATH_DENIED",
                                    f"{tool_name} on a protected credential path ({hit})")
    if tool_name == "Bash":
        command = str(tool_input.get("command") or "")
        for token in _command_paths(command):
            hit = protected_path(token)
            if hit:
                return HookDecision(False, "CREDENTIAL_PATH_DENIED",
                                    f"Bash command references a protected credential path ({hit})")
        violation = shell_policy_violation(command)
        if violation:
            return HookDecision(False, "SHELL_POLICY_DENIED", f"Bash command policy: {violation}")
    ws = _workspace_checks(tool_name, tool_input, workspace_allow, cwd)
    if ws is not None:
        return ws
    if tool_name == "Bash":
        interp = InterpreterExecGuard(allow=workspace_allow).inspect_command(str(tool_input.get("command") or ""))
        if not interp.allowed:
            where = f" on {interp.path}" if interp.path else ""
            return HookDecision(False, interp.rule_code, f"inline {interp.language} payload{where}: {interp.detail}")
    return HookDecision(True, "POLICY_COMPLIANT", "no workspace policy rule matched")


# --- hash-chained audit log -------------------------------------------------------

def _last_entry(path: Path) -> Optional[dict]:
    """Last chained entry, read from the tail of the file only."""
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            block = 4096
            data = b""
            pos = end
            while pos > 0:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
                lines = [ln for ln in data.splitlines() if ln.strip()]
                if len(lines) >= 2 or (pos == 0 and lines):
                    try:
                        obj = json.loads(lines[-1])
                    except ValueError:
                        return None
                    return obj if isinstance(obj, dict) else None
    except FileNotFoundError:
        return None
    return None


def append_audit_entry(path: Path, session_id: str, tool_name: str, decision: HookDecision,
                       elapsed_ms: float) -> dict:
    """Append one chained entry. Concurrent hook processes are serialized with ``flock`` where available."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as f:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        last = _last_entry(path)
        seq = int(last["seq"]) + 1 if last and isinstance(last.get("seq"), int) else 0
        prev = str(last["entry_hash"]) if last and isinstance(last.get("entry_hash"), str) else GENESIS
        entry = link({
            "ts": round(time.time(), 6),
            "session_id": session_id,
            "tool_name": tool_name,
            "verdict": decision.verdict,
            "rule_code": decision.rule_code,
            "elapsed_ms": round(elapsed_ms, 4),
        }, seq, prev)
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
    return entry


def verify_audit_log(path: Path) -> dict:
    """Recompute seq, prev_hash, and entry_hash for every line (``audit_chain.verify_chain_file``)."""
    return verify_chain_file(Path(path)).as_dict()


def block_response(decision: HookDecision, entry_hash: str = "") -> dict:
    """Claude Code ``PreToolUse`` deny response."""
    reason = f"AgentGate policy {decision.rule_code}: {decision.reason}"
    if entry_hash:
        reason += f" (audit {entry_hash[:12]})"
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def workspace_allow_from(value: Optional[str]) -> frozenset:
    """``"config,hook"`` -> ``{"config", "hook"}``; unknown words are ignored."""
    return frozenset(w.strip().lower() for w in (value or "").split(",") if w.strip().lower() in ("config", "hook"))


def handle(raw: str, audit_log: Path, workspace_allow: Iterable[str] = ()) -> Optional[dict]:
    """Evaluate one hook payload. Returns the block response, or None when allowed."""
    t0 = time.thread_time_ns()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        decision = HookDecision(False, "HOOK_INPUT_INVALID", "hook input is not a JSON object")
        session_id, tool_name = "unknown", ""
    else:
        session_id = str(payload.get("session_id") or "unknown")
        tool_name = str(payload.get("tool_name") or "")
        decision = evaluate(tool_name, payload.get("tool_input") or {}, workspace_allow=workspace_allow,
                            cwd=str(payload.get("cwd") or ""))
    elapsed_ms = (time.thread_time_ns() - t0) / 1e6
    entry_hash = ""
    try:
        entry_hash = append_audit_entry(audit_log, session_id, tool_name, decision, elapsed_ms)["entry_hash"]
    except OSError as exc:
        print(f"agentgate hook: audit log not written: {exc}", file=sys.stderr)
    return None if decision.allowed else block_response(decision, entry_hash)


# --- install / self-test ----------------------------------------------------------

def hook_command(audit_log: Optional[Path] = None, workspace_allow: Iterable[str] = ()) -> str:
    cmd = f"{shlex.quote(sys.executable)} -m {HOOK_MODULE}"
    if audit_log is not None:
        cmd += f" --audit-log {shlex.quote(str(audit_log))}"
    allow = sorted(workspace_allow_from(",".join(workspace_allow)))
    if allow:
        cmd += f" --allow-workspace-writes {','.join(allow)}"
    return cmd


def install(settings_path: Path, audit_log: Optional[Path] = None, workspace_allow: Iterable[str] = ()) -> bool:
    """Add the PreToolUse hook to ``settings_path``. Returns False when it was already present."""
    settings_path = Path(settings_path).expanduser()
    data: dict = {}
    if settings_path.is_file() and settings_path.read_text(encoding="utf-8").strip():
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{settings_path} is not a JSON object")
    hooks = data.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(hooks, dict) or not isinstance(pre, list):
        raise ValueError(f"{settings_path}: hooks.PreToolUse is not a list")
    for group in pre:
        for h in (group.get("hooks") or []) if isinstance(group, dict) else []:
            if isinstance(h, dict) and HOOK_MODULE in str(h.get("command") or ""):
                return False
    pre.append({"matcher": "*", "hooks": [{"type": "command",
                                            "command": hook_command(audit_log, workspace_allow)}]})
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings_path.with_name(settings_path.name + ".agentgate.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, settings_path)
    return True


SELF_TEST_CASES = (
    ("benign file read", "Read", {"file_path": "src/app/main.py"}, True),
    ("credential file read", "Read", {"file_path": "/srv/app/.env.production"}, False),
    ("template file read", "Read", {"file_path": "/srv/app/.env.example"}, True),
    ("link-local metadata URL", "WebFetch", {"url": "http://169.254.169.254/latest/meta-data/"}, False),
)


def self_test(out=sys.stdout) -> int:
    failures = 0
    for label, tool, args, expect in SELF_TEST_CASES:
        t0 = time.thread_time_ns()
        d = evaluate(tool, args)
        ms = (time.thread_time_ns() - t0) / 1e6
        ok = d.allowed == expect
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label:<24} {tool:<9} {d.verdict:<5} {d.rule_code:<24} "
              f"{ms:.3f} ms CPU", file=out)
    print(f"{len(SELF_TEST_CASES) - failures}/{len(SELF_TEST_CASES)} validation checks passed", file=out)
    return 1 if failures else 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=f"python -m {HOOK_MODULE}", description=__doc__.split("\n\n")[0])
    ap.add_argument("--install", action="store_true", help="add the PreToolUse hook to Claude Code settings")
    ap.add_argument("--self-test", action="store_true", help="run the four validation checks")
    ap.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS, help="settings.json path for --install")
    ap.add_argument("--audit-log", type=Path, default=None, help=f"audit log path (default {DEFAULT_AUDIT_LOG})")
    ap.add_argument("--allow-workspace-writes", default=None, metavar="config,hook",
                    help=f"opt in to agent config and / or execution-hook writes (or set {WORKSPACE_ENV})")
    args = ap.parse_args(argv)
    allow = workspace_allow_from(args.allow_workspace_writes if args.allow_workspace_writes is not None
                                 else os.environ.get(WORKSPACE_ENV))
    if args.install:
        added = install(args.settings, args.audit_log, allow)
        print(f"{'installed' if added else 'already installed'}: PreToolUse hook in {args.settings}")
        return 0
    if args.self_test:
        return self_test()
    out = handle(sys.stdin.read(), args.audit_log or DEFAULT_AUDIT_LOG, allow)
    if out is not None:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
