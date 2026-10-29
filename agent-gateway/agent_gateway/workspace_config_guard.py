"""Agent workspace config, skill, and hook persistence guard.

An agent that can write files can also rewrite what steers the next agent
session or what the host runs on its own: instruction and skill files, MCP
and IDE configuration, git hooks, CI workflows, and shell start-up files.
This guard checks structured file tool calls (write, edit, patch, delete,
rename, symlink, chmod) and shell commands (``>``, ``>>``, ``tee``, ``cp``,
``mv``, ``ln -s``, ``chmod``, ``sed -i``, ``rm``, ``touch``, ``truncate``,
``dd of=``, ``git config``) against normalized protected paths:

- Agent instructions and skills: ``CLAUDE.md``, ``CLAUDE.local.md``,
  ``AGENTS.md``, ``SKILL.md``, ``.cursorrules``, ``.cursor/**``,
  ``.claude/**``, ``.windsurf/**``, ``.github/copilot-instructions.md``.
- MCP and IDE configuration: ``.mcp.json``, ``mcp.json``,
  ``.vscode/settings.json``, ``.vscode/tasks.json``.
- Execution hooks: ``.git/hooks/**``, ``.git/config``,
  ``.github/workflows/**``, ``.bashrc``, ``.bash_profile``, ``.zshrc``,
  ``.profile``.

Rule codes:

- ``WORKSPACE_CONFIG_WRITE``: write, patch, rename, or delete of an
  instruction, skill, MCP, or IDE configuration file.
- ``WORKSPACE_HOOK_TAMPER``: write or permission change on an execution
  hook path, or ``git config`` that sets a value (``core.hooksPath`` etc.).
- ``WORKSPACE_SYMLINK_ESCAPE``: a symlink whose target or link path is a
  protected or credential path.
- ``WORKSPACE_HIDDEN_DIRECTIVE``: ``scan_workspace_instruction_file`` found
  an HTML comment, Unicode tag characters, or zero-width / bidi characters
  in an instruction file before the agent reads it.

``allow`` opts in to ``"config"`` and / or ``"hook"`` writes (for a session
where a person asked for them). Symlink escapes are never opted in. Matching
is case-insensitive, so a case-insensitive file system cannot be used to
slip past it. Denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). Lexical checks on paths and command words: a
write through an interpreter (``python -c``) or an obfuscated path is not
seen.
"""
from __future__ import annotations

import posixpath
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

CONFIG_WRITE = "WORKSPACE_CONFIG_WRITE"
HOOK_TAMPER = "WORKSPACE_HOOK_TAMPER"
SYMLINK_ESCAPE = "WORKSPACE_SYMLINK_ESCAPE"
HIDDEN_DIRECTIVE = "WORKSPACE_HIDDEN_DIRECTIVE"
RULE_CODES = (CONFIG_WRITE, HOOK_TAMPER, SYMLINK_ESCAPE, HIDDEN_DIRECTIVE)

CONFIG, HOOK, CREDENTIAL = "config", "hook", "credential"

_CONFIG_NAMES = frozenset({"claude.md", "claude.local.md", "agents.md", "skill.md", ".cursorrules",
                           ".windsurfrules", ".mcp.json", "mcp.json"})
_CONFIG_DIRS = frozenset({".cursor", ".claude", ".windsurf"})
_CONFIG_SUFFIXES = (".github/copilot-instructions.md", ".vscode/settings.json", ".vscode/tasks.json")
_HOOK_NAMES = frozenset({".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile"})
_CRED_DIRS = frozenset({".ssh", ".aws", ".gnupg", ".kube"})
_CRED_NAMES = frozenset({".npmrc", ".pypirc", ".netrc", ".git-credentials"})
_ENV_RE = re.compile(r"^\.env(?:\.[a-z0-9_.-]+)?$")
_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template"})

INSTRUCTION_NAMES = frozenset({"claude.md", "claude.local.md", "agents.md", "skill.md", ".cursorrules",
                               ".windsurfrules", "copilot-instructions.md"})

PATH_KEYS = ("file_path", "path", "notebook_path", "target", "target_path", "destination", "dest",
             "new_path", "old_path", "src", "source", "link", "link_path", "filename", "to", "from")
_WRITE_WORDS = ("write", "edit", "patch", "delete", "remove", "rename", "move", "create", "append",
                "save", "replace", "chmod", "symlink", "link", "update", "put", "insert", "truncate")
_READ_WORDS = ("read", "get", "view", "list", "cat", "search", "glob", "grep", "find", "fetch", "stat")

_SEGMENT_RE = re.compile(r"\|\||&&|;|\n|\|&|\||&")
_REDIRECT_RE = re.compile(r"(?<![<&\d])(?:\d|&)?>>?\|?\s*([^\s;|&<>]+)")
_INVISIBLE_RE = re.compile("[​‌⁠-⁤‪-‮⁦-⁩‎‏]")
_TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)(?:-->|$)", re.S)


def normalize_path(path: str) -> str:
    """Case-folded POSIX path with ``~``, ``$HOME``, ``./`` and ``..`` resolved lexically."""
    p = str(path).strip().strip("\"'`").replace("\\", "/")
    p = re.sub(r"^(?:\$\{?HOME\}?|%USERPROFILE%)(?=/|$)", "~", p)
    p = re.sub(r"^[a-zA-Z]:/", "/", p)
    if not p:
        return ""
    lead = "/" if p.startswith("/") else ""
    norm = posixpath.normpath(p)
    if norm == ".":
        return ""
    norm = norm.lstrip("/")
    return (lead + norm).casefold()


def classify_path(path: str) -> Optional[str]:
    """``"hook"``, ``"config"``, ``"credential"``, or None for an ordinary path."""
    norm = normalize_path(path)
    if not norm:
        return None
    parts = [p for p in norm.split("/") if p and p != "~"]
    if not parts:
        return None
    name = parts[-1]
    joined = "/".join(parts)
    for i, part in enumerate(parts):
        if part == ".git" and i + 1 < len(parts) and (parts[i + 1] == "hooks" or
                                                         (parts[i + 1] == "config" and i + 2 == len(parts))):
            return HOOK
        if part == ".github" and i + 1 < len(parts) and parts[i + 1] == "workflows":
            return HOOK
    if name in _HOOK_NAMES:
        return HOOK
    if name in _CONFIG_NAMES or any(p in _CONFIG_DIRS for p in parts):
        return CONFIG
    if any(joined == s or joined.endswith("/" + s) for s in _CONFIG_SUFFIXES):
        return CONFIG
    if any(p in _CRED_DIRS for p in parts[:-1]) or name in _CRED_DIRS or name in _CRED_NAMES:
        return CREDENTIAL
    if _ENV_RE.match(name) and name not in _ENV_TEMPLATES:
        return CREDENTIAL
    return None


@dataclass(frozen=True)
class WorkspaceDecision:
    allowed: bool
    rule_code: str
    path: str = ""
    operation: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "path": self.path,
                "operation": self.operation, "detail": self.detail}


COMPLIANT = WorkspaceDecision(True, "WORKSPACE_COMPLIANT")


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _strip_prefix(words: list[str]) -> list[str]:
    i = 0
    while i < len(words) and (words[i] in ("sudo", "env", "command", "exec", "nohup", "time", "doas")
                              or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i])):
        i += 1
    return words[i:]


def shell_operations(command: str) -> list[tuple[str, list[str]]]:
    """``(operation, paths)`` pairs a shell command would perform on files.

    Operations: ``write``, ``delete``, ``chmod``, ``symlink`` (paths = [target, link]),
    ``git_config``.
    """
    ops: list[tuple[str, list[str]]] = []
    for m in _REDIRECT_RE.finditer(command):
        target = m.group(1)
        if target not in ("/dev/null", "/dev/stdout", "/dev/stderr") and not target.startswith("&"):
            ops.append(("write", [target]))
    for seg in _SEGMENT_RE.split(command):
        words = _strip_prefix(_words(seg))
        if not words:
            continue
        cmd = posixpath.basename(words[0])
        args = [w for w in words[1:] if not re.match(r"^\d*>>?|^<", w)]
        files = [a for a in args if not a.startswith("-")]
        if cmd == "tee":
            ops.append(("write", files))
        elif cmd in ("cp", "install", "rsync") and len(files) >= 2:
            ops.append(("write", files[-1:]))
        elif cmd == "mv" and len(files) >= 2:
            ops.append(("delete", files[:-1]))
            ops.append(("write", files[-1:]))
        elif cmd in ("rm", "unlink", "shred"):
            ops.append(("delete", files))
        elif cmd in ("touch", "truncate"):
            ops.append(("write", [f for f in files if not re.fullmatch(r"[+-]?\d+[kmg]?", f, re.I)]))
        elif cmd == "ln" and any(a.startswith("-") and "s" in a.lstrip("-") or a == "--symbolic" for a in args):
            if len(files) >= 2:
                ops.append(("symlink", files[-2:]))
            elif files:
                ops.append(("symlink", [files[0], posixpath.basename(files[0])]))
        elif cmd == "chmod":
            ops.append(("chmod", files[1:] if files else []))
        elif cmd == "sed" and any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args):
            ops.append(("write", files[1:] if len(files) > 1 else files))
        elif cmd == "dd":
            ops.append(("write", [a[3:] for a in args if a.startswith("of=")]))
        elif cmd == "git" and "config" in words[1:3]:
            rest = words[words.index("config") + 1:]
            reading = any(r in ("--get", "--get-all", "--list", "-l", "--get-regexp") for r in rest)
            values = [r for r in rest if not r.startswith("-")]
            if not reading and len(values) >= 2:
                ops.append(("git_config", [".git/config"]))
    return ops


def _operation_for_tool(tool_name: str) -> Optional[str]:
    name = tool_name.casefold()
    if name in ("write", "edit", "multiedit", "notebookedit"):
        return "write"
    if "symlink" in name or re.search(r"(?:^|[._\-])(?:ln|link)(?:$|[._\-])", name):
        return "symlink"
    if "chmod" in name:
        return "chmod"
    if any(w in name for w in ("delete", "remove", "unlink")):
        return "delete"
    if any(w in name for w in _READ_WORDS) and not any(w in name for w in _WRITE_WORDS):
        return None
    if any(w in name for w in _WRITE_WORDS):
        return "write"
    return None


class WorkspaceConfigGuard:
    """Protects agent instruction, MCP / IDE configuration, and execution-hook files from writes."""

    def __init__(self, *, allow: Iterable[str] = (), audit_log: Optional[Path] = None) -> None:
        self.allow = frozenset(a for a in allow if a in (CONFIG, HOOK))
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None

    def _decide(self, operation: str, paths: list[str]) -> WorkspaceDecision:
        classes = [(p, classify_path(p)) for p in paths if isinstance(p, str) and p.strip()]
        if operation == "symlink":
            for p, cls in classes:
                if cls is not None:
                    return WorkspaceDecision(False, SYMLINK_ESCAPE, p, operation, f"symlink touches a {cls} path")
            return COMPLIANT
        if operation == "git_config":
            if HOOK in self.allow:
                return COMPLIANT
            return WorkspaceDecision(False, HOOK_TAMPER, ".git/config", operation, "git config sets a value")
        for p, cls in classes:
            if cls == HOOK and HOOK not in self.allow:
                return WorkspaceDecision(False, HOOK_TAMPER, p, operation, "execution hook path")
            if cls == CONFIG and CONFIG not in self.allow:
                return WorkspaceDecision(False, CONFIG_WRITE, p, operation, "agent instruction or configuration file")
        return COMPLIANT

    def _record(self, d: WorkspaceDecision, tool_name: str, session_id: str) -> WorkspaceDecision:
        if not d.allowed and self.chain is not None:
            self.chain.append({"ts": round(time.time(), 6), "kind": d.rule_code, "session_id": session_id,
                               "tool": tool_name, "verdict": "DENY", "rule_code": d.rule_code,
                               "path": d.path, "operation": d.operation})
        return d

    def inspect_command(self, command: str, *, session_id: str = "", tool_name: str = "Bash") -> WorkspaceDecision:
        for operation, paths in shell_operations(str(command)):
            d = self._decide(operation, paths)
            if not d.allowed:
                return self._record(d, tool_name, session_id)
        return COMPLIANT

    def inspect_tool_call(self, tool_name: str, args: Any, *, session_id: str = "") -> WorkspaceDecision:
        """Check a structured tool call (or a ``Bash`` / shell call through its ``command`` argument)."""
        if not isinstance(args, dict):
            return COMPLIANT
        command = args.get("command") or args.get("cmd")
        if isinstance(command, str) and (tool_name.casefold() in ("bash", "shell", "sh", "terminal")
                                         or any(w in tool_name.casefold() for w in ("shell", "exec", "bash", "run"))):
            return self.inspect_command(command, session_id=session_id, tool_name=tool_name)
        operation = _operation_for_tool(tool_name)
        if operation is None:
            return COMPLIANT
        paths = [args[k] for k in PATH_KEYS if isinstance(args.get(k), str)]
        if operation == "chmod" and any(classify_path(p) == HOOK for p in paths) and HOOK not in self.allow:
            p = next(p for p in paths if classify_path(p) == HOOK)
            return self._record(WorkspaceDecision(False, HOOK_TAMPER, p, operation, "permission change on a hook"),
                                tool_name, session_id)
        return self._record(self._decide(operation, paths), tool_name, session_id)


def _emoji_neighbour(text: str, i: int) -> bool:
    prev = ord(text[i - 1]) if i > 0 else 0
    nxt = ord(text[i + 1]) if i + 1 < len(text) else 0
    return any(c >= 0x1F000 or 0x2600 <= c <= 0x27BF or c == 0xFE0F for c in (prev, nxt))


def scan_workspace_instruction_file(path: str, content: str) -> Optional[WorkspaceDecision]:
    """Hidden directives in an instruction / README file before an agent reads it, or None.

    Flags HTML comments (rendered views hide them), Unicode tag characters,
    zero-width and bidi-control characters. A leading byte-order mark and
    zero-width joiners inside emoji sequences are not flagged.
    """
    text = content if isinstance(content, str) else str(content or "")
    findings: list[str] = []
    m = _HTML_COMMENT_RE.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        findings.append(f"html_comment at line {line}")
    m = _TAG_CHARS_RE.search(text)
    if m:
        findings.append(f"unicode_tag_characters at line {text.count(chr(10), 0, m.start()) + 1}")
    body = text[1:] if text.startswith("﻿") else text
    offset = len(text) - len(body)
    for m in _INVISIBLE_RE.finditer(body):
        findings.append(f"invisible U+{ord(m.group(0)):04X} at line {text.count(chr(10), 0, m.start() + offset) + 1}")
        break
    for m in re.finditer("[‍﻿]", body):
        if m.group(0) == "‍" and _emoji_neighbour(body, m.start()):
            continue
        findings.append(f"invisible U+{ord(m.group(0)):04X} at line {text.count(chr(10), 0, m.start() + offset) + 1}")
        break
    if not findings:
        return None
    return WorkspaceDecision(False, HIDDEN_DIRECTIVE, str(path), "read", "; ".join(findings))


def is_instruction_file(path: str) -> bool:
    """True for agent instruction / skill files (the files ``scan_workspace_instruction_file`` gates in hooks)."""
    norm = normalize_path(path)
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    if parts[-1] in INSTRUCTION_NAMES:
        return True
    return ".cursor" in parts and "rules" in parts
