"""A bounded literal-shell analyzer and an immutable filesystem MODEL.

This module executes nothing. Snapshot checks are NOT filesystem permissions.
Bind resulting intents to descriptor-based operations in a trusted broker,
or use OS-enforced protected mounts for real shell execution. See DESIGN.md.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from types import MappingProxyType

from .common import Denied, scalar_text


@dataclass(frozen=True, slots=True)
class Node:
    kind: str  # dir, file, symlink; other filesystem objects are rejected.
    inode: tuple[int, int] = (0, 0)
    links: int = 1
    target: str = ""


@dataclass(frozen=True, slots=True)
class Resolved:
    path: str
    node: Node | None
    visited: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Intent:
    operation: str
    path: str
    source: str | None = None


@dataclass(slots=True)
class PathBudget:
    remaining: int = 2048

    def spend(self, amount):
        self.remaining -= amount
        if self.remaining < 0:
            raise Denied("PATH_WORK_BUDGET")


def protected(path: str, root="/ws") -> bool:
    """Case-sensitive POSIX policy, deliberately protecting all .git/."""
    parts = path[len(root) + 1:].split("/")
    if any(p in {".mcp.json", "AGENTS.md", "CLAUDE.md", ".cursorrules",
                 ".clinerules"} for p in parts):
        return True
    if any(p in {".git", ".claude", ".cursor", ".vscode", ".idea", ".windsurf"}
           for p in parts):
        return True
    return any(parts[i:i + 2] in [
        [".github", "workflows"], [".github", "copilot-instructions.md"]]
        for i in range(len(parts) - 1))


class Snapshot:
    """Trusted, complete model. Never construct it from caller-supplied JSON.

    A real broker owns all namespace mutations, publishes new generations,
    checks real inode identities, and denies unmodeled objects/mounts.
    """
    def __init__(self, nodes: dict[str, Node], generation=0, root="/ws"):
        if not root.startswith("/") or root.endswith("/") or ".." in root.split("/"):
            raise Denied("ROOT")
        if nodes.get(root, Node("missing")).kind != "dir":
            raise Denied("ROOT_MISSING")
        if len(nodes) > 65536:
            raise Denied("SNAPSHOT_LIMIT")
        self.root = root
        self.generation = generation
        self.nodes = MappingProxyType(dict(nodes))
        self.protected_names = frozenset(p for p in nodes if protected(p, root))
        self.protected_inodes = frozenset(
            n.inode for p, n in nodes.items()
            if n.kind == "file" and p in self.protected_names)

    def _relative(self, path: str) -> list[str]:
        scalar_text(path, 4096)
        if not path or "\0" in path or path.startswith("//"):
            raise Denied("PATH_ENCODING")
        if path == self.root:
            return []
        if path.startswith("/"):
            if not path.startswith(self.root + "/"):
                raise Denied("OUTSIDE_WORKSPACE")
            path = path[len(self.root) + 1:]
        return path.split("/")

    def resolve(self, path: str, cwd: str | None = None, *, create=False,
                budget: PathBudget | None = None) -> Resolved:
        budget = PathBudget() if budget is None else budget
        cwd = self.root if cwd is None else cwd
        # cwd is a broker-pinned canonical physical directory, not $PWD.
        if self.nodes.get(cwd, Node("missing")).kind != "dir":
            raise Denied("CWD")
        current = [] if path.startswith("/") else self._relative(cwd)
        pending = deque(self._relative(path))
        visited = []
        hops = walked = 0
        while pending:
            part = pending.popleft()
            walked += 1
            budget.spend(1 + len(current))
            if walked > 512 or len(current) > 64 or len(part.encode("utf-8")) > 255:
                raise Denied("PATH_COMPONENT_BUDGET")
            if part in {"", "."}:
                continue
            if part == "..":
                if not current:
                    raise Denied("TRAVERSAL_ESCAPE")
                current.pop()
                continue
            candidate = self.root + "/" + "/".join(current + [part])
            budget.spend(len(candidate) // 32)
            visited.append(candidate)
            node = self.nodes.get(candidate)
            if node is None:
                if create and not pending:
                    return Resolved(candidate, None, tuple(visited))
                raise Denied("MISSING_COMPONENT")
            if node.kind == "symlink":
                hops += 1
                if hops > 40:
                    raise Denied("SYMLINK_CYCLE")
                target = self._relative(node.target)
                if node.target.startswith("/"):
                    current = []
                pending.extendleft(reversed(target))
                continue
            if node.kind not in {"file", "dir"}:
                raise Denied("SPECIAL_FILE")
            if pending and node.kind != "dir":
                raise Denied("NOT_DIRECTORY")
            current.append(part)
        result = self.root + ("/" + "/".join(current) if current else "")
        return Resolved(result, self.nodes[result], tuple(visited))

    def _mutation(self, target: Resolved):
        if target.path == self.root or any(
            p in self.protected_names if p in self.nodes else protected(p, self.root)
            for p in target.visited):
            raise Denied("PROTECTED_PATH")
        if target.node is not None:
            if target.node.kind != "file":
                # No recursive/directory mutations in this reference profile.
                raise Denied("DIRECTORY_MUTATION")
            if target.node.inode in self.protected_inodes or target.node.links != 1:
                raise Denied("PROTECTED_OR_SHARED_INODE")

    def check(self, intent: Intent, cwd: str | None = None,
              *, expected_generation: int | None = None,
              budget: PathBudget | None = None) -> Resolved:
        if expected_generation is not None and expected_generation != self.generation:
            raise Denied("STALE_FILESYSTEM_GENERATION")
        op = intent.operation
        cwd = self.root if cwd is None else cwd
        budget = PathBudget() if budget is None else budget
        if op == "read":
            result = self.resolve(intent.path, cwd, budget=budget)
            if result.node.kind != "file":
                raise Denied("READ_NOT_REGULAR")
            return result
        if op == "hardlink":
            raise Denied("HARDLINK_CREATION_DISABLED")
        if op in {"copy", "move"}:
            source = self.resolve(intent.source, cwd, budget=budget)
            if source.node.kind != "file":
                raise Denied("SOURCE_NOT_REGULAR")
            if op == "move":
                self._mutation(source)
            dest = self.resolve(intent.path, cwd, create=True, budget=budget)
            if dest.node is not None and dest.node.kind == "dir":
                basename = intent.source.rstrip("/").rsplit("/", 1)[-1]
                child = self.resolve(dest.path + "/" + basename, cwd, create=True, budget=budget)
                # Preserve protected names traversed while resolving a directory
                # alias; physical basename expansion must not erase this evidence.
                dest = Resolved(child.path, child.node, dest.visited + child.visited)
            self._mutation(dest)
            return dest
        if op == "symlink":
            dest = self.resolve(intent.path, cwd, create=True, budget=budget)
            self._mutation(dest)
            if dest.node is not None:
                raise Denied("LINK_DEST_EXISTS")
            target = intent.source
            if not target.startswith("/"):
                target = dest.path.rsplit("/", 1)[0] + "/" + target
            resolved_target = self.resolve(target, cwd, budget=budget)
            self._mutation(resolved_target)  # No links to protected/shared objects.
            return dest
        if op not in {"write", "append", "chmod", "remove", "edit"}:
            raise Denied("UNMODELED_OPERATION")
        result = self.resolve(intent.path, cwd, create=op in {"write", "append"}, budget=budget)
        self._mutation(result)
        return result

    def check_all(self, intents: tuple[Intent, ...], cwd: str | None = None) -> tuple[Resolved, ...]:
        if len(intents) > 64:
            raise Denied("EFFECT_BUDGET")
        # A flat static union cannot model a namespace change followed by use.
        if len(intents) > 1 and any(i.operation in {"move", "symlink", "hardlink"} for i in intents):
            raise Denied("SEQUENTIAL_NAMESPACE_REVALIDATION_REQUIRED")
        budget = PathBudget()
        return tuple(self.check(i, cwd, budget=budget) for i in intents)


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    quoted: bool = False


OPS = ("&>>", "<<-", "<<<", "&&", "||", ">>", ">|", "<>", "<<",
       "<&", ">&", "&>", ";;", ";", "|", "&", "(", ")", ">", "<")
REDIRS = {">", ">>", ">|", "<", "<>"}
CONNECT = {";", "|", "&&", "||"}


def lex(text: str) -> list[Token]:
    scalar_text(text, 8192)
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in text):
        raise Denied("SHELL_CONTROL")
    out = []
    i = 0
    while i < len(text):
        if len(out) >= 256:
            raise Denied("TOKEN_BUDGET")
        if text[i] in " \t":
            i += 1
            continue
        if text[i] == "\n":
            out.append(Token("op", ";", i, i + 1))
            i += 1
            continue
        op = next((x for x in OPS if text.startswith(x, i)), None)
        if op is not None:
            out.append(Token("op", op, i, i + len(op)))
            i += len(op)
            continue
        start = i
        buf = []
        quoted = False
        while i < len(text) and text[i] not in " \t\n;|&()<>":
            ch = text[i]
            if ch in "'\"":
                quoted = True
                quote = ch
                i += 1
                while i < len(text) and text[i] != quote:
                    ch = text[i]
                    if quote == '"' and ch in ("$", chr(96)):
                        raise Denied("SHELL_EXPANSION")
                    if quote == '"' and ch == "\\":
                        i += 1
                        if i >= len(text):
                            raise Denied("SHELL_ESCAPE")
                        if text[i] not in ('$', chr(96), '"', "\\", "\n"):
                            buf.append("\\")
                        if text[i] != "\n":
                            buf.append(text[i])
                    else:
                        buf.append(ch)
                    i += 1
                if i == len(text):
                    raise Denied("UNTERMINATED_QUOTE")
                i += 1
            elif ch == "\\":
                quoted = True
                i += 1
                if i >= len(text):
                    raise Denied("SHELL_ESCAPE")
                if text[i] != "\n":
                    buf.append(text[i])
                i += 1
            elif ch in "$*?[]{}~#" or ch == chr(96):
                raise Denied("UNSUPPORTED_SHELL_SYNTAX")
            else:
                buf.append(ch)
                i += 1
        out.append(Token("word", "".join(buf), start, i, quoted))
    return out


def command_intents(argv: list[str]) -> list[Intent]:
    if not argv:  # A redirection-only simple command.
        return []
    name, *args = argv
    if name in {":", "true", "false"}:
        if args:
            raise Denied("COMMAND_ARGUMENTS")
        return []
    if name in {"echo", "printf"}:
        return []  # Only stdout; binaries/builtins must be broker-selected.

    def operands(xs):
        if xs[:1] == ["--"]:
            xs = xs[1:]
        if not xs or any(not x or x.startswith("-") for x in xs):
            raise Denied("COMMAND_OPTIONS")
        return xs

    if name == "cat":
        return [Intent("read", p) for p in operands(args)] if args else []
    if name == "tee":
        append = args[:1] == ["-a"]
        if append:
            args = args[1:]
        return [Intent("append" if append else "write", p)
                for p in operands(args)] if args else []
    if name in {"cp", "mv"}:
        args = operands(args)
        if len(args) != 2:
            raise Denied("COPY_MOVE_ARITY")
        return [Intent("copy" if name == "cp" else "move", args[1], args[0])]
    if name == "ln":
        symbolic = args[:1] == ["-s"]
        if symbolic:
            args = args[1:]
        args = operands(args)
        if len(args) != 2:
            raise Denied("LINK_ARITY")
        return [Intent("symlink" if symbolic else "hardlink", args[1], args[0])]
    if name == "chmod":
        args = operands(args)
        if len(args) < 2 or not re.fullmatch(r"0?[0-7]{3}", args[0]):
            raise Denied("CHMOD_PROFILE")
        return [Intent("chmod", p) for p in args[1:]]
    if name == "sed":
        if args[:1] != ["-i"]:
            raise Denied("SED_PROFILE")
        args = operands(args[1:])
        if len(args) < 2 or not re.fullmatch(r"s/[A-Za-z0-9 _-]+/[A-Za-z0-9 _-]*/g?", args[0]):
            raise Denied("SED_SCRIPT")
        return [Intent("edit", p) for p in args[1:]]
    raise Denied("UNMODELED_COMMAND")


def analyze_shell(text: str) -> tuple[Intent, ...]:
    """Parse a literal subset, including (...) group redirections.

    Returns a conservative effect union, NOT an executable program or permit.
    All branches/pipeline members are inspected. Command substitution, dynamic
    words, fd duplication, heredocs, functions and arbitrary options are denied.
    """
    tokens = lex(text)
    if not tokens:
        raise Denied("EMPTY_COMMAND")
    intents = []
    pos = 0
    commands = 0

    def redirection():
        nonlocal pos
        op = tokens[pos].value
        if op not in REDIRS:
            raise Denied("UNSUPPORTED_REDIRECTION")
        pos += 1
        if pos == len(tokens) or tokens[pos].kind != "word":
            raise Denied("REDIRECTION_TARGET")
        intents.append(Intent("read" if op == "<" else
                              "append" if op == ">>" else "write",
                              tokens[pos].value))
        pos += 1

    def sequence(depth=0):
        nonlocal pos, commands
        if depth > 16:
            raise Denied("SHELL_DEPTH")
        while True:
            if pos >= len(tokens):
                raise Denied("MISSING_COMMAND")
            tok = tokens[pos]
            if tok.kind == "op" and tok.value == "(":
                pos += 1
                sequence(depth + 1)
                if pos >= len(tokens) or tokens[pos].value != ")" or tokens[pos].kind != "op":
                    raise Denied("MISSING_GROUP_CLOSE")
                pos += 1
                while pos < len(tokens) and tokens[pos].kind == "op" and tokens[pos].value in REDIRS:
                    redirection()
            else:
                argv = []
                start = pos
                while pos < len(tokens):
                    tok = tokens[pos]
                    if tok.kind == "op":
                        if tok.value in CONNECT or tok.value == ")":
                            break
                        redirection()
                    elif (not tok.quoted and tok.value.isascii() and tok.value.isdigit()
                          and pos + 1 < len(tokens) and tokens[pos + 1].kind == "op"
                          and tokens[pos + 1].value in REDIRS
                          and tok.end == tokens[pos + 1].start):
                        if tok.value not in {"0", "1", "2"}:
                            raise Denied("FD_PROFILE")
                        pos += 1
                        redirection()
                    else:
                        argv.append(tok.value)
                        pos += 1
                if pos == start:
                    raise Denied("MISSING_COMMAND")
                intents.extend(command_intents(argv))
            commands += 1
            if commands > 64 or len(intents) > 64:
                raise Denied("EFFECT_BUDGET")
            if pos == len(tokens) or (tokens[pos].kind == "op" and tokens[pos].value == ")"):
                return
            if tokens[pos].kind != "op" or tokens[pos].value not in CONNECT:
                raise Denied("COMMAND_SEPARATOR")
            separator = tokens[pos].value
            pos += 1
            if separator == ";" and (pos == len(tokens) or
                                      (tokens[pos].kind == "op" and tokens[pos].value == ")")):
                return

    sequence()
    if pos != len(tokens):
        raise Denied("UNEXPECTED_GROUP_CLOSE")
    return tuple(intents)
