"""Inline interpreter and subshell escape guard.

``workspace_config_guard.py`` reads shell redirections and file commands; an
agent can step around it by doing the same work inside an inline
interpreter: ``python -c``, ``node -e``, ``ruby -e``, ``perl -e``,
``php -r``, ``bash -c`` / ``sh -c`` / ``zsh -c``, a heredoc fed to an
interpreter, or a base64 / hex payload decoded straight into a shell. This
guard finds those payloads in a command string and analyses them:

- Python payloads are parsed with ``ast``. String constants, simple
  constant assignments, ``os.path.join`` / ``Path(...) / ...`` /
  concatenation are folded to static paths. File mutations are
  ``open(..., 'w'|'a'|'x'|'+')``, ``Path.write_text`` / ``write_bytes`` /
  ``touch`` / ``unlink`` / ``rename`` / ``symlink_to`` / ``chmod``,
  ``os.remove`` / ``unlink`` / ``rename`` / ``replace`` / ``symlink`` /
  ``chmod`` / ``truncate``, and ``shutil.copy*`` / ``move`` / ``rmtree``.
  Process, network, and dynamic-code calls (``os.system``, ``subprocess``,
  ``pty``, ``socket``, ``urllib.request``, ``http.client``, ``requests``,
  ``ctypes``, ``exec`` / ``eval`` / ``compile`` / ``__import__`` of a
  non-literal) are dangerous primitives. Unparseable Python falls back to
  the regex rules used for the other languages.
- Node, Ruby, Perl, and PHP payloads are read lexically: string literals,
  file-mutation calls (``fs.writeFileSync`` / ``appendFileSync`` /
  ``unlinkSync`` / ``symlinkSync`` ..., ``File.write`` / ``FileUtils``,
  ``open(FH, '>path')`` / ``unlink``, ``file_put_contents`` /
  ``fopen(..., 'w')`` / ``unlink`` / ``symlink``), and process / network /
  eval primitives (``child_process``, ``system``, backticks, ``popen``,
  ``eval``, sockets, HTTP clients).
- ``bash -c`` / ``sh -c`` payloads are checked again as shell commands
  (by ``workspace_config_guard`` and recursively by this guard).

Every mutated path goes through ``workspace_config_guard.classify_path``
(agent config, execution hook, or credential path).

Rule codes:

- ``INTERPRETER_PROTECTED_WRITE``: the payload writes, deletes, renames,
  chmods, or symlinks a protected config / hook / credential path.
- ``INTERPRETER_OBFUSCATED_PIPE``: decoded base64 / hex output reaches a
  shell or interpreter (a pipe, ``$(...)``, ``<(...)``, ``eval``), or inline
  code executes a decoded payload (``exec(base64.b64decode(...))``).
- ``INTERPRETER_DANGEROUS_PRIMITIVE``: the payload calls a process,
  network, or dynamic-code primitive.

Denials are appended to an optional SHA-256 hash-chained log
(``audit_chain.py`` format). Static analysis only: code fetched or
decrypted at run time, or paths computed from runtime values, are not
resolved (a payload with a mutation call and a protected-path literal is
still flagged).
"""
from __future__ import annotations

import ast
import posixpath
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .arg_ast_guard import SENSITIVE_PATH_SUBSTRINGS, canonicalize_path
from .audit_chain import ChainWriter
from .workspace_config_guard import CREDENTIAL, WorkspaceConfigGuard, classify_path

PROTECTED_WRITE = "INTERPRETER_PROTECTED_WRITE"
OBFUSCATED_PIPE = "INTERPRETER_OBFUSCATED_PIPE"
DANGEROUS_PRIMITIVE = "INTERPRETER_DANGEROUS_PRIMITIVE"
RULE_CODES = (PROTECTED_WRITE, OBFUSCATED_PIPE, DANGEROUS_PRIMITIVE)
# System locations a write must never reach (home directories are not here; their dotfiles are classified).
_SYSTEM_WRITE_PREFIXES = ("/etc", "/root", "/boot", "/proc", "/sys", "/var/run/secrets", "/run/secrets",
                          "/usr/bin", "/usr/local/bin", "/bin", "/sbin")

PYTHON, NODE, RUBY, PERL, PHP, SHELL = "python", "node", "ruby", "perl", "php", "shell"
_INTERPRETERS: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|pypy3?)$"), PYTHON, ("-c",)),
    (re.compile(r"^(?:node|nodejs|bun)$"), NODE, ("-e", "--eval", "-p", "--print")),
    (re.compile(r"^ruby$"), RUBY, ("-e",)),
    (re.compile(r"^perl$"), PERL, ("-e", "-E")),
    (re.compile(r"^php(?:\d(?:\.\d)?)?$"), PHP, ("-r",)),
    (re.compile(r"^(?:ba|z|da|k|fi|tc|c)?sh$"), SHELL, ("-c",)),
    (re.compile(r"^(?:pwsh|powershell(?:\.exe)?)$"), SHELL, ("-c", "-command", "-encodedcommand", "-e")),
)
_DECODERS = re.compile(
    r"\bbase64\s+(?:[^|;&]*\s)?(?:-d|--decode|-D)\b|\bxxd\s+(?:[^|;&]*\s)?-r\b|\bopenssl\s+(?:enc\s+)?"
    r"(?:-?base64|-a)\b[^|;&]*-d\b|\bbase32\s+(?:-d|--decode)\b|\bbasenc\b[^|;&]*(?:-d|--decode)\b"
    r"|\bprintf\s+['\"]?(?:\\x[0-9a-fA-F]{2}){4,}|\becho\s+-e\s+['\"]?(?:\\x[0-9a-fA-F]{2}){4,}"
    r"|\b(?:gunzip|zcat|uudecode)\b", re.I)
_SUBST_DECODE = re.compile(
    r"(?:\beval\b|\b(?:ba|z|da)?sh\b|\bpython\d*\b|\bnode\b|\bperl\b|\bphp\b|\bruby\b)[^|;&\n]*?"
    r"(?:\$\(|`|<\()[^)`]*?(?:base64\s+(?:[^|;&)`]*\s)?(?:-d|--decode|-D)|xxd\s+[^)`]*-r|base32\s+(?:-d|--decode))",
    re.I)
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1([^\n]*)\n(.*?)\n[ \t]*\2[ \t]*(?=\n|$)", re.S)
_STRING_RE = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|`((?:[^`\\]|\\.)*)`", re.S)

# Lexical mutation and danger patterns per language. Group "args" holds the call's argument text.
_NODE_FS = r"(?:\bfs|\bfsp|\bfs\.promises|require\(\s*['\"](?:node:)?fs(?:/promises)?['\"]\s*\)(?:\.promises)?)"
_MUTATIONS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    NODE: (
        ("write", re.compile(_NODE_FS + r"\s*\.(?:writeFile|appendFile|createWriteStream|truncate|cp|copyFile|rename|"
                             r"chmod|unlink|rm|rmdir)(?:Sync)?\s*\((?P<args>[^)]*)\)")),
        ("symlink", re.compile(_NODE_FS + r"\s*\.(?:symlink|link)(?:Sync)?\s*\((?P<args>[^)]*)\)")),
    ),
    RUBY: (
        ("write", re.compile(r"\b(?:File|IO)\s*\.\s*(?:write|binwrite|delete|unlink|rename|chmod|truncate)\s*\(?"
                             r"(?P<args>[^)\n;]*)")),
        ("write", re.compile(r"\bFile\s*\.\s*open\s*\((?P<args>[^)]*['\"][wa+][b+]?['\"][^)]*)\)")),
        ("write", re.compile(r"\bFileUtils\s*\.\s*(?:cp|mv|rm|rm_f|rm_rf|touch|chmod|install|copy)\s*\(?"
                             r"(?P<args>[^)\n;]*)")),
        ("symlink", re.compile(r"\b(?:File\s*\.\s*(?:symlink|link)|FileUtils\s*\.\s*ln(?:_s|_sf)?)\s*\(?"
                               r"(?P<args>[^)\n;]*)")),
    ),
    PERL: (
        ("write", re.compile(r"\bopen\s*\(?\s*(?:my\s+)?[\$\w]+\s*,\s*(?P<args>['\"](?:\+?>>?|\+<)[^'\"]*['\"]"
                             r"(?:\s*,\s*['\"][^'\"]*['\"])?)")),
        ("write", re.compile(r"\b(?:unlink|rename|chmod|truncate)\s*\(?(?P<args>[^);\n]*)")),
        ("symlink", re.compile(r"\b(?:symlink|link)\s*\(?(?P<args>[^);\n]*)")),
    ),
    PHP: (
        ("write", re.compile(r"\b(?:file_put_contents|unlink|rename|copy|chmod|touch|rmdir)\s*\((?P<args>[^)]*)\)", re.I)),
        ("write", re.compile(r"\bfopen\s*\((?P<args>[^)]*['\"][wacx]\+?b?['\"][^)]*)\)", re.I)),
        ("symlink", re.compile(r"\b(?:symlink|link)\s*\((?P<args>[^)]*)\)", re.I)),
    ),
}
_MUTATIONS[PYTHON] = (
    ("write", re.compile(r"\bopen\s*\((?P<args>[^)]*['\"][wax]\+?b?['\"][^)]*)\)")),
    ("write", re.compile(r"\.(?:write_text|write_bytes|touch|unlink|rename|replace|chmod)\s*\((?P<args>[^)]*)\)")),
    ("write", re.compile(r"\b(?:os\.(?:remove|unlink|rename|replace|chmod|truncate)|shutil\.(?:copy\w*|move|rmtree))"
                         r"\s*\((?P<args>[^)]*)\)")),
    ("symlink", re.compile(r"\b(?:os\.(?:symlink|link)|\.symlink_to)\s*\((?P<args>[^)]*)\)")),
)
_DANGERS: dict[str, re.Pattern[str]] = {
    PYTHON: re.compile(r"\b(?:os\.(?:system|popen|exec\w*|spawn\w*|fork)|subprocess|pty\.spawn|socket\.|"
                       r"urllib\.request|http\.client|requests\.|ctypes|__import__)\b"),
    NODE: re.compile(r"\bchild_process\b|\b(?:execSync|execFileSync|spawnSync|execFile|spawn|fork)\s*\(|"
                     r"\bnet\.(?:connect|createConnection)\b|\bhttps?\.(?:request|get)\s*\(|\bfetch\s*\(|"
                     r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\(|\bprocess\.binding\b"),
    RUBY: re.compile(r"\b(?:system|exec|spawn|syscall)\s*[\(\s'\"]|`[^`]+`|%x[\{\(\[]|\bIO\.popen\b|\bOpen3\b|"
                     r"\bNet::HTTP\b|\bTCPSocket\b|\bSocket\b|\beval\s*[\(\s'\"]|\bKernel\.(?:system|exec)\b"),
    PERL: re.compile(r"\b(?:system|exec)\s*[\(\s'\"]|`[^`]+`|\bqx[\{\(/!]|\bIO::Socket\b|\bLWP\b|\bHTTP::Tiny\b|"
                     r"\beval\s*[\(\{'\"]|\bSocket\b"),
    PHP: re.compile(r"\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|eval|assert|"
                    r"fsockopen|stream_socket_client|curl_exec)\s*\(|`[^`]+`", re.I),
}
_DECODE_EXEC: dict[str, re.Pattern[str]] = {
    NODE: re.compile(r"\b(?:eval|Function|vm\.run\w*)\s*\([^)]*Buffer\.from\([^)]*['\"](?:base64|hex)['\"]|"
                     r"\b(?:eval|Function)\s*\([^)]*\batob\s*\("),
    RUBY: re.compile(r"\beval\s*\(?[^\n;]*(?:Base64\.\w*decode|unpack1?\s*\(\s*['\"][mH])"),
    PERL: re.compile(r"\beval\s*\(?[^\n;]*(?:decode_base64|pack\s*\(\s*['\"]H)"),
    PHP: re.compile(r"\b(?:eval|assert)\s*\([^;]*(?:base64_decode|hex2bin|gzinflate|str_rot13)\s*\(", re.I),
    PYTHON: re.compile(r"\b(?:exec|eval|compile)\s*\([^\n]*(?:b64decode|b32decode|a85decode|fromhex|"
                       r"codecs\.decode|zlib\.decompress|unhexlify)"),
}

_PY_DANGER_CALLS = frozenset({
    "os.system", "os.popen", "os.fork", "os.forkpty", "pty.spawn", "socket.socket", "socket.create_connection",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.request", "requests.Session", "ctypes.CDLL", "ctypes.cdll.LoadLibrary",
    "importlib.import_module", "ftplib.FTP", "smtplib.SMTP", "telnetlib.Telnet", "paramiko.SSHClient",
})
_PY_DANGER_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn", "asyncio.create_subprocess")
_PY_WRITE_FUNCS = {"os.remove": (0,), "os.unlink": (0,), "os.rmdir": (0,), "os.rename": (0, 1),
                   "os.replace": (0, 1), "os.chmod": (0,), "os.truncate": (0,), "os.makedirs": (0,),
                   "shutil.copy": (1,), "shutil.copy2": (1,), "shutil.copyfile": (1,), "shutil.copytree": (1,),
                   "shutil.move": (0, 1), "shutil.rmtree": (0,)}
_PY_LINK_FUNCS = {"os.symlink": (0, 1), "os.link": (0, 1)}
_PY_PATH_METHODS_WRITE = frozenset({"write_text", "write_bytes", "touch", "unlink", "rename", "replace", "chmod",
                                    "rmdir", "mkdir"})
_PY_PATH_METHODS_LINK = frozenset({"symlink_to", "hardlink_to", "link_to"})
_DECODE_FUNCS = ("b64decode", "b32decode", "b85decode", "a85decode", "fromhex", "unhexlify", "decompress",
                 "codecs.decode", "urlsafe_b64decode", "decodebytes")


@dataclass(frozen=True)
class InterpreterDecision:
    allowed: bool
    rule_code: str
    language: str = ""
    path: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "language": self.language,
                "path": self.path, "detail": self.detail}


CLEAN = InterpreterDecision(True, "INTERPRETER_CLEAN")


# --- shell parsing ------------------------------------------------------------------

def _split(command: str, seps: str) -> list[str]:
    """Split on unquoted separator characters (each ``seps`` character ends a part)."""
    parts, buf, quote, i = [], [], "", 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                buf.append(command[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in seps:
            parts.append("".join(buf))
            buf = []
            while i + 1 < len(command) and command[i + 1] == ch and ch in "&|":
                i += 1
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p for p in parts if p.strip()]


def _pipeline_stages(pipeline: str) -> list[str]:
    """Stages of one pipeline: split on unquoted single ``|`` (``||`` is a list operator, not a pipe)."""
    stages, buf, quote, i = [], [], "", 0
    while i < len(pipeline):
        ch = pipeline[i]
        if quote:
            if ch == quote:
                quote = ""
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == "|" and i + 1 < len(pipeline) and pipeline[i + 1] == "|":
            stages = []  # the pipe chain restarts after ||
            buf = []
            i += 2
            continue
        elif ch == "|":
            stages.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    stages.append("".join(buf))
    return [s for s in stages if s.strip()]


def _words(segment: str) -> list[str]:
    try:
        words = shlex.split(segment, posix=True)
    except ValueError:
        words = segment.split()
    i = 0
    while i < len(words) and (words[i] in ("sudo", "env", "command", "exec", "nohup", "time", "doas", "xargs")
                              or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i])):
        i += 1
    return words[i:]


def _interpreter(word: str) -> Optional[tuple[str, tuple[str, ...]]]:
    name = posixpath.basename(word).casefold()
    for pattern, lang, flags in _INTERPRETERS:
        if pattern.match(name):
            return lang, flags
    return None


def inline_payloads(command: str) -> tuple[list[tuple[str, str]], list[str]]:
    """``([(language, code)], [obfuscated-pipe details])`` found in one shell command."""
    payloads: list[tuple[str, str]] = []
    pipes: list[str] = []
    heredocs: list[tuple[int, str]] = []

    def _take_heredoc(m: re.Match) -> str:
        heredocs.append((m.start(), m.group(4)))
        return f"<<{m.group(2)}{m.group(3)}\n"  # keep the rest of the line (``| node``)

    stripped = _HEREDOC_RE.sub(_take_heredoc, command)
    m = _SUBST_DECODE.search(stripped)
    if m:
        pipes.append(f"decoded payload executed through substitution: {m.group(0)[:80]}")
    for pipeline in _split(stripped, ";&\n"):
        stages = _pipeline_stages(pipeline)
        decoded_upstream = False
        heredoc_body = next((body for pos, body in heredocs if f"<<" in pipeline), None)
        for idx, stage in enumerate(stages):
            words = _words(stage)
            if not words:
                continue
            interp = _interpreter(words[0])
            if interp is None:
                if words[0] == "eval" and decoded_upstream:
                    pipes.append("decoded output passed to eval")
                if _DECODERS.search(stage):
                    decoded_upstream = True
                continue
            lang, flags = interp
            args = words[1:]
            code = None
            for i, a in enumerate(args):
                low = a.casefold()
                if low in flags or (lang == PYTHON and re.fullmatch(r"-[A-Za-z]*c", a)):
                    code = args[i + 1] if i + 1 < len(args) else ""
                    break
            reads_stdin = code is None and (not [a for a in args if not a.startswith("-")] or "-" in args)
            if code is not None:
                payloads.append((lang, code))
            elif "<<" in stage and heredoc_body is not None:
                payloads.append((lang, heredoc_body))
            elif reads_stdin and heredoc_body is not None and any("<<" in s for s in stages[:idx]):
                payloads.append((lang, heredoc_body))  # cat <<EOF | node
            if idx > 0 and decoded_upstream and (reads_stdin or code is None):
                pipes.append(f"decoded output piped into {posixpath.basename(words[0])}")
            if idx > 0 and reads_stdin and not decoded_upstream and heredoc_body is None:
                # cat file | python -  : the upstream text is the program
                upstream = " | ".join(stages[:idx])
                lit = _STRING_RE.findall(upstream)
                if lit:
                    payloads.append((lang, " ".join("".join(t) for t in lit)))
            if _DECODERS.search(stage):
                decoded_upstream = True
    return payloads, pipes


# --- Python payloads ------------------------------------------------------------------

class _PyAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.consts: dict[str, str] = {}
        self.literals: list[str] = []
        self.writes: list[tuple[str, Optional[str]]] = []  # (op, path or None when dynamic)
        self.dangers: list[str] = []
        self.decode_exec = False

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            if a.name.split(".")[0] in ("subprocess", "pty", "socket", "ctypes", "requests", "paramiko"):
                self.dangers.append(f"import {a.name}")
            if a.name.startswith(("urllib.request", "http.client")):
                self.dangers.append(f"import {a.name}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}"
        if mod.split(".")[0] in ("subprocess", "pty", "socket", "ctypes", "requests", "paramiko") or \
                mod.startswith(("urllib.request", "http.client")):
            self.dangers.append(f"from {mod} import")

    def visit_Assign(self, node: ast.Assign) -> None:
        value = self._static(node.value)
        if value is not None:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.consts[t.id] = value
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.literals.append(node.value)

    def _qualname(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._qualname(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._qualname(node.func)
        return ""

    def _static(self, node: Optional[ast.AST]) -> Optional[str]:
        """Constant-fold a path expression, or None when it depends on runtime values."""
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return node.value.decode("utf-8", "replace") if isinstance(node.value, bytes) else node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                elif isinstance(v, ast.FormattedValue) and (s := self._static(v.value)) is not None:
                    parts.append(s)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            left, right = self._static(node.left), self._static(node.right)
            if left is None or right is None:
                return None
            return f"{left}/{right}" if isinstance(node.op, ast.Div) else left + right
        if isinstance(node, ast.Call):
            name = self._qualname(node.func)
            args = [self._static(a) for a in node.args]
            if name.endswith(("path.join", "PurePath", "Path", "PosixPath", "WindowsPath", "joinpath")) and \
                    args and all(a is not None for a in args):
                base = self._static(node.func.value) if name.endswith("joinpath") and \
                    isinstance(node.func, ast.Attribute) else None
                return posixpath.join(*([base] if base else []), *args)  # type: ignore[arg-type]
            if name.endswith(("expanduser", "abspath", "realpath", "normpath", "fspath", "str")) and \
                    len(args) == 1 and args[0] is not None:
                return args[0]
        return None

    def visit_Call(self, node: ast.Call) -> None:
        name = self._qualname(node.func)
        short = name.rsplit(".", 1)[-1]
        if name in _PY_DANGER_CALLS or name.startswith(_PY_DANGER_PREFIXES):
            self.dangers.append(name)
        if short in ("exec", "eval", "compile", "__import__") and isinstance(node.func, ast.Name):
            arg = node.args[0] if node.args else None
            if any(isinstance(n, ast.Call) and any(d in self._qualname(n.func) for d in _DECODE_FUNCS)
                   for n in ast.walk(arg) if arg is not None):
                self.decode_exec = True
            elif not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                self.dangers.append(f"{short}() of a non-literal")
        if short == "open" and (isinstance(node.func, ast.Name) or name in ("io.open", "codecs.open", "os.open")):
            mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"),
                                                                 None)
            mode_s = self._static(mode) if mode is not None else "r"
            flags_write = name == "os.open" and any(
                f in ast.unparse(node) for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"))
            if (mode_s is not None and re.search(r"[wax+]", mode_s)) or flags_write or (mode is not None and mode_s is None):
                self.writes.append(("write", self._static(node.args[0]) if node.args else None))
        if name in _PY_WRITE_FUNCS:
            for i in _PY_WRITE_FUNCS[name]:
                self.writes.append(("write", self._static(node.args[i]) if len(node.args) > i else None))
        if name in _PY_LINK_FUNCS:
            for i in _PY_LINK_FUNCS[name]:
                self.writes.append(("symlink", self._static(node.args[i]) if len(node.args) > i else None))
        if isinstance(node.func, ast.Attribute) and node.func.attr in (_PY_PATH_METHODS_WRITE | _PY_PATH_METHODS_LINK):
            target = self._static(node.func.value)
            op = "symlink" if node.func.attr in _PY_PATH_METHODS_LINK else "write"
            if target is not None or name.split(".")[0] in ("Path", "pathlib") or "Path" in ast.unparse(node.func.value):
                self.writes.append((op, target))
                for a in node.args:
                    if (s := self._static(a)) is not None and node.func.attr in ("rename", "replace", "symlink_to"):
                        self.writes.append((op, s))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "open" and len(node.args) >= 1:
            mode_s = self._static(node.args[0])
            if mode_s and re.search(r"[wax+]", mode_s):
                self.writes.append(("write", self._static(node.func.value)))
        self.generic_visit(node)


# --- the guard ------------------------------------------------------------------------

def _lexical(lang: str, code: str) -> tuple[list[tuple[str, Optional[str]]], list[str], list[str], bool]:
    """(writes, literals, dangers, decode_exec) for a non-Python (or unparseable Python) payload."""
    literals = ["".join(t) for t in _STRING_RE.findall(code)]
    writes: list[tuple[str, Optional[str]]] = []
    for op, pattern in _MUTATIONS.get(lang, ()):
        for m in pattern.finditer(code):
            args = m.group("args")
            lits = ["".join(t) for t in _STRING_RE.findall(args)]
            if lang == PERL:
                lits = [re.sub(r"^\s*(?:\+?>>?|\+<)\s*", "", lit) for lit in lits]
                lits = [lit for lit in lits if lit and not re.fullmatch(r"\+?>>?|\+<", lit)]
            lits = [lit for lit in lits if not re.fullmatch(r"[wax]\+?b?|[rwa]b?\+?|utf-?8|base64|hex", lit, re.I)]
            if lits:
                writes += [(op, lit) for lit in lits]
            else:
                writes.append((op, None))
    danger = _DANGERS.get(lang)
    dangers = [m.group(0).strip() for m in danger.finditer(code)] if danger else []
    decode = _DECODE_EXEC.get(lang)
    return writes, literals, dangers, bool(decode and decode.search(code))


class InterpreterExecGuard:
    """Static analysis of inline interpreter payloads in shell commands and code-carrying tool calls."""

    def __init__(self, *, allow: Iterable[str] = (), audit_log: Optional[Path] = None, max_depth: int = 3) -> None:
        self.allow = frozenset(a for a in allow if a in ("config", "hook"))
        self.workspace = WorkspaceConfigGuard(allow=self.allow)
        self.chain = ChainWriter(Path(audit_log)) if audit_log else None
        self.max_depth = max_depth

    def _protected(self, path: str) -> Optional[str]:
        cls = classify_path(path)
        if cls is None:
            canon, _reasons = canonicalize_path(path)
            low = canon.casefold()
            if any(sub in low for sub in SENSITIVE_PATH_SUBSTRINGS) or \
                    any(low == p or low.startswith(p + "/") for p in _SYSTEM_WRITE_PREFIXES):
                cls = CREDENTIAL
        if cls is None or cls in self.allow:
            return None
        return cls

    def analyze_code(self, lang: str, code: str, *, depth: int = 0) -> InterpreterDecision:
        """Check one inline payload in ``lang`` (python, node, ruby, perl, php, shell)."""
        if lang == SHELL:
            if depth >= self.max_depth:
                return CLEAN
            ws = self.workspace.inspect_command(code)
            if not ws.allowed:
                code_ = PROTECTED_WRITE if ws.rule_code != "WORKSPACE_COMPLIANT" else ws.rule_code
                return InterpreterDecision(False, code_, SHELL, ws.path, f"shell payload: {ws.detail}")
            return self.inspect_command(code, depth=depth + 1, record=False)
        writes: list[tuple[str, Optional[str]]]
        if lang == PYTHON:
            try:
                tree = ast.parse(code)
            except (SyntaxError, ValueError):
                writes, literals, dangers, decode_exec = _lexical(PYTHON, code)
            else:
                an = _PyAnalyzer()
                an.visit(tree)
                writes, literals, dangers, decode_exec = an.writes, an.literals, an.dangers, an.decode_exec
        else:
            writes, literals, dangers, decode_exec = _lexical(lang, code)
        if decode_exec:
            return InterpreterDecision(False, OBFUSCATED_PIPE, lang, "", "inline code executes a decoded payload")
        for op, path in writes:
            if path is None:
                continue
            cls = self._protected(path)
            if cls is not None or (op == "symlink" and classify_path(path) is not None):
                return InterpreterDecision(False, PROTECTED_WRITE, lang, path,
                                           f"{op} of a {cls or classify_path(path)} path")
        if any(p is None for _, p in writes):
            for lit in literals:
                cls = self._protected(lit)
                if cls is not None and len(lit) < 512:
                    return InterpreterDecision(False, PROTECTED_WRITE, lang, lit,
                                               f"mutation call with a computed path and a {cls} path literal")
        if dangers:
            return InterpreterDecision(False, DANGEROUS_PRIMITIVE, lang, "", f"{dangers[0][:80]}")
        return CLEAN

    def inspect_command(self, command: str, *, depth: int = 0, record: bool = True,
                        session_id: str = "", tool_name: str = "Bash") -> InterpreterDecision:
        payloads, pipes = inline_payloads(str(command))
        decision = CLEAN
        if pipes:
            decision = InterpreterDecision(False, OBFUSCATED_PIPE, SHELL, "", pipes[0])
        else:
            for lang, code in payloads:
                decision = self.analyze_code(lang, code, depth=depth)
                if not decision.allowed:
                    break
        if not decision.allowed and record:
            self._record(decision, tool_name, session_id)
        return decision

    def inspect_tool_call(self, tool_name: str, args: Any, *, session_id: str = "") -> InterpreterDecision:
        """Check a shell tool's ``command`` or a code-execution tool's ``code`` argument."""
        if not isinstance(args, dict):
            return CLEAN
        for key in ("command", "cmd", "script"):
            if isinstance(args.get(key), str):
                return self.inspect_command(args[key], session_id=session_id, tool_name=tool_name)
        code = args.get("code") or args.get("source")
        if isinstance(code, str):
            name = tool_name.casefold()
            lang = next((lang for lang, words in ((PYTHON, ("python", "py")), (NODE, ("node", "javascript", "js")),
                                                 (RUBY, ("ruby",)), (PERL, ("perl",)), (PHP, ("php",)),
                                                 (SHELL, ("bash", "shell", "sh")))
                         if any(re.search(rf"(?:^|[._\-]){w}(?:$|[._\-])", name) for w in words)), None)
            lang = lang or str(args.get("language") or args.get("lang") or "").casefold() or None
            if lang in (PYTHON, NODE, RUBY, PERL, PHP, SHELL):
                d = self.analyze_code(lang, code)
                if not d.allowed:
                    self._record(d, tool_name, session_id)
                return d
        return CLEAN

    def _record(self, d: InterpreterDecision, tool_name: str, session_id: str) -> None:
        if self.chain is not None:
            self.chain.append({"ts": round(time.time(), 6), "kind": d.rule_code, "session_id": session_id,
                               "tool": tool_name, "verdict": "DENY", "rule_code": d.rule_code,
                               "language": d.language, "path": d.path, "detail": d.detail[:200]})
