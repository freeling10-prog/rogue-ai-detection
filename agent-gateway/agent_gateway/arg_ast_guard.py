"""Lexical and canonical argument firewall (approximate AML.T0051 / AML.T0053).

Stops a tool call from escalating inside its own arguments: turning an
``internal_read`` tool into a write or an arbitrary-file read, chaining shell
commands, splitting HTTP headers, or smuggling a mutating SQL statement into a
read-only query. All checks are deterministic string / lexical analysis; no
command, query, or file access is performed.

Three families:

- **Path canonicalization** on path-like arguments: directory traversal
  (``../``, ``..\\``, URL-encoded ``%2e%2e%2f``, double-encoded, Unicode
  overlong), nested sequences that become traversal after one naive
  ``../`` strip (``....//``), NUL bytes, UNC / device paths, invisible
  Unicode format characters (``/etc/pass\u200dwd``), NFKC compatibility
  spellings, and absolute paths outside the allowed roots (``/etc``,
  ``/proc``, ``~/.ssh`` ...).
- **Command and header injection**: unapproved shell metacharacter chaining
  (``;``, ``&&``, ``||``, ``|``, backtick, ``$()``, ``${}``, newline) in
  command / exec arguments, and CRLF header splitting in header-like
  arguments.
- **Read-only query enforcement**: for tools classified ``internal_read`` or
  ``sensitive_read``, any mutating or file-exfil keyword (``INTO OUTFILE``,
  ``COPY ... TO``, ``ATTACH DATABASE``, ``pg_read_file``, ``xp_cmdshell``,
  ``LOAD_FILE``, stacked mutating statements) is rejected.

``inspect_call(tool_name, arguments, tool_class)`` returns the first finding
or ``None``.
"""
from __future__ import annotations

import posixpath
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterator, Optional

ATLAS_INJECTION = "AML.T0051"
ATLAS_SSRF = "AML.T0053"

PATH_KEYS = frozenset({"path", "file", "filepath", "file_path", "filename", "dir", "directory",
                       "src", "dest", "destination", "source", "target", "location", "key", "object"})
COMMAND_KEYS = frozenset({"cmd", "command", "exec", "shell", "script", "run", "argv", "args",
                          "entrypoint", "program", "bin"})
HEADER_KEYS = frozenset({"header", "headers", "x_header", "user_agent", "useragent", "referer",
                         "referrer", "cookie", "authorization", "set_cookie", "content_type", "host"})
QUERY_KEYS = frozenset({"query", "sql", "q", "statement", "stmt", "filter", "where", "expr", "cql", "kql"})

SENSITIVE_PATH_PREFIXES = (
    "/etc", "/proc", "/sys", "/root", "/var/run/secrets", "/run/secrets",
    "/boot", "/dev", "/.aws", "/.ssh", "/home", "/users",
)
SENSITIVE_PATH_SUBSTRINGS = (
    ".ssh/", ".aws/credentials", ".aws/config", ".kube/config", ".docker/config",
    ".npmrc", ".netrc", "id_rsa", "id_ed25519", "shadow", "/.env", "web.config",
    ".git/config", "authorized_keys", ".gnupg/",
)
_WINDOWS_SENSITIVE = ("\\windows\\", "\\system32\\", "\\sam", "boot.ini")

_SHELL_META_RE = re.compile(r"(?:\|\||&&|[;&|`]|\$\(|\$\{|<\(|>\(|\n|\r)")
_CRLF_RE = re.compile(r"[\r\n]|%0d|%0a| | ", re.I)
_DANGEROUS_PATH_RE = re.compile(r"\x00|%00")
_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")

_SQL_FORBIDDEN = (
    ("into_outfile", re.compile(r"\binto\s+(?:out|dump)file\b", re.I)),
    ("copy_to", re.compile(r"\bcopy\b.+\bto\b", re.I | re.S)),
    ("attach_database", re.compile(r"\battach\s+database\b", re.I)),
    ("pg_read_file", re.compile(r"\bpg_(?:read|ls|stat)_(?:file|dir)\b", re.I)),
    ("pg_large_object", re.compile(r"\blo_(?:import|export)\b", re.I)),
    ("xp_cmdshell", re.compile(r"\bxp_cmdshell\b", re.I)),
    ("load_file", re.compile(r"\bload_file\s*\(", re.I)),
    ("load_data_infile", re.compile(r"\bload\s+data\b.+\binfile\b", re.I | re.S)),
    ("sqlite_load_extension", re.compile(r"\bload_extension\s*\(", re.I)),
)
_SQL_MUTATION_RE = re.compile(
    r"\b(?:insert|update|delete|drop|alter|create|truncate|replace|merge|grant|revoke|call|exec(?:ute)?)\b",
    re.I,
)
_READ_CLASSES = frozenset({"internal_read", "sensitive_read"})
_MAX_DECODE = 5
_MAX_STR = 8192


@dataclass
class ArgFinding:
    kind: str
    key: str
    detail: str
    atlas: str = ATLAS_INJECTION

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "arg": self.key[:120], "detail": self.detail[:200],
                "atlas": self.atlas, "atlas_approximate": True}


def _fully_unquote(text: str) -> str:
    """Resolve repeated percent-encoding so %252e%252e collapses to ``..``."""
    prev = text
    for _ in range(_MAX_DECODE):
        cur = urllib.parse.unquote(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def canonicalize_path(raw: str) -> tuple[str, list[str]]:
    """(canonical POSIX path, reasons). Reasons name every unsafe trait found."""
    reasons: list[str] = []
    if _DANGEROUS_PATH_RE.search(raw):
        reasons.append("nul_byte")
    decoded = _fully_unquote(raw)
    if decoded != raw and _DANGEROUS_PATH_RE.search(decoded):
        reasons.append("encoded_nul_byte")
    stripped = "".join(ch for ch in decoded if unicodedata.category(ch) != "Cf")
    if stripped != decoded:
        reasons.append("invisible_format_character")
    # Analyze the compatibility-folded form (fullwidth solidus, dots, ...).
    decoded = unicodedata.normalize("NFKC", stripped)
    unified = decoded.replace("\\", "/")
    if not _TRAVERSAL_RE.search(unified) and _TRAVERSAL_RE.search(unified.replace("../", "")):
        reasons.append("nested_traversal_sequence")
    low = decoded.lower()
    if any(w in low.replace("/", "\\") for w in _WINDOWS_SENSITIVE):
        reasons.append("windows_system_path")
    if re.match(r"^(?:[a-zA-Z]:|//|\\\\)", decoded) or decoded.startswith("\\\\"):
        if decoded.startswith(("//", "\\\\")):
            reasons.append("unc_path")
    if _TRAVERSAL_RE.search(unified) or ".." in unified.split("/"):
        reasons.append("directory_traversal")
    # Resolve the traversal to see where it actually lands.
    collapsed = posixpath.normpath(unified)
    norm = collapsed.lower().rstrip("/")
    if collapsed.startswith("/"):
        if any(norm == p or norm.startswith(p + "/") for p in SENSITIVE_PATH_PREFIXES):
            reasons.append("sensitive_system_path")
    if any(sub in norm for sub in SENSITIVE_PATH_SUBSTRINGS):
        reasons.append("sensitive_system_path")
    return collapsed, sorted(set(reasons))


def _leaf(key: str) -> str:
    return key.rsplit(".", 1)[-1].split("[", 1)[0].lower()


def _iter_leaves(obj: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    if depth > 10:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:128]:
            key = f"{prefix}.{k}" if prefix else str(k)
            yield from _iter_leaves(v, key, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(list(obj)[:128]):
            yield from _iter_leaves(v, f"{prefix}[{i}]", depth + 1)
    else:
        yield prefix, obj


def _check_value(key: str, value: str, tool_class: str) -> Optional[ArgFinding]:
    leaf = _leaf(key)
    value = value[:_MAX_STR]
    if leaf in PATH_KEYS or ("path" in leaf) or ("file" in leaf):
        _canon, reasons = canonicalize_path(value)
        if reasons:
            return ArgFinding("path_traversal", key, ",".join(reasons), ATLAS_SSRF)
    if leaf in COMMAND_KEYS:
        m = _SHELL_META_RE.search(value)
        if m:
            return ArgFinding("command_injection", key, f"shell metacharacter {m.group(0)!r}")
    if leaf in HEADER_KEYS or leaf.startswith("x_") or leaf.endswith("_header"):
        if _CRLF_RE.search(value):
            return ArgFinding("header_injection", key, "CRLF / line separator in header value")
    if tool_class in _READ_CLASSES and (leaf in QUERY_KEYS or _looks_like_sql(value)):
        hit = _scan_readonly_query(value)
        if hit:
            return ArgFinding("readonly_query_violation", key, hit)
    return None


def _looks_like_sql(value: str) -> bool:
    return bool(re.search(r"\b(?:select|with|copy|attach|pragma|insert|update|delete|drop)\b", value, re.I)
                and len(value) <= _MAX_STR)


def _scan_readonly_query(value: str) -> Optional[str]:
    for name, rx in _SQL_FORBIDDEN:
        if rx.search(value):
            return name
    # Stacked statements: a semicolon that separates two non-empty statements,
    # where a later one mutates. Trailing-semicolon single statements are fine.
    parts = [p.strip() for p in _split_sql(value) if p.strip()]
    if len(parts) > 1 and any(_SQL_MUTATION_RE.match(p) or _SQL_MUTATION_RE.search(p) for p in parts[1:]):
        return "stacked_mutating_statement"
    return None


def _split_sql(value: str) -> list[str]:
    """Split on semicolons that are not inside single/double quotes."""
    out, buf, quote = [], [], ""
    for ch in value:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ";":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def inspect_call(tool_name: str, arguments: Any, tool_class: str = "") -> Optional[dict]:
    """First argument-firewall finding for a call, or ``None``."""
    for key, value in _iter_leaves(arguments):
        if isinstance(value, str) and value:
            finding = _check_value(key, value, tool_class)
            if finding is not None:
                return {"tool": tool_name, **finding.as_dict()}
    return None
