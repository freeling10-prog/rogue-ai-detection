"""Python mirror of ``php_defense_guard.php`` (request input validation for PHP apps).

``php_defense_guard.php`` is a drop-in request input check for Laravel,
WordPress, or plain PHP (7.4 or later). This module applies the same
patterns to a request dictionary, so the rules can be tested, replayed over
captured requests, and kept in step with the PHP side
(``tests/test_php_defense.py`` runs both on the same fixtures when a ``php``
binary is available).

Every string value and every key in the request parameters (``$_GET``,
``$_POST``, ``$_COOKIE`` on the PHP side), nested to any depth, is checked as
received and once more after URL-decoding, which catches double-encoded
input. Rules, first match wins:

- ``PHP_SQLI_UNION``: ``UNION [ALL|DISTINCT] SELECT``, including with
  inline ``/**/`` comments between the words.
- ``PHP_SQLI_TAUTOLOGY``: ``OR 1=1`` / ``' OR 'a'='a`` style tautologies.
- ``PHP_PATH_TRAVERSAL``: two or more ``../`` or ``..\\`` segments.
- ``PHP_DESERIALIZE_DENIED``: a serialized PHP object (``O:<n>:"Class":<n>:{``
  or ``C:...``), the input that ``unserialize()`` turns into an object.
- ``PHP_RCE_EVAL``: a call to ``eval``, ``assert``, ``system``, ``exec``,
  ``shell_exec``, ``passthru``, ``popen``, ``proc_open``, or
  ``create_function``.

``excluded_keys`` names parameters that are not inspected at all (for
example a site search box, ``s`` or ``q``); a name also covers everything
nested under it (``s`` covers ``s[...]``). ``log_only`` records the finding
(verdict ``LOG_ONLY``) without enforcing it: the PHP class returns the
finding instead of answering 403. Both default to off.

Denied requests are appended to a SHA-256 hash-chained JSONL log
(``audit_chain.py`` format: ``seq``, ``prev_hash``, ``entry_hash``) holding
the rule code, the parameter name, and a SHA-256 of the offending value,
never the value itself. The PHP class writes the same format, so
``verify_chain_file`` checks either log.

These are lexical input checks. They complement parameterized queries,
``allowed_classes => false`` on ``unserialize()``, and disabled shell
functions; they do not replace them. A pattern list will miss encodings it
does not know and can deny unusual benign input.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .audit_chain import ChainWriter

# (rule code, pattern). Keep in step with RULES in php_defense_guard.php; the
# pattern strings are valid in both PCRE and Python ``re``.
RULES: tuple[tuple[str, str], ...] = (
    ("PHP_SQLI_UNION", r"\bUNION(?:\s|/\*.*?\*/)+(?:ALL(?:\s|/\*.*?\*/)+|DISTINCT(?:\s|/\*.*?\*/)+)?SELECT\b"),
    ("PHP_SQLI_TAUTOLOGY",
     r"""\b(?:OR|AND)\s+(?:\d+\s*=\s*\d+|(['"])[^'"]*\1\s*=\s*['"])"""),
    ("PHP_PATH_TRAVERSAL", r"(?:\.\.[/\\]){2,}"),
    ("PHP_DESERIALIZE_DENIED", r"""\b[OC]:\d+:"[A-Za-z0-9_\\]+":\d+:\{"""),
    ("PHP_RCE_EVAL", r"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|create_function)\s*\("),
)
_COMPILED = tuple((code, re.compile(pat, re.IGNORECASE | re.DOTALL)) for code, pat in RULES)
RULE_CODES = tuple(code for code, _ in RULES)
MAX_VALUE_CHARS = 65_536
COMPLIANT = "COMPLIANT"


@dataclass(frozen=True)
class PhpDefenseDecision:
    allowed: bool
    rule_code: str
    field: str = ""
    value_sha256: str = ""
    enforced: bool = True  # False when a guard in log_only mode recorded the finding

    @property
    def verdict(self) -> str:
        if self.allowed:
            return "ALLOW"
        return "DENY" if self.enforced else "LOG_ONLY"

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule_code": self.rule_code, "field": self.field,
                "value_sha256": self.value_sha256, "enforced": self.enforced, "verdict": self.verdict}


def _leaves(obj: Any, prefix: str = "", excluded: frozenset = frozenset()) -> Iterable[tuple[str, str]]:
    """``(field, text)`` for every key and string value, nested keys joined PHP-style (``a[b]``).

    A field whose name is in ``excluded`` is skipped together with everything under it.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            name = f"{prefix}[{key}]" if prefix else key
            if name in excluded:
                continue
            yield name, key
            yield from _leaves(v, name, excluded)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            name = f"{prefix}[{i}]"
            if name in excluded:
                continue
            yield from _leaves(v, name, excluded)
    elif isinstance(obj, (str, bytes)):
        text = obj.decode("utf-8", "replace") if isinstance(obj, bytes) else obj
        yield prefix, text
    elif obj is not None and not isinstance(obj, bool):
        yield prefix, str(obj)


def match_value(text: str) -> Optional[str]:
    """Rule code for one input string (as received, then URL-decoded once), or None."""
    text = text[:MAX_VALUE_CHARS]
    forms = [text]
    decoded = urllib.parse.unquote(text)
    if decoded != text:
        forms.append(decoded)
    for code, pattern in _COMPILED:
        if any(pattern.search(f) for f in forms):
            return code
    return None


def inspect_params(params: Any, excluded_keys: Iterable[str] = ()) -> PhpDefenseDecision:
    """Check request parameters (``$_GET`` + ``$_POST`` + ``$_COOKIE``) without logging.

    ``excluded_keys``: parameter names (``s``, or ``filter[q]`` for a nested one) left uninspected.
    """
    for field, text in _leaves(params, "", frozenset(str(k) for k in excluded_keys)):
        code = match_value(text)
        if code is not None:
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            return PhpDefenseDecision(False, code, field, digest)
    return PhpDefenseDecision(True, COMPLIANT)


class PhpDefenseGuard:
    """Request validator with a hash-chained violation log, mirroring ``AgentGate\\PhpDefenseGuard``."""

    def __init__(self, audit_log: Path, *, log_allowed: bool = False, excluded_keys: Iterable[str] = (),
                 log_only: bool = False) -> None:
        self.chain = ChainWriter(Path(audit_log))
        self.log_allowed = log_allowed
        self.excluded_keys = tuple(str(k) for k in excluded_keys)
        self.log_only = log_only

    def inspect(self, request: dict) -> PhpDefenseDecision:
        """Check a request dictionary and log a denial.

        ``request`` holds ``get`` / ``post`` / ``cookie`` parameter dictionaries
        and optional ``uri``, ``method``, ``client_ip``. A dictionary without
        those keys is treated as the parameters themselves.
        """
        sections = ("get", "post", "cookie")
        if any(k in request for k in sections):
            decision = PhpDefenseDecision(True, COMPLIANT)
            for section in sections:
                decision = inspect_params(request.get(section) or {}, self.excluded_keys)
                if not decision.allowed:
                    break
        else:
            decision = inspect_params(request, self.excluded_keys)
        if not decision.allowed and self.log_only:
            decision = PhpDefenseDecision(False, decision.rule_code, decision.field, decision.value_sha256,
                                          enforced=False)
        if not decision.allowed or self.log_allowed:
            self.chain.append({
                "ts": round(time.time(), 6),
                "kind": "php_defense",
                "uri": str(request.get("uri") or ""),
                "method": str(request.get("method") or ""),
                "client_ip": str(request.get("client_ip") or ""),
                "verdict": decision.verdict,
                "rule_code": decision.rule_code,
                "field": decision.field,
                "value_sha256": decision.value_sha256,
            })
        return decision


def sarif_report(audit_log: Path) -> dict:
    """Audit-report shape for ``sarif_export.build_sarif`` from a PHP Defense log (either language).

    One ``gateway_findings`` row per logged finding; allowed entries are left out.
    """
    rows = []
    for line in Path(audit_log).read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or entry.get("kind") != "php_defense" or entry.get("verdict") == "ALLOW":
            continue
        rows.append({
            "kind": entry.get("rule_code"),
            "tool": entry.get("field") or "",
            "session": entry.get("client_ip") or "",
            "atlas": "",
            "detail": f"{entry.get('method') or ''} {entry.get('uri') or ''} verdict={entry.get('verdict')} "
                      f"value_sha256={str(entry.get('value_sha256') or '')[:16]}".strip(),
        })
    return {"gateway_findings": {"rows": rows}, "source_log": str(audit_log)}
