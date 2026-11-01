"""Per-session descriptor pins, sticky ambiguity and revocation.

Enrollment is a trusted control-plane operation. Provider IDs come from an
authenticated transport, never a provider-controlled JSON field.
Full JSON Schema validation remains the existing schema validator's job.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from threading import RLock

from .common import Denied, digest, scalar_text, strict_json

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
DIALECT = "https://json-schema.org/draft/2020-12/schema"
MAPS = {"$defs", "properties", "patternProperties", "dependentSchemas"}
SINGLE = {"additionalProperties", "unevaluatedProperties", "propertyNames",
          "contains", "not", "if", "then", "else", "items", "unevaluatedItems"}
ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}
MARKERS = ("<|", "|>", "<system", "</system", "<developer", "</developer",
           chr(96) * 3, "### system", "### developer", "[inst]", "[/inst]")
DIRECTIVES = ("ignore previous", "ignore all previous", "override policy",
              "override instructions", "disable validation", "execute this",
              "run this command", "send secrets")


def lint_description(text: str) -> tuple[str, ...]:
    scalar_text(text, 4096)
    findings = set()
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in {"Cf", "Cs"} or (cat == "Cc" and ch not in "\n\r\t"):
            findings.add("CONTROL_OR_FORMAT")
    view = unicodedata.normalize("NFKC", text).casefold()
    view = " ".join(view.split())
    if any(t in view for t in MARKERS):
        findings.add("STRUCTURAL_TOKEN")
    if any(t in view for t in DIRECTIVES):
        findings.add("DIRECTIVE_TOKEN")
    if re.search(r"(?:^|\s)(?:system|developer|assistant)\s*:", view):
        findings.add("ROLE_TOKEN")
    return tuple(sorted(findings))


def schema_profile(root: object) -> None:
    """Local JSON Pointer profile; no URI fetch or dynamic resolution."""
    if type(root) is not bool and not isinstance(root, dict):
        raise Denied("SCHEMA_ROOT")
    stack = [root]
    seen = set()
    while stack:
        node = stack.pop()
        if type(node) is bool:
            continue
        if not isinstance(node, dict):
            raise Denied("SCHEMA_NODE")
        if id(node) in seen:
            continue
        seen.add(id(node))
        if any(k in node for k in ("$id", "$anchor", "$dynamicRef", "$dynamicAnchor")):
            raise Denied("UNSUPPORTED_SCHEMA_RESOLUTION")
        if "$schema" in node and node["$schema"] != DIALECT:
            raise Denied("SCHEMA_DIALECT")
        if "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or (ref != "#" and not ref.startswith("#/")):
                raise Denied("NONLOCAL_REF")
            if "%" in ref:
                raise Denied("ENCODED_REF")
            target = root
            try:
                for token in ref[2:].split("/") if ref != "#" else ():
                    if re.search(r"~(?![01])", token):
                        raise Denied("POINTER_ESCAPE")
                    token = token.replace("~1", "/").replace("~0", "~")
                    if isinstance(target, list):
                        if not re.fullmatch(r"0|[1-9][0-9]*", token):
                            raise Denied("POINTER_INDEX")
                        target = target[int(token)]
                    elif isinstance(target, dict):
                        target = target[token]
                    else:
                        raise Denied("POINTER_TARGET")
            except (KeyError, IndexError, ValueError):
                raise Denied("UNRESOLVED_REF") from None
            if type(target) is not bool and not isinstance(target, dict):
                raise Denied("POINTER_TARGET")
            stack.append(target)
        for field in ("description", "title", "$comment"):
            if field in node:
                if not isinstance(node[field], str) or lint_description(node[field]):
                    raise Denied("METADATA_LINT")
        for key in sorted(MAPS & node.keys()):
            if not isinstance(node[key], dict):
                raise Denied("SCHEMA_MAP")
            stack.extend(node[key][name] for name in sorted(node[key]))
        for key in sorted(SINGLE & node.keys()):
            stack.append(node[key])
        for key in sorted(ARRAYS & node.keys()):
            if not isinstance(node[key], list):
                raise Denied("SCHEMA_ARRAY")
            stack.extend(node[key])


@dataclass(frozen=True, slots=True)
class Pin:
    provider: str
    method: str
    digest: str


def make_pin(provider: str, method: str, raw: bytes | str) -> Pin:
    if not NAME.fullmatch(provider) or not NAME.fullmatch(method) or method.startswith("rpc."):
        raise Denied("METHOD_NAME")
    doc = strict_json(raw)
    if not isinstance(doc, dict) or "inputSchema" not in doc:
        raise Denied("DESCRIPTOR")
    if set(doc) - {"description", "inputSchema", "outputSchema", "annotations", "title"}:
        raise Denied("DESCRIPTOR_FIELD")
    for field in ("description", "title"):
        if field in doc and (not isinstance(doc[field], str) or lint_description(doc[field])):
            raise Denied("METADATA_LINT")
    schema_profile(doc["inputSchema"])
    if "outputSchema" in doc:
        schema_profile(doc["outputSchema"])
    h = digest("registry-pin:CJSON-DECIMAL-v1:local-pointer-v1",
               {"provider": provider, "method": method, "dialect": DIALECT,
                "descriptor": doc, "lintVersion": "lint-v1",
                "unicodeVersion": unicodedata.unidata_version})
    return Pin(provider, method, h)


class Registry:
    """ONE session, ONE owning process; lookup is not deferred execution."""
    def __init__(self):
        self._pins: dict[tuple[str, str], Pin] = {}
        self._owners: dict[str, set[str]] = {}
        self._revoked: set[tuple[str, str]] = set()
        self._lock = RLock()
        self._sealed = False
        self.generation = 0

    def register(self, provider: str, method: str, raw: bytes | str) -> Pin:
        key = (provider, method)
        # Enrollment hashing/linting is control-plane work, outside hot locks.
        try:
            pin = make_pin(provider, method, raw)
        except Denied:
            with self._lock:
                if key in self._pins:
                    self._revoked.add(key)
                    self.generation += 1
            raise
        with self._lock:
            old = self._pins.get(key)
            if old is not None:
                if old != pin or key in self._revoked:
                    self._revoked.add(key)
                    self.generation += 1
                    raise Denied("REGISTRY_DRIFT")
                return old
            if method not in self._owners:
                if self._sealed:
                    raise Denied("NEW_SESSION_REQUIRED")
                if len(self._pins) >= 256:
                    raise Denied("REGISTRY_LIMIT")
            owners = self._owners.setdefault(method, set())
            if provider not in owners:
                if len(owners) >= 2:
                    raise Denied("ALIAS_ALREADY_AMBIGUOUS")
                owners.add(provider)
                self.generation += 1
            if self._sealed:
                raise Denied("NEW_SESSION_REQUIRED")
            if len(self._pins) >= 256:
                raise Denied("REGISTRY_LIMIT")
            self._pins[key] = pin
            self.generation += 1
            return pin

    def seal(self) -> None:
        with self._lock:
            self._sealed = True

    def retire(self, provider: str, method: str) -> None:
        with self._lock:
            if (provider, method) in self._pins:
                self._revoked.add((provider, method))
                self.generation += 1

    def lookup(self, method: str, provider: str | None = None) -> Pin:
        with self._lock:
            if not self._sealed:
                raise Denied("REGISTRY_NOT_SEALED")
            if provider is None:
                owners = self._owners.get(method, ())
                if len(owners) != 1:
                    raise Denied("AMBIGUOUS_OR_UNKNOWN_ALIAS")
                provider = next(iter(owners))
            key = (provider, method)
            if key in self._revoked or key not in self._pins:
                raise Denied("REVOKED_OR_UNKNOWN")
            return self._pins[key]
