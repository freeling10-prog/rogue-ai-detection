"""Predicate S: canonical tool arguments and typed command option confinement.

Two representation-level blind spots stay open after the other validators:

* Covert channels in structured arguments. Two argument objects that mean the
  same thing can differ in key order, number spelling (``1``, ``1.0``,
  ``10e-1``, ``-0``), set element order, duplicate keys, or explicit defaults.
  Each difference can carry bits past checks that only look at meaning.
  ``Policy.canonicalize`` maps every accepted object onto ONE byte string
  under a pinned per-tool policy, and that string is what gets dispatched.
* Option injection. A file name that starts with ``-`` is read as a flag by
  ``cp``, ``tee``, ``sed`` and friends. ``confine`` turns a typed ``Command``
  into a fixed argv with ``--`` before every positional argument and refuses
  operands that start with ``-`` (``./-name`` is the explicit spelling).

Standard library only. Every denial raises ``Denied`` with a fixed reason
code that never carries caller data.

Canonical form C_P under a policy P, for an accepted object x:

* keys sorted by their UTF-8 bytes, compact separators, UTF-8 output;
* numbers quantized to the field's scale with ROUND_HALF_EVEN under a local
  40-digit context, written in plain positional notation, ``-0`` -> ``0``;
* ``set`` fields as JSON arrays of distinct strings sorted by their canonical
  UTF-8 JSON encodings;
* optional fields whose canonical encoding equals the pinned default omitted.

C_P is idempotent: C_P(C_P(x)) == C_P(x). Inputs are bounded before parsing:
2048 wire bytes, nesting depth 2 (the object plus one array level), 16
fields, 32 set elements of at most 128 characters, and numbers of at most 48
characters, 24 significant digits and exponent magnitude 12.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from decimal import Context, Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext

from .common import Denied, digest

MAX_WIRE = 2048
MAX_DEPTH = 2
MAX_FIELDS = 16
MAX_SCALE = 6
MAX_SET = 32
MAX_ELEMENT = 128
MAX_NUMBER_CHARS = 48
MAX_DIGITS = 24
MAX_EXPONENT = 12
KINDS = ("number", "set", "text", "bool")

UTILITIES = ("cp", "mv", "tee", "ln", "chmod", "sed")
MAX_OPERANDS = 16
MAX_OPERAND = 256
MAX_COMMAND = 1024
# The same literal profiles workspace_path_validator.command_intents accepts.
MODE_RE = re.compile(r"0?[0-7]{3}")
SED_RE = re.compile(r"s/[A-Za-z0-9 _-]+/[A-Za-z0-9 _-]*/g?")


# --- Structured argument canonicalization ------------------------------------------

def _depth_scan(wire: bytes) -> None:
    """Quote- and escape-aware nesting depth over raw bytes, before any parse."""
    depth = 0
    quoted = escaped = False
    for byte in wire:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                quoted = False
        elif byte == 0x22:
            quoted = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > MAX_DEPTH:
                raise Denied("WIRE_DEPTH")
        elif byte in (0x5D, 0x7D):
            depth -= 1


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise Denied("DUPLICATE_KEY")
        out[key] = value
    return out


def _number(token: str) -> Decimal:
    if len(token) > MAX_NUMBER_CHARS:
        raise Denied("NUMBER_LIMIT")
    value = Decimal(token)
    _sign, digits, exponent = value.as_tuple()
    if len(digits) > MAX_DIGITS or abs(exponent) > MAX_EXPONENT:
        raise Denied("NUMBER_LIMIT")
    return value


def _constant(_):
    raise Denied("NONFINITE")


def _loads(wire: bytes | str):
    if isinstance(wire, str):
        try:
            wire = wire.encode("utf-8")
        except UnicodeError:
            raise Denied("INVALID_UNICODE") from None
    if not isinstance(wire, (bytes, bytearray)):
        raise Denied("WIRE_TYPE")
    wire = bytes(wire)
    if len(wire) > MAX_WIRE:
        raise Denied("WIRE_LIMIT")
    _depth_scan(wire)
    try:
        text = wire.decode("utf-8", "strict")
    except UnicodeError:
        raise Denied("WIRE_ENCODING") from None
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_float=_number,
                          parse_int=_number, parse_constant=_constant)
    except (json.JSONDecodeError, RecursionError, ArithmeticError):
        raise Denied("INVALID_JSON") from None


def _utf8_json(value: str) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    except UnicodeError:
        raise Denied("INVALID_UNICODE") from None


@dataclass(frozen=True, slots=True)
class FieldPolicy:
    name: str
    kind: str  # 'number', 'set', 'text', 'bool'
    scale: int = 0
    default: bytes | None = None
    required: bool = False

    def __post_init__(self):
        if type(self.name) is not str or not 1 <= len(self.name) <= 64:
            raise Denied("FIELD_NAME")
        if self.kind not in KINDS:
            raise Denied("FIELD_KIND")
        if type(self.scale) is not int or not 0 <= self.scale <= MAX_SCALE or (
                self.kind != "number" and self.scale):
            raise Denied("FIELD_SCALE")
        if type(self.required) is not bool:
            raise Denied("FIELD_REQUIRED")
        if self.default is not None and type(self.default) is not bytes:
            raise Denied("FIELD_DEFAULT")
        if self.required and self.default is not None:
            raise Denied("DEFAULT_CONFLICT")

    def encode(self, value) -> bytes:
        """Canonical UTF-8 JSON encoding of one field value."""
        if self.kind == "number":
            if type(value) is not Decimal:
                raise Denied("FIELD_TYPE")
            try:
                with localcontext(Context(prec=40, rounding=ROUND_HALF_EVEN,
                                          traps=[InvalidOperation])):
                    quantized = value.quantize(Decimal(1).scaleb(-self.scale))
            except InvalidOperation:
                raise Denied("NUMBER_RANGE") from None
            if quantized.is_zero():
                quantized = quantized.copy_abs()  # -0 -> 0
            text = format(quantized, "f")
            # The output must itself be accepted input, or C_P is not idempotent.
            if len(quantized.as_tuple().digits) > MAX_DIGITS or len(text) > MAX_NUMBER_CHARS:
                raise Denied("NUMBER_RANGE")
            return text.encode("ascii")
        if self.kind == "bool":
            if type(value) is not bool:
                raise Denied("FIELD_TYPE")
            return b"true" if value else b"false"
        if self.kind == "text":
            if type(value) is not str:
                raise Denied("FIELD_TYPE")
            return _utf8_json(value)
        if type(value) is not list:
            raise Denied("FIELD_TYPE")
        if len(value) > MAX_SET:
            raise Denied("SET_LIMIT")
        encoded = {}
        for element in value:
            if type(element) is not str or len(element) > MAX_ELEMENT:
                raise Denied("ELEMENT_LIMIT")
            if element in encoded:
                raise Denied("DUPLICATE_ELEMENT")
            encoded[element] = _utf8_json(element)
        return b"[" + b",".join(sorted(encoded.values())) + b"]"


@dataclass(frozen=True, slots=True)
class Policy:
    fields: tuple[FieldPolicy, ...]
    _index: dict = field(init=False, repr=False, compare=False)
    commitment: str = field(init=False, compare=False)

    def __post_init__(self):
        fields = tuple(self.fields)
        if not 1 <= len(fields) <= MAX_FIELDS or any(type(f) is not FieldPolicy for f in fields):
            raise Denied("POLICY_FIELDS")
        index = {}
        for f in fields:
            if f.name in index:
                raise Denied("DUPLICATE_FIELD")
            index[f.name] = f
            # A default that is not itself canonical could never match, so the
            # field would leak whether a caller sent it explicitly.
            if f.default is not None and f.encode(_loads(f.default)) != f.default:
                raise Denied("DEFAULT_NOT_CANONICAL")
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "_index", index)
        object.__setattr__(self, "commitment", digest("argument-policy-v1", [
            {"name": f.name, "kind": f.kind, "scale": f.scale, "required": f.required,
             "default": None if f.default is None else f.default.decode("utf-8")}
            for f in sorted(fields, key=lambda f: f.name.encode("utf-8"))]))

    def canonicalize(self, wire: bytes | str) -> bytes:
        value = _loads(wire)
        if type(value) is not dict:
            raise Denied("NOT_OBJECT")
        for name in value:
            if name not in self._index:
                raise Denied("UNKNOWN_FIELD")
        members = []
        for f in self.fields:
            if f.name not in value:
                if f.required:
                    raise Denied("REQUIRED_FIELD")
                continue
            encoded = f.encode(value[f.name])
            if f.default is not None and encoded == f.default:
                continue
            members.append((_utf8_json(f.name), encoded))
        members.sort(key=lambda m: m[0])
        return b"{" + b",".join(k + b":" + v for k, v in members) + b"}"


def encode_arguments(args: dict) -> bytes:
    """Compact UTF-8 JSON for an already-parsed argument object.

    For callers that only hold a parsed object (the lab gateway). Duplicate
    keys and number spelling were already collapsed by whoever parsed the
    wire, so the wire-level checks apply in full only to raw bytes.
    """
    try:
        return json.dumps(args, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=True).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise Denied("ARGUMENT_TYPE") from None
    except UnicodeError:
        raise Denied("INVALID_UNICODE") from None


# --- Typed command option confinement ----------------------------------------------

@dataclass(frozen=True, slots=True, repr=False)
class Command:
    utility: str
    operands: tuple[str, ...]
    mode: str = ""
    script: str = ""
    append: bool = False


def confine(c: Command) -> tuple[str, ...]:
    """Compile a fixed argv: (utility, *options, '--', *positionals).

    ``chmod``'s mode and ``sed``'s script are positional and follow ``--``
    ahead of the operands. Options come only from typed fields, never from
    operand text.
    """
    if type(c) is not Command:
        raise Denied("COMMAND_TYPE")
    if c.utility not in UTILITIES:
        raise Denied("UTILITY")
    if type(c.mode) is not str or type(c.script) is not str or type(c.append) is not bool:
        raise Denied("COMMAND_FIELD")
    if ((c.mode and c.utility != "chmod") or (c.script and c.utility != "sed")
            or (c.append and c.utility != "tee")):
        raise Denied("COMMAND_FIELD")
    operands = c.operands
    if type(operands) is not tuple or not 1 <= len(operands) <= MAX_OPERANDS:
        raise Denied("OPERAND_COUNT")
    total = len(c.mode) + len(c.script)
    for operand in operands:
        if type(operand) is not str or not 1 <= len(operand) <= MAX_OPERAND:
            raise Denied("OPERAND_LIMIT")
        if "\0" in operand:
            raise Denied("OPERAND_NUL")
        if operand.startswith("-"):
            raise Denied("OPERAND_OPTION")
        total += len(operand)
    if total > MAX_COMMAND:
        raise Denied("COMMAND_LIMIT")
    options: tuple[str, ...] = ()
    lead: tuple[str, ...] = ()
    if c.utility in {"cp", "mv", "ln"} and len(operands) != 2:
        raise Denied("COMMAND_ARITY")
    if c.utility == "ln":
        options = ("-s",)  # Hard links are disabled in the workspace profile.
    elif c.utility == "tee" and c.append:
        options = ("-a",)
    elif c.utility == "chmod":
        if not MODE_RE.fullmatch(c.mode):
            raise Denied("MODE_PROFILE")
        lead = (c.mode,)
    elif c.utility == "sed":
        if not SED_RE.fullmatch(c.script):
            raise Denied("SED_SCRIPT")
        options, lead = ("-i",), (c.script,)
    return (c.utility, *options, "--", *lead, *operands)


COMMAND_KEYS = frozenset({"utility", "operands", "mode", "script", "append"})


def command_from_arguments(args: dict) -> Command:
    """Typed adapter for a tool call whose arguments are exactly a Command."""
    if type(args) is not dict or not set(args) <= COMMAND_KEYS or "utility" not in args:
        raise Denied("COMMAND_ARGUMENTS")
    operands = args.get("operands")
    if type(operands) is not list:
        raise Denied("OPERAND_COUNT")
    return Command(args["utility"], tuple(operands), args.get("mode", ""),
                   args.get("script", ""), args.get("append", False))
