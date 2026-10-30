"""Python 3.12, standard-library-only runtime primitives."""
from __future__ import annotations

import json
from decimal import Decimal
from hashlib import sha256


class Denied(ValueError):
    """Stable reason codes only: never embed caller data in errors."""


def scalar_text(value: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise Denied("TEXT_LIMIT")
    try:
        if len(value.encode("utf-8")) > limit:
            raise Denied("TEXT_LIMIT")
    except UnicodeError:
        raise Denied("INVALID_UNICODE") from None
    return value


def strict_json(raw: bytes | str) -> object:
    """Exact decimals, duplicate rejection, 64 KiB wire budget."""
    if isinstance(raw, bytes):
        if len(raw) > 65536:
            raise Denied("JSON_LIMIT")
        try:
            raw = raw.decode("utf-8", "strict")
        except UnicodeError:
            raise Denied("JSON_ENCODING") from None
    scalar_text(raw, 65536)
    depth = 0
    quoted = escaped = False
    for ch in raw:
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch in "[{":
            depth += 1
            if depth > 32:
                raise Denied("JSON_DEPTH")
        elif ch in "]}":
            depth -= 1

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Denied("DUPLICATE_KEY")
            out[key] = value
        return out

    def number(token):
        if len(token) > 272:
            raise Denied("NUMBER_LIMIT")
        value = Decimal(token)
        tup = value.as_tuple()
        if len(tup.digits) > 256 or abs(tup.exponent) > 4096:
            raise Denied("NUMBER_LIMIT")
        return value

    def constant(_):
        raise Denied("NONFINITE")

    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_float=number, parse_int=number,
                           parse_constant=constant)
        canonical(value)
        return value
    except (json.JSONDecodeError, RecursionError, ArithmeticError):
        raise Denied("INVALID_JSON") from None


def canonical(value: object) -> bytes:
    """CJSON-DECIMAL-v1; deliberately NOT RFC 8785/JCS.

    UTF-8 key order; exact decimals; strings unchanged; array order unchanged.
    Nonzero numbers: signed integer coefficient followed by e and exponent.
    """
    budget = [0]

    def emit(x, depth):
        budget[0] += 1
        if budget[0] > 4096 or depth > 32:
            raise Denied("CANONICAL_BUDGET")
        if x is None:
            return "null"
        if type(x) is bool:
            return "true" if x else "false"
        if isinstance(x, str):
            scalar_text(x, 65536)
            return json.dumps(x, ensure_ascii=False, separators=(",", ":"))
        if type(x) is int or isinstance(x, Decimal):
            if type(x) is int and x.bit_length() > 851:
                raise Denied("NUMBER_LIMIT")
            d = Decimal(x)
            if not d.is_finite():
                raise Denied("NONFINITE")
            sign, digits, exponent = d.as_tuple()
            if len(digits) > 256 or abs(exponent) > 4096:
                raise Denied("NUMBER_LIMIT")
            if not d:
                return "0"
            digits = list(digits)
            while digits[-1] == 0:
                digits.pop()
                exponent += 1
            if abs(exponent) > 4096:
                raise Denied("NUMBER_LIMIT")
            return ("-" if sign else "") + "".join(map(str, digits)) + "e" + str(exponent)
        if isinstance(x, list):
            return "[" + ",".join(emit(v, depth + 1) for v in x) + "]"
        if isinstance(x, dict):
            for key in x:
                scalar_text(key, 65536)
            return "{" + ",".join(
                emit(k, depth + 1) + ":" + emit(x[k], depth + 1)
                for k in sorted(x, key=lambda s: s.encode("utf-8"))
            ) + "}"
        raise Denied("UNSUPPORTED_CANONICAL_TYPE")

    out = emit(value, 0).encode("utf-8")
    if len(out) > 131072:
        raise Denied("CANONICAL_BYTES")
    return out


def digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()
