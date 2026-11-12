"""Independent cost oracle for P3.

``gamma`` is a doubling loop. ``qb_choice`` is the smallest q with
``2**q >= n**4``. DEFLATE length builds its own ``compressobj``. Kraft sums
of quarter-bit lengths are exact elements of ``Q(2**(1/4))``, compared with
integer arithmetic. This module does not import the ledger's cost functions.
"""
from __future__ import annotations

import zlib
from fractions import Fraction

_DEFLATE = dict(level=9, method=zlib.DEFLATED, wbits=-15, memLevel=9,
                strategy=zlib.Z_DEFAULT_STRATEGY)


def gamma_bits(x: int) -> int:
    """``2 * floor(log2 x) + 1`` by doubling. ``x >= 1``."""
    if type(x) is not int or x < 1:
        raise ValueError("gamma domain")
    log = 0
    power = 1
    while power * 2 <= x:
        power *= 2
        log += 1
    return 2 * log + 1


def qb_choice(n: int) -> int:
    """Smallest ``q`` with ``2**q >= n**4``."""
    if type(n) is not int or n < 1:
        raise ValueError("choice domain")
    target = n ** 4
    q = 0
    while (1 << q) < target:
        q += 1
    return q


def qb_gamma(x: int) -> int:
    return 4 * gamma_bits(x)


def deflate_len(payload: bytes, zdict: bytes = b"") -> int:
    if zdict:
        comp = zlib.compressobj(**_DEFLATE, zdict=zdict)
    else:
        comp = zlib.compressobj(**_DEFLATE)
    return len(comp.compress(payload) + comp.flush())


def length_header(length: int) -> int:
    return gamma_bits(length + 1)


def content_bits(compressed_len: int, *, header: bool = True) -> int:
    extra = length_header(compressed_len) if header else 0
    return 8 * compressed_len + extra


def content_qb(payload: bytes, zdict: bytes = b"") -> int:
    return 4 * content_bits(deflate_len(payload, zdict))


def fold_observable(destination: str, tool: str, payload: bytes) -> bytes:
    dest = destination.encode("utf-8")
    name = tool.encode("utf-8")
    return (len(dest).to_bytes(4, "big") + dest
            + len(name).to_bytes(4, "big") + name
            + payload)


def fold_destination(destination: str, payload: bytes) -> bytes:
    dest = destination.encode("utf-8")
    return len(dest).to_bytes(4, "big") + dest + payload


def event_qb(*, gap: int, members: int, manifest_n: int, content_qb_value: int,
             charge_member: bool, continuation_qb: int = 4) -> dict:
    """Quarter-bit components of one charged event. ``gap >= 1``."""
    member_qb = qb_choice(members) if charge_member and members > 1 else 0
    selection_qb = qb_choice(manifest_n) if manifest_n else 0
    gap_qb = qb_gamma(gap)
    charge = continuation_qb + gap_qb + member_qb + selection_qb + content_qb_value
    return {
        "charge_qb": charge, "gap_qb": gap_qb, "member_qb": member_qb,
        "selection_qb": selection_qb, "content_qb": content_qb_value,
        "continuation_qb": continuation_qb, "gap": gap,
    }


def _sqrt2_nonneg(p: int, q: int) -> bool:
    """``p + q*sqrt(2) >= 0`` exactly."""
    if p >= 0 and q >= 0:
        return True
    if p <= 0 and q <= 0:
        return p == 0 and q == 0
    if q < 0:
        return p > 0 and p * p >= 2 * q * q
    return q > 0 and 2 * q * q >= p * p


def _poly_nonneg(a: int, b: int, c: int, d: int) -> bool:
    """``a + b*x + c*x**2 + d*x**3 >= 0`` for ``x = 2**(1/4)``."""
    u_nn = _sqrt2_nonneg(a, c)
    v_nn = _sqrt2_nonneg(b, d)
    u_zero = a == 0 and c == 0
    v_zero = b == 0 and d == 0
    if u_zero and v_zero:
        return True
    if u_nn and v_nn:
        return True
    if (not u_nn) and (not v_nn):
        return False
    # u^2 = (a^2 + 2 c^2) + (2 a c) sqrt(2)
    # v^2 = (b^2 + 2 d^2) + (2 b d) sqrt(2)
    # sqrt(2) * v^2 = 2*(2 b d) + (b^2 + 2 d^2) sqrt(2)
    up = a * a + 2 * c * c
    uq = 2 * a * c
    vp = b * b + 2 * d * d
    vq = 2 * b * d
    sp = 4 * b * d
    sq = vp
    if u_nn and not v_nn:
        # u^2 >= sqrt(2) v^2
        return _sqrt2_nonneg(up - sp, uq - sq)
    # sqrt(2) v^2 >= u^2
    return _sqrt2_nonneg(sp - up, sq - uq)


class QbSum:
    """Exact sum of terms ``times * 2**(-q/4)``.

    Stored as ``(a + b x + c x^2 + d x^3) / 2**scale`` with ``x = 2**(1/4)``.
    """

    def __init__(self) -> None:
        self.a = self.b = self.c = self.d = 0
        self.scale = 0

    def copy(self) -> "QbSum":
        out = QbSum()
        out.a, out.b, out.c, out.d, out.scale = self.a, self.b, self.c, self.d, self.scale
        return out

    def _add_scaled(self, a: int, b: int, c: int, d: int, scale: int) -> None:
        if self.scale < scale:
            shift = scale - self.scale
            self.a <<= shift
            self.b <<= shift
            self.c <<= shift
            self.d <<= shift
            self.scale = scale
        elif scale < self.scale:
            shift = self.scale - scale
            a <<= shift
            b <<= shift
            c <<= shift
            d <<= shift
        self.a += a
        self.b += b
        self.c += c
        self.d += d

    def add_qb(self, quarter_bits: int, times: int = 1) -> None:
        if times == 0:
            return
        n, r = divmod(quarter_bits, 4)
        if r == 0:
            self._add_scaled(times, 0, 0, 0, n)
        elif r == 1:
            self._add_scaled(0, 0, 0, times, n + 1)
        elif r == 2:
            self._add_scaled(0, 0, times, 0, n + 1)
        else:
            self._add_scaled(0, times, 0, 0, n + 1)

    def mul(self, other: "QbSum") -> "QbSum":
        a, b, c, d = self.a, self.b, self.c, self.d
        e, f, g, h = other.a, other.b, other.c, other.d
        # x**4 = 2, x**5 = 2x, x**6 = 2 x**2
        const = a * e + 2 * (b * h + c * g + d * f)
        coef_x = a * f + b * e + 2 * (c * h + d * g)
        coef_x2 = a * g + b * f + c * e + 2 * d * h
        coef_x3 = a * h + b * g + c * f + d * e
        out = QbSum()
        out.a, out.b, out.c, out.d = const, coef_x, coef_x2, coef_x3
        out.scale = self.scale + other.scale
        return out

    def le_dyadic(self, numer: int, den_pow2: int) -> bool:
        """``self <= numer / 2**den_pow2``."""
        if self.scale >= den_pow2:
            threshold = numer << (self.scale - den_pow2)
            return _poly_nonneg(threshold - self.a, -self.b, -self.c, -self.d)
        shift = den_pow2 - self.scale
        return _poly_nonneg(
            numer - (self.a << shift),
            -(self.b << shift),
            -(self.c << shift),
            -(self.d << shift),
        )
