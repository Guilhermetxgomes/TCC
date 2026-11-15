"""
NIST P-256 group arithmetic in pure Python.

Why this file exists: threshold decryption (crypto/threshold.py) needs the full
group law -- adding points and multiplying *arbitrary* points by scalars. The
`cryptography` package only exposes ECDH (x-coordinate of d*P) and key generation
(d*G), and X25519 (RFC 7748) is an x-only ladder on a curve with cofactor 8, so
neither can combine partial decryptions. P-256 has prime order (cofactor 1): every
point on the curve is in the group, which keeps input validation to an on-curve check.

Didactic implementation: correct (cross-checked against OpenSSL in
tests/test_crypto.py) but NOT constant time. A deployment would use a vetted
library (e.g. ristretto255 in libsodium).
"""
from typing import Optional

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

# Affine point (x, y); None is the point at infinity (the group identity).
Point = Optional[tuple[int, int]]
_INFINITY = (0, 1, 0)  # Jacobian coordinates: Z == 0


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x - 3 * x + B)) % P == 0


def _double(X: int, Y: int, Z: int) -> tuple[int, int, int]:
    if Z == 0 or Y == 0:
        return _INFINITY
    delta = Z * Z % P
    gamma = Y * Y % P
    beta = X * gamma % P
    alpha = 3 * (X - delta) * (X + delta) % P  # uses a = -3
    X3 = (alpha * alpha - 8 * beta) % P
    Z3 = ((Y + Z) * (Y + Z) - gamma - delta) % P
    Y3 = (alpha * (4 * beta - X3) - 8 * gamma * gamma) % P
    return X3, Y3, Z3


def _add_affine(X1: int, Y1: int, Z1: int, x2: int, y2: int) -> tuple[int, int, int]:
    """Jacobian (X1, Y1, Z1) + affine (x2, y2)."""
    if Z1 == 0:
        return x2, y2, 1
    z1z1 = Z1 * Z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * Z1 * z1z1 % P
    h = (u2 - X1) % P
    r = (s2 - Y1) % P
    if h == 0:
        return _double(X1, Y1, Z1) if r == 0 else _INFINITY
    hh = h * h % P
    hhh = h * hh % P
    v = X1 * hh % P
    X3 = (r * r - hhh - 2 * v) % P
    Y3 = (r * (v - X3) - Y1 * hhh) % P
    Z3 = Z1 * h % P
    return X3, Y3, Z3


def _to_affine(X: int, Y: int, Z: int) -> Point:
    if Z == 0:
        return None
    z_inv = pow(Z, -1, P)
    z_inv2 = z_inv * z_inv % P
    return X * z_inv2 % P, Y * z_inv2 * z_inv % P


def add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return _to_affine(*_add_affine(p1[0], p1[1], 1, p2[0], p2[1]))


def multiply(scalar: int, point: Point) -> Point:
    """scalar * point (double-and-add, most significant bit first)."""
    scalar %= ORDER
    if scalar == 0 or point is None:
        return None
    x, y = point
    acc = _INFINITY
    for bit in bin(scalar)[2:]:
        acc = _double(*acc)
        if bit == "1":
            acc = _add_affine(*acc, x, y)
    return _to_affine(*acc)


def encode(point: Point) -> bytes:
    """SEC1 uncompressed encoding (65 bytes). The identity is never a valid output here."""
    if point is None:
        raise ValueError("cannot encode the point at infinity")
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode(data: bytes) -> Point:
    if len(data) != 65 or data[0] != 4:
        raise ValueError("expected a 65-byte uncompressed P-256 point")
    point = (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
    if not is_on_curve(point):
        raise ValueError("point is not on P-256")
    return point
