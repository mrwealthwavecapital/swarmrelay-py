"""Pure-Python Ed25519 (RFC 8032), stdlib only.

Implements key generation, signing and verification over the Edwards25519
curve, byte-compatible with the WebCrypto Ed25519 used by the TypeScript
SwarmRelay/OpenAgentForum implementation. No third-party dependencies.

Private keys are handled as 32-byte seeds. PKCS#8 DER import/export matches
the identity-file format used by `swarmrelay hello` and the TypeScript MCP
server, so identities created here load in the TypeScript tooling and
vice versa.
"""

from __future__ import annotations

import hashlib
import secrets

# Field prime and curve constants (RFC 8032).
_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)

# PKCS#8 DER prefix for an Ed25519 private key: the 16-byte header followed
# by the 32-byte seed. This is the exact structure WebCrypto exports.
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _decode_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _encode_int(value: int) -> bytes:
    return value.to_bytes(32, "little")


def _recover_x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if (x * x - xx) % _Q != 0:
        return None
    if x & 1 != sign:
        x = _Q - x
    return x


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = _decode_int(data) & ((1 << 255) - 1)
    sign = (_decode_int(data) >> 255) & 1
    x = _recover_x(y, sign)
    if x is None:
        raise ValueError("invalid encoded point")
    return (x, y)


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2 % _Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _Q - 2, _Q) % _Q
    return (x3, y3)


def _scalarmult(point: tuple[int, int], e: int) -> tuple[int, int]:
    result = (0, 1)  # neutral element
    while e:
        if e & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        e >>= 1
    return result


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_BX = _recover_x(_BY, 0)
assert _BX is not None
_BASE_POINT = (_BX, _BY)


def _clamp(h: bytes) -> int:
    a = _decode_int(h[:32])
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def generate_seed() -> bytes:
    """Generate a fresh 32-byte Ed25519 seed."""
    return secrets.token_bytes(32)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte encoded public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    return _encode_point(_scalarmult(_BASE_POINT, _clamp(h)))


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message. Returns the 64-byte signature (R || S)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = _clamp(h)
    public = _encode_point(_scalarmult(_BASE_POINT, a))
    r = _decode_int(_sha512(h[32:] + message)) % _L
    r_point = _encode_point(_scalarmult(_BASE_POINT, r))
    k = _decode_int(_sha512(r_point + public + message)) % _L
    s = (r + k * a) % _L
    return r_point + _encode_int(s)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte signature against a 32-byte public key."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r_point = _decode_point(signature[:32])
        a_point = _decode_point(public_key)
    except ValueError:
        return False
    s = _decode_int(signature[32:])
    if s >= _L:
        return False
    k = _decode_int(_sha512(signature[:32] + public_key + message)) % _L
    return _scalarmult(_BASE_POINT, s) == _point_add(r_point, _scalarmult(a_point, k))


def seed_to_pkcs8_hex(seed: bytes) -> str:
    """Encode a 32-byte seed as a PKCS#8 DER hex string (WebCrypto format)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return (_PKCS8_PREFIX + seed).hex()


def pkcs8_hex_to_seed(pkcs8_hex: str) -> bytes:
    """Extract the 32-byte seed from a PKCS#8 DER hex string."""
    raw = bytes.fromhex(pkcs8_hex[2:] if pkcs8_hex.startswith("0x") else pkcs8_hex)
    if len(raw) != 48 or raw[:16] != _PKCS8_PREFIX:
        raise ValueError("not an Ed25519 PKCS#8 private key")
    return raw[16:]
