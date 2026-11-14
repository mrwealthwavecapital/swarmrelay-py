"""Pure-Python X25519 (RFC 7748), stdlib only.

Used for identity-file compatibility with the TypeScript SwarmRelay tooling:
an identity file carries both an Ed25519 signing key and an X25519 encryption
key. This module implements the Montgomery ladder and PKCS#8 import/export so
identities created here load in `swarmrelay hello` and the TypeScript MCP
server. E2E message encryption itself is not implemented in this package
(public channels and tasks only); see the README for scope.
"""

from __future__ import annotations

import secrets

_P = (1 << 255) - 19
_A24 = 121665

# PKCS#8 DER prefix for an X25519 private key, matching WebCrypto exports.
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")


def _decode_u(data: bytes) -> int:
    return int.from_bytes(data, "little") & ((1 << 255) - 1)


def scalarmult(scalar: bytes, u_coordinate: bytes) -> bytes:
    """X25519(scalar, u). Both inputs are 32 bytes; output is 32 bytes."""
    if len(scalar) != 32 or len(u_coordinate) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    x_1 = _decode_u(u_coordinate)
    x_2, z_2, x_3, z_3, swap = 1, 0, x_1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        a = (x_2 + z_2) % _P
        aa = a * a % _P
        b = (x_2 - z_2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x_3 + z_3) % _P
        d = (x_3 - z_3) % _P
        da = d * a % _P
        cb = c * b % _P
        x_3 = (da + cb) ** 2 % _P
        z_3 = x_1 * (da - cb) ** 2 % _P
        x_2 = aa * bb % _P
        z_2 = e * (aa + _A24 * e) % _P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    return (x_2 * pow(z_2, _P - 2, _P) % _P).to_bytes(32, "little")


def generate_private() -> bytes:
    """Generate a fresh 32-byte X25519 private scalar."""
    return secrets.token_bytes(32)


def public_key(private: bytes) -> bytes:
    """Derive the 32-byte X25519 public key from a private scalar."""
    return scalarmult(private, (9).to_bytes(32, "little"))


def private_to_pkcs8_hex(private: bytes) -> str:
    """Encode a 32-byte X25519 private scalar as PKCS#8 DER hex."""
    if len(private) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    return (_PKCS8_PREFIX + private).hex()


def pkcs8_hex_to_private(pkcs8_hex: str) -> bytes:
    """Extract the 32-byte X25519 private scalar from a PKCS#8 DER hex."""
    raw = bytes.fromhex(pkcs8_hex[2:] if pkcs8_hex.startswith("0x") else pkcs8_hex)
    if len(raw) != 48 or raw[:16] != _PKCS8_PREFIX:
        raise ValueError("not an X25519 PKCS#8 private key")
    return raw[16:]
