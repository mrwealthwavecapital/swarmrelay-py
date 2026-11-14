"""SwarmRelay message envelopes and registration proofs.

Implements the exact signing formats from @openagentforum/protocol:

- Envelope checksum: SHA-256 hex of the canonical JSON of the payload.
- Envelope signature: Ed25519 over the UTF-8 bytes of
  ``id|channel|sender|type|sequence|timestamp|checksum``.
- Agent ID: ``agent_`` + first 16 hex chars of SHA-256 of the lowercase
  hex-encoded public key.
- Profile registration (proof v2): Ed25519 over
  ``"openagentforum:registration:v2\\n" + canonical_json(document)``.
"""

from __future__ import annotations

import hashlib
import time
import uuid

from . import ed25519
from .canonical import canonicalize_json

REGISTRATION_DOMAIN = "openagentforum:registration:v2\n"
REGISTRATION_MAX_AGE_MS = 5 * 60 * 1000


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def derive_agent_id(public_key_hex: str) -> str:
    """agent_<sha256(lowercase pubkey hex)[0..16]> (hash of the hex string)."""
    return "agent_" + sha256_hex(public_key_hex.lower())[:16]


def payload_checksum(payload: object) -> str:
    return sha256_hex(canonicalize_json(payload))


def envelope_sign_string(
    *, envelope_id: str, channel: str, sender: str, type_: str,
    sequence: int, timestamp: int, checksum: str,
) -> str:
    return f"{envelope_id}|{channel}|{sender}|{type_}|{sequence}|{timestamp}|{checksum}"


def sign_envelope(
    *,
    seed: bytes,
    sender: str,
    channel: str,
    type_: str,
    payload: object,
    sequence: int = 0,
    timestamp: int | None = None,
    envelope_id: str | None = None,
    reply_to_id: str | None = None,
) -> dict:
    """Build and sign a message envelope. Returns the envelope dict."""
    envelope_id = envelope_id or str(uuid.uuid4())
    timestamp = timestamp if timestamp is not None else int(time.time() * 1000)
    checksum = payload_checksum(payload)
    sign_string = envelope_sign_string(
        envelope_id=envelope_id, channel=channel, sender=sender, type_=type_,
        sequence=sequence, timestamp=timestamp, checksum=checksum,
    )
    signature = ed25519.sign(seed, sign_string.encode("utf-8")).hex()
    envelope: dict = {
        "id": envelope_id,
        "channel": channel,
        "sender": sender,
        "type": type_,
        "sequence": sequence,
        "timestamp": timestamp,
        "payload": payload,
        "signature": signature,
        "checksum": checksum,
    }
    if reply_to_id is not None:
        envelope["replyToId"] = reply_to_id
    return envelope


def verify_envelope(envelope: dict, public_key_hex: str) -> tuple[bool, str | None]:
    """Verify an envelope's checksum, sender binding and signature."""
    try:
        payload = envelope["payload"]
        if payload_checksum(payload) != str(envelope["checksum"]).lower():
            return False, "payload checksum mismatch"
        expected_sender = derive_agent_id(public_key_hex)
        if str(envelope["sender"]).lower() != expected_sender.lower():
            return False, "sender does not match public key fingerprint"
        sign_string = envelope_sign_string(
            envelope_id=envelope["id"], channel=envelope["channel"],
            sender=envelope["sender"], type_=envelope["type"],
            sequence=envelope["sequence"], timestamp=envelope["timestamp"],
            checksum=envelope["checksum"],
        )
        valid = ed25519.verify(
            bytes.fromhex(public_key_hex),
            sign_string.encode("utf-8"),
            bytes.fromhex(str(envelope["signature"])),
        )
        return (valid, None if valid else "invalid Ed25519 signature")
    except (KeyError, ValueError) as exc:
        return False, f"malformed envelope: {exc}"


def build_registration_document(
    *, hub_origin: str, public_key_hex: str, expected_revision: int,
    name: str, x25519_public_key_hex: str | None,
    capabilities: list[str] | None = None,
    metadata: dict | None = None, endpoint: str | None = None,
    issued_at: int | None = None,
) -> dict:
    """Build the v2 profile-registration document (unsigned)."""
    issued_at = issued_at if issued_at is not None else int(time.time() * 1000)
    return {
        "proofVersion": 2,
        "action": "register-profile",
        "hub": hub_origin,
        "publicKey": public_key_hex.lower(),
        "expectedRevision": expected_revision,
        "issuedAt": issued_at,
        "expiresAt": issued_at + REGISTRATION_MAX_AGE_MS,
        "profile": {
            "name": name,
            "x25519PublicKey": x25519_public_key_hex.lower() if x25519_public_key_hex else None,
            "capabilities": capabilities or [],
            "metadata": metadata or {},
            "endpoint": endpoint,
        },
    }


def sign_registration(document: dict, seed: bytes) -> dict:
    """Sign a registration document. Returns the document plus `signature`."""
    message = (REGISTRATION_DOMAIN + canonicalize_json(document)).encode("utf-8")
    signed = dict(document)
    signed["signature"] = ed25519.sign(seed, message).hex()
    return signed


def registration_digest(signed_registration: dict) -> str:
    return sha256_hex(REGISTRATION_DOMAIN + canonicalize_json(signed_registration))
