"""Agent identity files, byte-compatible with the TypeScript tooling.

An identity file is the JSON object `swarmrelay hello` and the TypeScript MCP
server read and write at ``~/.swarmrelay/identity.json``::

    {
      "agentId": "agent_<sha256(pubkey hex)[0..16]>",
      "signingPublicKey": "<64 hex, Ed25519>",
      "signingPrivateKey": "<96 hex, PKCS#8 DER>",
      "encryptionPublicKey": "<64 hex, X25519>",
      "encryptionPrivateKey": "<96 hex, PKCS#8 DER>"
    }

Files are created with mode 0600 inside a 0700 directory. Identities created
here load in the TypeScript tools, and identities created there load here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from . import ed25519, x25519
from .envelope import derive_agent_id

DEFAULT_IDENTITY_PATH = os.path.join(
    os.path.expanduser("~"), ".swarmrelay", "identity.json"
)


@dataclass(frozen=True)
class Identity:
    agent_id: str
    signing_public_key: str  # hex, 32-byte Ed25519 public key
    signing_seed: bytes  # 32-byte Ed25519 seed (kept in memory only)
    encryption_public_key: str  # hex, 32-byte X25519 public key
    encryption_private: bytes  # 32-byte X25519 private scalar

    def to_file_dict(self) -> dict:
        return {
            "agentId": self.agent_id,
            "signingPublicKey": self.signing_public_key,
            "signingPrivateKey": ed25519.seed_to_pkcs8_hex(self.signing_seed),
            "encryptionPublicKey": self.encryption_public_key,
            "encryptionPrivateKey": x25519.private_to_pkcs8_hex(self.encryption_private),
        }


def generate_identity() -> Identity:
    seed = ed25519.generate_seed()
    signing_public_key = ed25519.public_key_from_seed(seed).hex()
    encryption_private = x25519.generate_private()
    return Identity(
        agent_id=derive_agent_id(signing_public_key),
        signing_public_key=signing_public_key,
        signing_seed=seed,
        encryption_public_key=x25519.public_key(encryption_private).hex(),
        encryption_private=encryption_private,
    )


def identity_from_file_dict(data: dict) -> Identity:
    """Parse and validate an identity file dict (either tooling's format)."""
    try:
        signing_seed = ed25519.pkcs8_hex_to_seed(data["signingPrivateKey"])
        encryption_private = x25519.pkcs8_hex_to_private(data["encryptionPrivateKey"])
        signing_public_key = str(data["signingPublicKey"]).lower()
        encryption_public_key = str(data["encryptionPublicKey"]).lower()
        agent_id = str(data["agentId"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"invalid identity file: {exc}") from exc
    if ed25519.public_key_from_seed(signing_seed).hex() != signing_public_key:
        raise ValueError("signing public key does not match private key")
    if x25519.public_key(encryption_private).hex() != encryption_public_key:
        raise ValueError("encryption public key does not match private key")
    if derive_agent_id(signing_public_key) != agent_id:
        raise ValueError("agentId does not match signing public key")
    return Identity(
        agent_id=agent_id,
        signing_public_key=signing_public_key,
        signing_seed=signing_seed,
        encryption_public_key=encryption_public_key,
        encryption_private=encryption_private,
    )


def default_identity_path() -> str:
    return os.environ.get("SWARM_IDENTITY") or DEFAULT_IDENTITY_PATH


def load_identity(path: str | None = None) -> Identity:
    path = path or default_identity_path()
    with open(path, "r", encoding="utf-8") as handle:
        return identity_from_file_dict(json.load(handle))


def save_identity(identity: Identity, path: str | None = None) -> str:
    """Write an identity file with 0600 permissions. Returns the path."""
    path = path or default_identity_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(identity.to_file_dict(), handle, indent=2)
            handle.write("\n")
    except BaseException:
        os.close(fd)
        raise
    os.chmod(path, 0o600)
    return path


def load_or_create_identity(path: str | None = None) -> Identity:
    path = path or default_identity_path()
    if os.path.exists(path):
        return load_identity(path)
    identity = generate_identity()
    save_identity(identity, path)
    return identity
