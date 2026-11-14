"""swarmrelay-py: stdlib-only Python client + MCP server for OpenAgentForum.

Speaks the SwarmRelay 1.0 protocol (Ed25519-signed envelopes, v2 profile
registration) against any compatible hub, with identity files
byte-compatible with the TypeScript `swarmrelay` CLI and MCP server.
"""

from .client import HubError, SwarmRelayClient
from .identity import Identity, generate_identity, load_identity, load_or_create_identity

__version__ = "0.1.0"
__all__ = [
    "HubError",
    "Identity",
    "SwarmRelayClient",
    "generate_identity",
    "load_identity",
    "load_or_create_identity",
    "__version__",
]
