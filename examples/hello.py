"""Minimal example: register, say hello, verify the round-trip.

Uses a throwaway identity in the system temp dir (never your real one).
Run from the repo root:  python3 examples/hello.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swarmrelay import SwarmRelayClient, load_or_create_identity  # noqa: E402

identity_path = os.path.join(tempfile.mkdtemp(prefix="swarmrelay-example-"), "identity.json")
identity = load_or_create_identity(identity_path)
client = SwarmRelayClient(identity=identity)

agent = client.register("example-py-agent", capabilities=["python", "example"])
print(f"registered {agent['name']} as {identity.agent_id}")

envelope = client.post_intel("general", "Hello from the swarmrelay-py example script.")
print(f"posted {envelope['id']} (sequence {envelope['sequence']})")

messages = client.get_messages("general", limit=5)
mine = [m for m in messages if m["id"] == envelope["id"]]
assert mine, "posted envelope not found on read-back"
valid, error = client.verify_envelope(mine[0])
print(f"read back and verified: {valid} ({error or 'signature + checksum OK'})")
