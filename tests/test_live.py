"""Live tests against the real hub. Gated: only run with SWARMRELAY_LIVE=1.

Uses a throwaway identity in a temp dir. Posts exactly one honest hello to
#general, reads it back, and verifies the envelope against the hub.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swarmrelay import SwarmRelayClient, load_or_create_identity  # noqa: E402

LIVE = os.environ.get("SWARMRELAY_LIVE") == "1"


@unittest.skipUnless(LIVE, "live test: set SWARMRELAY_LIVE=1")
class TestLive(unittest.TestCase):
    def test_register_post_read_verify(self):
        identity_path = os.path.join(
            tempfile.mkdtemp(prefix="swarmrelay-live-"), "identity.json"
        )
        identity = load_or_create_identity(identity_path)
        client = SwarmRelayClient(identity=identity)

        agent = client.register(
            "swarmrelay-py-live-test",
            capabilities=["python", "test"],
            metadata={"client": "swarmrelay-py/0.1.0", "test": "live"},
        )
        self.assertEqual(agent["agentId"], identity.agent_id)
        self.assertTrue(agent.get("profileVerified"))

        envelope = client.post_intel(
            "general",
            "Live test of swarmrelay-py (stdlib-only Python client). "
            "Posting once to verify the signed-envelope round-trip.",
        )
        messages = client.get_messages("general", limit=10)
        mine = [m for m in messages if m["id"] == envelope["id"]]
        self.assertEqual(len(mine), 1, "posted envelope not found on read-back")
        valid, error = client.verify_envelope(mine[0])
        self.assertTrue(valid, error)

    def test_anonymous_reads(self):
        client = SwarmRelayClient()
        channels = client.list_channels()
        self.assertTrue(any(c["name"] == "general" for c in channels))
        messages = client.get_messages("general", limit=3)
        self.assertLessEqual(len(messages), 3)
        tasks = client.list_tasks("open")
        self.assertIsInstance(tasks, list)


if __name__ == "__main__":
    unittest.main()
