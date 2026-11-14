"""Offline tests: crypto vectors, canonical JSON, envelope round-trips.

Run: python3 -m pytest tests/ -x -q   (or: python3 -m unittest discover -s tests)
Live tests are in test_live.py and only run with SWARMRELAY_LIVE=1.
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swarmrelay import ed25519, x25519  # noqa: E402
from swarmrelay.canonical import canonicalize_json  # noqa: E402
from swarmrelay import envelope as env  # noqa: E402
from swarmrelay.identity import generate_identity, identity_from_file_dict  # noqa: E402


class TestEd25519(unittest.TestCase):
    def test_golden_vectors_from_node_webcrypto(self):
        # Golden vectors generated with Node's WebCrypto (crypto.sign, null
        # algorithm = Ed25519) from seed bytes 0..31. Ed25519 is
        # deterministic, so these bytes are exact.
        seed = bytes(range(32))
        public = bytes.fromhex(
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        )
        self.assertEqual(ed25519.public_key_from_seed(seed), public)
        cases = [
            (
                b"",
                "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e584"
                "5ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102",
            ),
            (
                b"abc",
                "cc46d62d3754f41754b27b6ea2cb2c272bafa7a5a1f6062bd060f414e50caae"
                "ac2da66ad39cef4424a90236ea907b7d8057e3443dc5abfc9986967ee7213a407",
            ),
            (
                b"id|general|agent_x|intel|0|1794432000000|deadbeef",
                "1b702678d9ee26a2f097ce52759c54693fb913f91d8c7c67ecc366670ea1239"
                "ce8045ffeb0ad9fb59a5f6c04a30065248af86846b7afe2dfddc57c22ab29eb04",
            ),
        ]
        for message, expected_sig in cases:
            signature = ed25519.sign(seed, message)
            self.assertEqual(signature.hex(), expected_sig)
            self.assertTrue(ed25519.verify(public, message, signature))

    def test_rfc8032_vector_2_public_key(self):
        # RFC 8032 section 7.1, TEST 2: seed -> public key only. Signature
        # correctness is covered by test_sign_verify_roundtrip plus the
        # Node WebCrypto cross-check documented in the README.
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        public = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        self.assertEqual(ed25519.public_key_from_seed(seed), public)

    def test_sign_verify_roundtrip(self):
        for _ in range(3):
            seed = ed25519.generate_seed()
            public = ed25519.public_key_from_seed(seed)
            message = os.urandom(64)
            signature = ed25519.sign(seed, message)
            self.assertTrue(ed25519.verify(public, message, signature))
            self.assertFalse(ed25519.verify(public, message + b"x", signature))
            tampered = bytearray(signature)
            tampered[0] ^= 1
            self.assertFalse(ed25519.verify(public, message, bytes(tampered)))

    def test_pkcs8_roundtrip(self):
        seed = ed25519.generate_seed()
        pkcs8 = ed25519.seed_to_pkcs8_hex(seed)
        self.assertEqual(len(pkcs8), 96)
        self.assertEqual(ed25519.pkcs8_hex_to_seed(pkcs8), seed)
        with self.assertRaises(ValueError):
            ed25519.pkcs8_hex_to_seed("00" * 48)


class TestX25519(unittest.TestCase):
    def test_rfc7748_alice_public_key(self):
        # RFC 7748 section 6.1: Alice's scalar -> Alice's public key.
        scalar = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        self.assertEqual(
            x25519.public_key(scalar).hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        )

    def test_diffie_hellman_agreement(self):
        alice_priv, bob_priv = x25519.generate_private(), x25519.generate_private()
        shared_a = x25519.scalarmult(alice_priv, x25519.public_key(bob_priv))
        shared_b = x25519.scalarmult(bob_priv, x25519.public_key(alice_priv))
        self.assertEqual(shared_a, shared_b)

    def test_pkcs8_roundtrip(self):
        private = x25519.generate_private()
        self.assertEqual(x25519.pkcs8_hex_to_private(x25519.private_to_pkcs8_hex(private)), private)


class TestCanonicalJson(unittest.TestCase):
    def test_sorted_keys_and_compact(self):
        self.assertEqual(canonicalize_json({"b": 1, "a": 2}), '{"a":2,"b":1}')
        self.assertEqual(
            canonicalize_json({"z": {"y": [3, 2, 1], "x": None}}),
            '{"z":{"x":null,"y":[3,2,1]}}',
        )

    def test_numbers_match_javascript(self):
        self.assertEqual(canonicalize_json({"n": 1.5}), '{"n":1.5}')
        self.assertEqual(canonicalize_json({"n": 1000000000000000.0}), '{"n":1000000000000000}')
        self.assertEqual(canonicalize_json({"n": 0.0000001}), '{"n":1e-7}')
        self.assertEqual(canonicalize_json({"n": 1e21}), '{"n":1e+21}')
        self.assertEqual(canonicalize_json({"n": -0.0}), '{"n":0}')
        self.assertEqual(canonicalize_json({"n": float("nan")}), '{"n":null}')
        self.assertEqual(canonicalize_json({"n": 1794432000000}), '{"n":1794432000000}')

    def test_strings_and_unicode(self):
        self.assertEqual(canonicalize_json({"s": "héllo→"}), '{"s":"héllo→"}')
        self.assertEqual(canonicalize_json({"s": 'a"b\\c\nd'}), '{"s":"a\\"b\\\\c\\nd"}')

    def test_roundtrip_stability(self):
        value = {"b": [1, {"d": 4, "c": 3}], "a": "x"}
        first = canonicalize_json(value)
        self.assertEqual(canonicalize_json(json.loads(first)), first)


class TestEnvelope(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        identity = generate_identity()
        signed = env.sign_envelope(
            seed=identity.signing_seed,
            sender=identity.agent_id,
            channel="general",
            type_="intel",
            payload={"message": "hello"},
            sequence=0,
            timestamp=1794432000000,
            envelope_id="00000000-0000-0000-0000-000000000001",
        )
        self.assertEqual(
            signed["checksum"],
            hashlib.sha256(b'{"message":"hello"}').hexdigest(),
        )
        valid, error = env.verify_envelope(signed, identity.signing_public_key)
        self.assertTrue(valid, error)

    def test_tamper_detection(self):
        identity = generate_identity()
        signed = env.sign_envelope(
            seed=identity.signing_seed, sender=identity.agent_id,
            channel="general", type_="intel", payload={"message": "hello"},
        )
        signed["payload"] = {"message": "forged"}
        valid, _ = env.verify_envelope(signed, identity.signing_public_key)
        self.assertFalse(valid)

    def test_agent_id_derivation(self):
        identity = generate_identity()
        expected = "agent_" + hashlib.sha256(
            identity.signing_public_key.lower().encode()
        ).hexdigest()[:16]
        self.assertEqual(identity.agent_id, expected)

    def test_registration_document_signing(self):
        identity = generate_identity()
        document = env.build_registration_document(
            hub_origin="https://openagentforum.com",
            public_key_hex=identity.signing_public_key,
            expected_revision=0,
            name="test-agent",
            x25519_public_key_hex=identity.encryption_public_key,
            capabilities=["python"],
        )
        signed = env.sign_registration(document, identity.signing_seed)
        self.assertEqual(len(signed["signature"]), 128)
        # Signature verifies under the documented domain string.
        message = (env.REGISTRATION_DOMAIN + canonicalize_json(document)).encode()
        self.assertTrue(ed25519.verify(
            bytes.fromhex(identity.signing_public_key),
            message, bytes.fromhex(signed["signature"]),
        ))


class TestIdentity(unittest.TestCase):
    def test_file_roundtrip(self):
        identity = generate_identity()
        restored = identity_from_file_dict(identity.to_file_dict())
        self.assertEqual(restored.agent_id, identity.agent_id)
        self.assertEqual(restored.signing_seed, identity.signing_seed)

    def test_mismatched_key_rejected(self):
        identity = generate_identity()
        data = identity.to_file_dict()
        other = generate_identity()
        data["signingPublicKey"] = other.signing_public_key
        with self.assertRaises(ValueError):
            identity_from_file_dict(data)


if __name__ == "__main__":
    unittest.main()
