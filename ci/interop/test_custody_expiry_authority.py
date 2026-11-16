"""Finite expiry binds the production custody configuration and loaded key."""

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from custody_expiry_authority import capture_custody_authority


class CustodyAuthorityTests(unittest.TestCase):
    def context(self, root):
        key = root / "consensus-keys/public-test-seed"
        key.parent.mkdir()
        key.write_bytes(b"owned public fixture seed")
        validator = hashlib.sha256(b"n6-validator-id-5").hexdigest()
        prepared = {
            "public_test_member": 5,
            "validator_id": validator,
            "consensus_key_id": "a" * 64,
            "consensus_key_file": str(key),
            "signer_expire_at": 200,
        }
        config = {
            "pq_consensus": {
                "@type": "engine.validator.pqConsensus",
                "validator_id": base64.b64encode(bytes.fromhex(validator)).decode(),
                "consensus_key_file": "",
                "keys": [
                    {
                        "@type": "engine.validator.pqConsensusKey",
                        "consensus_key_file": str(key),
                        "valid_from": 0,
                        "expire_at": 200,
                    }
                ],
            }
        }
        line = f"post-quantum consensus custody: validator_id {validator} key_id {'a' * 64} valid_from 0 expire_at 200"
        (root / "node.log").write_text(line + "\n")
        self.save(root, config, prepared)
        return config, prepared

    def save(self, root, config, prepared):
        (root / "config.json").write_text(json.dumps(config))
        (root / "validator-prepared.json").write_text(json.dumps(prepared))

    def test_actual_config_loaded_identity_and_hashes_are_bound_without_seed_copy(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.context(root)
            result = capture_custody_authority(root, 200)
            self.assertEqual(result["expire_at"], 200)
            self.assertEqual(result["kind"], "configured_pq_custody")
            self.assertEqual(len(result["authority_file_hashes"]), 3)
            self.assertNotIn("owned public fixture seed", json.dumps(result))
            for filename, digest in result["authority_file_hashes"].items():
                self.assertEqual(
                    hashlib.sha256(Path(filename).read_bytes()).hexdigest(), digest
                )

    def test_mismatched_identity_window_key_or_extra_authority_refuses(self):
        for change in [
            "expiry",
            "validator",
            "key",
            "extra",
            "unbounded",
            "bool",
            "loaded",
            "outside",
        ]:
            with self.subTest(change=change), TemporaryDirectory() as tmp:
                root = Path(tmp)
                config, prepared = self.context(root)
                entry = config["pq_consensus"]["keys"][0]
                if change == "expiry":
                    prepared["signer_expire_at"] = 201
                if change == "validator":
                    prepared["validator_id"] = "b" * 64
                if change == "key":
                    prepared["consensus_key_id"] = "b" * 64
                if change == "extra":
                    config["pq_consensus"]["keys"].append(copy.deepcopy(entry))
                if change == "unbounded":
                    entry["expire_at"] = 0
                if change == "bool":
                    entry["valid_from"] = False
                if change == "loaded":
                    (root / "node.log").write_text("other session\n")
                if change == "outside":
                    entry["consensus_key_file"] = "/outside/key"
                self.save(root, config, prepared)
                with self.assertRaises(ValueError):
                    capture_custody_authority(root, 200)
