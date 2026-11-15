import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

from cpp_baseline import (
    ACTIVE_CPP_REVISION,
    HISTORICAL_CPP_REVISIONS,
    PREVIOUS_CPP_REVISION,
    configure_auth_namespace,
    require_cpp_baseline,
)


class CppBaselineTests(unittest.TestCase):
    def test_default_profile_and_vectors_pin_current_tos(self):
        self.assertEqual(
            ACTIVE_CPP_REVISION, "5af405dcb1f523be0ff3b812e9f6945275c4945b"
        )
        profile = json.loads(Path(__file__).with_name("testnet-v16.json").read_text())
        self.assertEqual(profile["cpp_revision"], ACTIVE_CPP_REVISION)
        reference = Path(__file__).parents[1] / "conformance/REFERENCE"
        self.assertEqual(reference.read_text().strip(), ACTIVE_CPP_REVISION)
        require_cpp_baseline(profile["cpp_revision"])

    def test_active_default_rejects_old_and_unknown_snapshots(self):
        require_cpp_baseline(ACTIVE_CPP_REVISION)
        for revision in [next(iter(HISTORICAL_CPP_REVISIONS)), "0" * 40]:
            with self.assertRaises(ValueError):
                require_cpp_baseline(revision)

    def test_previous_requires_explicit_matching_profile(self):
        with self.assertRaises(ValueError):
            require_cpp_baseline(PREVIOUS_CPP_REVISION)
        profile = {"cpp_revision": PREVIOUS_CPP_REVISION}
        require_cpp_baseline(PREVIOUS_CPP_REVISION, profile)
        with self.assertRaises(ValueError):
            require_cpp_baseline(ACTIVE_CPP_REVISION, profile)
        config = types.SimpleNamespace()
        with self.assertRaises(ValueError):
            configure_auth_namespace(config, profile)
        configure_auth_namespace(config, {**profile, "auth_network_tag": "ab" * 32})
        self.assertEqual(config.auth_network_tag, bytes.fromhex("ab" * 32))

    def test_signing_cli_rejects_previous_without_explicit_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            (snapshot / "manifest.json").write_text(
                json.dumps({"cpp_source_commit": PREVIOUS_CPP_REVISION})
            )
            command = [
                sys.executable,
                str(Path(__file__).with_name("mixed_bootstrap.py")),
                "--snapshot",
                str(snapshot),
                "--rust-node",
                str(root / "missing-node"),
                "--validator-preparer",
                str(root / "missing-preparer"),
                "--output",
                str(root / "result"),
            ]
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=10, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("C++ snapshot must match", result.stderr)
            self.assertFalse((root / "result" / "network").exists())

    def test_historical_replay_requires_matching_explicit_profile(self):
        old = PREVIOUS_CPP_REVISION
        require_cpp_baseline(old, {"cpp_revision": old})
        with self.assertRaises(ValueError):
            require_cpp_baseline(ACTIVE_CPP_REVISION, {"cpp_revision": old})
        with self.assertRaises(ValueError):
            require_cpp_baseline("0" * 40, {"cpp_revision": "0" * 40})

    def test_current_genesis_refuses_missing_or_malformed_namespace(self):
        for tag in [None, "", "a" * 63, "z" * 64, 42]:
            config = types.SimpleNamespace(auth_network_tag=None)
            with self.assertRaises(ValueError):
                configure_auth_namespace(
                    config,
                    {"cpp_revision": ACTIVE_CPP_REVISION, "auth_network_tag": tag},
                )
            self.assertIsNone(config.auth_network_tag)
        config = types.SimpleNamespace()
        configure_auth_namespace(
            config, {"cpp_revision": ACTIVE_CPP_REVISION, "auth_network_tag": "AB" * 32}
        )
        self.assertEqual(config.auth_network_tag, bytes.fromhex("ab" * 32))

    def test_historical_genesis_needs_no_new_namespace(self):
        config = types.SimpleNamespace()
        configure_auth_namespace(
            config, {"cpp_revision": "8f083dc06bff16705710a01de15eb3123d5d696b"}
        )
        self.assertFalse(hasattr(config, "auth_network_tag"))


if __name__ == "__main__":
    unittest.main()
