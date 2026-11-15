"""Async group startup must not reset the original expiry observation budget."""

import tempfile
import unittest
from pathlib import Path

import signer_expiry_fixture as expiry
import test_signer_expiry as fixtures


class RuntimeReadyTests(unittest.TestCase):
    def test_missing_profile_retries_without_resetting_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, checkpoint, namespace = fixtures.SignerExpiryTests().context(
                root
            )
            profile = namespace / "isolated-signing.json"
            raw = profile.read_bytes()
            profile.unlink()
            with self.assertRaises(expiry.SignerExpiryRuntimePending):
                expiry.SignerExpiry(args, root, node, checkpoint)
            anchor = args.signer_expiry_observation_start
            profile.write_bytes(raw)
            observer = expiry.SignerExpiry(args, root, node, checkpoint)
            self.assertEqual(args.signer_expiry_observation_start, anchor)
            self.assertEqual(observer.started, anchor[0])
            self.assertEqual(observer.deadline, anchor[0] + args.recovery_timeout)

    def test_existing_malformed_profile_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, checkpoint, namespace = fixtures.SignerExpiryTests().context(
                root
            )
            (namespace / "isolated-signing.json").write_text("invalid")
            with self.assertRaises(ValueError):
                expiry.SignerExpiry(args, root, node, checkpoint)
