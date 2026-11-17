"""Async group startup must not reset the original expiry observation budget."""

import tempfile
import unittest
from pathlib import Path

import signer_expiry_fixture as expiry
import test_signer_expiry as fixtures


class RuntimeReadyTests(unittest.TestCase):
    def test_custody_receipt_binds_raw_public_copies_and_rejects_tampering(self):
        from scenario_expiry import check_expiry_authority_copies

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, checkpoint, namespace = fixtures.SignerExpiryTests().context(
                root
            )
            observer = expiry.SignerExpiry(args, root, node, checkpoint)
            self.assertEqual(
                observer.receipt["authority_kind"], "configured_pq_custody"
            )
            self.assertFalse((namespace / "isolated-signing.json").exists())
            check_expiry_authority_copies(root, observer.receipt)
            saved = root / "signer-expiry/original-custody.json"
            saved.write_text("{}")
            with self.assertRaisesRegex(ValueError, "Saved custody authority"):
                check_expiry_authority_copies(root, observer.receipt)

    def test_missing_runtime_retries_without_resetting_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, checkpoint, namespace = fixtures.SignerExpiryTests().context(
                root
            )
            profile = namespace / "session-runtime.json"
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
            args, node, checkpoint, _namespace = fixtures.SignerExpiryTests().context(
                root
            )
            (node["directory"] / "config.json").write_text("invalid")
            with self.assertRaises(ValueError):
                expiry.SignerExpiry(args, root, node, checkpoint)
