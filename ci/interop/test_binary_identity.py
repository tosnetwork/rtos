import unittest
from types import SimpleNamespace
from unittest.mock import patch

from binary_identity import require_revision_banner, require_rust_revision

REVISION = "a" * 40


class BinaryIdentityTests(unittest.TestCase):
    def test_exact_version_identity(self):
        require_revision_banner(f'RTOS version\nCOMMIT_ID: "{REVISION}"\n', REVISION)

    def test_help_or_incidental_hash_is_not_identity(self):
        for text in ["Usage: rtos [OPTIONS]", f"argument example {REVISION}"]:
            with self.assertRaises(ValueError):
                require_revision_banner(text, REVISION)

    def test_wrong_missing_or_duplicate_identity(self):
        for text in [
            f'COMMIT_ID: "{"b" * 40}"',
            'COMMIT_ID: "not set"',
            f'COMMIT_ID: "{REVISION}"\nCOMMIT_ID: "{REVISION}"',
        ]:
            with self.assertRaises(ValueError):
                require_revision_banner(text, REVISION)

    def test_short_or_empty_revision_rejected(self):
        for revision in ["", "a", "a" * 39, "A" * 40]:
            with self.assertRaises(ValueError):
                require_revision_banner(f'COMMIT_ID: "{REVISION}"', revision)

    @patch("binary_identity.subprocess.run")
    def test_queries_version_not_help(self, run):
        run.return_value = SimpleNamespace(
            stdout=f'COMMIT_ID: "{REVISION}"\n', stderr=""
        )
        require_rust_revision("node", REVISION)
        self.assertEqual(run.call_args.args[0], ["node", "--version"])
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
