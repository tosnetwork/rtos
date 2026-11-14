import base64
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from cpp_baseline import CANDIDATE_CPP_REVISION
from successor_ledger_fixture import prepare_successor_ledgers


class SuccessorLedgerTest(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(snapshot=self.root, rust_node=True)
        self.zero = {
            k: base64.b64encode(bytes([i]) * 32).decode()
            for i, k in enumerate(["root_hash", "file_hash"])
        }
        self.profile = {
            "cpp_revision": CANDIDATE_CPP_REVISION,
            "initial_members": [0, 1, 2, 3],
            "successor_members": [0, 2, 4, 5],
            "expected_zerostate": self.zero,
        }
        self.nodes = []
        for i in range(6):
            directory = self.root / str(i)
            directory.mkdir()
            (directory / "keyring").mkdir()
            (directory / "pq-consensus.seed").write_bytes(b"fixture")
            self.nodes.append(
                SimpleNamespace(
                    directory=directory,
                    process_id=None,
                    pq_initial_validator=SimpleNamespace(
                        validator_id=hashlib.sha256(
                            f"n6-validator-id-{i}".encode()
                        ).digest()
                    ),
                )
            )

    def run_ceremony(self):
        prepare_successor_ledgers(
            self.args, self.profile, self.nodes, self.zero, self.root
        )

    def create_ledger(self, command, **kwargs):
        ledger = Path(command[3]) / "consensus/signing-ledger/ledger"
        ledger.parent.mkdir(parents=True)
        ledger.write_bytes(b"ledger")
        return SimpleNamespace(returncode=0, stderr="")

    def test_only_fresh_cpp_successor_and_second_invocation_refused(self):
        with patch(
            "successor_ledger_fixture.subprocess.run", side_effect=self.create_ledger
        ) as run:
            self.run_ceremony()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][3], str(self.nodes[4].directory))
            self.assertEqual(
                run.call_args.args[0][4],
                self.nodes[4].pq_initial_validator.validator_id.hex(),
            )
            with self.assertRaises(ValueError):
                self.run_ceremony()
            self.assertEqual(run.call_count, 1)

    def test_existing_state_or_running_process_refused_before_command(self):
        with patch("successor_ledger_fixture.subprocess.run") as run:
            self.nodes[4].process_id = 123
            with self.assertRaises(ValueError):
                self.run_ceremony()
            self.nodes[4].process_id = None
            (self.nodes[4].directory / "state").mkdir()
            with self.assertRaises(ValueError):
                self.run_ceremony()
            run.assert_not_called()

    def test_identity_and_genesis_mismatch_refused(self):
        with patch("successor_ledger_fixture.subprocess.run") as run:
            self.nodes[4].pq_initial_validator.validator_id = b"wrong"
            with self.assertRaises(ValueError):
                self.run_ceremony()
            self.profile["expected_zerostate"] = {}
            with self.assertRaises(ValueError):
                self.run_ceremony()
            run.assert_not_called()

    def test_command_failure_and_missing_output_fail_closed(self):
        for code in [1, 0]:
            with (
                patch(
                    "successor_ledger_fixture.subprocess.run",
                    return_value=SimpleNamespace(returncode=code, stderr="controlled"),
                ),
                self.assertRaises(RuntimeError),
            ):
                self.run_ceremony()

    def test_all_cpp_preflights_every_successor_before_any_write(self):
        self.args.rust_node = None
        (self.nodes[5].directory / "consensus").mkdir()
        with patch("successor_ledger_fixture.subprocess.run") as run:
            with self.assertRaises(ValueError):
                self.run_ceremony()
            run.assert_not_called()

    def test_historical_profile_does_not_invoke_new_tool(self):
        self.profile["cpp_revision"] = "historical"
        with patch("successor_ledger_fixture.subprocess.run") as run:
            self.run_ceremony()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
