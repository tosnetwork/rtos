import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from bootstrap_control import network_factory
from cpp_baseline import ACTIVE_CPP_REVISION, DEFAULT_AUTH_NETWORK_TAG
from mixed_matrix import digest
from scenario_bootstrap import bootstrap_commands, check_bootstrap_result
from scenarios import CATALOG, order, validate


class BootstrapAdapterTests(unittest.TestCase):
    def test_native_control_includes_its_nonvoting_verifier(self):
        native = {
            "evidence_class": "DIAGNOSTIC_SCAFFOLDING_ONLY",
            "release_evidence_eligible": False,
            "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
            "nodes": [
                {"name": f"node-{i}", "adnl_identity": str(i), "role": "validator"}
                for i in range(4)
            ]
            + [
                {
                    "name": "observer",
                    "adnl_identity": "other",
                    "role": "non-validator-verifier",
                }
            ],
        }
        result = {
            "cpp_commit": "revision",
            "status": "passed_cpp_control_only",
            "mixed_network_qualified": False,
            "result": native,
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "result.json").write_text(json.dumps(native))
            check_bootstrap_result(
                "cpp-bootstrap", result, {"cpp_revision": "revision"}, root
            )
            native["nodes"][-1]["role"] = "validator"
            (root / "result.json").write_text(json.dumps(native))
            with self.assertRaises(ValueError):
                check_bootstrap_result(
                    "cpp-bootstrap", result, {"cpp_revision": "revision"}, root
                )

    def test_native_control_receives_explicit_auth_tag_before_genesis(self):
        network = SimpleNamespace(config=SimpleNamespace(auth_network_tag=None))
        received = []

        def constructor(*args, **kwargs):
            received.append((args, kwargs))
            return network

        create = network_factory(
            constructor,
            {
                "cpp_revision": ACTIVE_CPP_REVISION,
                "auth_network_tag": DEFAULT_AUTH_NETWORK_TAG,
            },
        )
        self.assertIs(create("install", base_port=59800), network)
        self.assertEqual(
            network.config.auth_network_tag, bytes.fromhex(DEFAULT_AUTH_NETWORK_TAG)
        )
        self.assertEqual(received, [(("install",), {"base_port": 59800})])

    def test_native_control_precedes_both_mixed_modes(self):
        entries = validate(json.loads(CATALOG.read_text()), CATALOG.parent)
        self.assertEqual(
            order(entries, ["unsigned-bootstrap", "required-rust-vote"]),
            ["cpp-bootstrap", "unsigned-bootstrap", "required-rust-vote"],
        )
        for name in ("cpp-bootstrap", "unsigned-bootstrap", "required-rust-vote"):
            self.assertEqual(entries[name]["execution"], "bootstrap_v1")

    def test_unsigned_command_cannot_inherit_signing_preparer(self):
        args = SimpleNamespace(
            cpp_python="python",
            snapshot="snapshot",
            rust_node="rtos",
            validator_preparer="prepare",
            block_checker="check",
        )
        prepare, command = bootstrap_commands(args, "unsigned-bootstrap", Path("case"))
        self.assertIsNone(prepare)
        self.assertNotIn("--validator-preparer", command)
        self.assertIn("--verify-full-state", command)
        _, active = bootstrap_commands(args, "required-rust-vote", Path("case"))
        self.assertIn("--validator-preparer", active)
        self.assertEqual(active[active.index("--cpp-count") + 1], "2")

    def fixture(self, root):
        directory = root / "bootstrap-evidence"
        directory.mkdir()
        (root / "rust").mkdir()
        target = {
            "workchain": -1,
            "shard": str(-(1 << 63)),
            "seqno": 4,
            "root_hash": "root",
            "file_hash": "file",
        }
        observation = {"zerostate": {}, "references": [], "rust": {"last": target}}
        sample = {
            **observation,
            "block": {"id": target},
            "masterchain_state": {"name": "rust-bootstrap"},
        }
        checked = {
            "block": target,
            "state_root_hash": "state",
            "cell_hash_checked": True,
            "file_hash_checked": True,
            "header_identity_checked": True,
            "state_update_matches_both": True,
            "verified_final_certificates": [{"final_certificate_checked": True}],
        }
        for path, value in {
            "bootstrap-evidence/sample.json": sample,
            "bootstrap-evidence/checked.json": checked,
            "rust/config.json": {},
            "process.json": {
                "rust_pid": 1,
                "cpp_pids": {"a": 2, "b": 3, "c": 4},
                "unused_cpp_pids": {"d": None},
            },
            "rust-shutdown.json": {"returncode": -15},
        }.items():
            (root / path).write_text(json.dumps(value))
        result = {
            "cpp_commit": "revision",
            "status": "rust_public_sync_observed",
            "active_rust_signing": False,
            "cpp_process_count": 3,
            "committee_size": 4,
            "mixed_validator_qualified": False,
            "applied_state_sample": observation,
            "config_sha256": digest(root / "rust/config.json"),
            "body_state_evidence": {
                "source": "rust_bootstrap",
                "body_and_full_state_checked": True,
                "sample_directory": str(directory),
                "block": target,
                "state_root_hash": "state",
                "sample_sha256": digest(directory / "sample.json"),
                "checked_sha256": digest(directory / "checked.json"),
                "required_rust_vote": None,
            },
        }
        return result

    def test_raw_evidence_and_unsigned_custody_are_required(self):
        for mutation in (
            None,
            "root-only",
            "hash",
            "path",
            "custody",
            "extra-process",
            "killed",
        ):
            with self.subTest(mutation=mutation), TemporaryDirectory() as tmp:
                root = Path(tmp)
                result = copy.deepcopy(self.fixture(root))
                if mutation == "root-only":
                    result["body_state_evidence"] = {}
                elif mutation == "hash":
                    (root / "bootstrap-evidence/sample.json").write_text("{}")
                elif mutation == "path":
                    result["body_state_evidence"]["sample_directory"] = str(root.parent)
                elif mutation == "custody":
                    (root / "rust/config.json").write_text(
                        '{"pq_consensus":{"keys":["unexpected"]}}'
                    )
                    result["config_sha256"] = digest(root / "rust/config.json")
                elif mutation == "extra-process":
                    path = root / "process.json"
                    value = json.loads(path.read_text())
                    value["unused_cpp_pids"]["d"] = 5
                    path.write_text(json.dumps(value))
                elif mutation == "killed":
                    (root / "rust-shutdown.json").write_text('{"returncode":-9}')
                if mutation is None:
                    check_bootstrap_result(
                        "unsigned-bootstrap", result, {"cpp_revision": "revision"}, root
                    )
                else:
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        check_bootstrap_result(
                            "unsigned-bootstrap",
                            result,
                            {"cpp_revision": "revision"},
                            root,
                        )
