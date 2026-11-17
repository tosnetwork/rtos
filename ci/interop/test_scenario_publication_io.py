"""Refuse missing live EIO evidence and mismatched restart/budget claims."""

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from scenario_execution import ROTATIONS, check_result
from scenario_packet import file_hash
from scenario_publication_io import (
    check_publication_io_result,
    publication_io_arguments,
    publication_io_artifacts,
    require_original_cleanup,
    require_original_intent,
)
from test_scenario_execution import rotation_result
from test_scenario_restart import fixture


def result_fixture():
    partition, recovery = fixture()
    recovery["before"] = {"seqno": 10}
    partition["budget_started_at_unix"] = 90
    publication = {
        "record_id": None,
        "node_receipt": None,
        "delivery_id": "delivery",
        "stage": "LiveAcceptance",
    }
    source = {
        "mode": "live-acceptance-body-sync-eio",
        "member": 2,
        "phase": "recovered",
        "interruption_returncode": -9,
        "original_intents_preserved": True,
        "pending_preserved_after_interruption": True,
        "pending_preserved_before_restart": True,
        "original_intents_resolved": True,
        "original_block_native_state_match": True,
        "original_final_certificate_checked": True,
        "node_io_original_source_recovered": True,
        "source_canonical_delivery_before_interruption": False,
        "node_io_failure_before_callback": True,
        "manual_database_repair": False,
        "recovery_limit_seconds": 180,
        "elapsed_seconds": 46,
        "budget_started_at_unix": 90,
        "original_intents": [{"path": "intent"}],
        "original_block": {"workchain": -1, "seqno": 11},
        "final_checkpoint": recovery["last_checkpoint"],
        "session": "session",
        "node_io_target": {
            "pid": 10,
            "selector": {"pid": 10, "session_id": "session", "delivery_id": "delivery"},
            "publication": publication,
        },
        "node_observed_error": {
            "pid": 10,
            "publication": publication,
            "typed_durability_failure": True,
            "publication_owner_marked_fatal": True,
            "accepted_callback_returned": False,
            "retained_draft_verified": False,
            "error": "Input/output error (os error 5)",
        },
    }
    for key in ("old_pid", "new_pid", "new_start_ticks", "survivor_checkpoint"):
        source[key] = partition[key]
    wrapper = {
        "mode": "node_body_sync_eio_and_partition_restart",
        "member": 2,
        "phase": "recovered",
        "source_phase": "recovered",
        "partition_phase": "recovered",
        "recovery_limit_seconds": 180,
        "elapsed_seconds": 47,
        "budget_started_at_unix": 90,
    }
    result = rotation_result()
    result.update(
        node_io_source=source,
        publication_io_restart=wrapper,
        partition_restart=partition,
        recovery=recovery,
    )
    return result


class PublicationIoScenarioTest(unittest.TestCase):
    def test_other_intent_or_certificate_cannot_replace_selected_request(self):
        with TemporaryDirectory() as directory:
            namespace = Path(directory)
            original = namespace / "finality-intents/3-candidate.json"
            saved = namespace / "original-0.json"
            cert = {
                "slot": 3,
                "candidate_hash": "candidate",
                "session_id": "session",
                "certificate": [1, 2, 3],
            }
            saved.write_text(json.dumps(cert))
            intent = {
                "path": str(original),
                "sha256": file_hash(saved),
                "bytes": saved.stat().st_size,
            }
            selected = dict(intent, slot=3, candidate_hash="candidate")
            require_original_intent(
                original, saved, intent, selected, namespace, "session"
            )
            for key, value in (("candidate_hash", "other"), ("certificate", [4, 5, 6])):
                with self.subTest(key=key):
                    changed = dict(cert, **{key: value})
                    saved.write_text(json.dumps(changed))
                    forged = dict(
                        intent, sha256=file_hash(saved), bytes=saved.stat().st_size
                    )
                    if key == "candidate_hash":
                        forged["path"] = str(original.with_name("3-other.json"))
                    with self.assertRaisesRegex(ValueError, "original intent identity"):
                        require_original_intent(
                            Path(forged["path"]),
                            saved,
                            forged,
                            selected,
                            namespace,
                            "session",
                        )

    def test_retained_outputs_under_actual_intent_directory_rejected(self):
        with TemporaryDirectory() as directory:
            original = Path(directory) / "finality-intents/3-candidate.json"
            output = original.parent / "outputs-v1/3-candidate.outputs"
            output.parent.mkdir(parents=True)
            output.write_text("sealed outputs")
            with self.assertRaisesRegex(
                ValueError, "retains original intent or outputs"
            ):
                require_original_cleanup(original)
            output.unlink()
            require_original_cleanup(original)
            original.write_text("intent")
            with self.assertRaisesRegex(
                ValueError, "retains original intent or outputs"
            ):
                require_original_cleanup(original)

    def test_integrated_result_requires_live_eio(self):
        self.assertIn("publication-io", ROTATIONS)
        check_result("publication-io", result_fixture())
        with self.assertRaisesRegex(TypeError, "Missing live publication"):
            check_result("publication-io", rotation_result())

    def test_budget_custody_and_identity_mutations(self):
        result = result_fixture()
        check_publication_io_result(result)
        for section, key, value in [
            ("node_io_source", "original_intents", []),
            ("node_io_source", "original_block_native_state_match", False),
            ("node_io_source", "new_pid", 21),
            ("publication_io_restart", "budget_started_at_unix", 91),
            ("publication_io_restart", "recovery_limit_seconds", 181),
            ("publication_io_restart", "elapsed_seconds", 181),
        ]:
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(result)
                changed[section][key] = value
                with self.assertRaises((ValueError, TypeError)):
                    check_publication_io_result(changed)
        changed = copy.deepcopy(result)
        changed["node_io_source"]["node_observed_error"][
            "accepted_callback_returned"
        ] = True
        with self.assertRaises(ValueError):
            check_publication_io_result(changed)
        changed = copy.deepcopy(result)
        changed["source_ack_fault"] = {}
        with self.assertRaisesRegex(ValueError, "propagation custody"):
            check_publication_io_result(changed)

    def test_launch_uses_live_io_and_original_partition(self):
        command = publication_io_arguments(Path("io.so"), Path("mark.so"))
        self.assertEqual(command[command.index("--interrupt-rust-member") + 1], "2")
        self.assertIn("--partition-restart", command)
        self.assertNotIn("--source-retention-cut-library", command)
        self.assertNotIn("--source-ack-fault", command)
        with self.assertRaisesRegex(ValueError, "native library and build record"):
            publication_io_artifacts(SimpleNamespace(), Path("ci/interop"))
