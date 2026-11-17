"""Never qualify a Final trigger while omitting a sibling approval output."""

import base64
import copy
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from workchain_output_evidence import (
    block_text,
    matches_workchain_outputs,
    sealed_workchain_outputs,
    verify_sealed_workchain_requests,
    verify_workchain_output_requests,
)


def fixture():
    intent = {"session_id": "11" * 32, "slot": 10, "candidate_hash": "22" * 32}
    proofs, outputs = [], []
    for height, role in [(5, True), (4, False)]:
        block = {
            "workchain": 0,
            "shard": str(-(1 << 63)),
            "seqno": height,
            "root_hash": base64.b64encode(bytes([height]) * 32).decode(),
            "file_hash": base64.b64encode(bytes([height + 1]) * 32).decode(),
        }
        outputs.append(
            {
                "block_id": block_text(block),
                "is_final": role,
                "source_validator": "33" * 32,
            }
        )
        proofs.append(
            {
                "mode": "workchain-carrier",
                "status": "block_and_state_match",
                "verified_final_certificates": [{"final_certificate_checked": True}],
                "workchain_check": {
                    "block": block,
                    "created_by": base64.b64encode(bytes.fromhex("33" * 32)).decode(),
                    "masterchain_anchor_checked": True,
                    "block_file_cell_and_header_checked": True,
                    "all_declared_states_match_block_update": True,
                    "verified_carrier": {
                        "is_final": role,
                        "final_certificate_checked": role,
                        "approval_checked": not role,
                        "session_id": base64.b64encode(
                            bytes.fromhex(intent["session_id"])
                        ).decode(),
                        "slot": 10,
                        "candidate_hash": intent["candidate_hash"],
                    },
                },
            }
        )
    return intent, outputs, proofs


class WorkchainOutputEvidenceTests(unittest.TestCase):
    def test_sealed_original_set_preserves_both_roles_and_binding(self):
        intent, outputs, _ = fixture()
        intent.update(workchain=0, shard_prefix=1 << 63, certificate="original")
        sealed = {
            "schema": 1,
            "digest": hashlib.sha256(
                json.dumps(intent, separators=(",", ":")).encode()
            ).hexdigest(),
            "metadata": dict(intent, certificate=""),
            "released": False,
            "outputs": outputs,
        }
        self.assertEqual(
            [b["seqno"] for b in sealed_workchain_outputs(intent, sealed)], [5, 4]
        )
        for changed in [
            None,
            {},
            dict(sealed, digest="wrong"),
            dict(sealed, metadata={}),
            dict(sealed, released=1),
            dict(sealed, outputs=[]),
            dict(sealed, outputs=outputs * 2),
            dict(sealed, outputs=outputs[1:]),
            dict(sealed, outputs=[dict(outputs[0], is_final=1)]),
            dict(sealed, outputs=[dict(outputs[0], source_validator="bad")]),
            dict(
                sealed,
                outputs=[
                    dict(
                        outputs[0],
                        block_id=outputs[0]["block_id"].replace("(0:", "(-1:"),
                    )
                ],
            ),
        ]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                sealed_workchain_outputs(intent, changed)
        with patch(
            "workchain_output_evidence.verify_workchain_output_requests",
            return_value=["verified"],
        ) as verify:
            self.assertEqual(
                verify_sealed_workchain_requests(
                    intent, sealed, ["request"], "checker", "out", 12
                ),
                ["verified"],
            )
            verify.assert_called_once_with(
                intent, outputs, ["request"], "checker", "out", 12
            )
        with patch(
            "workchain_output_evidence.verify_workchain_output_requests"
        ) as verify:
            with self.assertRaises(ValueError):
                verify_sealed_workchain_requests(
                    intent, dict(sealed, outputs=[]), [], "checker", "out", 12
                )
            verify.assert_not_called()

    def test_complete_outputs_and_trigger_required(self):
        intent, outputs, proofs = fixture()
        self.assertTrue(matches_workchain_outputs(intent, outputs, proofs))
        self.assertFalse(matches_workchain_outputs(intent, outputs, proofs[:1]))
        self.assertFalse(matches_workchain_outputs(intent, outputs, proofs[1:]))
        self.assertFalse(
            matches_workchain_outputs(intent, outputs + outputs[:1], proofs)
        )
        self.assertFalse(matches_workchain_outputs(intent, [], proofs))
        for field, value in [
            ("session_id", "00" * 32),
            ("candidate_hash", "00" * 32),
            ("slot", 11),
            ("slot", True),
        ]:
            with self.subTest(field=field, value=value):
                self.assertFalse(
                    matches_workchain_outputs(
                        dict(intent, **{field: value}), outputs, proofs
                    )
                )

    def test_each_native_boundary_and_output_identity_required(self):
        intent, outputs, proofs = fixture()
        for mutate in [
            lambda p: p[1].update(mode="state-copies"),
            lambda p: p[1].update(verified_final_certificates=[]),
            lambda p: p[1]["workchain_check"].update(masterchain_anchor_checked=False),
            lambda p: p[1]["workchain_check"].update(
                all_declared_states_match_block_update=False
            ),
            lambda p: p[1]["workchain_check"]["block"].update(seqno=99),
            lambda p: p[1]["workchain_check"].update(
                created_by=base64.b64encode(bytes(32)).decode()
            ),
            lambda p: p[1]["workchain_check"]["verified_carrier"].update(
                final_certificate_checked=True
            ),
            lambda p: p[1]["workchain_check"]["verified_carrier"].update(
                approval_checked=False
            ),
        ]:
            changed = copy.deepcopy(proofs)
            mutate(changed)
            self.assertFalse(matches_workchain_outputs(intent, outputs, changed))


class WorkchainRequestExecutionTests(unittest.TestCase):
    def test_expired_deadline_does_not_launch_or_create_evidence(self):
        intent, outputs, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            with patch("subprocess.run") as run:
                with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                    verify_workchain_output_requests(
                        intent,
                        outputs,
                        ["missing.json"],
                        "checker",
                        evidence,
                        time.monotonic() - 1,
                    )
                run.assert_not_called()
            self.assertFalse(evidence.exists())

    def test_wrong_mode_does_not_launch_checker(self):
        intent, outputs, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "request.json"
            source.write_text(json.dumps({"mode": "state-copies"}))
            with patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "native workchain carrier"):
                    verify_workchain_output_requests(
                        intent,
                        outputs,
                        [source],
                        "checker",
                        Path(directory) / "evidence",
                        time.monotonic() + 10,
                    )
                run.assert_not_called()
