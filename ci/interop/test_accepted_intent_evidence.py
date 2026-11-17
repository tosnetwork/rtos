"""Reject missing obligations and unrelated historical state/certificate witnesses."""

import asyncio
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from accepted_intent_evidence import (
    check_original_output,
    masterchain_outputs,
    verify_masterchain_intent,
)


def fixture():
    record = {
        "slot": 10,
        "candidate_hash": "11" * 32,
        "session_id": "22" * 32,
        "certificate": "aa",
    }
    sealed = {
        "schema": 1,
        "digest": hashlib.sha256(
            json.dumps(record, separators=(",", ":")).encode()
        ).hexdigest(),
        "metadata": dict(record, certificate=""),
        "released": False,
        "outputs": [
            {
                "block_id": "(-1:8000000000000000, 9, rh "
                + "33" * 32
                + ", fh "
                + "44" * 32
                + ")",
                "is_final": True,
                "source_validator": "55" * 32,
            }
        ],
    }
    block = masterchain_outputs(record, sealed)[0]
    checked = {
        "mode": "finality-witness",
        "status": "block_and_state_match",
        "block": block,
        "rpc_heads_checked": False,
        "state_update_matches_full_state": True,
        "file_hash_checked": True,
        "cell_hash_checked": True,
        "header_identity_checked": True,
        "created_by": base64.b64encode(bytes.fromhex("55" * 32)).decode(),
        "verified_final_certificates": [{"final_certificate_checked": True}],
        "state_root_hash": "same-root",
    }
    states = {
        "mode": "state-copies",
        "block": block,
        "state_root_hash": "same-root",
        "sources": ["cpp-reference", "restarted-rust"],
        "finality_checked": False,
    }
    return record, sealed, block, checked, states


class AcceptedIntentEvidenceTests(unittest.TestCase):
    def test_complete_original_mc_set_and_matching_state_copies(self):
        record, sealed, block, checked, states = fixture()
        self.assertEqual(masterchain_outputs(record, sealed), [block])
        check_original_output(sealed["outputs"][0], block, checked, states)

    def test_missing_or_changed_set_is_not_zero_work(self):
        record, sealed, *_ = fixture()
        for altered in [
            None,
            {},
            dict(sealed, outputs=[]),
            dict(sealed, digest="wrong"),
            dict(sealed, metadata={}),
            dict(sealed, released=1),
            dict(sealed, outputs=sealed["outputs"] * 2),
        ]:
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                masterchain_outputs(record, altered)

    def test_workchain_and_approval_obligations_cannot_be_silently_skipped(self):
        record, sealed, *_ = fixture()
        for key, value in [
            ("is_final", False),
            ("block_id", sealed["outputs"][0]["block_id"].replace("(-1:", "(0:")),
            ("source_validator", "bad"),
        ]:
            altered = copy.deepcopy(sealed)
            altered["outputs"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                masterchain_outputs(record, altered)

    def test_wrong_creator_certificate_or_unchecked_block_rejected(self):
        _, sealed, block, checked, states = fixture()
        mutations = [
            ("created_by", base64.b64encode(bytes(32)).decode()),
            ("verified_final_certificates", []),
            ("verified_final_certificates", [{"final_certificate_checked": False}]),
            ("rpc_heads_checked", True),
            ("file_hash_checked", False),
            ("cell_hash_checked", False),
            ("header_identity_checked", False),
        ]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_original_output(
                    sealed["outputs"][0], block, dict(checked, **{key: value}), states
                )

    def test_other_block_root_or_missing_restarted_node_rejected(self):
        _, sealed, block, checked, states = fixture()
        for key, value in [
            ("state_root_hash", "other-root"),
            ("block", dict(block, seqno=10)),
            ("sources", ["cpp-reference"]),
            ("sources", ["cpp-reference", "cpp-reference"]),
            ("sources", ["cpp-reference", "restarted-rust", "restarted-rust"]),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_original_output(
                    sealed["outputs"][0], block, checked, dict(states, **{key: value})
                )

    def test_valid_other_final_does_not_complete_original_trigger(self):
        record, sealed, block, checked, states = fixture()
        checked["verified_final_certificates"] = [
            {
                "final_certificate_checked": True,
                "session_id": base64.b64encode(
                    bytes.fromhex(record["session_id"])
                ).decode(),
                "slot": record["slot"] + 1,
                "candidate_hash": record["candidate_hash"],
            }
        ]

        async def checker(command, log):
            result = checked if Path(command[1]).stem == "finality" else states
            Path(command[2]).write_text(json.dumps(result))

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "accepted_intent_evidence.cpp_block",
                new=AsyncMock(return_value={"id": block}),
            ),
            patch(
                "accepted_intent_evidence.cpp_certificate",
                new=AsyncMock(return_value={}),
            ),
            patch(
                "accepted_intent_evidence.native_state",
                new=AsyncMock(return_value={"id": block}),
            ),
            patch("accepted_intent_evidence.child_checked", new=checker),
        ):
            import time

            with self.assertRaisesRegex(ValueError, "exact Final trigger"):
                asyncio.run(
                    verify_masterchain_intent(
                        record,
                        sealed,
                        snapshot=None,
                        checker=None,
                        cpp_node=None,
                        cpp_config=None,
                        rust_config=None,
                        zero={},
                        governing={},
                        directory=Path(tmp) / "proof",
                        deadline=time.monotonic() + 2,
                    )
                )

    def test_expired_budget_does_not_start_io(self):
        record, sealed, *_ = fixture()
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("accepted_intent_evidence.cpp_block") as fetch,
        ):
            target = Path(tmp) / "proof"
            with self.assertRaises(TimeoutError):
                asyncio.run(
                    verify_masterchain_intent(
                        record,
                        sealed,
                        snapshot=None,
                        checker=None,
                        cpp_node=None,
                        cpp_config=None,
                        rust_config=None,
                        zero=None,
                        governing=None,
                        directory=target,
                        deadline=0,
                    )
                )
            fetch.assert_not_called()
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
