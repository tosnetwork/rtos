"""Body/state evidence must come from the receiver and preserve finality checks."""

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from receiver_evidence import collect_receiver_evidence, require_receiver_check


class ReceiverEvidenceTests(unittest.IsolatedAsyncioTestCase):
    def checked(self):
        block = {
            "workchain": -1,
            "shard": "-9223372036854775808",
            "seqno": 10,
            "root_hash": "root",
            "file_hash": "file",
        }
        return {
            "block": block,
            "state_root_hash": "state",
            "cell_hash_checked": True,
            "file_hash_checked": True,
            "header_identity_checked": True,
            "state_update_matches_both": True,
            "verified_final_certificates": [{"final_certificate_checked": True}],
        }

    async def test_receivers_own_body_and_state_replace_peer_inputs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference"
            reference.mkdir()
            checked = self.checked()
            target = checked["block"]
            original = {
                "block": {"id": target, "boc": "peer-body"},
                "masterchain_state": "peer-state",
                "certificates": ["peer-proof"],
            }
            (reference / "sample.json").write_text(json.dumps(original))
            (reference / "epoch-checked.json").write_text(json.dumps(checked))
            receiver = SimpleNamespace(
                root=root,
                node=SimpleNamespace(liteserver_config="receiver-config"),
                receipt={},
                save=Mock(),
            )
            args = SimpleNamespace(
                snapshot=root / "snapshot", block_checker=root / "checker"
            )

            async def check(command, log):
                sample = json.loads(command[1].read_text())
                self.assertEqual(sample["block"]["boc"], "receiver-body")
                self.assertEqual(sample["masterchain_state"], "receiver-state")
                self.assertEqual(sample["certificates"], ["peer-proof"])
                command[2].write_text(json.dumps(checked))

            with (
                patch(
                    "receiver_evidence.cpp_block",
                    new=AsyncMock(return_value={"id": target, "boc": "receiver-body"}),
                ) as body,
                patch(
                    "receiver_evidence.native_state",
                    new=AsyncMock(return_value="receiver-state"),
                ) as state,
                patch("receiver_evidence.child_checked", new=check),
            ):
                await collect_receiver_evidence(args, receiver, target, reference)
            self.assertIs(body.call_args.args[1], receiver.node)
            self.assertEqual(state.call_args.args[1], "receiver-config")
            self.assertEqual(
                json.loads((reference / "sample.json").read_text()), original
            )
            receiver.save.assert_called_once()

    async def test_wrong_identity_state_and_unchecked_data_are_rejected(self):
        checked = self.checked()
        for field in (
            "cell_hash_checked",
            "file_hash_checked",
            "header_identity_checked",
            "state_update_matches_both",
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                require_receiver_check(
                    {**checked, field: False}, checked["block"], "state"
                )
        for change in (
            lambda d: d["block"].update(seqno=11),
            lambda d: d.update(state_root_hash="wrong"),
            lambda d: d.update(verified_final_certificates=[]),
            lambda d: d["verified_final_certificates"][0].update(
                final_certificate_checked=False
            ),
        ):
            bad = copy.deepcopy(checked)
            change(bad)
            with self.assertRaises(ValueError):
                require_receiver_check(bad, checked["block"], "state")
