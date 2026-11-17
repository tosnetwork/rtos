import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import bootstrap_evidence as fixture


class RequiredVoteTests(unittest.TestCase):
    def inputs(self):
        required = {
            "validator_id": "rust",
            "cpp_ids": ["cpp0", "cpp1"],
            "committee": {"cpp0": 17, "cpp1": 17, "absent": 17, "rust": 17},
        }
        checked = {
            "configuration": {
                "state_root_checked": True,
                "current": {
                    "members": [
                        {"validator_id": member, "weight": weight}
                        for member, weight in required["committee"].items()
                    ]
                },
            },
            "verified_final_certificates": [
                {
                    "final_certificate_checked": True,
                    "validator_ids": ["cpp0", "cpp1", "rust"],
                    "verified_weight": 51,
                    "session_id": "actual-session",
                    "slot": 7,
                }
            ],
        }
        return checked, required

    def test_required_vote_is_bound_to_checked_weight_and_topology(self):
        checked, required = self.inputs()
        result = fixture.require_bootstrap_vote(checked, required)
        self.assertEqual(result["quorum_weight"], 46)
        self.assertEqual(result["cpp_weight"], 34)
        self.assertEqual(result["verified_weight"], 51)

    def test_metadata_and_wrong_certificates_cannot_replace_required_vote(self):
        checked, required = self.inputs()
        for mutation in (
            "missing",
            "unchecked",
            "duplicate",
            "absent",
            "weight",
            "committee",
            "state",
        ):
            with self.subTest(mutation=mutation):
                bad = deepcopy(checked)
                cert = bad["verified_final_certificates"][0]
                if mutation == "missing":
                    cert.update(validator_ids=["cpp0", "cpp1"], verified_weight=34)
                elif mutation == "unchecked":
                    cert["final_certificate_checked"] = False
                elif mutation == "duplicate":
                    cert["validator_ids"] = ["cpp0", "rust", "rust"]
                elif mutation == "absent":
                    cert["validator_ids"] = ["cpp0", "absent", "rust"]
                elif mutation == "weight":
                    cert["verified_weight"] = 52
                elif mutation == "committee":
                    bad["configuration"]["current"]["members"][0]["weight"] = 18
                else:
                    bad["configuration"]["state_root_checked"] = False
                with self.assertRaises(ValueError):
                    fixture.require_bootstrap_vote(bad, required)


class BootstrapEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def collect(self, root, *, wrong_body=False, unchecked=False):
        target = {
            "workchain": -1,
            "shard": str(-(1 << 63)),
            "seqno": 4,
            "root_hash": "root",
            "file_hash": "file",
        }
        observed = {"last": target, "state_root_hash": "state"}
        observation = {
            "zerostate": dict(target, seqno=0),
            "references": [observed],
            "rust": observed,
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
        if unchecked:
            checked["state_update_matches_both"] = False

        async def checker(command, log):
            sample = json.loads(command[1].read_text())
            self.assertEqual(sample["reference"], observed)
            self.assertEqual(sample["masterchain_state"]["name"], "rust-bootstrap")
            command[2].write_text(json.dumps(checked))

        config = object()
        state = AsyncMock(
            return_value={"name": "rust-bootstrap", "boc": "actual-state"}
        )
        body = {
            "id": dict(target, seqno=5) if wrong_body else target,
            "data": "actual-body",
        }
        with (
            patch.object(fixture, "native_state", state),
            patch.object(
                fixture,
                "cpp_certificate",
                AsyncMock(return_value={"kind": "cpp_lite"}),
            ),
            patch.object(fixture, "child_checked", checker),
        ):
            result = await fixture.collect_bootstrap_evidence(
                SimpleNamespace(
                    snapshot=Path("snapshot"), block_checker=Path("checker")
                ),
                observation,
                "rust-rpc",
                lambda *args: body,
                config,
                object(),
                b"zerostate",
                root / "evidence",
            )
        self.assertIs(state.call_args.args[1], config)
        self.assertEqual(result["source"], "rust_bootstrap")
        self.assertTrue(result["body_and_full_state_checked"])

    async def test_own_body_and_state_are_checked(self):
        with TemporaryDirectory() as tmp:
            await self.collect(Path(tmp))

    async def test_wrong_checkpoint_body_is_rejected(self):
        with (
            TemporaryDirectory() as tmp,
            self.assertRaisesRegex(ValueError, "checkpoint"),
        ):
            await self.collect(Path(tmp), wrong_body=True)

    async def test_unchecked_state_cannot_be_qualified(self):
        with (
            TemporaryDirectory() as tmp,
            self.assertRaisesRegex(ValueError, "state_update"),
        ):
            await self.collect(Path(tmp), unchecked=True)
