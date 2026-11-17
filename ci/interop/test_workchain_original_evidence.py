"""Keep original role, ancestor identity, source set and recovery budget intact."""

import asyncio
import copy
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_workchain_output_evidence import fixture
from workchain_original_evidence import plan_workchain_requests, verify_workchain_intent


def inputs():
    intent, outputs, proofs = fixture()
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
    captures = []
    for index, proof in enumerate(proofs):
        block = dict(proof["workchain_check"]["block"], **{"@type": "tos.blockIdExt"})
        captures.append(
            {
                "block": {"id": block, "boc": f"body-{index}"},
                "previous": [],
                "is_final": index == 0,
                "signature_set": f"carrier-{index}",
            }
        )
    captures[0]["previous"] = [captures[1]["block"]["id"]]
    checkpoint = {
        "workchain": {
            "block": captures[0]["block"],
            "states": [
                {"name": name} for name in ["cpp-0", "rust-2", "cpp-4", "rust-5"]
            ],
        }
    }
    return intent, sealed, captures, checkpoint, proofs


class OriginalWorkchainTests(unittest.TestCase):
    def test_roles_and_exact_ancestry_are_preserved(self):
        intent, sealed, captures, checkpoint, _ = inputs()
        original = copy.deepcopy(checkpoint)
        planned = plan_workchain_requests(intent, sealed, captures, checkpoint)
        self.assertEqual(
            [r["workchain_certificate"]["is_final"] for r in planned], [True, False]
        )
        self.assertEqual(
            planned[1]["workchain"]["anchor_chain"], [captures[0]["block"]]
        )
        self.assertEqual(planned[1]["workchain"]["block"], captures[1]["block"])
        self.assertEqual(checkpoint, original)
        for change in ["missing", "wrong_parent", "cycle", "ambiguous", "role"]:
            altered = copy.deepcopy(captures)
            if change == "missing":
                altered = altered[:1]
            if change == "wrong_parent":
                altered[0]["previous"][0]["root_hash"] = "AA=="
            if change == "cycle":
                altered[0]["previous"] = [altered[0]["block"]["id"]]
            if change == "ambiguous":
                altered.append(dict(altered[1], signature_set="another"))
            if change == "role":
                altered[1]["is_final"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan_workchain_requests(intent, sealed, altered, checkpoint)

    def test_collects_every_source_and_fails_incomplete_native_proof(self):
        intent, sealed, captures, checkpoint, proofs = inputs()
        names = [v["name"] for v in checkpoint["workchain"]["states"]]

        async def state(snapshot, config, name, block, directory):
            return {"name": name, "id": block, "boc": "fresh"}

        async def checker(args, log):
            request = json.loads(Path(args[1]).read_text())
            self.assertEqual(
                {x["name"] for x in request["workchain"]["states"]}, set(names)
            )
            height = request["workchain"]["block"]["id"]["seqno"]
            proof = next(
                p for p in proofs if p["workchain_check"]["block"]["seqno"] == height
            )
            Path(args[2]).write_text(json.dumps(proof))

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "workchain_original_evidence.native_state", side_effect=state
            ) as states,
            patch("workchain_original_evidence.child_checked", side_effect=checker),
        ):
            kwargs = {
                "captures": captures,
                "checkpoint": checkpoint,
                "state_configs": dict.fromkeys(names, "config"),
                "snapshot": "snapshot",
                "checker": "checker",
                "directory": Path(tmp) / "ok",
                "deadline": time.monotonic() + 10,
            }
            result = asyncio.run(verify_workchain_intent(intent, sealed, **kwargs))
            self.assertEqual(len(result), 2)
            self.assertEqual(states.call_count, 8)
            self.assertTrue((Path(tmp) / "ok/receipt.json").exists())
            proofs[1]["workchain_check"]["verified_carrier"]["approval_checked"] = False
            with self.assertRaises(ValueError):
                asyncio.run(
                    verify_workchain_intent(
                        intent, sealed, **dict(kwargs, directory=Path(tmp) / "bad")
                    )
                )
            self.assertFalse((Path(tmp) / "bad/receipt.json").exists())
            with self.assertRaises(ValueError):
                asyncio.run(
                    verify_workchain_intent(
                        intent,
                        sealed,
                        **dict(kwargs, state_configs={"cpp-0": "config"}),
                    )
                )
            with self.assertRaises(TimeoutError):
                asyncio.run(
                    verify_workchain_intent(
                        intent, sealed, **dict(kwargs, deadline=time.monotonic() - 1)
                    )
                )

    def test_slow_state_collection_cannot_extend_original_deadline(self):
        intent, sealed, captures, checkpoint, _ = inputs()

        async def slow(*args):
            await asyncio.sleep(1)

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("workchain_original_evidence.native_state", side_effect=slow),
            patch("workchain_original_evidence.child_checked") as checker,
        ):
            with self.assertRaises(TimeoutError):
                asyncio.run(
                    verify_workchain_intent(
                        intent,
                        sealed,
                        captures=captures,
                        checkpoint=checkpoint,
                        state_configs={
                            x["name"]: None for x in checkpoint["workchain"]["states"]
                        },
                        snapshot="snapshot",
                        checker="checker",
                        directory=Path(tmp) / "proof",
                        deadline=time.monotonic() + 0.02,
                    )
                )
            checker.assert_not_called()
            self.assertFalse((Path(tmp) / "proof/receipt.json").exists())

    def test_first_source_failure_drains_all_sibling_requests(self):
        intent, sealed, captures, checkpoint, _ = inputs()
        ended, completed = [], []

        async def state(snapshot, config, name, block, directory):
            if name == "cpp-0":
                raise RuntimeError("first source failed")
            try:
                await asyncio.sleep(0.05)
                completed.append(name)
            finally:
                ended.append(name)

        async def exercise(directory):
            with self.assertRaisesRegex(RuntimeError, "first source failed"):
                await verify_workchain_intent(
                    intent,
                    sealed,
                    captures=captures,
                    checkpoint=checkpoint,
                    state_configs={
                        x["name"]: None for x in checkpoint["workchain"]["states"]
                    },
                    snapshot="snapshot",
                    checker="checker",
                    directory=directory,
                    deadline=time.monotonic() + 0.02,
                )
            self.assertEqual(set(ended), {"rust-2", "cpp-4", "rust-5"})
            await asyncio.sleep(0.06)
            self.assertEqual(completed, [])

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("workchain_original_evidence.native_state", side_effect=state),
            patch("workchain_original_evidence.child_checked") as checker,
        ):
            asyncio.run(exercise(Path(tmp) / "proof"))
            checker.assert_not_called()
