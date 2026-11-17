import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import bootstrap_evidence as fixture


class BootstrapEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def collect(self, root, *, wrong_body=False, unchecked=False):
        target = dict(
            workchain=-1,
            shard=str(-(1 << 63)),
            seqno=4,
            root_hash="root",
            file_hash="file",
        )
        observed = dict(last=target, state_root_hash="state")
        observation = dict(
            zerostate=dict(target, seqno=0), references=[observed], rust=observed
        )
        checked = dict(
            block=target,
            state_root_hash="state",
            cell_hash_checked=True,
            file_hash_checked=True,
            header_identity_checked=True,
            state_update_matches_both=True,
            verified_final_certificates=[dict(final_certificate_checked=True)],
        )
        if unchecked:
            checked["state_update_matches_both"] = False

        async def checker(command, log):
            sample = json.loads(command[1].read_text())
            self.assertEqual(sample["reference"], observed)
            self.assertEqual(sample["masterchain_state"]["name"], "rust-bootstrap")
            command[2].write_text(json.dumps(checked))

        config = object()
        state = AsyncMock(return_value=dict(name="rust-bootstrap", boc="actual-state"))
        body = dict(
            id=dict(target, seqno=5) if wrong_body else target, data="actual-body"
        )
        with (
            patch.object(fixture, "native_state", state),
            patch.object(
                fixture,
                "cpp_certificate",
                AsyncMock(return_value=dict(kind="cpp_lite")),
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
