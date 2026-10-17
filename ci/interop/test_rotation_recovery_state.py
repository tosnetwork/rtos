#!/usr/bin/env python3
"""Recovery capture waits for explicit availability without weakening full-state checks."""
import asyncio
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import rotation_fixture as rotation
from mixed_matrix import NativeStateNotReady, native_state_not_ready


class RecoveryStateTests(unittest.IsolatedAsyncioTestCase):
    def test_only_explicit_native_availability_errors_retry(self):
        miss = 'liteserver error: [Error : 500 : LITE_SERVER_UNKNOWN: Cannot load handle for (0:8000, 243)]'
        bad = 'liteserver error: [Error : 500 : LITE_SERVER_INVALID_DATA: state hash mismatch]'
        self.assertTrue(native_state_not_ready(miss))
        self.assertTrue(native_state_not_ready('liteserver error: [Error : 651 : block is not in db]'))
        for log in ['', 'Cannot load handle for old diagnostic', bad, miss + '\n' + bad]:
            self.assertFalse(native_state_not_ready(log))

    async def test_retry_preserves_failed_attempt_and_full_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'state'; block = {'seqno': 248, 'root_hash': 'exact-root'}
            expected = {'id': block, 'boc': 'complete-verified-later-by-native-checker'}
            attempts = []
            async def native(snapshot, config, name, identity, directory):
                self.assertEqual(identity, block)
                directory.mkdir(); attempts.append(directory)
                (directory / 'client.log').write_text('original failed availability' if len(attempts) == 1 else 'full receipt')
                if len(attempts) == 1:raise NativeStateNotReady('state dependency unavailable')
                return expected
            with patch.object(rotation, 'native_state', native):
                got = await rotation.native_recovery_state(None, None, '2', block, root, time.monotonic() + 2)
            self.assertIs(got, expected)
            self.assertEqual(len(attempts), 2)
            self.assertEqual((attempts[0] / 'client.log').read_text(), 'original failed availability')
            self.assertTrue((root / 'not-ready-attempts.json').is_file())

    async def test_bad_receipt_or_state_mismatch_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            async def native(*args):
                calls.append(args); raise RuntimeError('state receipt hash mismatch')
            with patch.object(rotation, 'native_state', native):
                with self.assertRaisesRegex(RuntimeError, 'state receipt hash mismatch'):
                    await rotation.native_recovery_state(None, None, '2', {}, Path(tmp) / 'state', time.monotonic() + 2)
            self.assertEqual(len(calls), 1)

    async def test_missing_dependency_cannot_extend_original_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            async def native(*args):raise NativeStateNotReady('permanently absent dependency')
            started = time.monotonic()
            with patch.object(rotation, 'native_state', native):
                with self.assertRaisesRegex(TimeoutError, 'original recovery deadline'):
                    await rotation.native_recovery_state(None, None, '2', {}, Path(tmp) / 'state', started + .03)
            self.assertLess(time.monotonic() - started, .5)

    async def test_permanent_failure_cancels_and_reaps_sibling_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            entered = asyncio.Event(); reaped = asyncio.Event()
            async def capture(snapshot, config, name, block, directory, deadline):
                if name == '0':
                    await entered.wait(); raise RuntimeError('invalid native state proof')
                entered.set()
                try:await asyncio.Future()
                finally:reaped.set()
            with patch.object(rotation, 'native_recovery_state', capture):
                with self.assertRaisesRegex(RuntimeError, 'invalid native state proof'):
                    await rotation.recovery_workchain_states(None, [None, None], [0, 1], {}, Path(tmp), time.monotonic() + 2)
            self.assertTrue(reaped.is_set())


if __name__ == '__main__':unittest.main()
