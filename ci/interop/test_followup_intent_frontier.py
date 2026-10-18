"""Live frontier capture races and ordering after the unchanged original recovery gate."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import expired_member_restart_fixture as fixture


class LiveFrontierTests(unittest.TestCase):
    def context(self, root, slot=7):
        pending = root / 'owned/session.validator/finality-intents'
        pending.mkdir(parents=True, exist_ok=True)
        record = {'slot': slot, 'candidate_hash': format(slot, '064x'), 'certificate': 'exact source proof'}
        source = pending / (str(slot) + '-' + record['candidate_hash'] + '.json')
        source.write_text(json.dumps(record))
        return root / 'owned', source, record

    def finish(self, source, record):
        proof = source.parent / 'completed-v1' / source.with_suffix('.complete').name
        proof.parent.mkdir(exist_ok=True)
        proof.write_text(json.dumps({'schema': 1, 'record': record}))
        source.unlink()
        return proof

    def test_live_frontier_preserves_exact_source_and_uses_a_separate_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            namespaces, source, record = self.context(root)
            before = source.read_bytes()
            with patch.object(fixture.time, 'monotonic', return_value=100):
                frontier = fixture.LiveIntentFrontier(namespaces, root / 'evidence')
                self.assertEqual(frontier.deadline, 280)
                self.assertEqual(source.read_bytes(), before)
                self.assertFalse(frontier.complete())
            self.finish(source, record)
            with patch.object(fixture.time, 'monotonic', return_value=279.9):
                self.assertTrue(frontier.complete())
            receipt = json.loads((root / 'evidence/receipt.json').read_text())
            self.assertEqual(receipt['phase'], 'followup_frontier_completed')
            self.assertEqual(receipt['count'], 1)
            self.assertFalse(receipt['original_recovery_budget_extended'])
            self.assertEqual(receipt['separate_budget_seconds'], 180)

    def test_completion_after_deadline_or_crossing_it_during_proof_read_cannot_pass(self):
        for readings in [[280], [279, 281]]:
            with self.subTest(readings=readings), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                namespaces, source, record = self.context(root)
                with patch.object(fixture.time, 'monotonic', return_value=100):
                    frontier = fixture.LiveIntentFrontier(namespaces, root / 'evidence')
                self.finish(source, record)
                with patch.object(fixture.time, 'monotonic', side_effect=readings):
                    with self.assertRaises(TimeoutError):
                        frontier.complete()
                self.assertEqual(json.loads((root / 'evidence/receipt.json').read_text())['phase'],
                                 'followup_frontier_captured')

    def test_live_unlink_race_is_audited_and_cannot_drop_an_unfinished_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            namespaces, first, record = self.context(root)
            _, second, _ = self.context(root, 8)
            original_read = Path.read_bytes

            def raced_read(path):
                if path == first:
                    self.finish(first, record)
                    raise FileNotFoundError(first)
                return original_read(path)

            with patch.object(Path, 'read_bytes', raced_read):
                frontier = fixture.LiveIntentFrontier(namespaces, root / 'evidence')
            self.assertEqual(len(frontier.records), 1)
            self.assertTrue(frontier.records[0]['path'].endswith(second.name))
            self.assertEqual(len(frontier.completed_during_capture), 1)
            self.assertFalse(frontier.complete())
            self.assertTrue(second.exists())

    def test_live_race_without_matching_regular_completion_refuses(self):
        for mode in ['missing', 'other_candidate', 'symlink']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                namespaces, first, record = self.context(root)
                self.context(root, 8)
                original_read = Path.read_bytes

                def raced_read(path):
                    if path == first:
                        if mode == 'missing':
                            first.unlink()
                        else:
                            altered = {**record, 'candidate_hash': 'f' * 64} if mode == 'other_candidate' else record
                            proof = self.finish(first, altered)
                            if mode == 'symlink':
                                outside = root / 'outside.complete'
                                proof.rename(outside)
                                proof.symlink_to(outside)
                        raise FileNotFoundError(first)
                    return original_read(path)

                with patch.object(Path, 'read_bytes', raced_read):
                    with self.assertRaises(RuntimeError):
                        fixture.LiveIntentFrontier(namespaces, root / 'evidence')

    def test_stopped_original_capture_does_not_silently_adopt_live_race_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            namespaces, source, record = self.context(root)
            original_read = Path.read_bytes

            def raced_read(path):
                if path == source:
                    self.finish(source, record)
                    raise FileNotFoundError(source)
                return original_read(path)

            with patch.object(Path, 'read_bytes', raced_read):
                with self.assertRaises(FileNotFoundError):
                    fixture.PendingIntentRecovery(namespaces, root / 'evidence')

    def test_empty_live_frontier_does_not_vacuously_qualify_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            namespaces, source, _ = self.context(root)
            source.unlink()
            with self.assertRaises(RuntimeError):
                fixture.LiveIntentFrontier(namespaces, root / 'evidence')

    def test_followup_requires_the_explicit_original_expired_ack_restart(self):
        fixture.validate_followup_frontier(SimpleNamespace())
        for expired, combined in [(False, False), (True, False), (False, True)]:
            with self.assertRaises(RuntimeError):
                fixture.validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
                    expired_member_restart=expired, source_ack_partition_restart=combined))
        fixture.validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
            expired_member_restart=True, source_ack_partition_restart=True))


class FollowupOrderingTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, failure=None):
        import rotation_fixture
        events = []
        receipt = {'phase': 'recovered'}

        async def qualify(*args):
            events.append('qualify')
            return {}

        async def original_ack(_):
            events.append('original_ack')
            if failure == 'original_ack':
                raise TimeoutError('unchanged original deadline expired')
            receipt['original_ack_checked'] = True

        async def expiry_complete(_):
            events.append('expiry_complete')

        async def followup():
            events.append('followup')
            self.assertTrue(receipt['original_ack_checked'])
            self.assertEqual(args.original_recovery_budget, {'monotonic': 100, 'unix': 200})
            if failure == 'followup':
                raise TimeoutError('separate frontier deadline expired')

        async def recover(*args):
            events.append('recover')
            return receipt, followup

        source_receipt = {'phase': 'recovered', 'elapsed_seconds': 120,
                          'metadata': {'proof': 'original'}}
        combined_receipt = {'phase': 'recovered', 'elapsed_seconds': 120.01}
        partition_receipt = {'phase': 'recovered', 'elapsed_seconds': 119}
        expiry_receipt = {'phase': 'expired_member_restarted_without_signing', 'elapsed_seconds': 120.02}
        expiry = SimpleNamespace(started=100, started_unix=200, qualify=qualify,
            complete=expiry_complete, receipt=expiry_receipt)
        args = SimpleNamespace(signer_expiry_member=5, signer_expiry_observer=expiry,
            source_ack_partition_restart=True, interrupt_rust_member=5)

        def close():
            events.append('close')
            for value in [source_receipt, combined_receipt, partition_receipt, expiry_receipt]:
                value['elapsed_seconds'] = 400
            source_receipt['metadata']['proof'] = 'later cleanup'

        fault = SimpleNamespace(complete=original_ack, close=close,
            source=SimpleNamespace(receipt=source_receipt), receipt=combined_receipt,
            partition=SimpleNamespace(receipt=partition_receipt))
        with patch('source_ack_partition_fixture.SourceAckPartitionRestart', return_value=fault), \
             patch.object(rotation_fixture, '_recover_rotation_member', recover), \
             patch.object(rotation_fixture, 'write'):
            call = rotation_fixture.recover_rotation_member(args, Path('/unused'), [], ['peer'] * 6,
                [], [{'index': 5}], None, None, {}, {})
            if failure:
                with self.assertRaises(TimeoutError):
                    await call
            else:
                self.assertIs(await call, receipt)
        if failure == 'original_ack':
            self.assertNotIn('original_recovery_acceptance', receipt)
        else:
            saved = receipt['original_recovery_acceptance']
            self.assertEqual(saved['source_ack_fault']['elapsed_seconds'], 120)
            self.assertEqual(saved['source_ack_fault']['metadata']['proof'], 'original')
            self.assertEqual(saved['source_ack_partition_restart']['elapsed_seconds'], 120.01)
            self.assertEqual(saved['partition_restart']['elapsed_seconds'], 119)
            self.assertEqual(saved['signer_expiry']['elapsed_seconds'], 120.02)
        return events

    async def test_original_ack_and_expiry_finish_before_any_followup_budget(self):
        self.assertEqual(await self.run_case(),
            ['qualify', 'recover', 'original_ack', 'expiry_complete', 'followup', 'close'])

    async def test_failed_original_budget_never_enters_followup(self):
        self.assertEqual(await self.run_case('original_ack'), ['qualify', 'recover', 'original_ack', 'close'])

    async def test_followup_failure_preserves_completed_original_checks_and_closes_owner(self):
        self.assertEqual(await self.run_case('followup'),
            ['qualify', 'recover', 'original_ack', 'expiry_complete', 'followup', 'close'])
