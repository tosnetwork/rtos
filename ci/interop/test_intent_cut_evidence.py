#!/usr/bin/env python3
"""Evidence binding tests; actual syscall/node coverage remains independently required."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from verify_intent_cut_evidence import digest, verify, verify_written_prefix


class CutEvidenceTests(unittest.TestCase):
    def fixture(self, root, point='after-partial-write', mode='write-enospc'):
        archive = root / 'source-ack-recovery'
        (archive / 'recovery').mkdir(parents=True)
        (root / 'builds').mkdir()
        directory = root / 'source-ack-partition'; directory.mkdir()
        runtime = root / 'live'
        pending = runtime / 'rust-5/node_db/catchains/consensus/v2/session/finality-pending'
        target = pending.parent / 'finality-intents' / ('7-' + 'c' * 64 + '.tmp')
        record = {'schema': 1, 'session_id': 's', 'slot': 7, 'candidate_hash': 'c' * 64,
                  'certificate': 'signed evidence belongs to paired native checks'}
        intended = json.dumps(record).encode()
        raw = b'' if point == 'before-write' else intended[:len(intended)//2] if point == 'after-partial-write' else intended
        completed = json.dumps({'schema': 1, 'record': record}).encode()
        live = target.parent / 'completed-v1' / target.with_suffix('.complete').name
        live.parent.mkdir(parents=True); live.write_bytes(completed)
        cut = dict(path=str(target), pid=123, point=point, bytes=len(raw), sha256=digest(raw),
            intended_bytes=len(intended), intended_sha256=digest(intended), slot=7,
            candidate_hash='c'*64, stopped_state_verified=True, preserved_after_interruption=True,
            preserved_before_restart=True, normal_replay_completed=True, observed_at_unix=20,
            completed_sha256=digest(completed))
        fault = dict(mode=mode, temporary_bytes=0 if mode == 'write-enospc' else 100,
            pending_directory=str(pending), session='s', native_error_observed_at_unix=19,
            elapsed_seconds=100, recovery_limit_seconds=180, budget_started_at_unix=1)
        combined = dict(fault, intent_cut=cut, source_ack_fault=mode,
            original_source_ack_recovered=True, source_fault_removed_before_restart=True,
            manual_database_repair=False)
        recovery = dict(old_process={'pid':123}, interrupted_at_unix=21,
            original_recovery_acceptance={'source_ack_fault':fault,
                'source_ack_partition_restart':combined,'partition_restart':copy.deepcopy(fault),
                'signer_expiry':copy.deepcopy(fault)},original_recovery_verified_at_unix=101,
            followup_intent_frontier={'budget_started_at_unix':102})
        def write(path, value):path.write_text(json.dumps(value))
        write(archive/'recovery/recovery.json', recovery)
        write(root/'functional-observations.json',dict(genesis=107, source_commit='node',
            fixture_commit='fixture',independent_functional_recovery_gate_passed=True))
        write(root/'builds/expired-member-ack-empty-intent-source.json',dict(genesis='107',
            compiled_product_commit='node',commit='fixture'))
        write(archive/'source.json',dict(command=['fixture','--output',str(runtime),
            '--source-ack-intent-cut-point',point,'--source-ack-intent-stop','--source-ack-fault',mode]))
        for name, data in [('intent-before.json',raw),('intent-original-record.json',intended),
            ('intent-completed.json',completed)]: (directory/name).write_bytes(data)
        if point != 'after-fsync':(directory/'intent-intended.json').write_bytes(intended)
        (directory/'intent-stop.marker').write_text(f'intent {point} pid=123: {target}\n')
        (directory/'intent-stopped-process.txt').write_text('State:\tT (stopped)\nPid:\t123\n')
        return recovery

    def check(self, root, **kw):
        return verify(root,genesis=kw.get('genesis',107),mode=kw.get('mode','write-enospc'),
                      point=kw.get('point','after-partial-write'))

    def test_three_cut_points_and_both_modes_keep_report_identity(self):
        for mode in ['sync-eio','write-enospc']:
            for point in ['before-write','after-partial-write','after-fsync']:
                with self.subTest(mode=mode,point=point), tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp);self.fixture(root,point,mode);out=self.check(root,mode=mode,point=point)
                    self.assertEqual((out['genesis'],out['source_ack_mode'],out['point']),(107,mode,point))

    def test_declared_case_mode_and_point_cannot_be_relabelled(self):
        for kw in [dict(genesis=106),dict(mode='sync-eio'),dict(point='before-write')]:
            with self.subTest(kw=kw),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.fixture(root)
                with self.assertRaises(ValueError):self.check(root,**kw)

    def test_altered_half_prefix_refused_even_with_updated_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);r=self.fixture(root);p=root/'source-ack-partition/intent-before.json'
            data=b'!'+p.read_bytes()[1:];p.write_bytes(data)
            r['original_recovery_acceptance']['source_ack_partition_restart']['intent_cut']['sha256']=digest(data)
            (root/'source-ack-recovery/recovery/recovery.json').write_text(json.dumps(r))
            with self.assertRaisesRegex(ValueError,'exact intended prefix'):self.check(root)

    def test_deadline_normal_proof_and_stopped_pid_are_independent_gates(self):
        for mutation in ['deadline','proof','pid']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);r=self.fixture(root)
                if mutation=='deadline':
                    r['original_recovery_acceptance']['signer_expiry']['elapsed_seconds']=181
                    (root/'source-ack-recovery/recovery/recovery.json').write_text(json.dumps(r))
                elif mutation=='proof':
                    (root/'source-ack-partition/intent-completed.json').write_text('{}')
                else:(root/'source-ack-partition/intent-stopped-process.txt').write_text('State:\tT\nPid:\t999\n')
                with self.assertRaises(ValueError):self.check(root)

    def test_missing_original_receipts_cannot_silently_reduce_deadline_checks(self):
        for missing in ['partition_restart', 'signer_expiry']:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                recovery = self.fixture(root)
                del recovery['original_recovery_acceptance'][missing]
                (root/'source-ack-recovery/recovery/recovery.json').write_text(json.dumps(recovery))
                with self.assertRaisesRegex(ValueError, 'original receipt set differs'):
                    self.check(root)

    def test_wrong_length_or_full_record_cannot_pass_as_partial(self):
        for raw in [b'',b'123',b'12345678',b'9234']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                verify_written_prefix(raw,b'12345678','after-partial-write')


if __name__ == '__main__':unittest.main()
