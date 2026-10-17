#!/usr/bin/env python3
"""Interrupt one owned source retain at its real fsync/rename boundary."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import time

from network_faults import require_namespace
from source_ack_fault_fixture import SourceAckFailure


def paths(root):
    directory = root / 'source-retention-cut'
    directory.mkdir(exist_ok=True)
    return directory


def retention_cut_environment(args, root):
    require_namespace()
    if os.environ.get('LD_PRELOAD') or any(key.startswith(('RTOS_TEST_SOURCE_FAULT_', 'RTOS_TEST_RETAIN_CUT_')) for key in os.environ):
        raise RuntimeError('Retention fixture refuses inherited fault/preload settings')
    directory = paths(root)
    return {**os.environ, 'LD_PRELOAD': str(args.source_retention_cut_library),
        'RTOS_TEST_RETAIN_CUT_DIRECTORY_FILE': str(directory / 'selected-directory'),
        'RTOS_TEST_RETAIN_CUT_ARM': str(directory / 'armed'),
        'RTOS_TEST_RETAIN_CUT_MARKER': str(directory / 'native-stop.marker')}


class SourceRetentionCut(SourceAckFailure):
    def __init__(self, args, root, node, checkpoint):
        super().__init__(args, root, node, checkpoint, directory=paths(root))
        self.mode = 'retain-after-fsync'
        self.receipt.update(mode=self.mode, fault_mechanism='test-only native stop after successful source retain fsync before commit rename; not media failure')
        self.save()

    def process_status(self):
        return Path('/proc', str(self.node['process'].pid), 'status').read_text()

    def stopped(self):
        status = self.process_status()
        return any(line.startswith('State:') and line.split()[1] == 'T' for line in status.splitlines())

    async def arm(self):
        (self.directory / 'selected-directory').write_text(str(self.pending_directory) + '\n')
        (self.directory / 'armed').write_text('one authenticated owned source retain\n')
        self.receipt.update(phase='waiting_for_retention_cut', armed_at_unix=time.time())
        self.save()
        marker = self.directory / 'native-stop.marker'
        while True:
            self.check_budget()
            if self.node['process'].returncode is not None:
                raise RuntimeError('Retention target exited before the intended cut')
            if marker.is_file() and self.stopped():
                self.capture_stop(marker)
                return
            await asyncio.sleep(.05)

    def capture_stop(self, marker):
        prefix = f'source retain-after-fsync pid={self.node["process"].pid}: '
        lines = marker.read_text().splitlines()
        if len(lines) != 1 or not lines[0].startswith(prefix) or not self.stopped():
            raise RuntimeError('Retention marker is not this stopped owned process')
        target = Path(lines[0][len(prefix):])
        if target.parent != self.pending_directory or not re.fullmatch(r'[0-9a-f]{64}\.tmp', target.name):
            raise RuntimeError('Retention cut reached a different source path')
        self.source_id = target.stem
        self.pending = target
        if target.is_symlink():
            raise RuntimeError('Retention target is not a regular owned source')
        self.original = target.read_bytes()
        if self.has_committed_source():
            raise RuntimeError('Retention cut was already committed')
        record = json.loads(self.original)
        identity = ['rtos-source-finality-v1', record['global_id'], record['zerostate'],
            record['protocol'], record['carrier_version'], record['wire_profile'], record['profile'],
            record['session_id'], record['block_id'], record['is_final'],
            [record['local_adnl'], record['local_validator_index'], record['source_validator']]]
        source_id = hashlib.sha256(json.dumps(identity, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        if record['schema'] != 1 or record['session_id'] != self.receipt['session'] or not record['is_final'] or source_id != self.source_id:
            raise RuntimeError('Interrupted retain changed authenticated source identity')
        (self.directory / 'retained-before.json').write_bytes(self.original)
        (self.directory / 'stopped-process-status.txt').write_text(self.process_status())
        self.receipt.update(phase='retention_cut_observed', source_id=self.source_id,
            pending_sha256=hashlib.sha256(self.original).hexdigest(), pending_bytes=len(self.original),
            temporary_bytes=len(self.original), source_is_final=True, source_block=record['block_id'],
            stopped_pid=self.node['process'].pid, stopped_state_verified=True,
            native_stop_observed_at_unix=time.time(), source_pending_committed_before_interruption=False,
            source_acknowledged_before_interruption=False)
        self.save()

    def has_committed_source(self):
        return any(path.exists() for path in [self.pending.with_suffix('.json'), self.pending.with_suffix('.acked'),
            self.pending_directory / 'references-v1' / (self.source_id + '.reference'),
            self.pending_directory / 'references-v1' / (self.source_id + '.delivered')])

    async def after_interruption(self):
        if self.has_committed_source():
            raise RuntimeError('Interrupted retain was committed before restart')
        await super().after_interruption()
        self.receipt['retention_uncommitted_after_interruption'] = True
        self.save()

    def environment(self):
        if self.has_committed_source():
            raise RuntimeError('Interrupted retain was committed before reopening')
        result = super().environment()
        self.receipt['retention_uncommitted_before_restart'] = True
        self.save()
        return result

    def has_unacknowledged_source(self):
        return self.pending.exists() or self.pending.with_suffix('.json').exists()

    async def complete(self, recovered):
        await super().complete(recovered)
        self.receipt['interrupted_retention_recovered'] = True
        self.save()
