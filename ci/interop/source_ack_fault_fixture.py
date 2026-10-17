#!/usr/bin/env python3
"""Fail only an owned current-MC source ACK operation, then reopen its original DB."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time

from mixed_matrix import write
from network_faults import require_namespace
from partition_restart_fixture import hold


def paths(root):
    directory = root / 'source-ack-fault'
    directory.mkdir(exist_ok=True)
    return directory


def source_ack_environment(args, root):
    require_namespace()
    if os.environ.get('LD_PRELOAD') or any(key.startswith('RTOS_TEST_SOURCE_FAULT_') for key in os.environ):
        raise RuntimeError('Source ACK fixture refuses inherited fault/preload settings')
    directory = paths(root)
    return {**os.environ, 'LD_PRELOAD': str(args.source_ack_fault_library),
        'RTOS_TEST_SOURCE_FAULT_MODE': args.source_ack_fault,
        'RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE': str(directory / 'selected-directory'),
        'RTOS_TEST_SOURCE_FAULT_ARM': str(directory / 'armed'),
        'RTOS_TEST_SOURCE_FAULT_MARKER': str(directory / 'native-error.marker')}


class SourceAckFailure:
    def __init__(self, args, root, node, checkpoint, *, directory=None):
        self.directory = directory if directory is not None else paths(root)
        self.node = node
        self.mode = args.source_ack_fault
        self.started = time.monotonic()
        self.deadline = self.started + args.recovery_timeout
        session = base64.b64decode(checkpoint['verified_final_certificates'][0]['session_id'], validate=True).hex()
        candidates = []
        for manifest in (node['directory'] / 'node_db/catchains/consensus/v2').glob('*/session-runtime.json'):
            runtime = json.loads(manifest.read_text())
            if runtime['session'] == session and runtime['shard_workchain'] == -1:
                candidates.append((manifest, runtime))
        if len(candidates) != 1:
            raise RuntimeError('Expected one exact authenticated current MC source runtime')
        manifest, runtime = candidates[0]
        namespace = manifest.parent.resolve()
        if not namespace.is_relative_to((node['directory'] / 'node_db').resolve()):
            raise RuntimeError('Source ACK namespace is outside the owned node database')
        index = runtime['validator_index']
        if runtime['role'] != 'validator' or runtime['catchain_seqno'] != checkpoint['gen_catchain_seqno'] or type(index) is not int or not 0 <= index < 4:
            raise RuntimeError('Source ACK target is not the current MC validator runtime')
        (self.directory / 'selected-runtime.json').write_bytes(manifest.read_bytes())
        self.pending_directory = namespace / 'finality-pending'
        if not self.pending_directory.is_dir() or self.pending_directory.is_symlink():
            raise RuntimeError('Source ACK directory is not an existing owned source store')
        self.receipt = {'phase': 'prepared', 'mode': self.mode, 'member': node['index'],
            'session': session, 'namespace': str(namespace), 'pending_directory': str(self.pending_directory),
            'old_pid': node['process'].pid, 'recovery_limit_seconds': args.recovery_timeout,
            'budget_started_at_unix': time.time(), 'fault_mechanism': 'test-only native syscall interposition; not physical media failure'}
        self.save()

    def save(self):
        self.receipt['elapsed_seconds'] = time.monotonic() - self.started
        write(self.directory / 'receipt.json', self.receipt)

    def check_budget(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError('Source ACK failure/restart exceeded the original recovery deadline')

    async def arm(self):
        log = self.node['directory'] / 'node.log'
        offset = log.stat().st_size
        (self.directory / 'selected-directory').write_text(str(self.pending_directory) + '\n')
        (self.directory / 'armed').write_text('one owned authenticated current MC source store\n')
        self.receipt.update(phase='waiting_for_native_ack_failure', armed_at_unix=time.time())
        self.save()
        buffer = ''
        expected = 'Input/output error' if self.mode == 'sync-eio' else 'No space left on device'
        marker = self.directory / 'native-error.marker'
        while True:
            self.check_budget()
            if self.node['process'].returncode is not None:
                raise RuntimeError('Source ACK target exited before the intended interruption')
            with log.open('rb') as stream:
                stream.seek(offset); chunk = stream.read(1 << 20); offset += len(chunk)
            buffer = (buffer + chunk.decode(errors='replace'))[-65536:]
            errors = [line for line in buffer.splitlines()
                if 'Node WAL durable but source ACK needs retry:' in line and expected in line]
            if marker.is_file() and errors:
                self.capture_failure(marker, errors[-1])
                return
            await asyncio.sleep(.1)

    def capture_failure(self, marker, error):
        lines = marker.read_text().splitlines()
        prefix = 'source ' + self.mode + ': '
        if len(lines) != 1 or not lines[0].startswith(prefix):
            raise RuntimeError('Native source ACK fault marker is malformed')
        target = Path(lines[0][len(prefix):])
        if target.parent != self.pending_directory or not re.fullmatch(r'[0-9a-f]{64}\.ack\.tmp', target.name):
            raise RuntimeError('Native source ACK fault reached a different path')
        self.source_id = target.name[:64]
        self.pending = self.pending_directory / (self.source_id + '.json')
        self.original = self.pending.read_bytes()
        if (self.pending_directory / (self.source_id + '.acked')).exists():
            raise RuntimeError('Failed source ACK was already published')
        size = target.stat().st_size
        if (size > 0) != (self.mode == 'sync-eio'):
            raise RuntimeError('Source ACK temporary bytes do not match the failed syscall')
        record = json.loads(self.original)
        if record['session_id'] != self.receipt['session']:
            raise RuntimeError('Failed source record changed authenticated session')
        (self.directory / 'retained-before.json').write_bytes(self.original)
        self.receipt.update(phase='native_ack_failure_observed', source_id=self.source_id,
            pending_sha256=hashlib.sha256(self.original).hexdigest(), pending_bytes=len(self.original),
            temporary_bytes=size, source_is_final=record['is_final'], source_block=record['block_id'],
            native_error_line=error, native_error_observed_at_unix=time.time(),
            source_acknowledged_before_interruption=False)
        self.save()

    async def after_interruption(self):
        if self.node['process'].returncode != -9 or self.pending.read_bytes() != self.original:
            raise RuntimeError('Failed source evidence did not survive the intended SIGKILL')
        self.receipt.update(phase='waiting_for_survivors', interruption_returncode=-9,
            pending_preserved_after_interruption=True)
        self.save()
        await hold(4, self.deadline, self.check_budget)

    def survivor(self, checked):
        self.receipt['survivor_checkpoint'] = checked['block']
        self.save()

    def disarm(self):
        arm = self.directory / 'armed'
        if arm.exists():
            arm.rename(self.directory / 'disarmed')
            self.receipt['disarmed_at_unix'] = time.time()

    def environment(self):
        if self.pending.read_bytes() != self.original:
            raise RuntimeError('Original source evidence changed before reopening the database')
        self.receipt['pending_preserved_before_restart'] = True
        self.disarm(); self.save()
        return None  # The restarted process uses its ordinary environment.

    async def after_restart(self, node):
        self.receipt.update(phase='waiting_for_recovered_ack', new_pid=node['process'].pid,
            new_start_ticks=node['start_ticks'], restarted_at_unix=time.time())
        self.save()

    def has_unacknowledged_source(self):
        return self.pending.exists()

    async def complete(self, recovered):
        before = json.loads(self.original)
        while True:
            self.check_budget()
            if self.node['process'].returncode is not None:
                raise RuntimeError('Recovered source ACK node exited')
            for kind, path in [('acked', self.pending_directory / (self.source_id + '.acked')),
                    ('reference', self.pending_directory / 'references-v1' / (self.source_id + '.reference')),
                    ('delivered', self.pending_directory / 'references-v1' / (self.source_id + '.delivered'))]:
                try:
                    data = path.read_bytes()
                except FileNotFoundError:
                    continue
                value = json.loads(data)
                if kind == 'acked':
                    valid = value['record'] == before
                    reference = value
                else:
                    reference = value['reference'] if kind == 'delivered' else value
                    metadata = {**before, 'data': '', 'signature_set': ''}
                    valid = reference['digest'] == hashlib.sha256(self.original).hexdigest() and reference['metadata'] == metadata
                if not valid or not re.fullmatch('[0-9a-f]{64}', reference['node_receipt']):
                    raise RuntimeError('Recovered ACK differs from the original retained source')
                if self.has_unacknowledged_source():
                    continue
                (self.directory / 'recovered-ack.json').write_bytes(data)
                self.receipt.update(phase='recovered', recovered_ack_kind=kind,
                    recovered_ack_sha256=hashlib.sha256(data).hexdigest(),
                    recovered_node_receipt=reference['node_receipt'], final_checkpoint=recovered['last_checkpoint'],
                    original_source_ack_recovered=True, manual_database_repair=False)
                self.save()
                return
            await asyncio.sleep(.1)

    def close(self):
        self.disarm(); self.save()
