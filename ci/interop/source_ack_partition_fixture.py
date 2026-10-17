#!/usr/bin/env python3
"""Compose owned source ACK IO failure and packet isolation across original-DB restart."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import time

from mixed_matrix import write
from network_faults import marked_environment
from partition_restart_fixture import PartitionRestart
from source_ack_fault_fixture import SourceAckFailure, source_ack_environment


def source_ack_partition_environment(args, root):
    environment = source_ack_environment(args, root)
    marked = marked_environment(args.socket_mark_library)
    environment['LD_PRELOAD'] += ':' + marked['LD_PRELOAD']
    environment['RTOS_FIXTURE_SOCKET_MARK'] = marked['RTOS_FIXTURE_SOCKET_MARK']
    if getattr(args, 'source_ack_intent_stop', False):
        if any(key.startswith('RTOS_TEST_SOURCE_INTENT_') for key in os.environ):
            raise RuntimeError('Intent cut refuses inherited controls')
        environment['RTOS_TEST_SOURCE_INTENT_ARM'] = str(root / 'source-ack-partition/intent-armed')
        environment['RTOS_TEST_SOURCE_INTENT_MARKER'] = str(root / 'source-ack-partition/intent-stop.marker')
    return environment


async def join_owned(*operations):
    tasks = [asyncio.create_task(operation) for operation in operations]
    try:
        return await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class SourceAckPartitionRestart:
    def __init__(self, args, root, node, endpoint, member_id, checkpoint):
        self.source = SourceAckFailure(args, root, node, checkpoint)
        self.partition = PartitionRestart(args, root, node, endpoint, member_id)
        # Both components and the main recovery loop spend the original source
        # budget, including waiting for the native error and both partition holds.
        self.started = self.source.started
        self.deadline = self.source.deadline
        self.partition.started = self.started
        self.partition.deadline = self.deadline
        self.partition.receipt['budget_started_at_unix'] = self.source.receipt['budget_started_at_unix']
        self.directory = root / 'source-ack-partition'
        self.directory.mkdir()
        self.intent_stop = getattr(args, 'source_ack_intent_stop', False)
        self.receipt = {'phase': 'prepared', 'member': args.interrupt_rust_member,
            'mode': 'source_ack_failure_and_partition_across_restart',
            'source_ack_fault': args.source_ack_fault,
            'budget_started_at_unix': self.source.receipt['budget_started_at_unix'],
            'recovery_limit_seconds': args.recovery_timeout,
            'hold_before_survivor_seconds': args.network_fault_seconds,
            'hold_after_restart_seconds': args.network_fault_seconds}
        self.save()

    def save(self):
        self.receipt['elapsed_seconds'] = time.monotonic() - self.started
        self.receipt['source_phase'] = self.source.receipt['phase']
        self.receipt['partition_phase'] = self.partition.receipt['phase']
        write(self.directory / 'receipt.json', self.receipt)

    async def arm(self):
        await self.source.arm()
        if self.intent_stop:
            await self.stop_synced_intent()
        # Observe durable node WAL + failed source ACK before isolating the node.
        await self.partition.arm()
        self.receipt.update(phase='ack_failed_and_partitioned',
            native_error_observed_at_unix=self.source.receipt['native_error_observed_at_unix'],
            partition_armed_at_unix=self.partition.receipt['armed_at_unix'])
        self.save()

    async def after_interruption(self):
        await join_owned(self.source.after_interruption(), self.partition.after_interruption())
        if self.intent_stop:
            self.check_intent_preserved('after_interruption')
        self.receipt['phase'] = 'waiting_for_survivors'
        self.save()

    def survivor(self, checked):
        self.partition.survivor(checked)
        self.source.survivor(checked)
        self.receipt['survivor_checkpoint'] = checked['block']
        self.save()

    def environment(self):
        if self.intent_stop:
            self.check_intent_preserved('before_restart')
            self.disarm_intent()
        if self.source.environment() is not None:
            raise RuntimeError('Restart must remove the source IO fault environment')
        environment = self.partition.environment()
        if any(key.startswith(('RTOS_TEST_SOURCE_FAULT_', 'RTOS_TEST_SOURCE_INTENT_')) for key in environment):
            raise RuntimeError('Restart inherited source IO fault settings')
        self.receipt['source_fault_removed_before_restart'] = True
        self.save()
        return environment

    async def after_restart(self, node):
        await self.source.after_restart(node)
        await self.partition.after_restart(node)
        self.receipt.update(phase='network_restored',
            restored_at_unix=self.partition.receipt['restored_at_unix'])
        self.save()

    async def complete(self, recovered):
        await self.source.complete(recovered)
        await self.partition.complete(recovered)
        if self.intent_stop:
            cut = self.receipt['intent_cut']
            temporary = Path(cut['path'])
            completed = temporary.parent / 'completed-v1' / temporary.with_suffix('.complete').name
            value = json.loads(completed.read_text())
            if value.get('schema') != 1 or value.get('record') != json.loads(self.intent_original):
                raise RuntimeError('Completed intent differs from the original stopped certificate')
            if temporary.exists() or temporary.with_suffix('.json').exists():
                raise RuntimeError('Stopped certificate intent remains unresolved')
            (self.directory / 'intent-completed.json').write_bytes(completed.read_bytes())
            cut.update(normal_replay_completed=True, completed_sha256=hashlib.sha256(completed.read_bytes()).hexdigest())
        self.receipt.update(phase='recovered',
            original_source_ack_recovered=self.source.receipt['original_source_ack_recovered'],
            isolated_rpc_timeout_observed=self.partition.receipt['isolated_rpc_timeout_observed'],
            final_checkpoint=recovered['last_checkpoint'],
            manual_database_repair=recovered['manual_database_repair'])
        self.save()

    async def stop_synced_intent(self):
        (self.directory / 'intent-armed').write_text('one exact current source intent after ACK failure\n')
        marker = self.directory / 'intent-stop.marker'
        process = self.source.node['process']
        while True:
            self.source.check_budget()
            if process.returncode is not None:
                raise RuntimeError('Intent cut target exited before the selected sync')
            if marker.exists():
                match = re.fullmatch(r'intent after-fsync pid=(\d+): (.+)\n', marker.read_text())
                if not match or int(match[1]) != process.pid:
                    raise RuntimeError('Intent cut marker has a different process')
                temporary = Path(match[2])
                if temporary.parent != self.source.pending_directory.parent / 'finality-intents':
                    raise RuntimeError('Intent cut reached a different namespace')
                if not re.fullmatch(r'(0|[1-9][0-9]{0,9})-[0-9a-f]{64}\.tmp', temporary.name):
                    raise RuntimeError('Intent cut filename is not canonical')
                status = Path(f'/proc/{process.pid}/status').read_text()
                if not any(line.startswith('State:') and line.split()[1] == 'T' for line in status.splitlines()):
                    await asyncio.sleep(.02)
                    continue
                original = temporary.read_bytes()
                value = json.loads(original)
                if value['session_id'] != self.source.receipt['session'] or temporary.stem != f"{value['slot']}-{value['candidate_hash']}":
                    raise RuntimeError('Stopped intent identity differs from the authenticated source')
                completed = temporary.parent / 'completed-v1' / temporary.with_suffix('.complete').name
                if temporary.with_suffix('.json').exists() or temporary.with_suffix('.resolved').exists() or completed.exists():
                    raise RuntimeError('Intent cut already has committed or completed proof')
                self.intent_original = original
                (self.directory / 'intent-before.json').write_bytes(original)
                (self.directory / 'intent-stopped-process.txt').write_text(status)
                self.receipt['intent_cut'] = {'path': str(temporary), 'pid': process.pid,
                    'slot': value['slot'], 'candidate_hash': value['candidate_hash'],
                    'bytes': len(original), 'sha256': hashlib.sha256(original).hexdigest(),
                    'observed_at_unix': time.time(), 'stopped_state_verified': True,
                    'normal_replay_completed': False}
                self.save()
                return
            await asyncio.sleep(.05)

    def check_intent_preserved(self, phase):
        cut = self.receipt['intent_cut']
        temporary = Path(cut['path'])
        if temporary.read_bytes() != self.intent_original or temporary.with_suffix('.json').exists():
            raise RuntimeError('Stopped intent bytes or publication changed before restart')
        cut['preserved_' + phase] = True

    def disarm_intent(self):
        arm = self.directory / 'intent-armed'
        if arm.exists():
            arm.rename(self.directory / 'intent-disarmed')

    def close(self):
        try:
            self.disarm_intent()
        finally:
            try:
                self.source.close()
            finally:
                try:
                    self.partition.close()
                finally:
                    self.save()
