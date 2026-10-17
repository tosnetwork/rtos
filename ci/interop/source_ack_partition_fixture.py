#!/usr/bin/env python3
"""Compose owned source ACK IO failure and packet isolation across original-DB restart."""
import asyncio
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
        # Observe durable node WAL + failed source ACK before isolating the node.
        await self.partition.arm()
        self.receipt.update(phase='ack_failed_and_partitioned',
            native_error_observed_at_unix=self.source.receipt['native_error_observed_at_unix'],
            partition_armed_at_unix=self.partition.receipt['armed_at_unix'])
        self.save()

    async def after_interruption(self):
        await join_owned(self.source.after_interruption(), self.partition.after_interruption())
        self.receipt['phase'] = 'waiting_for_survivors'
        self.save()

    def survivor(self, checked):
        self.partition.survivor(checked)
        self.source.survivor(checked)
        self.receipt['survivor_checkpoint'] = checked['block']
        self.save()

    def environment(self):
        if self.source.environment() is not None:
            raise RuntimeError('Restart must remove the source IO fault environment')
        environment = self.partition.environment()
        if any(key.startswith('RTOS_TEST_SOURCE_FAULT_') for key in environment):
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
        self.receipt.update(phase='recovered',
            original_source_ack_recovered=self.source.receipt['original_source_ack_recovered'],
            isolated_rpc_timeout_observed=self.partition.receipt['isolated_rpc_timeout_observed'],
            final_checkpoint=recovered['last_checkpoint'],
            manual_database_repair=recovered['manual_database_repair'])
        self.save()

    def close(self):
        try:
            self.source.close()
        finally:
            try:
                self.partition.close()
            finally:
                self.save()
