#!/usr/bin/env python3
"""Pinned C++ tester requests SIGTERM; record that separately from Rust normal exit."""
import asyncio
import signal
import sys
import unittest

from network_fault_fixture import stop_cpp_with_receipt


class Node:
    def __init__(self, process, stop_signal=signal.SIGTERM):
        self._Node__process = process
        self.stop_signal = stop_signal

    async def stop(self):
        if self._Node__process.returncode is None:
            self._Node__process.send_signal(self.stop_signal)
        await self._Node__process.wait()


class CppPacketTeardownTests(unittest.IsolatedAsyncioTestCase):
    async def spawn(self):
        process = await asyncio.create_subprocess_exec(sys.executable,'-c',
            'import time; print("ready",flush=True);time.sleep(60)', stdout=asyncio.subprocess.PIPE)
        self.assertEqual(await process.stdout.readline(),b'ready\n')
        return process

    async def test_live_process_requested_sigterm_matches_cpp_tester(self):
        process=await self.spawn()
        _,receipt=await stop_cpp_with_receipt(2,Node(process))
        self.assertEqual(receipt['returncode'],-signal.SIGTERM)
        self.assertTrue(receipt['matches_pinned_tester_teardown'])
        self.assertTrue(receipt['alive_before_stop'])

    async def test_killed_process_is_not_a_successful_teardown(self):
        process=await self.spawn()
        _,receipt=await stop_cpp_with_receipt(2,Node(process,signal.SIGKILL))
        self.assertEqual(receipt['returncode'],-signal.SIGKILL)
        self.assertFalse(receipt['matches_pinned_tester_teardown'])

    async def test_already_exited_process_is_not_a_successful_teardown(self):
        process=await self.spawn();process.terminate();await process.wait()
        _,receipt=await stop_cpp_with_receipt(2,Node(process))
        self.assertFalse(receipt['alive_before_stop'])
        self.assertFalse(receipt['matches_pinned_tester_teardown'])


if __name__ == '__main__':
    unittest.main()
