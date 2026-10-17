"""Control-flow checks; real native body/state checks are exercised separately."""
import asyncio
import copy
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import workchain_history_fixture as history


def block_id(n, wc=0):
    return dict(workchain=wc, shard=str(-(1 << 63)), seqno=n,
        root_hash='root-' + str(n), file_hash='file-' + str(n))


def wc(n):
    return dict(block=block_id(n), previous_block=block_id(n-1),
        gen_utime=100+n, gen_catchain_seqno=1,
        created_by='missing' if n == 1 else 'seen', all_four_states_match_block_update=True)


class HistoryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / '100'
        self.directory.mkdir()
        self.sample = dict(reference=dict(last=block_id(100, -1)),
            certificates=[dict(proof='real-checker-required')],
            workchain=dict(block=dict(id=block_id(3), boc='body-3'), states=[]))
        self.checked = dict(block=block_id(100, -1), workchain_check=wc(3))
        self.cache = {}
        self.cpp = AsyncMock(side_effect=self.body)
        self.state = AsyncMock(side_effect=self.states)
        self.check = AsyncMock(side_effect=self.native)
        for name, value in [('cpp_block',self.cpp),('native_state',self.state),('child_checked',self.check)]:
            patcher = patch.object(history, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def body(self, snapshot, node, identity, target):
        return dict(id=identity, boc='body-' + str(identity['seqno']))

    async def states(self, snapshot, config, name, identity, target):
        return dict(id=identity, name=name)

    async def native(self, command, log):
        sample = json.loads(Path(command[1]).read_text())
        n = sample['workchain']['block']['id']['seqno']
        checked = dict(block=sample['reference']['last'], workchain_check=wc(n))
        checked['workchain_check']['masterchain_anchor_links'] = len(sample['workchain']['anchor_chain'])
        Path(command[2]).write_text(json.dumps(checked))

    async def collect(self, **options):
        args = dict(args=SimpleNamespace(snapshot='snapshot',block_checker='checker'),
            nodes=['cpp'],lite_configs=list(range(6)),endpoint_names=['peer-'+str(i) for i in range(6)],
            committee=[0,2,4,5],sample=self.sample,checked=self.checked,directory=self.directory,
            deadline=time.monotonic()+5,missing={'missing'},phase='after',activation=100,
            baseline_wc_cc=0,cache=self.cache)
        args.update(options)
        return await history.collect_workchain_history(**args)

    async def test_missed_creator_needs_real_parent_body_and_every_endpoint_state(self):
        result = await self.collect()
        self.assertEqual([x[0]['block']['seqno'] for x in result], [1])
        self.assertEqual(self.cpp.await_count, 2)
        self.assertEqual(self.state.await_count, 8)
        request = json.loads((result[0][1]/'sample.json').read_text())
        self.assertEqual([b['id']['seqno'] for b in request['workchain']['anchor_chain']], [3,2])
        self.assertEqual({s['name'] for s in request['workchain']['states']}, {'peer-0','peer-2','peer-4','peer-5'})
        self.assertEqual(request['reference'], self.sample['reference'])
        self.assertEqual(request['certificates'], self.sample['certificates'])
        self.assertEqual(self.sample['workchain']['block']['id']['seqno'], 3)

    async def test_all_creators_already_seen_requires_no_history(self):
        self.assertEqual(await self.collect(missing=set()), [])
        self.cpp.assert_not_awaited()

    async def test_no_workchain_requires_no_history(self):
        self.checked['workchain_check'] = None
        self.assertEqual(await self.collect(), [])
        self.cpp.assert_not_awaited()

    async def test_old_checker_cannot_silently_supply_history(self):
        del self.checked['workchain_check']['previous_block']
        with self.assertRaisesRegex(RuntimeError, 'ancestry-capable'):
            await self.collect()

    async def test_original_rotation_deadline_is_enforced_before_reads(self):
        with self.assertRaises(TimeoutError):
            await self.collect(deadline=time.monotonic()-1)
        self.cpp.assert_not_awaited()

    async def test_original_deadline_cancels_and_joins_slow_export(self):
        closed = []
        async def slow(*args):
            try:
                await asyncio.Event().wait()
            finally:
                closed.append(True)
        self.cpp.side_effect = slow
        with self.assertRaises(TimeoutError):
            await self.collect(deadline=time.monotonic()+.02)
        self.assertEqual(closed, [True])
        self.state.assert_not_awaited()

    async def test_cache_reuses_original_evidence_path_and_anchor(self):
        first = await self.collect()
        self.cpp.reset_mock()
        self.state.reset_mock()
        second_dir = self.root/'101'
        second_dir.mkdir()
        other = copy.deepcopy(self.sample)
        other['reference']['last'] = block_id(101,-1)
        checked = copy.deepcopy(self.checked)
        checked['block'] = block_id(101,-1)
        second = await self.collect(sample=other,checked=checked,directory=second_dir)
        self.assertEqual(first,second)
        self.assertEqual(json.loads((second[0][1]/'sample.json').read_text())['reference']['last'],block_id(100,-1))
        self.cpp.assert_not_awaited()
        self.state.assert_not_awaited()

    async def test_prior_epoch_is_not_counted_as_successor(self):
        self.assertEqual(await self.collect(activation=200), [])
        self.assertEqual(self.cpp.await_count, 1)

    async def test_same_catchain_is_not_counted_as_successor(self):
        self.assertEqual(await self.collect(baseline_wc_cc=1), [])
        self.assertEqual(self.cpp.await_count, 1)

    async def test_native_rejection_propagates_without_caching_unchecked_parent(self):
        self.check.side_effect = RuntimeError('native rejected')
        with self.assertRaisesRegex(RuntimeError, 'native rejected'):
            await self.collect()
        self.assertNotIn(('after',history.identity(block_id(2))),self.cache)

    async def test_native_result_must_match_anchor_target_path_and_full_states(self):
        for field in ['mc','target','links','states']:
            with self.subTest(field=field):
                directory = self.root / field
                directory.mkdir()
                async def altered(command, log):
                    await self.native(command,log)
                    p = Path(command[2]); d = json.loads(p.read_text())
                    if field == 'mc':d['block'] = block_id(999,-1)
                    if field == 'target':d['workchain_check']['block'] = block_id(999)
                    if field == 'links':d['workchain_check']['masterchain_anchor_links'] = 999
                    if field == 'states':d['workchain_check']['all_four_states_match_block_update'] = False
                    p.write_text(json.dumps(d))
                self.check.side_effect = altered
                with self.assertRaisesRegex(RuntimeError, 'exact checkpoint'):
                    await self.collect(directory=directory,cache={})

    async def test_search_stops_at_native_chain_bound(self):
        sample = copy.deepcopy(self.sample)
        sample['workchain']['block']['id'] = block_id(1000)
        checked = dict(block=block_id(100,-1),workchain_check=wc(1000))
        self.assertEqual(await self.collect(sample=sample,checked=checked), [])
        self.assertEqual(self.cpp.await_count, 64)


if __name__ == '__main__':
    unittest.main()
