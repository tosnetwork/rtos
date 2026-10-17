"""Negative gates for a high-weight member's original-database restart."""
import asyncio
import copy
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import recovery_quorum_fixture as quorum


class RecoveryQuorumTests(unittest.IsolatedAsyncioTestCase):
    def profile(self):
        return {'successor_weights': {'0': 10, '2': 30, '4': 10, '5': 10}}

    def info(self, seqno=10):
        return {'init': {'workchain': -1, 'shard': '-9223372036854775808', 'seqno': 0, 'root_hash': 'zero', 'file_hash': 'zero-file'},
            'last': {'workchain': -1, 'shard': '-9223372036854775808', 'seqno': seqno, 'root_hash': 'block', 'file_hash': 'file'}, 'state_root_hash': 'state'}

    def test_plan_requires_declared_insufficient_weight_and_retains_original_committee(self):
        plan = quorum.recovery_quorum_plan(self.profile(), 2, True)
        self.assertEqual((plan['total_weight'], plan['quorum_weight'], plan['surviving_weight']), (60, 40, 30))
        self.assertEqual(plan['survivor_members'], [0, 4, 5])
        self.assertEqual(plan['live_endpoints'], [0, 1, 3, 4, 5])
        with self.assertRaisesRegex(ValueError, 'explicit below-quorum'):
            quorum.recovery_quorum_plan(self.profile(), 2, False)
        with self.assertRaisesRegex(ValueError, 'insufficient'):
            quorum.recovery_quorum_plan({}, 2, True)
        with self.assertRaises(ValueError):quorum.recovery_quorum_plan(self.profile(), 3, True)
        self.assertIsNone(quorum.recovery_quorum_plan({}, 2, False))

    def test_expired_signer_keeps_original_weight_but_cannot_count_as_available(self):
        plan=quorum.recovery_quorum_plan({},2,True,unavailable=(5,))
        self.assertEqual(plan['weights'],{0:17,2:17,4:17,5:17})
        self.assertEqual((plan['total_weight'],plan['quorum_weight'],plan['surviving_weight']),(68,46,34))
        self.assertEqual(plan['survivor_members'],[0,4])
        self.assertEqual(plan['unavailable_signer_members'],[5])
        for bad in [(2,),(1,),(5,5),(True,)]:
            with self.assertRaises(ValueError):quorum.recovery_quorum_plan({},2,True,unavailable=bad)

    async def observe(self, root, reader, *, deadline=None):
        plan=quorum.recovery_quorum_plan(self.profile(), 2, True)
        with patch.object(quorum, 'rpc', side_effect=reader):
            return await quorum.observe_below_quorum(root, list(range(6)), self.info()['init'], plan,
                deadline if deadline is not None else time.monotonic()+2, settle_seconds=.001, observe_seconds=.015, interval=.001)

    async def test_all_five_endpoints_must_keep_exact_block_and_applied_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            infos=await self.observe(Path(tmp), lambda *a:self.info())
            self.assertEqual(set(infos), {0,1,3,4,5})
            import json
            x=json.loads((Path(tmp)/'recovery-quorum/receipt.json').read_text())
            self.assertEqual(x['phase'], 'observed_no_finality')
            self.assertGreaterEqual(x['observation_count'], 2)
            self.assertGreaterEqual(x['observation_elapsed_seconds'], .015)

    async def test_new_block_or_same_height_fork_cannot_pass_as_stall(self):
        for key,value in [('seqno',11),('root_hash','fork'),('file_hash','other')]:
            with tempfile.TemporaryDirectory() as tmp:
                calls=0
                def reader(*args):
                    nonlocal calls
                    calls+=1;x=self.info()
                    if calls>5:x['last'][key]=value
                    return x
                with self.assertRaisesRegex(RuntimeError, 'advanced or forked'):
                    await self.observe(Path(tmp),reader)

    async def test_wrong_genesis_state_disagreement_and_missing_rpc_refuse(self):
        for mode in ['genesis','state','unavailable']:
            with tempfile.TemporaryDirectory() as tmp:
                def reader(i,*args):
                    x=self.info()
                    if i==1:
                        if mode=='genesis':x['init']['root_hash']='other'
                        if mode=='state':x['state_root_hash']='other'
                        if mode=='unavailable':raise ConnectionError('owned RPC unavailable')
                    return x
                with self.assertRaises((RuntimeError,ConnectionError)):
                    await self.observe(Path(tmp),reader)

    async def test_original_deadline_cannot_be_reset_for_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TimeoutError):
                await self.observe(Path(tmp),lambda *a:self.info(),deadline=time.monotonic()+.005)

    def test_old_certificate_is_not_claimed_as_fresh_survivor_quorum(self):
        plan=quorum.recovery_quorum_plan(self.profile(),2,True)
        checked={'block':self.info()['last'],'state_root_hash':'state','configuration':{'current':{'members':[{'validator_id':str(i),'weight':w} for i,w in plan['weights'].items()]}},
            'verified_final_certificates':[{'validator_ids':['0','2','4'],'verified_weight':50}]}
        observation={'phase':'observed_no_finality','block':self.info()['last'],'state_root_hash':'state',
            'plan':plan,'observation_count':10,'observation_elapsed_seconds':12,'required_observe_seconds':12}
        quorum.validate_below_quorum_checkpoint(checked,observation,plan,str)
        for mode in ['block','weights','phase','duration','duplicate','state']:
            bad=copy.deepcopy(checked);obs=copy.deepcopy(observation)
            if mode=='state':bad['state_root_hash']='other'
            if mode=='block':obs['block']['file_hash']='other'
            if mode=='weights':bad['configuration']['current']['members'][0]['weight']=11
            if mode=='phase':obs['phase']='waiting'
            if mode=='duration':obs['observation_elapsed_seconds']=11
            if mode=='duplicate':bad['configuration']['current']['members'].append(copy.deepcopy(bad['configuration']['current']['members'][0]))
            with self.assertRaises(RuntimeError):quorum.validate_below_quorum_checkpoint(bad,obs,plan,str)
