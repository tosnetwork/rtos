#!/usr/bin/env python3
"""Cold-control composition bindings; native body/consensus remains a runtime gate."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock
from source_ack_partition_fixture import SourceAckPartitionRestart, validate_intent_cut


class ColdBootstrapScopeTests(unittest.TestCase):
    def args(self, **changes):
        value=dict(cold_bootstrap_body=True, source_ack_intent_stop=True,
            source_ack_intent_cut_point='after-partial-write', expired_member_restart=True,
            source_ack_partition_restart=True, partition_restart=True, source_ack_fault='sync-eio')
        value.update(changes)
        return SimpleNamespace(**value)

    def test_explicit_half_cut_and_expired_restart_are_required(self):
        for mode in ['sync-eio','write-enospc']:
            validate_intent_cut(self.args(source_ack_fault=mode))
        for changes in [dict(source_ack_intent_stop=False), dict(expired_member_restart=False),
                        dict(source_ack_intent_cut_point='before-write'), dict(partition_restart=False),
                        dict(source_ack_fault=None)]:
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                validate_intent_cut(self.args(**changes))


class ColdBootstrapCompletionTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self, root):
        body=b'body binding only; no native/cryptographic coverage claimed by this fixture'
        directory=root/'cold';directory.mkdir()
        witness=dict(schema=1,selector_sha256='selector',pid=20,session_id='session',slot=7,
            candidate_hash='hash',payload_bytes=len(body),payload_sha256=hashlib.sha256(body).hexdigest(),
            leader_index=0,local_validator_index=3)
        (directory/'payload-before.bin').write_bytes(body)
        block=b'scope-only block bytes'
        witness.update(block_bytes=len(block),block_sha256=hashlib.sha256(block).hexdigest(),
            block_id='(-1:8000000000000000, 9, rh root, fh '+hashlib.sha256(block).hexdigest()+')')
        (directory/'block-before.bin').write_bytes(block)
        for name in ['applied.json','delivered.json']:(directory/name).write_text(json.dumps(witness))
        marker='LOCAL_CANDIDATE_RECOVERY: session=session slot=7 hash=hash validated local lookup delivered'
        (root/'node-restart.log').write_text(marker)
        context=SourceAckPartitionRestart.__new__(SourceAckPartitionRestart)
        context.source=SimpleNamespace(complete=AsyncMock(),receipt={'session':'session','original_source_ack_recovered':True},node={'directory':root})
        context.partition=SimpleNamespace(complete=AsyncMock(),receipt={'isolated_rpc_timeout_observed':True})
        context.intent_stop=False
        context.cold_body=True
        context.receipt={'intent_cut':{'slot':7,'candidate_hash':'hash'},
            'cold_bootstrap_body':{'directory':str(directory),'selector_sha256':'selector'}}
        context.save=Mock()
        recovered={'new_process':{'pid':20},'last_checkpoint':{'seqno':9},'manual_database_repair':False}
        return context,recovered,directory,witness

    async def test_consensus_completion_cannot_replace_exact_body_witness(self):
        for mutation in ['missing','pid','slot','body_hash','own_producer','marker']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);context,recovered,directory,witness=self.fixture(root)
                if mutation=='missing':(directory/'delivered.json').unlink()
                elif mutation=='marker':(root/'node-restart.log').write_text('another candidate only')
                else:
                    if mutation=='pid':witness['pid']=99
                    elif mutation=='slot':witness['slot']=8
                    elif mutation=='body_hash':witness['payload_sha256']='wrong'
                    else:witness['leader_index']=3
                    for name in ['applied.json','delivered.json']:(directory/name).write_text(json.dumps(witness))
                with self.assertRaises((RuntimeError,FileNotFoundError)):
                    await context.complete(recovered)
                context.save.assert_not_called()

    async def test_witness_bound_to_selected_candidate_new_pid_and_validated_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,recovered,_,_=self.fixture(Path(tmp))
            await context.complete(recovered)
            self.assertTrue(context.receipt['cold_bootstrap_body']['normal_local_delivery_observed'])
            self.assertEqual(context.receipt['phase'],'recovered')
            context.save.assert_called_once()


if __name__=='__main__':unittest.main()
