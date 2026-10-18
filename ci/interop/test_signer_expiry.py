"""Expiry composition must not extend authority or restart the observation budget."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import signer_expiry_fixture as expiry
import source_ack_fault_fixture as source
import test_source_ack_fault as source_tests


class SignerExpiryTests(unittest.IsolatedAsyncioTestCase):
    def args(self):
        return SimpleNamespace(signer_expiry_member=5,interrupt_rust_member=2,
            source_ack_partition_restart=True,recovery_below_quorum=True,source_ack_fault='sync-eio',recovery_timeout=2)

    def test_only_explicit_equal_weight_composition_can_expire_member5(self):
        args=self.args();profile={'genesis_time':1000,'activation_delay':90}
        self.assertEqual(expiry.expiry_plan(profile,args)['expire_at'],1140)
        for field,value in [('signer_expiry_member',2),('interrupt_rust_member',5),('recovery_below_quorum',False),('source_ack_fault','write-enospc')]:
            changed=self.args();setattr(changed,field,value)
            with self.assertRaises(ValueError):expiry.expiry_plan(profile,changed)
        with self.assertRaises(ValueError):expiry.expiry_plan({**profile,'successor_weights':{'0':10,'2':30,'4':10,'5':10}},args)

    def context(self,root):
        args=self.args();args.signer_expiry_plan={'member':5,'expire_at':int(time.time())+20}
        node=root/'rust-5';ns=node/'node_db/catchains/consensus/v2/current';ns.mkdir(parents=True)
        session=bytes([4])*32
        (ns/'session-runtime.json').write_text(json.dumps({'session':session.hex(),'shard_workchain':-1,'role':'validator'}))
        (ns/'isolated-signing.json').write_text(json.dumps({'expire_at':args.signer_expiry_plan['expire_at'],'session':session.hex(),
            'validator':hashlib.sha256(b'n6-validator-id-5').hexdigest()}))
        (ns.parent/'isolated-signing-schedule.json').write_text(json.dumps({'expire_at':args.signer_expiry_plan['expire_at']}))
        (node/'validator-prepared.json').write_text('{}');(node/'node.log').write_text('')
        item={'directory':node,'process':SimpleNamespace(pid=os.getpid(),returncode=None),'start_ticks':Path('/proc/self/stat').read_text().split()[21]}
        checkpoint={'block':{'seqno':10},'verified_final_certificates':[{'session_id':base64.b64encode(session).decode()}]}
        return args,item,checkpoint,ns

    async def test_expiry_authority_is_checked_and_extended_schedule_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,cp,ns=self.context(root)
            (ns.parent/'isolated-signing-schedule.json').write_text(json.dumps({'expire_at':args.signer_expiry_plan['expire_at']+600}))
            with self.assertRaisesRegex(RuntimeError,'original profile and successor schedule'):expiry.SignerExpiry(args,root,node,cp)

    async def test_wrong_session_refusal_does_not_qualify_as_current_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,cp,ns=self.context(root);ctx=expiry.SignerExpiry(args,root,node,cp)
            ctx.deadline=time.monotonic()+.01
            (node['directory']/'node.log').write_text('signing generation expired and retired\nSession wrong broadcast_vote: failed to sign vote: signing journal stopped/retired\n')
            with patch.object(expiry.time,'time',return_value=ctx.plan['expire_at']+1):
                with self.assertRaises(TimeoutError):await ctx.qualify(args,[],[],[],{},None,cp,str)

    async def test_authority_cannot_change_after_actual_expiry_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,cp,ns=self.context(root);ctx=expiry.SignerExpiry(args,root,node,cp)
            (ns/'isolated-signing.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError,'authority changed'):await ctx.complete({'last_checkpoint':{}})

    async def test_expiry_wait_is_charged_to_original_source_ack_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old,node,pending=source_tests.SourceAckTests().context(root)
            cp={'gen_catchain_seqno':1,'verified_final_certificates':[{'session_id':base64.b64encode(bytes([4])*32).decode()}]}
            start=time.monotonic()-10;args=SimpleNamespace(source_ack_fault='sync-eio',recovery_timeout=180,
                original_recovery_budget={'monotonic':start,'unix':123.0})
            (root/'second').mkdir()
            new=source.SourceAckFailure(args,root,node,cp,directory=root/'second')
            self.assertEqual(new.started,start);self.assertEqual(new.deadline,start+180)
            self.assertEqual(new.receipt['budget_started_at_unix'],123.0)

    async def test_post_expiry_progress_requires_exact_unexpired_quorum(self):
        for expired_signature in [False,True]:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);args,node,cp,ns=self.context(root);ctx=expiry.SignerExpiry(args,root,node,cp)
                args.snapshot=Path('cpp');args.block_checker=Path('checker')
                block={'workchain':-1,'shard':'-9223372036854775808','seqno':11,'root_hash':'root','file_hash':'file'}
                zero={**block,'seqno':0};info={'init':zero,'last':block,'state_root_hash':'state'}
                line=f'Session {ctx.session} broadcast_vote: failed to sign vote: signing generation expired and retired'
                (node['directory']/'node.log').write_text(line+'\n')
                checked={'block':block,'gen_utime':ctx.plan['expire_at']+5,
                    'configuration':{'current':{'members':[{'validator_id':str(i),'weight':17} for i in [0,2,4,5]]}},
                    'verified_governing_key_blocks':[{}],'key_block':False,
                    'verified_final_certificates':[{'validator_ids':['0','2','5' if expired_signature else '4'],'verified_weight':51}]}
                async def checker(command,log):Path(command[2]).write_text(json.dumps(checked))
                with patch.object(expiry.time,'time',return_value=ctx.plan['expire_at']+10), \
                        patch.object(expiry,'rpc',return_value=info), \
                        patch.object(expiry,'cpp_certificate',AsyncMock(return_value={})), \
                        patch.object(expiry,'cpp_block',AsyncMock(return_value={})), \
                        patch.object(expiry,'native_state',AsyncMock(return_value={})), \
                        patch.object(expiry,'child_checked',checker):
                    if expired_signature:
                        with self.assertRaisesRegex(RuntimeError,'three authorized survivors'):
                            await ctx.qualify(args,[None]*6,list(range(6)),[None]*6,zero,{},cp,str)
                    else:
                        out=await ctx.qualify(args,[None]*6,list(range(6)),[None]*6,zero,{},cp,str)
                        self.assertEqual(out['block'],block)
                        self.assertEqual(ctx.receipt['phase'],'qualified_before_interruption')

    async def test_recovery_reuses_observer_started_at_first_successor_checkpoint(self):
        import rotation_fixture as rotation
        import source_ack_partition_fixture as combined
        args=self.args();observer=SimpleNamespace(started=time.monotonic()-30,started_unix=time.time()-30,
            qualify=AsyncMock(return_value={'qualified':'early-observer'}),complete=AsyncMock())
        args.signer_expiry_observer=observer
        class Context:
            async def complete(self,recovered):pass
            def close(self):pass
        operation=AsyncMock(return_value=({'last_checkpoint':{'seqno':100}},None))
        with patch.object(expiry,'SignerExpiry',side_effect=AssertionError('late observer reconstruction')), \
                patch.object(combined,'SourceAckPartitionRestart',return_value=Context()), \
                patch.object(rotation,'_recover_rotation_member',operation):
            await rotation.recover_rotation_member(args,Path('root'),[None]*6,[None]*6,[None]*6,
                [{'index':2},{'index':5}],{}, {}, {'original':'checkpoint'}, {})
        observer.qualify.assert_awaited_once()
        self.assertEqual(operation.call_args.args[8],{'qualified':'early-observer'})
        self.assertEqual(args.original_recovery_budget['monotonic'],observer.started)
        observer.complete.assert_awaited_once()


    def test_runtime_start_retry_preserves_first_observation_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,cp,ns=self.context(root)
            runtime=ns/'session-runtime.json';original=runtime.read_bytes();runtime.unlink()
            with patch.object(expiry.time,'monotonic',return_value=100.0):
                with self.assertRaisesRegex(RuntimeError,'exact current active MC runtime'):
                    expiry.SignerExpiry(args,root,node,cp)
            self.assertFalse((root/'signer-expiry/receipt.json').exists())
            runtime.write_bytes(original)
            with patch.object(expiry.time,'monotonic',return_value=100.5):
                ctx=expiry.SignerExpiry(args,root,node,cp)
            self.assertEqual(ctx.started,100.0)
            self.assertEqual(ctx.deadline,102.0)
            self.assertEqual(ctx.receipt['budget_started_at_unix'],ctx.started_unix)


    def test_runtime_start_wait_cannot_extend_expiry_or_observation_deadline(self):
        for overdue in ['budget','expiry']:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);args,node,cp,ns=self.context(root)
                runtime=ns/'session-runtime.json';original=runtime.read_bytes();runtime.unlink()
                with patch.object(expiry.time,'monotonic',return_value=100.0):
                    with self.assertRaises(expiry.SignerExpiryRuntimePending):expiry.SignerExpiry(args,root,node,cp)
                runtime.write_bytes(original)
                if overdue=='budget':
                    with patch.object(expiry.time,'monotonic',return_value=103.0):
                        with self.assertRaisesRegex(TimeoutError,'original recovery deadline'):expiry.SignerExpiry(args,root,node,cp)
                else:
                    with patch.object(expiry.time,'monotonic',return_value=100.5), \
                            patch.object(expiry.time,'time',return_value=args.signer_expiry_plan['expire_at']):
                        with self.assertRaisesRegex(RuntimeError,'live pre-expiry'):expiry.SignerExpiry(args,root,node,cp)
                self.assertFalse((root/'signer-expiry').exists())

    def test_ambiguous_current_runtime_is_fatal_not_startup_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,cp,ns=self.context(root)
            other=ns.parent/'duplicate';other.mkdir()
            (other/'session-runtime.json').write_bytes((ns/'session-runtime.json').read_bytes())
            with self.assertRaisesRegex(RuntimeError,'exact current active MC runtime') as error:
                expiry.SignerExpiry(args,root,node,cp)
            self.assertNotIsInstance(error.exception,expiry.SignerExpiryRuntimePending)
