import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import expired_member_restart_fixture as passive
from signer_expiry_fixture import expiry_plan


class ExpiredMemberRestartTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(signer_expiry_member=5,interrupt_rust_member=5,source_ack_partition_restart=True,
            recovery_below_quorum=False,source_ack_fault='sync-eio',expired_member_restart=True)

    def sample(self,n):
        return {'block':{'seqno':n},'gen_utime':200,'created_by':'0',
            'configuration':{'current':{'members':[{'validator_id':str(i),'weight':17} for i in [0,2,4,5]]}},
            'verified_final_certificates':[{'validator_ids':['0','2','4'],'verified_weight':51}],
            'workchain_check':{'block':{'seqno':n+100},'gen_utime':200,'created_by':'2',
                'all_four_states_match_block_update':True,'masterchain_anchor_checked':True}}

    def test_expired_restart_requires_same_member_and_retains_full_committee(self):
        plan=expiry_plan({'genesis_time':1000,'activation_delay':90},self.args())
        self.assertEqual(plan['interrupted_member'],5)
        self.assertEqual(plan['surviving_weight_during_interruption'],51)
        self.assertEqual(plan['quorum_weight'],46)
        for field,value in [('interrupt_rust_member',2),('recovery_below_quorum',True),('signer_expiry_member',None)]:
            args=self.args();setattr(args,field,value)
            with self.assertRaises(ValueError):expiry_plan({'genesis_time':1000,'activation_delay':90},args)

    def test_fresh_six_peer_and_wc_progress_must_continue_for_twelve_seconds(self):
        ctx=passive.ExpiredFullNodeAcceptance(str,100,100,1000,'session')
        with patch.object(passive.time,'monotonic',side_effect=[0,6,12]):
            self.assertFalse(ctx.observe(self.sample(10),False,'a'))
            self.assertFalse(ctx.observe(self.sample(11),False,'b'))
            self.assertTrue(ctx.observe(self.sample(12),False,'c'))

    def test_stale_block_or_wc_cannot_begin_post_restart_observation(self):
        for field in ['mc','wc']:
            ctx=passive.ExpiredFullNodeAcceptance(str,100,100,1000,'session');x=self.sample(10)
            if field=='mc':x['gen_utime']=100
            else:x['workchain_check']['gen_utime']=100
            with patch.object(passive.time,'monotonic',return_value=0):self.assertFalse(ctx.observe(x,False,'a'))
            self.assertEqual(ctx.samples,[])

    def test_expired_vote_signature_creator_wrong_weights_or_missing_state_refuse(self):
        for mode in ['vote','signature','creator','weight','state']:
            ctx=passive.ExpiredFullNodeAcceptance(str,100,100,1000,'session');x=self.sample(10)
            if mode=='signature':x['verified_final_certificates'][0]['validator_ids']=['0','2','5']
            if mode=='creator':x['workchain_check']['created_by']='5'
            if mode=='weight':x['configuration']['current']['members'][0]['weight']=18
            if mode=='state':x['workchain_check']['all_four_states_match_block_update']=False
            with patch.object(passive.time,'monotonic',return_value=0):
                with self.assertRaises(RuntimeError):ctx.observe(x,mode=='vote','a')

    def test_refusal_must_bind_current_session_and_no_collation(self):
        ctx=passive.ExpiredFullNodeAcceptance(str,100,100,1000,'current')
        line='SESSION_LIFECYCLE: pre_create_engine failed session_id=current: Isolated custody key differs from authenticated descriptor or has expired'
        self.assertEqual(ctx.refusal(line),line)
        for text in ['Retired recovery has no signing or voting authority',line.replace('current','old'),line+'\nValidatorGroup::on_generate_slot: Collation successful']:
            with self.assertRaises(RuntimeError):ctx.refusal(text)

    def test_original_deadline_is_not_extended_for_passive_observation(self):
        ctx=passive.ExpiredFullNodeAcceptance(str,100,100,12,'current')
        with patch.object(passive.time,'monotonic',return_value=12):
            with self.assertRaises(TimeoutError):ctx.observe(self.sample(10),False,'a')

    def test_expired_restart_complete_requires_prior_expiry_and_replaced_process(self):
        import asyncio
        import tempfile
        from pathlib import Path
        import test_signer_expiry as helpers
        from signer_expiry_fixture import SignerExpiry
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args,node,checkpoint,namespace=helpers.SignerExpiryTests().context(root)
            args.expired_member_restart=True;ctx=SignerExpiry(args,root,node,checkpoint)
            recovered={'last_checkpoint':{'seqno':20},'expired_full_node':{'signing_authority_restored':False}}
            with self.assertRaisesRegex(RuntimeError,'qualified natural expiry'):
                asyncio.run(ctx.complete(recovered))
            ctx.receipt['phase']='qualified_before_interruption'
            with self.assertRaisesRegex(RuntimeError,'new process'):
                asyncio.run(ctx.complete(recovered))
            ctx.pid=0
            asyncio.run(ctx.complete(recovered))
            self.assertEqual(ctx.receipt['phase'],'expired_member_restarted_without_signing')
            self.assertTrue(ctx.receipt['authority_unchanged'])

    def test_adjacent_scoped_constructor_failure_is_correlated_without_accepting_other_sessions(self):
        ctx=passive.ExpiredFullNodeAcceptance(str,100,100,1000,'current')
        scope='SESSION_LIFECYCLE: reset_after_failure shard=-1:8000000000000000 cc_seqno=1 session_id=current status=created -> retry (existing session ownership retained)'
        error='Cannot start group: Isolated custody key differs from authenticated descriptor or has expired (construction drained=true); resetting session to Created for retry'
        self.assertEqual(ctx.refusal(scope+'\n'+error),scope+'\n'+error)
        for text in [scope.replace('session_id=current','session_id=old')+'\n'+error,
                     scope+'\nother event\n'+error,
                     scope+'\n'+error.replace('drained=true','drained=false'),
                     scope.replace('reset_after_failure','unrelated')+'\n'+error]:
            with self.assertRaises(RuntimeError):ctx.refusal(text)


class PendingIntentRecoveryTests(unittest.TestCase):
    def context(self, root):
        from pathlib import Path
        import json
        namespaces=root/'owned';pending=namespaces/'session.validator/finality-intents'
        pending.mkdir(parents=True)
        record={'slot':7,'candidate_hash':'a'*64,'certificate':'original exact proof'}
        source=pending/('7-'+'a'*64+'.json');source.write_text(json.dumps(record))
        return namespaces,source,record

    def test_original_record_is_observation_only_and_missing_proof_cannot_complete(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);namespaces,source,record=self.context(root);original=source.read_bytes()
            ctx=passive.PendingIntentRecovery(namespaces,root/'evidence')
            self.assertEqual(source.read_bytes(),original)
            self.assertFalse(ctx.complete());source.unlink();self.assertFalse(ctx.complete())

    def test_exact_completed_proof_and_removed_pending_are_both_required(self):
        import tempfile,json
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);namespaces,source,record=self.context(root)
            ctx=passive.PendingIntentRecovery(namespaces,root/'evidence')
            proof=source.parent/'completed-v1'/source.with_suffix('.complete').name
            proof.parent.mkdir();proof.write_text(json.dumps({'schema':1,'record':record}))
            self.assertFalse(ctx.complete());source.unlink();self.assertTrue(ctx.complete())
            self.assertTrue((root/'evidence/receipt.json').exists())

    def test_other_certificate_or_symlink_cannot_close_original_obligation(self):
        import tempfile,json
        from pathlib import Path
        for mode in ['changed','symlink']:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);namespaces,source,record=self.context(root)
                ctx=passive.PendingIntentRecovery(namespaces,root/'evidence');source.unlink()
                proof=source.parent/'completed-v1'/source.with_suffix('.complete').name;proof.parent.mkdir()
                if mode=='changed':proof.write_text(json.dumps({'schema':1,'record':{**record,'certificate':'other proof'}}))
                else:proof.symlink_to(root/'missing')
                with self.assertRaises(RuntimeError):ctx.complete()

    def test_empty_snapshot_or_candidate_filename_mismatch_refuses(self):
        import tempfile
        from pathlib import Path
        for mode in ['empty','wrong_name']:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);namespaces,source,record=self.context(root)
                if mode=='empty':source.unlink()
                else:source.rename(source.with_name('8-'+'a'*64+'.json'))
                with self.assertRaises(RuntimeError):passive.PendingIntentRecovery(namespaces,root/'evidence')
