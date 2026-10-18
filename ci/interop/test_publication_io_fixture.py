#!/usr/bin/env python3
"""Distinguish full-WAL custody, failed block acceptance and canonical completion."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from publication_io_fixture import PublicationIoSource, selector_for, delivery_receipt
from expired_member_restart_fixture import validate_followup_frontier

sha=lambda data:hashlib.sha256(data).hexdigest()

class PublicationIoFixtureTests(unittest.TestCase):
    def context(self, root, acknowledged=True):
        directory=root/'node'; namespace=directory/'node_db/catchains/consensus/v2/owned'
        namespace.mkdir(parents=True); pending=namespace/'finality-pending'; pending.mkdir()
        session=bytes([4])*32
        (namespace/'session-runtime.json').write_text(json.dumps({'session':session.hex(),'role':'validator',
            'shard_workchain':-1,'catchain_seqno':1,'validator_index':0}))
        node={'index':5,'directory':directory,'process':SimpleNamespace(pid=10,returncode=None)}
        args=SimpleNamespace(source_ack_fault=None,recovery_timeout=180,source_retention_cut_point='after-fsync')
        checkpoint={'gen_catchain_seqno':1,'verified_final_certificates':[{'session_id':base64.b64encode(session).decode()}]}
        source=PublicationIoSource(args,root,node,checkpoint)
        source.io_directory=root/'publication-io'; source.io_directory.mkdir()
        source.source_id='a'*64
        source.pending=pending/(source.source_id+'.tmp')
        identity=lambda height,root_hash,file_hash:f'(-1:8000000000000000, {height}, rh {root_hash}, fh {file_hash})'
        record={'data':b'actual block'.hex(),'signature_set':'ab','is_final':True,'session_id':session.hex(),
            'block_id':identity(5,'1'*64,sha(b'actual block')),'global_id':4,'protocol':2,'wire_profile':1,
            'profile':'a'*64,'zerostate':identity(0,'0'*64,'2'*64)}
        source.original=json.dumps(record).encode()
        selector=selector_for(record,source.source_id,10)
        if acknowledged:
            source.pending.with_suffix('.acked').write_text(json.dumps({'record':record,'node_receipt':selector['node_receipt']}))
        else:source.pending.with_suffix('.json').write_bytes(source.original)
        selected=json.dumps(selector).encode(); (source.io_directory/'selector.json').write_bytes(selected)
        body=directory/'node_db/body';body.write_bytes(bytes.fromhex(record['data']));info=body.stat()
        publication={'record_id':13,'node_receipt':selector['node_receipt'],'stage':'DraftDurable'}
        target={'schema':1,'selector':selector,'selector_sha256':sha(selected),'pid':10,'tid':11,
            'artifact':'loose_block_body','path':str(body),'device':info.st_dev,'inode':info.st_ino,
            'publication':publication}
        raw=json.dumps(target).encode();(source.io_directory/'target.json').write_bytes(raw)
        marker=source.io_directory/'native-error.marker'
        marker.write_text(f'publication sync-eio pid=10 tid=11 syscall=fsync errno=5: {body}\n')
        failed={'schema':1,'pid':10,'typed_durability_failure':True,'publication_owner_marked_fatal':True,
            'accepted_callback_returned':False,'selector_sha256':sha(selected),'target_sha256':sha(raw),
            'native_marker_sha256':sha(marker.read_bytes()),'error':'Publication storage durability failed: Input/output error (os error 5)',
            'retained_draft_verified':True,'publication':publication}
        (source.io_directory/'failed.json').write_text(json.dumps(failed))
        return source,selector,marker,target,failed

    def capture(self, source, selector, marker):
        with patch.object(source,'process_status',return_value='State:\tT (stopped)\n'):
            source.capture_io_failure(marker,selector)

    def test_delivery_coordinate_encoding_matches_actual_rust_wal_receipt(self):
        coordinates={'zerostate': '(-1:8000000000000000, 0, rh 34ef43d3c8c49734aa3c0a8e15947531fecda01d96df7b758b48559ab75c6844, fh ac210537d97ab7a4ac6c4de2ba8dc3b82ddcce38db76f9f917ebf2fee1fe616c)', 'global_id': 4, 'wire_profile': 1, 'protocol': 2, 'profile': '3c4a338fb0b5129de7ad6102b2d0a92442469bdbc3a922f8fc5a978b172341da', 'session_id': '4bfd2a02f2403601c53658f6456082ecf5e275d71cd46881586bd872d0c0ecb3', 'block_id': '(-1:8000000000000000, 212, rh dfbf311ad91495b0154685bd3d35c32492bd984b62466c8bc8e52aa8ed983b77, fh dadb8e45e202a70d9a8cc529a5aa04838960f99e6b094cfc8bbb0481860739f4)', 'is_final': True}
        self.assertEqual(delivery_receipt(coordinates),'20758516678bd6b147aa1ade12051b8f9442be5854b38522edc79d37943f188a')
        coordinates["is_final"]=False
        self.assertNotEqual(delivery_receipt(coordinates),'20758516678bd6b147aa1ade12051b8f9442be5854b38522edc79d37943f188a')

    def test_full_wal_handoff_ack_is_not_block_acceptance(self):
        for acknowledged in [False,True]:
            with self.subTest(acknowledged=acknowledged),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,_,_=self.context(Path(temporary),acknowledged);self.capture(source,selector,marker)
                self.assertEqual(source.receipt['source_acknowledged_before_interruption'],acknowledged)
                self.assertFalse(source.receipt['source_canonical_delivery_before_interruption'])
                self.assertTrue(source.receipt['node_observed_error']['retained_draft_verified'])
                self.assertIsNone(source.environment())

    def test_native_marker_without_real_node_error_receipt_cannot_pass(self):
        for mode in ['fatal','callback','digest','error','draft']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,_,failed=self.context(Path(temporary))
                if mode=='fatal':failed['publication_owner_marked_fatal']=False
                if mode=='callback':failed['accepted_callback_returned']=True
                if mode=='digest':failed['target_sha256']='0'*64
                if mode=='error':failed['error']='unrelated failure'
                if mode=='draft':failed['retained_draft_verified']=False
                (source.io_directory/'failed.json').write_text(json.dumps(failed))
                with self.assertRaises(RuntimeError):self.capture(source,selector,marker)

    def test_changed_inode_or_body_or_worker_cannot_pass(self):
        for mode in ['inode','body','thread']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,target,failed=self.context(Path(temporary))
                if mode=='inode':
                    body=Path(target['path']);body.rename(body.with_suffix('.old'));body.write_bytes(b'actual block')
                if mode=='body':Path(target['path']).write_bytes(b'other block')
                if mode=='thread':
                    marker.write_text(marker.read_text().replace('tid=11','tid=12'))
                    failed['native_marker_sha256']=sha(marker.read_bytes())
                    (source.io_directory/'failed.json').write_text(json.dumps(failed))
                with self.assertRaisesRegex(RuntimeError,'worker/body'):self.capture(source,selector,marker)

    def test_wrong_delivery_or_accepted_stage_cannot_be_a_failed_draft(self):
        for mode in ['delivery','stage']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,target,failed=self.context(Path(temporary))
                if mode=='delivery':target['publication']['node_receipt']='0'*64
                else:target['publication']['stage']='AcceptedDraft'
                failed['publication']=target['publication']
                raw=json.dumps(target).encode();(source.io_directory/'target.json').write_bytes(raw)
                failed['target_sha256']=sha(raw);(source.io_directory/'failed.json').write_text(json.dumps(failed))
                with self.assertRaisesRegex(RuntimeError,'retained WAL draft'):self.capture(source,selector,marker)

    def test_source_mutation_or_early_canonical_proof_cannot_pass(self):
        for mode in ['source','missing','receipt','reference']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,_,_=self.context(Path(temporary));ack=source.pending.with_suffix('.acked')
                if mode=='missing':ack.unlink()
                if mode in ['source','receipt']:
                    value=json.loads(ack.read_text())
                    if mode=='source':value['record']['data']='abcd'
                    else:value['node_receipt']='0'*64
                    ack.write_text(json.dumps(value))
                if mode=='reference':
                    directory=source.pending_directory/'references-v1';directory.mkdir();(directory/(source.source_id+'.reference')).write_text('{}')
                with self.assertRaises(RuntimeError):self.capture(source,selector,marker)

    def test_recovery_waits_for_canonical_delivery_after_full_handoff_ack(self):
        with tempfile.TemporaryDirectory() as temporary:
            source,selector,marker,_,_=self.context(Path(temporary));self.capture(source,selector,marker)
            with patch('publication_io_fixture.asyncio.sleep',side_effect=RuntimeError('still waiting')):
                with self.assertRaisesRegex(RuntimeError,'still waiting'):
                    asyncio.run(source.complete({'last_checkpoint':{'seqno':9}}))
            reference={'digest':sha(source.original),'metadata':{**json.loads(source.original),'data':'','signature_set':''},
                       'node_receipt':selector['node_receipt']}
            directory=source.pending_directory/'references-v1';directory.mkdir()
            (directory/(source.source_id+'.delivered')).write_text(json.dumps({'schema':1,'reference':reference}))
            for path in source.source_snapshot:path.unlink()
            asyncio.run(source.complete({'last_checkpoint':{'seqno':9}}))
            self.assertTrue(source.receipt['original_source_canonical_delivery_recovered'])
            self.assertEqual(source.receipt['recovered_ack_kind'],'delivered')

    def test_approval_and_empty_body_cannot_select_node_final_acceptance(self):
        for record in [{'is_final':False,'data':'ab'},{'is_final':True,'data':''}]:
            with self.assertRaises(RuntimeError):selector_for(record,'a'*64,10)

    def test_expiry_plan_accepts_only_complete_explicit_node_io_composition(self):
        from signer_expiry_fixture import expiry_plan
        def args():return SimpleNamespace(signer_expiry_member=5,interrupt_rust_member=5,
            expired_member_restart=True,source_ack_partition_restart=False,recovery_below_quorum=False,
            source_ack_fault=None,publication_io_library=Path('io.so'),partition_restart=True,
            source_retention_cut_library=Path('retain.so'),source_retention_cut_point='after-fsync')
        profile={'genesis_time':1000,'activation_delay':90}
        plan=expiry_plan(profile,args())
        self.assertEqual((plan['expire_at'],plan['total_weight'],plan['quorum_weight'],plan['surviving_weight_during_interruption']),(1140,68,46,51))
        for field,value in [('partition_restart',False),('source_retention_cut_library',None),
                            ('source_retention_cut_point','before-write'),('source_ack_fault','sync-eio'),
                            ('interrupt_rust_member',2),('recovery_below_quorum',True)]:
            changed=args();setattr(changed,field,value)
            with self.subTest(field=field),self.assertRaises(ValueError):expiry_plan(profile,changed)

    def test_followup_requires_expired_original_restart_for_new_case(self):
        validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
            expired_member_restart=True,publication_io_library=Path('fault.so')))
        with self.assertRaises(RuntimeError):
            validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
                expired_member_restart=False,publication_io_library=Path('fault.so')))

if __name__=='__main__':unittest.main()
