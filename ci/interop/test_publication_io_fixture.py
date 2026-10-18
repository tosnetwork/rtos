#!/usr/bin/env python3
"""The integrated fixture must distinguish a node fatal EIO from a retain cut."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from publication_io_fixture import PublicationIoSource, selector_for
from expired_member_restart_fixture import validate_followup_frontier

sha=lambda data:hashlib.sha256(data).hexdigest()

class PublicationIoFixtureTests(unittest.TestCase):
    def context(self, root):
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
        record={'data':b'actual block'.hex(),'is_final':True,'session_id':session.hex(),'block_id':'full block id'}
        source.original=json.dumps(record).encode()
        source.pending.with_suffix('.json').write_bytes(source.original)
        selector=selector_for(record,source.source_id,10)
        selected=json.dumps(selector).encode(); (source.io_directory/'selector.json').write_bytes(selected)
        body=directory/'node_db/body';body.write_bytes(bytes.fromhex(record['data']));info=body.stat()
        target={'schema':1,'selector':selector,'selector_sha256':sha(selected),'pid':10,'tid':11,
            'artifact':'loose_block_body','path':str(body),'device':info.st_dev,'inode':info.st_ino}
        raw=json.dumps(target).encode();(source.io_directory/'target.json').write_bytes(raw)
        marker=source.io_directory/'native-error.marker'
        marker.write_text(f'publication sync-eio pid=10 tid=11 syscall=fsync errno=5: {body}\n')
        failed={'schema':1,'pid':10,'typed_durability_failure':True,'publication_owner_marked_fatal':True,
            'accepted_callback_returned':False,'selector_sha256':sha(selected),'target_sha256':sha(raw),
            'native_marker_sha256':sha(marker.read_bytes()),'error':'Publication storage durability failed: Input/output error (os error 5)'}
        (source.io_directory/'failed.json').write_text(json.dumps(failed))
        return source,selector,marker,target,failed

    def capture(self, source, selector, marker):
        with patch.object(source,'process_status',return_value='State:\tT (stopped)\n'):
            source.capture_io_failure(marker,selector)

    def test_exact_failed_acceptance_requires_committed_source_and_fatal_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            source,selector,marker,_,_=self.context(Path(temporary));self.capture(source,selector,marker)
            self.assertEqual(source.pending.suffix,'.json')
            self.assertTrue(source.receipt['source_pending_committed_before_interruption'])
            self.assertFalse(source.receipt['source_acknowledged_before_interruption'])
            self.assertTrue(source.receipt['node_observed_error']['publication_owner_marked_fatal'])
            self.assertIsNone(source.environment())

    def test_native_marker_without_real_node_error_receipt_cannot_pass(self):
        for mode in ['fatal','callback','digest','error']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,_,failed=self.context(Path(temporary))
                if mode=='fatal':failed['publication_owner_marked_fatal']=False
                if mode=='callback':failed['accepted_callback_returned']=True
                if mode=='digest':failed['target_sha256']='0'*64
                if mode=='error':failed['error']='unrelated failure'
                (source.io_directory/'failed.json').write_text(json.dumps(failed))
                with self.assertRaisesRegex(RuntimeError,'observe selected EIO'):self.capture(source,selector,marker)

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

    def test_source_mutation_or_any_ack_attempt_cannot_pass(self):
        for mode in ['source','acked','ack.tmp']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source,selector,marker,_,_=self.context(Path(temporary))
                if mode=='source':source.pending.with_suffix('.json').write_bytes(b'changed')
                else:source.pending.with_suffix('.'+mode).write_bytes(b'ack')
                with self.assertRaises(RuntimeError):self.capture(source,selector,marker)

    def test_approval_and_empty_body_cannot_select_node_final_acceptance(self):
        for record in [{'is_final':False,'data':'ab'},{'is_final':True,'data':''}]:
            with self.assertRaises(RuntimeError):selector_for(record,'a'*64,10)

    def test_followup_requires_expired_original_restart_for_new_case(self):
        validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
            expired_member_restart=True,publication_io_library=Path('fault.so')))
        with self.assertRaises(RuntimeError):
            validate_followup_frontier(SimpleNamespace(followup_intent_frontier=True,
                expired_member_restart=False,publication_io_library=Path('fault.so')))

if __name__=='__main__':unittest.main()
