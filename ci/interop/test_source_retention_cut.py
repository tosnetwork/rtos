#!/usr/bin/env python3
"""Exact successful sync cut and uncommitted source recovery invariants."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import source_ack_fault_fixture as ack
import source_retention_cut_fixture as cut


class RetentionTests(unittest.IsolatedAsyncioTestCase):
    def context(self, root):
        node = root/'node'; namespace=node/'node_db/catchains/consensus/v2/owned';namespace.mkdir(parents=True)
        pending=namespace/'finality-pending';pending.mkdir()
        session=bytes([4])*32
        (namespace/'session-runtime.json').write_text(json.dumps({'session':session.hex(),'role':'validator',
            'shard_workchain':-1,'catchain_seqno':1,'validator_index':0}))
        checkpoint={'gen_catchain_seqno':1,'verified_final_certificates':[{'session_id':base64.b64encode(session).decode()}]}
        node={'index':2,'directory':node,'process':SimpleNamespace(pid=10,returncode=None)}
        args=SimpleNamespace(source_ack_fault=None,recovery_timeout=1)
        return cut.SourceRetentionCut(args,root,node,checkpoint),node,pending

    def captured(self, context, pending):
        record={'schema':1,'global_id':4,'zerostate':'exact-zero','protocol':2,'carrier_version':5,'wire_profile':1,
            'profile':'a'*64,'session_id':context.receipt['session'],'block_id':'exact-block',
            'is_final':True,'local_adnl':'b'*64,'local_validator_index':0,'source_validator':'c'*64,
            'data':'original-body','signature_set':'original-cert'}
        identity=['rtos-source-finality-v1',record['global_id'],record['zerostate'],record['protocol'],
            record['carrier_version'],record['wire_profile'],record['profile'],record['session_id'],
            record['block_id'],record['is_final'],[record['local_adnl'],record['local_validator_index'],record['source_validator']]]
        name=hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest()
        original=json.dumps(record,separators=(',',':')).encode();temporary=pending/(name+'.tmp');temporary.write_bytes(original)
        marker=context.directory/'native-stop.marker';marker.write_text(f'source retain-after-fsync pid=10: {temporary}\n')
        with patch.object(context,'process_status',return_value='Pid:\t10\nState:\tT (stopped)\n'):
            context.capture_stop(marker)
        return temporary,original

    async def test_uncommitted_source_survives_kill_and_reopens_without_preload(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));temporary,original=self.captured(context,pending)
            self.assertFalse(temporary.with_suffix('.json').exists())
            node['process'].returncode=-9
            async def no_delay(*args):pass
            with patch.object(ack,'hold',no_delay):await context.after_interruption()
            (context.directory/'armed').write_text('armed')
            self.assertIsNone(context.environment());self.assertTrue(context.receipt['retention_uncommitted_before_restart'])
            node['process']=SimpleNamespace(pid=20,returncode=None)
            await context.after_restart({**node,'start_ticks':'777'})
            temporary.with_suffix('.acked').write_text(json.dumps({'record':json.loads(original),'node_receipt':'d'*64}))
            temporary.unlink();await context.complete({'last_checkpoint':{'seqno':18}})
            self.assertTrue(context.receipt['interrupted_retention_recovered'])
            self.assertEqual(context.receipt['pending_sha256'],hashlib.sha256(original).hexdigest())

    async def test_changed_temporary_cannot_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,pending=self.context(Path(tmp));temporary,_=self.captured(context,pending)
            temporary.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError,'changed before reopening'):context.environment()

    async def test_committed_source_is_not_an_interrupted_retain(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,pending=self.context(Path(tmp));temporary,original=self.captured(context,pending)
            temporary.with_suffix('.json').write_bytes(original)
            with self.assertRaisesRegex(RuntimeError,'committed before reopening'):context.environment()

    async def test_marker_requires_actual_stopped_state_and_exact_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,_=self.context(Path(tmp));marker=context.directory/'native-stop.marker'
            marker.write_text('source retain-after-fsync pid=11: /unrelated/'+('a'*64)+'.tmp\n')
            with patch.object(context,'process_status',return_value='State:\tT (stopped)\n'):
                with self.assertRaisesRegex(RuntimeError,'stopped owned process'):context.capture_stop(marker)
            marker.write_text('source retain-after-fsync pid=10: /unrelated/'+('a'*64)+'.tmp\n')
            with patch.object(context,'process_status',return_value='State:\tS (sleeping)\n'):
                with self.assertRaisesRegex(RuntimeError,'stopped owned process'):context.capture_stop(marker)
            with patch.object(context,'process_status',return_value='State:\tT (stopped)\n'):
                with self.assertRaisesRegex(RuntimeError,'different source path'):context.capture_stop(marker)

    async def test_pending_json_blocks_success_and_deadline_is_not_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,pending=self.context(Path(tmp));temporary,original=self.captured(context,pending)
            temporary.with_suffix('.acked').write_text(json.dumps({'record':json.loads(original),'node_receipt':'d'*64}))
            temporary.with_suffix('.json').write_bytes(original);temporary.unlink()
            context.deadline=time.monotonic()+.01
            with self.assertRaisesRegex(TimeoutError,'original recovery deadline'):
                await context.complete({'last_checkpoint':{}})
            self.assertNotEqual(context.receipt['phase'],'recovered')

    async def test_wrong_recovered_record_cannot_satisfy_retention_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,pending=self.context(Path(tmp));temporary,original=self.captured(context,pending)
            temporary.with_suffix('.acked').write_text(json.dumps({'record':{**json.loads(original),'data':'wrong'},'node_receipt':'d'*64}))
            temporary.unlink()
            with self.assertRaisesRegex(RuntimeError,'differs from the original'):
                await context.complete({'last_checkpoint':{}})


class NativeRetentionCutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory();cls.library=Path(cls.directory.name)/'cut.so'
        source=Path(__file__).resolve().parents[2]/'rtos/src/tests/finality_retention_cut.c'
        subprocess.run(['/usr/bin/clang-21','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(cls.library)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()

    def probe(self, operation='fsync', correct=True, name=None, empty=False, control_kind='regular'):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);selected=root/'selected';selected.mkdir();other=root/'other';other.mkdir()
            target=(selected if correct else other)/(name or ('a'*64+'.tmp'));marker=root/'marker';arm=root/'armed';arm.write_text('armed')
            control=root/'control';control.write_text(str(selected)+'\n')
            if control_kind=='symlink':
                control.rename(root/'real-control');control.symlink_to(root/'real-control')
            elif control_kind=='relative':control.write_text('selected\n')
            after=root/'after';data=b'' if empty else b'durable-source-proof'
            script='import os,sys;from pathlib import Path;p,after,op,data=sys.argv[1:];fd=os.open(p,os.O_WRONLY|os.O_CREAT,0o600);os.write(fd,bytes.fromhex(data));getattr(os,op)(fd);os.close(fd);Path(after).write_text("returned")'
            environment={**os.environ,'LD_PRELOAD':str(self.library),'RTOS_TEST_RETAIN_CUT_DIRECTORY_FILE':str(control),'RTOS_TEST_RETAIN_CUT_ARM':str(arm),'RTOS_TEST_RETAIN_CUT_MARKER':str(marker)}
            process=subprocess.Popen([sys.executable,'-c',script,str(target),str(after),operation,data.hex()],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            expect_stop=correct and name is None and not empty and control_kind=='regular'
            try:
                if expect_stop:
                    deadline=time.monotonic()+5
                    while True:
                        if process.poll() is not None:self.fail('native cut returned: '+process.stderr.read().decode())
                        status=Path('/proc',str(process.pid),'status').read_text()
                        if any(l.startswith('State:') and l.split()[1]=='T' for l in status.splitlines()):break
                        if time.monotonic()>deadline:self.fail('native cut never stopped')
                        time.sleep(.01)
                    self.assertEqual(target.read_bytes(),data);self.assertFalse(after.exists())
                    self.assertEqual(marker.read_text(),f'source retain-after-fsync pid={process.pid}: {target}\n')
                else:
                    out,err=process.communicate(timeout=5);self.assertEqual(process.returncode,0,err.decode())
                    self.assertTrue(after.exists());self.assertFalse(marker.exists())
            finally:
                if process.poll() is None:process.kill()
                process.communicate(timeout=5)

    def test_successful_fsync_stops_before_return_and_commit(self):self.probe()
    def test_successful_fdatasync_stops_before_return_and_commit(self):self.probe(operation='fdatasync')
    def test_wrong_directory_is_untouched(self):self.probe(correct=False)
    def test_ack_temporary_is_untouched(self):self.probe(name='a'*64+'.ack.tmp')
    def test_unknown_temporary_is_untouched(self):self.probe(name='unknown.tmp')
    def test_empty_temporary_is_untouched(self):self.probe(empty=True)
    def test_symlink_control_is_rejected(self):self.probe(control_kind='symlink')
    def test_relative_control_is_rejected(self):self.probe(control_kind='relative')


if __name__=='__main__':unittest.main()
