#!/usr/bin/env python3
"""Native exact-path probes and hermetic source ACK preservation checks."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import source_ack_fault_fixture as source


class SourceAckTests(unittest.IsolatedAsyncioTestCase):
    def context(self, root, mode='sync-eio', stale_prepared=False):
        node = root/'node'; namespace=node/'node_db/catchains/consensus/v2'/'owned-current-session'; namespace.mkdir(parents=True)
        pending=namespace/'finality-pending'; pending.mkdir()
        session=bytes([4])*32
        (namespace/'session-runtime.json').write_text(json.dumps({'session':session.hex(), 'role':'validator', 'shard_workchain':-1, 'catchain_seqno':1, 'validator_index':0}))
        (node/'validator-prepared.json').write_text(json.dumps({'sessions':[{'masterchain':True,
            'committee_phase':'successor','session':('0'*64 if stale_prepared else session.hex()),'namespace':str(namespace)}]}))
        checkpoint={'gen_catchain_seqno':1,'verified_final_certificates':[{'session_id':base64.b64encode(session).decode()}]}
        process=SimpleNamespace(pid=10,returncode=None)
        item={'index':2,'directory':node,'process':process}
        args=SimpleNamespace(source_ack_fault=mode,recovery_timeout=1)
        context=source.SourceAckFailure(args,root,item,checkpoint)
        return context,item,pending

    def captured(self, context, node, pending):
        original=json.dumps({'session_id':context.receipt['session'],'is_final':True,'block_id':'exact-public-block',
            'data':'original-boc','signature_set':'original-certificate'},separators=(',',':')).encode()
        name='a'*64; (pending/(name+'.json')).write_bytes(original)
        temporary=pending/(name+'.ack.tmp');temporary.write_bytes(b'nonempty ACK' if context.mode=='sync-eio' else b'')
        marker=context.directory/'native-error.marker';marker.write_text('source '+context.mode+': '+str(temporary)+'\n')
        context.capture_failure(marker,'Node WAL durable but source ACK needs retry: native error')
        return name,original

    async def test_ack_truncate_retry_waits_for_nonempty_observation_in_original_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, node, pending = self.context(Path(tmp))
            log = node['directory'] / 'node.log'; log.write_text('')
            name = 'a' * 64
            original = json.dumps({'session_id':context.receipt['session'], 'is_final':True,
                'block_id':'public block', 'data':'boc', 'signature_set':'certificate'}).encode()
            (pending / (name + '.json')).write_bytes(original)
            temporary = pending / (name + '.ack.tmp')
            async def publish_failure_then_retry_bytes():
                await asyncio.sleep(.01)
                temporary.write_bytes(b'')
                (context.directory / 'native-error.marker').write_text('source sync-eio: ' + str(temporary) + '\n')
                log.write_text('Node WAL durable but source ACK needs retry: Input/output error\n')
                await asyncio.sleep(.2)
                temporary.write_bytes(b'complete retry ACK')
            producer = asyncio.create_task(publish_failure_then_retry_bytes())
            started = time.monotonic(); deadline = context.deadline
            try:
                await context.arm()
                self.assertGreaterEqual(time.monotonic() - started, .2)
                self.assertEqual(context.deadline, deadline)
                self.assertEqual(context.receipt['temporary_bytes'], len(b'complete retry ACK'))
                self.assertEqual(context.receipt['source_id'], name)
                self.assertEqual(context.receipt['pending_sha256'], hashlib.sha256(original).hexdigest())
            finally:
                producer.cancel()
                await asyncio.gather(producer, return_exceptions=True)
                context.close()

    async def test_empty_ack_retry_observation_cannot_extend_deadline_or_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, node, pending = self.context(Path(tmp))
            context.deadline = time.monotonic() + .15
            log = node['directory'] / 'node.log'; log.write_text('')
            name = 'a' * 64; temporary = pending / (name + '.ack.tmp')
            (pending / (name + '.json')).write_text(json.dumps({'session_id':context.receipt['session']}))
            async def publish():
                await asyncio.sleep(.01)
                temporary.write_bytes(b'')
                (context.directory / 'native-error.marker').write_text('source sync-eio: ' + str(temporary) + '\n')
                log.write_text('Node WAL durable but source ACK needs retry: Input/output error\n')
            producer = asyncio.create_task(publish())
            try:
                with self.assertRaisesRegex(TimeoutError, 'original recovery deadline'):
                    await context.arm()
                self.assertEqual(context.receipt['phase'], 'waiting_for_native_ack_failure')
                self.assertNotIn('native_error_observed_at_unix', context.receipt)
                self.assertEqual(temporary.read_bytes(), b'')
            finally:
                producer.cancel()
                await asyncio.gather(producer, return_exceptions=True)
                context.close()

    async def test_authenticated_runtime_is_used_when_offline_preparation_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,_=self.context(Path(tmp),stale_prepared=True)
            runtime=json.loads((context.directory/'selected-runtime.json').read_text())
            self.assertEqual(runtime['session'],context.receipt['session'])
            self.assertEqual(runtime['catchain_seqno'],1)

    async def test_duplicate_authenticated_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);context,node,_=self.context(root)
            current=Path(context.receipt['namespace'])/'session-runtime.json'
            duplicate=current.parent.parent/'duplicate';duplicate.mkdir()
            (duplicate/'session-runtime.json').write_bytes(current.read_bytes())
            args=SimpleNamespace(source_ack_fault='sync-eio',recovery_timeout=1)
            checkpoint={'gen_catchain_seqno':1,'verified_final_certificates':[{'session_id':base64.b64encode(bytes([4])*32).decode()}]}
            with self.assertRaisesRegex(RuntimeError,'one exact authenticated'):
                source.SourceAckFailure(args,root,node,checkpoint)

    async def test_exact_original_source_survives_interruption_and_recovered_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));name,original=self.captured(context,node,pending)
            node['process'].returncode=-9
            async def no_delay(*args):pass
            with patch.object(source,'hold',no_delay):await context.after_interruption()
            (context.directory/'armed').write_text('owned fault')
            self.assertIsNone(context.environment());self.assertFalse((context.directory/'armed').exists())
            self.assertEqual((context.directory/'disarmed').read_text(),'owned fault')
            node['process']=SimpleNamespace(pid=20,returncode=None)
            await context.after_restart({**node,'start_ticks':'777'})
            metadata={**json.loads(original),'data':'','signature_set':''}
            reference={'digest':hashlib.sha256(original).hexdigest(),'metadata':metadata,'node_receipt':'b'*64}
            refs=pending/'references-v1';refs.mkdir();(refs/(name+'.reference')).write_text(json.dumps(reference))
            (pending/(name+'.json')).unlink()
            await context.complete({'last_checkpoint':{'seqno':18}})
            self.assertTrue(context.receipt['original_source_ack_recovered'])
            self.assertEqual(context.receipt['recovered_ack_kind'],'reference')

    async def test_changed_source_cannot_be_reopened(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));name,_=self.captured(context,node,pending)
            (pending/(name+'.json')).write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError,'changed before reopening'):context.environment()

    async def test_missing_recovered_ack_cannot_extend_original_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));self.captured(context,node,pending)
            context.deadline=time.monotonic()+.01
            with self.assertRaisesRegex(TimeoutError,'original recovery deadline'):
                await context.complete({'last_checkpoint':{'seqno':18}})

    async def test_conflicting_recovered_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));name,original=self.captured(context,node,pending)
            refs=pending/'references-v1';refs.mkdir();(refs/(name+'.reference')).write_text(json.dumps({
                'digest':'0'*64,'metadata':{**json.loads(original),'data':'','signature_set':''},'node_receipt':'b'*64}))
            with self.assertRaisesRegex(RuntimeError,'differs from the original'):await context.complete({'last_checkpoint':{'seqno':18}})

    async def test_native_marker_for_another_directory_is_not_a_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,node,pending=self.context(Path(tmp));marker=context.directory/'native-error.marker'
            marker.write_text('source sync-eio: /another/session/'+('a'*64)+'.ack.tmp\n')
            with self.assertRaisesRegex(RuntimeError,'different path'):context.capture_failure(marker,'native error')

    async def test_cleanup_disarms_the_owned_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            context,_,_=self.context(Path(tmp));(context.directory/'armed').write_text('owned')
            context.close();self.assertFalse((context.directory/'armed').exists())


class NativeFaultTests(unittest.TestCase):
    def test_native_fault_selects_current_directory_and_preserves_legacy_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);library=root/'fault.so'
            csource=Path(__file__).resolve().parents[2]/'rtos/src/tests/finality_source_fault.c'
            subprocess.run(['/usr/bin/clang-21','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',str(csource),'-o',str(library)],check=True,capture_output=True)
            probe=root/'probe.c';probe.write_text('#include <fcntl.h>\n#include <unistd.h>\n#include <errno.h>\nint main(int c,char**v){(void)c;int f=open(v[1],O_WRONLY|O_CREAT|O_TRUNC,0600);if(f<0)return 90;if(write(f,"payload",7)<0)return errno;return fsync(f)<0?errno:0;}\n')
            binary=root/'probe';subprocess.run(['/usr/bin/clang-21',str(probe),'-o',str(binary)],check=True,capture_output=True)
            selected=root/'current';selected.mkdir();other=root/'old';other.mkdir()
            control=root/'directory';control.write_text(str(selected)+'\n');arm=root/'armed';arm.write_text('armed')
            for mode,expected in [('sync-eio',5),('write-enospc',28)]:
                for selection in ['control','legacy-directory','legacy-file']:
                    marker=root/('marker-'+mode+'-'+selection);target=selected/(('a'*64)+'.ack.tmp')
                    env={k:v for k,v in os.environ.items() if k!='LD_PRELOAD' and not k.startswith('RTOS_TEST_SOURCE_FAULT_')}
                    env.update(LD_PRELOAD=str(library),RTOS_TEST_SOURCE_FAULT_MODE=mode,
                        RTOS_TEST_SOURCE_FAULT_ARM=str(arm),RTOS_TEST_SOURCE_FAULT_MARKER=str(marker))
                    key={'control':'RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE','legacy-directory':'RTOS_TEST_SOURCE_FAULT_DIRECTORY','legacy-file':'RTOS_TEST_SOURCE_FAULT_FILE'}[selection]
                    env[key]=str(control if selection=='control' else selected if selection=='legacy-directory' else target)
                    self.assertEqual(subprocess.run([str(binary),str(other/target.name)],env=env).returncode,0)
                    self.assertEqual(subprocess.run([str(binary),str(target)],env=env).returncode,expected)
                    self.assertEqual(marker.read_text().strip(),'source '+mode+': '+str(target))
                    self.assertEqual(target.stat().st_size>0,mode=='sync-eio')


if __name__ == '__main__':unittest.main()
