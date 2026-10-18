#!/usr/bin/env python3
"""Exercise the real preload syscall boundary and all target discriminators."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

CHILD = r'''
import json, os
from pathlib import Path
root=Path(os.environ['RTOS_TEST_PUBLICATION_IO_CONTROL'])
body=root/'body'; body.write_bytes(b'actual block bytes')
other=root/'other'; other.write_bytes(b'unrelated bytes')
st=body.stat(); pid=os.getpid(); tid=pid; dev=st.st_dev; ino=st.st_ino
mode=os.environ['CASE']
path=str(body)
if mode=='pid': pid+=1
if mode=='tid': tid+=1
if mode=='device': dev+=1
if mode=='inode': ino+=1
if mode=='path': path=str(other)
(root/'target.native').write_text(f'{pid} {tid} {dev} {ino}\n{path}\n')
with other.open('rb') as stream: os.fsync(stream.fileno())
assert not (root/'native-error.marker').exists()
try:
 with body.open('rb') as stream:
  if os.environ['OP']=='fdatasync': os.fdatasync(stream.fileno())
  else: os.fsync(stream.fileno())
except OSError as error:
 result={'errno':error.errno,'pid':os.getpid()}
else: result={'errno':0,'pid':os.getpid()}
(root/'result.json').write_text(json.dumps(result))
'''

class PublicationIoNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='rtos-publication-native-')
        cls.library = Path(cls.temp.name) / 'fault.so'
        source = Path(__file__).resolve().parents[2] / 'rtos/src/tests/publication_io_fault.c'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        '-o', str(cls.library), str(source)], check=True, capture_output=True)
        cls.retain_library = Path(cls.temp.name) / 'retain.so'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        '-o', str(cls.retain_library), str(source.with_name('finality_retention_cut.c'))],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, case, operation='fsync'):
        with tempfile.TemporaryDirectory(dir=self.temp.name) as directory:
            root = Path(directory)
            process = subprocess.Popen([sys.executable, '-c', CHILD],
                env={**os.environ, 'LD_PRELOAD': str(self.library),
                     'RTOS_TEST_PUBLICATION_IO_CONTROL': str(root), 'CASE': case, 'OP': operation,
                     'RTOS_TEST_PUBLICATION_IO_RETURN_EIO':'1' if case=='return' else '0'},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                if case == 'exact':
                    while True:
                        self.assertIsNone(process.poll(), 'target exited without native stopped boundary')
                        state = Path('/proc', str(process.pid), 'status').read_text()
                        if (root/'native-error.marker').exists() and any(
                                line.startswith('State:') and line.split()[1]=='T' for line in state.splitlines()):
                            break
                        if time.monotonic() >= deadline: self.fail('no selected syscall stop')
                        time.sleep(.01)
                    marker = (root/'native-error.marker').read_text()
                    self.assertIn(f'pid={process.pid} tid={process.pid} syscall={operation} errno=5:', marker)
                    self.assertFalse((root/'result.json').exists(), 'callback ran before stopped boundary')
                    process.send_signal(signal.SIGCONT)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                self.assertEqual(json.loads((root/'result.json').read_text())['errno'], 5 if case in ('exact','return') else 0)
                self.assertEqual((root/'native-error.marker').exists(), case in ('exact','return'))
            finally:
                if process.poll() is None: process.kill()
                process.communicate()

    def two_stage(self, early_continue=False):
        with tempfile.TemporaryDirectory(dir=self.temp.name) as directory:
            root=Path(directory); pending=root/'pending'; pending.mkdir()
            temporary=pending/('a'*64+'.tmp'); canonical=temporary.with_suffix('.json')
            body=root/'body'; body.write_bytes(b'actual block')
            (root/'selected-directory').write_text(str(pending)+'\n')
            arm=root/'armed'; arm.write_text('armed')
            child = "import os; from pathlib import Path; p=Path(os.environ['TEMP_SOURCE']); f=p.open('wb'); f.write(b'complete source'); f.flush(); os.fsync(f.fileno()); f.close(); p.rename(p.with_suffix('.json')); b=Path(os.environ['BODY']).open('rb'); os.fsync(b.fileno())"
            process=subprocess.Popen([sys.executable,'-c',child],env={**os.environ,
                'LD_PRELOAD':str(self.library)+':'+str(self.retain_library),
                'RTOS_TEST_PUBLICATION_IO_CONTROL':str(root),
                'RTOS_TEST_RETAIN_CUT_DIRECTORY_FILE':str(root/'selected-directory'),
                'RTOS_TEST_RETAIN_CUT_ARM':str(arm),
                'RTOS_TEST_RETAIN_CUT_MARKER':str(root/'retain.marker'),
                'RTOS_TEST_RETAIN_CUT_RESUME_SYNCED':'1','RTOS_TEST_RETAIN_CUT_POINT':'after-fsync',
                'TEMP_SOURCE':str(temporary),'BODY':str(body)},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            def stopped_at(marker):
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    self.assertIsNone(process.poll())
                    state=Path('/proc',str(process.pid),'status').read_text()
                    if marker.exists() and any(line.startswith('State:') and line.split()[1]=='T' for line in state.splitlines()):return
                    time.sleep(.01)
                self.fail('missing native stopped boundary')
            try:
                stopped_at(root/'retain.marker')
                self.assertEqual(temporary.read_bytes(),b'complete source'); self.assertFalse(canonical.exists())
                if early_continue:
                    # Model the issuing thread reaching the arm check before
                    # the entire multithreaded process has entered group stop.
                    process.send_signal(signal.SIGCONT)
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:
                        state=Path('/proc',str(process.pid),'status').read_text()
                        if not any(line.startswith('State:') and line.split()[1]=='T' for line in state.splitlines()):break
                        time.sleep(.01)
                    self.assertFalse(canonical.exists(), 'armed retain advanced on an early continue')
                st=body.stat()
                (root/'target.native').write_text(f'{process.pid} {process.pid} {st.st_dev} {st.st_ino}\n{body}\n')
                arm.unlink(); process.send_signal(signal.SIGCONT)
                stopped_at(root/'native-error.marker')
                self.assertFalse(temporary.exists()); self.assertEqual(canonical.read_bytes(),b'complete source')
                self.assertIn(f'pid={process.pid} tid={process.pid}',(root/'native-error.marker').read_text())
                process.kill(); process.communicate(timeout=10); self.assertEqual(process.returncode,-9)
            finally:
                if process.poll() is None:process.kill()
                process.communicate()

    def test_two_stage_interposers_resume_complete_retain_then_stop_exact_body(self):self.two_stage()
    def test_resume_rechecks_disarm_after_early_continue(self):self.two_stage(early_continue=True)

    def test_node_mode_returns_real_eio_to_caller_without_native_stop(self): self.exercise('return')
    def test_exact_fsync_delivers_eio_only_after_resume(self): self.exercise('exact')
    def test_exact_fdatasync_delivers_eio_only_after_resume(self): self.exercise('exact', 'fdatasync')
    def test_other_process_not_selected(self): self.exercise('pid')
    def test_other_thread_not_selected(self): self.exercise('tid')
    def test_other_device_not_selected(self): self.exercise('device')
    def test_other_inode_not_selected(self): self.exercise('inode')
    def test_other_path_not_selected(self): self.exercise('path')

if __name__ == '__main__': unittest.main()
