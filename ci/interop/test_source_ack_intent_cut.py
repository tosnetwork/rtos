#!/usr/bin/env python3
"""Actual owned subprocess stops after a successful intent sync, before return."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


class IntentCutNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        root = Path(cls.workspace.name)
        cls.library = root / 'fault.so'
        source = Path(__file__).resolve().parents[2] / 'rtos/src/tests/finality_source_fault.c'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
            '-o', str(cls.library), str(source)], check=True, capture_output=True)
        helper = root / 'probe.c'
        helper.write_text(r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 5) return 20;
    int ack = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (ack < 0 || write(ack, "ack", 3) != 3) return 21;
    if (fsync(ack) != -1 || errno != EIO) return 22;
    close(ack);
    if (!strcmp(argv[3], "arm")) {
        int arm = open(getenv("RTOS_TEST_SOURCE_INTENT_ARM"), O_WRONLY|O_CREAT, 0600);
        if (arm < 0 || write(arm, "1", 1) != 1 || close(arm)) return 23;
    }
    int intent = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0600);
    const char *body = "{\"complete_test_write\":true}";
    if (intent < 0 || write(intent, body, strlen(body)) != (ssize_t)strlen(body)) return 24;
    int result = !strcmp(argv[4], "fsync") ? fsync(intent) : fdatasync(intent);
    if (result || close(intent)) return 25;
    puts("sync returned");
    return 0;
}
''')
        cls.probe = root / 'probe'
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-o', str(cls.probe), str(helper)],
            check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def invoke(self, mode='fsync', negative=None, point='after-fsync'):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); namespace = root / 'owned'; pending = namespace / 'finality-pending'
            pending.mkdir(parents=True); intents = namespace / 'finality-intents'; intents.mkdir()
            name = '104-' + 'a' * 64 + '.tmp'; target = intents / name
            if negative == 'other_namespace':
                target = root / 'other/finality-intents' / name; target.parent.mkdir(parents=True)
            if negative == 'completed':
                target = intents / 'completed-v1' / name; target.parent.mkdir()
            if negative == 'wrong_name': target = intents / ('104-' + 'a' * 64 + '.ack.tmp')
            if negative == 'leading_zero': target = intents / ('0104-' + 'a' * 64 + '.tmp')
            if negative == 'out_of_range': target = intents / ('4294967296-' + 'a' * 64 + '.tmp')
            selector = root / 'selected-directory'; selector.write_text(str(pending) + '\n')
            if negative == 'selector_symlink':
                link = root / 'selector-link'; link.symlink_to(selector); selector = link
            ack = pending / ('b' * 64 + '.ack.tmp'); arm = root / 'armed'; arm.write_text('1')
            marker = root / 'intent-stop.marker'
            env = {**os.environ, 'LD_PRELOAD': str(self.library),
                'RTOS_TEST_SOURCE_FAULT_FILE': str(ack), 'RTOS_TEST_SOURCE_FAULT_MODE': 'sync-eio',
                'RTOS_TEST_SOURCE_FAULT_ARM': str(arm), 'RTOS_TEST_SOURCE_FAULT_MARKER': str(root / 'ack-error.marker'),
                'RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE': str(selector),
                'RTOS_TEST_SOURCE_INTENT_ARM': str(root / 'intent-armed'),
                'RTOS_TEST_SOURCE_INTENT_MARKER': str(marker),
                'RTOS_TEST_SOURCE_INTENT_POINT': point,
                'RTOS_TEST_SOURCE_INTENT_INTENDED': str(root / 'intended.json')}
            child = subprocess.Popen([str(self.probe), str(target), str(ack),
                'no-arm' if negative == 'missing_arm' else 'arm', mode], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                if negative:
                    stdout, stderr = child.communicate(timeout=3)
                    self.assertEqual(child.returncode, 0, stderr)
                    self.assertEqual(stdout, b'sync returned\n')
                    self.assertFalse(marker.exists())
                else:
                    deadline = time.monotonic() + 3
                    status = ''
                    while time.monotonic() < deadline and child.poll() is None:
                        status = Path(f'/proc/{child.pid}/status').read_text()
                        if marker.exists() and any(l.startswith('State:') and l.split()[1] == 'T' for l in status.splitlines()):
                            break
                        time.sleep(.01)
                    self.assertTrue(marker.exists())
                    self.assertTrue(any(l.startswith('State:') and l.split()[1] == 'T' for l in status.splitlines()))
                    self.assertEqual(marker.read_text(), f'intent {point} pid={child.pid}: {target}\n')
                    expected = b'{"complete_test_write":true}'
                    actual = expected if point == 'after-fsync' else expected[:0 if point == 'before-write' else len(expected)//2]
                    self.assertEqual(target.read_bytes(), actual)
                    if point != 'after-fsync':self.assertEqual((root / 'intended.json').read_bytes(), expected)
                    self.assertFalse(target.with_suffix('.json').exists())
                    child.kill(); stdout, stderr = child.communicate(timeout=3)
                    self.assertEqual(child.returncode, -9, stderr)
                    self.assertEqual(stdout, b'', 'selected sync must not have returned')
            finally:
                if child.poll() is None:child.kill()
                child.communicate(timeout=3)

    def test_actual_fsync_and_fdatasync_stop_before_return(self):
        for point in ['after-fsync', 'before-write', 'after-partial-write']:
            for mode in ['fsync', 'fdatasync']:
                with self.subTest(mode=mode, point=point):self.invoke(mode, point=point)

    def test_exact_scope_and_arm_counterexamples(self):
        for negative in ['other_namespace', 'completed', 'wrong_name', 'leading_zero',
                'out_of_range', 'selector_symlink', 'missing_arm']:
            with self.subTest(negative=negative):self.invoke(negative=negative)


if __name__ == '__main__':unittest.main()
