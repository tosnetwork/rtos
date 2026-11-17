"""Exercise the actual LD_PRELOAD deletion boundary, without a validator."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CONTROL = r"""
import errno,os,tempfile,json
from pathlib import Path
r=Path(os.environ['RTOS_TEST_INTENT_CLEANUP_CONTROL']);r.mkdir()
outputs=r/'namespace/finality-intents/outputs-v1';outputs.mkdir(parents=True)
stem='12-'+'ab'*32
pending=outputs.parent/(stem+'.json');pending.write_bytes(b'original intent')
p=outputs/(stem+'.outputs');p.write_bytes(b'complete outputs')
selector=r/'selector'
selector.write_text(f'{os.getpid()+1}\n{outputs}\n')
p.unlink();assert not p.exists();p.write_bytes(b'complete outputs')
selector.write_text(f'{os.getpid()}\n{outputs}\n')
for i in range(3):
 try:p.unlink()
 except OSError as e:assert e.errno==errno.EIO
 else:raise AssertionError('fault did not return EIO')
 assert p.read_bytes()==b'complete outputs' and pending.read_bytes()==b'original intent'
assert (r/'original.outputs').read_bytes()==p.read_bytes()
assert (r/'original.json').read_bytes()==pending.read_bytes()
link=outputs/'alias';link.symlink_to(p);link.unlink();assert p.exists()
for name in ['13-'+'ab'*32+'.outputs','12-invalid.outputs','plain-file']:
 q=outputs/name;q.write_text('unrelated');q.unlink();assert not q.exists()
selector.unlink();p.unlink();assert not p.exists()
print(json.dumps({'passed':True,'repeated_eio':3,'wrong_pid_passthrough':True,'unrelated_passthrough':3,'disarmed_passthrough':True,'copies_equal':True,'captured':(r/'captured').read_text().splitlines()}))
"""


@unittest.skipUnless(
    sys.platform == "linux" and shutil.which("cc"), "Linux C interposer"
)
class IntentCleanupFaultTests(unittest.TestCase):
    def test_exact_target_eio_and_passthrough(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "rtos/src/tests/intent_cleanup_fault.c"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / "cleanup.so"
            subprocess.run(
                [
                    "cc",
                    "-shared",
                    "-fPIC",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pthread",
                    str(source),
                    "-o",
                    str(library),
                    "-ldl",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            run = subprocess.run(
                [sys.executable, "-c", CONTROL],
                env={
                    **os.environ,
                    "LD_PRELOAD": str(library),
                    "RTOS_TEST_INTENT_CLEANUP_CONTROL": str(root / "evidence"),
                },
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            result = json.loads(run.stdout)
            self.assertTrue(result["passed"])
            self.assertEqual(result["repeated_eio"], 3)
            self.assertTrue(result["copies_equal"])
            self.assertTrue(result["wrong_pid_passthrough"])
            self.assertEqual(result["unrelated_passthrough"], 3)
            self.assertTrue(result["disarmed_passthrough"])
            environment = dict(os.environ)
            environment.pop("LD_PRELOAD", None)
            environment["RTOS_TEST_INTENT_CLEANUP_CONTROL"] = str(root / "negative")
            negative = subprocess.run(
                [sys.executable, "-c", CONTROL],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(negative.returncode, 0)
            self.assertIn("fault did not return EIO", negative.stderr)


if __name__ == "__main__":
    unittest.main()
