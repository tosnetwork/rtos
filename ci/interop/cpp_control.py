#!/usr/bin/env python3
"""Run the fixed C++ diagnostic control; this does not qualify a mixed network."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--snapshot', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--base-port', type=int, default=55300)
args = parser.parse_args()
snapshot = args.snapshot.resolve()
output = args.output.resolve()
assert not output.exists(), 'Use a fresh output directory'
manifest = json.loads((snapshot / 'manifest.json').read_text())
for artifact in manifest['binaries']:
    path = snapshot / 'build' / artifact['path']
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == artifact['sha256']
sys.path.insert(0, str(snapshot / 'source/test/tostester/src'))
from tostester.install import Install
from tostester.n6_cluster import run_cluster
from tostester.process_backend import LocalProcessBackend

started = time.time()
try:
    result = asyncio.run(run_cluster(
        Install(snapshot / 'build', snapshot / 'source'), output,
        LocalProcessBackend(), 4, args.base_port, False,
    ))
except BaseException as error:
    output.mkdir(parents=True, exist_ok=True)
    (output / 'driver-status.json').write_text(json.dumps({
        'status': 'failed', 'started_unix': started, 'finished_unix': time.time(),
        'error_type': type(error).__name__, 'error': str(error),
        'cpp_commit': manifest['cpp_source_commit'],
    }, indent=2) + '\n')
    raise
else:
    (output / 'driver-status.json').write_text(json.dumps({
        'status': 'passed_cpp_control_only', 'started_unix': started,
        'finished_unix': time.time(), 'cpp_commit': manifest['cpp_source_commit'],
        'mixed_network_qualified': False, 'result': result,
    }, indent=2, default=str) + '\n')
    print(json.dumps({'status': 'passed_cpp_control_only', 'output': str(output)}))
