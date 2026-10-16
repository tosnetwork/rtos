#!/usr/bin/env python3
"""Freeze the C++ programs and test sources used by a local interop run."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cpp-source', type=Path, required=True)
parser.add_argument('--cpp-build', type=Path, required=True)
parser.add_argument('--revision', required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
repo, build, root = args.cpp_source.resolve(), args.cpp_build.resolve(), args.output.resolve()


def git(*arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments], text=True).strip()


revision = git('rev-parse', args.revision + '^{commit}')
if git('rev-parse', 'HEAD') != revision or git('status', '--porcelain'):
    raise SystemExit('The C++ source must be clean and checked out at the requested revision')
version = subprocess.check_output([str(build / 'validator-engine/validator-engine'), '--version'],
                                  text=True, stderr=subprocess.STDOUT)
if revision not in version:
    raise SystemExit('The C++ executable does not report the requested source revision')
root.mkdir(parents=True, exist_ok=False)
source = root / 'source'
source.mkdir()
paths = ['crypto/fift/lib', 'crypto/smartcont', 'test/tostester',
         'test/pq-native/fixtures/N6-ACCEPTANCE-CRITERIA.json',
         'test/pq-native/n6-scale-profiles/no-simulated-latency.json',
         'lite-client/ext-client.cpp', 'lite-client/lite-client.cpp']
proc = subprocess.Popen(['git', '-C', str(repo), 'archive', revision, *paths], stdout=subprocess.PIPE)
with tarfile.open(fileobj=proc.stdout, mode='r|') as archive:
    archive.extractall(source, filter='data')
if proc.wait() != 0:
    raise SystemExit('C++ test-source export failed')
# The existing control runner reads HEAD. Keep that reference detached from
# moving branches; object storage is shared with the input checkout.
subprocess.run(['git', 'init', '--quiet', str(source)], check=True)
common = git('rev-parse', '--path-format=absolute', '--git-common-dir')
(source / '.git/objects/info/alternates').write_text(common + '/objects\n')
subprocess.run(['git', '-C', str(source), 'update-ref', '--no-deref', 'HEAD', revision], check=True)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


files = ['validator-engine/validator-engine', 'crypto/create-state',
         'crypto/pq/tos-pq-consensus-key', 'utils/generate-random-id',
         'dht-server/dht-server', 'validator-engine-console/validator-engine-console',
         'lite-client/lite-client', 'toslib/libtoslibjson.so']
artifacts = []
for relative in files:
    original, copy = build / relative, root / 'build' / relative
    before = digest(original)
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, copy)
    if digest(copy) != before or digest(original) != before:
        raise SystemExit('A C++ program changed while copying: ' + relative)
    artifacts.append(dict(path=relative, bytes=copy.stat().st_size, sha256=before))
shutil.copytree(build / 'crypto/smartcont', root / 'build/crypto/smartcont')
if git('rev-parse', 'HEAD') != revision or git('status', '--porcelain'):
    raise SystemExit('The C++ source changed while creating the snapshot')
(root / 'manifest.json').write_text(json.dumps(dict(cpp_source_commit=revision,
    source_clean=True, source_paths=paths, binaries=artifacts, version=version), indent=2) + '\n')
print(json.dumps(dict(snapshot=str(root), cpp_commit=revision)))
