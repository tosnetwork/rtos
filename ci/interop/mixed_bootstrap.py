#!/usr/bin/env python3
"""Observe public Rust synchronization against three C++ test validators."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--snapshot', type=Path, required=True)
parser.add_argument('--rust-node', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--base-port', type=int, default=55400)
args = parser.parse_args()
snapshot = args.snapshot.resolve()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=False)
manifest = json.loads((snapshot / 'manifest.json').read_text())
with args.rust_node.open('rb') as stream:
    rust_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
(root / 'source.json').write_text(json.dumps(dict(
    cpp_snapshot=manifest, rust_binary=str(args.rust_node.resolve()),
    rust_binary_sha256=rust_sha256, driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    command=sys.argv, initial_rust_signing=False,
), indent=2) + '\n')
for item in manifest['binaries']:
    with (snapshot / 'build' / item['path']).open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == item['sha256']
sys.path.insert(0, str(snapshot / 'source/test/tostester/src'))
from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.n6_cluster import require_agreed_masterchain_block


async def main():
    network_dir = root / 'network'
    network_dir.mkdir()
    async with Network(Install(snapshot / 'build', snapshot / 'source'),
                       network_dir, base_port=args.base_port) as network:
        network.config.shard_validators = 4
        dht = network.create_dht_node()
        members = []
        for i in range(4):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest(),
                hashlib.sha256(f'n6-validator-seed-{i}'.encode()).digest(),
            )
            node.announce_to(dht)
            members.append(node)
        await dht.run(StartOptions(threads=1, verbosity=3))
        # The fourth test identity is reserved for the Rust validator. Its C++
        # process never starts; this first stage measures public synchronization.
        for node in members[:3]:
            await node.run(StartOptions(threads=2, verbosity=3))
        rust = root / 'rust'
        rust.mkdir()
        zero_dir = rust / 'zero'
        zero_dir.mkdir()
        for state in [network.zerostate.masterchain, network.zerostate.shardchain]:
            shutil.copyfile(state.file, zero_dir / (state.file_hash.hex() + '.boc'))
        global_config = members[0].directory / 'config.global.json'
        shutil.copyfile(global_config, rust / 'global.json')
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        default = dict(log_config_name='node-log.yml', ton_global_config_name='global.json',
                       internal_db_path=str(rust / 'node_db'),
                       ip_address='127.0.0.1:' + str(sockets[0].getsockname()[1]),
                       ip_address_quic='127.0.0.1:' + str(sockets[1].getsockname()[1]),
                       boot_from_zerostate=True, restore_db=True, archival_mode=None)
        (rust / 'default_config.json').write_text(json.dumps(default))
        for sock in sockets:
            sock.close()
        (rust / 'node-log.yml').write_text(
            "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\n"
            "root:\n  level: info\n  appenders: [console]\n")
        with (rust / 'node.log').open('w') as log:
            process = await asyncio.create_subprocess_exec(
                str(args.rust_node.resolve()), '--configs', str(rust), '--zerostate', str(zero_dir),
                '--initial-sync-disabled', cwd=rust, stdout=log, stderr=log,
                env={**os.environ, 'TOKIO_WORKER_THREADS': '2'},
                start_new_session=True,
            )
            (root / 'process.json').write_text(json.dumps(dict(rust_pid=process.pid)))
            try:
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    text = (rust / 'node.log').read_text(errors='replace')
                    heights = [int(x) for x in re.findall(r'^Processing masterblock (\d+)$', text, re.M)]
                    if heights and max(heights) >= 4:
                        clients = {node.name: await node.toslib_client() for node in members[:3]}
                        common = await require_agreed_masterchain_block(clients, 4)
                        return dict(status='rust_public_sync_observed', rust_height=max(heights),
                                    cpp_common_block_at_4=common, active_rust_signing=False,
                                    mixed_validator_qualified=False)
                    if process.returncode is not None:
                        raise RuntimeError(f'Rust node exited {process.returncode}; see rust/node.log')
                    await asyncio.sleep(0.5)
                raise TimeoutError('Rust did not apply MC4 from the C++ quorum within 90 seconds')
            finally:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 5)
                    except TimeoutError:
                        process.kill()
                        await process.wait()


try:
    result = asyncio.run(main())
except BaseException as error:
    (root / 'result.json').write_text(json.dumps(dict(status='failed', error_type=type(error).__name__,
        error=str(error), cpp_commit=manifest['cpp_source_commit']), indent=2) + '\n')
    raise
else:
    result['cpp_commit'] = manifest['cpp_source_commit']
    (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
