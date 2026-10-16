#!/usr/bin/env python3
"""Require every active validator to create a block accepted by the mixed network."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def identity(block):
    return (int(block['workchain']), int(block['shard']), int(block['seqno']),
            block['root_hash'], block['file_hash'])


def rpc(url, method, params=None):
    body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params or {})).encode()
    request = urllib.request.Request(url, body, {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=3) as response:
        value = json.load(response)
    if 'error' in value:
        raise RuntimeError(str(value['error']))
    return value['result']


def reserve_port(kind, used):
    while True:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        if port not in used:
            used.add(port)
            return port


async def child_checked(command, log_path):
    with log_path.open('w') as log:
        process = await asyncio.create_subprocess_exec(*map(str, command), stdout=log, stderr=log)
        try:
            code = await asyncio.wait_for(process.wait(), 60)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    if code:
        raise RuntimeError(f'Program exited {code}; see {log_path}')


async def stop_rust(node):
    process = node['process']
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), 20)
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
    return process.returncode


async def run(args, root, snapshot, artifacts):
    sys.path.insert(0, str(snapshot / 'source/test/tostester/src'))
    from nacl.signing import SigningKey
    from tostester.install import Install
    from tostester.key import Key
    from tostester.network import Network, StartOptions

    tcp_used, udp_used = set(), set()
    network_dir = root / 'network'
    network_dir.mkdir()
    rust_nodes = []
    cpp_nodes = []
    endpoint_names, endpoints = [], []
    async with Network(Install(snapshot / 'build', snapshot / 'source'), network_dir,
                       base_port=args.base_port) as network:
        profile = json.loads(args.genesis_profile.read_text())
        network.config.shard_validators = profile['shard_validators']
        network.config.global_id = profile['global_id']
        network.config.global_version = profile['global_version']
        network.config.genesis_time = profile['genesis_time']
        network.config.genesis_wallet_seed = hashlib.sha256(profile['genesis_wallet_seed_label'].encode()).digest()
        network.config.bootstrap_validator_set_valid_for = profile['bootstrap_validator_set_valid_for']
        if profile['economics'] != 'cpp-local-test-default':
            raise RuntimeError('This fixture requires the explicitly declared local-test economics')
        for consensus in [network.config.mc_consensus, network.config.shard_consensus]:
            for key, value in profile['consensus'].items():
                if not hasattr(consensus, key):
                    raise RuntimeError(f'Unknown frozen consensus option: {key}')
                setattr(consensus, key, value)
        dht = network.create_dht_node()
        members = []
        for i in range(4):
            transport = Key(SigningKey(hashlib.sha256(f'n6-validator-transport-{i}'.encode()).digest()))
            node = network.create_full_node(validator_key=transport)
            node.make_initial_pq_validator(
                hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest(),
                hashlib.sha256(f'n6-validator-seed-{i}'.encode()).digest())
            node.announce_to(dht)
            members.append(node)
        generated = network._get_or_generate_zerostate().masterchain
        zero = dict(workchain=-1, shard=str(-(1 << 63)), seqno=0,
            root_hash=base64.b64encode(generated.root_hash).decode(),
            file_hash=base64.b64encode(generated.file_hash).decode())
        zero['@type'] = 'tosNode.blockIdExt'
        shard_genesis = network.zerostate.shardchain
        shard_zero = dict(workchain=0, shard=str(-(1 << 63)), seqno=0,
            root_hash=base64.b64encode(shard_genesis.root_hash).decode(),
            file_hash=base64.b64encode(shard_genesis.file_hash).decode())
        shard_zero['@type'] = 'tosNode.blockIdExt'
        write(root / 'genesis.json', dict(zerostate=zero, workchain_zerostate=shard_zero,
            profile_sha256=digest(args.genesis_profile), body_sha256=digest(generated.file)))
        if profile['expected_zerostate'] is not None and identity(zero) != identity(profile['expected_zerostate']):
            raise RuntimeError('Generated Genesis differs from the frozen full identity')
        if profile.get('expected_workchain_zerostate') is not None and identity(shard_zero) != identity(profile['expected_workchain_zerostate']):
            raise RuntimeError('Generated workchain Genesis differs from the frozen full identity')
        if args.prepare_genesis_only:
            return dict(status='genesis_prepared_only', zerostate=zero, active_validators_started=False)
        await dht.run(StartOptions(threads=1, verbosity=3))
        for i, node in enumerate(members[:args.cpp_count]):
            address = f'127.0.0.1:{reserve_port(socket.SOCK_STREAM, tcp_used)}'
            await node.run(StartOptions(threads=2, verbosity=3, args=['--json-rpc-address', address]))
            cpp_nodes.append(node)
            endpoint_names.append(f'cpp-{i}')
            endpoints.append('http://' + address + '/jsonRPC')
        global_config = members[0].directory / 'config.global.json'
        if identity(json.loads(global_config.read_text())['validator']['zero_state']) != identity(zero):
            raise RuntimeError('Generated C++ global configuration differs from the frozen Genesis')
        expected_creators = {
            base64.b64encode(hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest()).decode():
                ('cpp' if i < args.cpp_count else 'rust', i)
            for i in range(4)
        }
        try:
            for i in range(args.cpp_count, 4):
                directory = root / f'rust-{i}'
                directory.mkdir()
                (directory / 'zero').mkdir()
                for state in [network.zerostate.masterchain, network.zerostate.shardchain]:
                    shutil.copyfile(state.file, directory / 'zero' / (state.file_hash.hex() + '.boc'))
                shutil.copyfile(global_config, directory / 'global.json')
                address = f'127.0.0.1:{reserve_port(socket.SOCK_STREAM, tcp_used)}'
                config = dict(log_config_name='node-log.yml', ton_global_config_name='global.json',
                    internal_db_path=str(directory / 'node_db'),
                    ip_address=f'127.0.0.1:{reserve_port(socket.SOCK_DGRAM, udp_used)}',
                    ip_address_quic=f'127.0.0.1:{reserve_port(socket.SOCK_DGRAM, udp_used)}',
                    boot_from_zerostate=True, restore_db=True, archival_mode=None,
                    validation_countdown_mode='except-zerostate', json_rpc_server={'address': address})
                write(directory / 'default_config.json', config)
                (directory / 'node-log.yml').write_text(
                    "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\n"
                    "root:\n  level: info\n  appenders: [console]\n")
                await child_checked([args.validator_preparer, '--configs', directory,
                    '--global-config', directory / 'global.json', '--zerostate', directory / 'zero' /
                    (network.zerostate.masterchain.file_hash.hex() + '.boc'), '--member', i],
                    root / f'prepare-{i}.log')
                prepared = json.loads((directory / 'validator-prepared.json').read_text())
                if prepared['public_test_member'] != i or prepared['validator_id'] != hashlib.sha256(
                        f'n6-validator-id-{i}'.encode()).hexdigest():
                    raise RuntimeError('Prepared Rust identity differs from the reserved member')
                log = (directory / 'node.log').open('w')
                try:
                    process = await asyncio.create_subprocess_exec(str(args.rust_node), '--configs',
                        str(directory), '--zerostate', str(directory / 'zero'), '--initial-sync-disabled',
                        cwd=directory, stdout=log, stderr=log,
                        env={**os.environ, 'TOKIO_WORKER_THREADS': '2'}, start_new_session=True)
                finally:
                    log.close()
                rust_nodes.append(dict(index=i, directory=directory, process=process))
                endpoint_names.append(f'rust-{i}')
                endpoints.append('http://' + address + '/jsonRPC')
                write(root / 'processes.json', dict(cpp={node.name: node.process_id for node in cpp_nodes},
                    rust={str(node['index']): dict(pid=node['process'].pid,
                        start_ticks=Path(f"/proc/{node['process'].pid}/stat").read_text().split()[21])
                        for node in rust_nodes}))
            write(root / 'rpc-endpoints.json', dict(zip(endpoint_names, endpoints)))
            first_prepared = json.loads((rust_nodes[0]['directory'] / 'validator-prepared.json').read_text())
            master = next(s for s in first_prepared['sessions'] if s['masterchain'] and s['catchain_seqno'] == 0)
            weights = {m['validator_id']: m['weight'] for m in master['committee']}
            if len(weights) != 4 or set(weights) != {base64.b64decode(c).hex() for c in expected_creators}:
                raise RuntimeError('Authenticated committee differs from the four reserved identities')
            total = sum(weights.values())
            cpp_weight = sum(weights[hashlib.sha256(f'n6-validator-id-{i}'.encode()).hexdigest()]
                             for i in range(args.cpp_count))
            write(root / 'quorum.json', dict(total_weight=total, quorum_weight=total * 2 // 3 + 1,
                cpp_weight=cpp_weight, rust_weight=total - cpp_weight,
                cpp_alone_can_finalize=cpp_weight >= total * 2 // 3 + 1))
            observations = [{} for _ in endpoints]
            checked_keys, creators = set(), {}
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                for node in rust_nodes:
                    if node['process'].returncode is not None:
                        raise RuntimeError(f"Rust {node['index']} exited {node['process'].returncode}")
                replies = await asyncio.gather(*(asyncio.to_thread(rpc, url, 'getMasterchainInfo')
                    for url in endpoints), return_exceptions=True)
                for n, reply in enumerate(replies):
                    if isinstance(reply, BaseException):
                        continue
                    if identity(reply['init']) != identity(zero):
                        raise RuntimeError(f'RPC network identity mismatch: {endpoint_names[n]}')
                    observations[n][identity(reply['last'])] = reply
                    if len(observations[n]) > 512:
                        del observations[n][next(iter(observations[n]))]
                common = set.intersection(*(set(items) for items in observations))
                common = sorted((key for key in common if key[2] >= args.min_height and key not in checked_keys),
                                key=lambda key: key[2], reverse=True)
                write(root / 'status.json', dict(status='waiting_for_all_creators',
                    heights={name: (reply['last']['seqno'] if not isinstance(reply, BaseException) else None)
                             for name, reply in zip(endpoint_names, replies)},
                    creators=list(creators), common_checkpoints=len(common)))
                for key in common:
                    infos = [items[key] for items in observations]
                    if any(info['state_root_hash'] != infos[0]['state_root_hash'] for info in infos):
                        raise RuntimeError(f'Applied state roots differ at MC{key[2]}')
                    directory = root / 'checks' / str(key[2])
                    directory.mkdir(parents=True)
                    block = await asyncio.to_thread(rpc, endpoints[args.cpp_count], 'getBlock',
                        {k: infos[0]['last'][k] for k in ['workchain', 'shard', 'seqno', 'root_hash', 'file_hash']})
                    write(directory / 'sample.json', dict(zerostate=zero, reference=infos[0],
                        references=dict(zip(endpoint_names, infos)), rust=infos[args.cpp_count], block=block))
                    await child_checked([args.block_checker, directory / 'sample.json',
                        directory / 'checked.json'], directory / 'checker.log')
                    checked = json.loads((directory / 'checked.json').read_text())
                    checked_keys.add(key)
                    creator = checked['created_by']
                    if creator not in expected_creators:
                        raise RuntimeError('Accepted block has an unexpected creator')
                    language, member = expected_creators[creator]
                    evidence = dict(member=member, language=language, block_check=checked,
                        sample_directory=str(directory))
                    if language == 'rust':
                        node = next(node for node in rust_nodes if node['index'] == member)
                        text = (node['directory'] / 'node.log').read_text(errors='replace')
                        pattern = (r'^\(-1:8000000000000000, ' + str(key[2]) +
                            r'\): ValidatorGroup::on_generate_slot: .*Collation successful$')
                        match = re.search(pattern, text, re.M)
                        if not match:
                            continue
                        evidence['local_collation'] = match.group(0)
                    creators.setdefault(creator, evidence)
                    write(root / 'creators.json', creators)
                    if set(creators) == set(expected_creators):
                        for path, expected in artifacts.items():
                            if digest(Path(path)) != expected:
                                raise RuntimeError('An executable changed during matrix validation')
                        return dict(status='all_four_creators_accepted_with_matching_states',
                            cpp_count=args.cpp_count, rust_count=4 - args.cpp_count,
                            creators=creators, common_state_checkpoints=len(checked_keys),
                            mixed_validator_qualified=False)
                await asyncio.sleep(0.1)
            raise TimeoutError(f'Not all four creators were accepted within {args.timeout} seconds')
        finally:
            codes = await asyncio.gather(*(stop_rust(node) for node in rust_nodes), return_exceptions=True)
            write(root / 'rust-shutdown.json', {str(node['index']):
                (str(code) if isinstance(code, BaseException) else code) for node, code in zip(rust_nodes, codes)})
            if any(code != 0 for code in codes):
                raise RuntimeError('At least one owned Rust process did not shut down normally')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--rust-node', type=Path, required=True)
    parser.add_argument('--validator-preparer', type=Path, required=True)
    parser.add_argument('--block-checker', type=Path, required=True)
    parser.add_argument('--rust-revision', required=True)
    parser.add_argument('--cpp-count', type=int, choices=[1, 2, 3], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-port', type=int, default=55700)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--min-height', type=int, default=1)
    parser.add_argument('--genesis-profile', type=Path,
                        default=Path(__file__).with_name('testnet-v16.json'))
    parser.add_argument('--prepare-genesis-only', action='store_true')
    args = parser.parse_args()
    args.snapshot = args.snapshot.resolve()
    for name in ['rust_node', 'validator_preparer', 'block_checker']:
        setattr(args, name, getattr(args, name).resolve())
    manifest = json.loads((args.snapshot / 'manifest.json').read_text())
    args.genesis_profile = args.genesis_profile.resolve()
    profile = json.loads(args.genesis_profile.read_text())
    if profile['schema'] != 1 or profile['cpp_revision'] != manifest['cpp_source_commit']:
        raise SystemExit('Frozen Genesis profile does not match this baseline')
    if manifest['cpp_source_commit'] != '8f083dc06bff16705710a01de15eb3123d5d696b':
        raise SystemExit('Matrix requires the frozen C++ 8f083dc baseline')
    banner = subprocess.run([str(args.rust_node), '--help'], capture_output=True, text=True, check=True)
    if args.rust_revision not in banner.stdout + banner.stderr:
        raise SystemExit('Rust executable does not report the pinned source revision')
    artifacts = {str(path): digest(path) for path in [args.rust_node, args.validator_preparer, args.block_checker]}
    for item in manifest['binaries']:
        path = args.snapshot / 'build' / item['path']
        if digest(path) != item['sha256']:
            raise SystemExit(f'C++ snapshot executable changed: {path}')
        artifacts[str(path)] = item['sha256']
    artifacts[str(args.genesis_profile)] = digest(args.genesis_profile)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    write(root / 'source.json', dict(cpp_snapshot=manifest, rust_revision=args.rust_revision,
        artifacts=artifacts, driver_sha256=digest(Path(__file__)), command=sys.argv,
        genesis_profile=profile, genesis_profile_sha256=digest(args.genesis_profile)))
    try:
        result = asyncio.run(run(args, root, args.snapshot, artifacts))
    except BaseException as error:
        write(root / 'result.json', dict(status='failed', error_type=type(error).__name__, error=str(error)))
        raise
    else:
        write(root / 'result.json', result)


if __name__ == '__main__':
    main()
