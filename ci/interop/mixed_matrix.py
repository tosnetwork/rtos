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
import urllib.error
from quorum_profile import quorum_threshold, matrix_committee_size, check_committee_weights


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
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        # Preserve the node's reason and exact requested height. A bare HTTP
        # status cannot distinguish unavailable proof data from invalid data.
        with error:
            raw = error.read(64 * 1024 + 1)
        detail = raw[:64 * 1024].decode('utf-8', errors='replace')
        if len(raw) > 64 * 1024:
            detail += ' [response truncated]'
        raise RuntimeError(f'RPC {method} params={params or {}} HTTP {error.code}: {detail}') from error
    if 'error' in value:
        raise RuntimeError(f'RPC {method} params={params or {}}: {value["error"]}')
    return value['result']


def reserve_port(kind, used):
    # Stay below the kernel's automatic client-port pool. Closing an ephemeral
    # reservation before offline preparation lets unrelated outgoing traffic
    # claim it before the validator's listener starts.
    ephemeral_low = int(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[0])
    for port in range(20000, min(ephemeral_low, 32768)):
        if port in used:
            continue
        try:
            # ADNL uses its UDP port for a TCP listener too. Check both
            # transports and share one reservation set across all listeners.
            for probe_kind in [kind, socket.SOCK_STREAM if kind == socket.SOCK_DGRAM else socket.SOCK_DGRAM]:
                with socket.socket(socket.AF_INET, probe_kind) as sock:
                    sock.bind(('0.0.0.0', port))
        except OSError:
            continue
        used.add(port)
        return port
    raise RuntimeError('No free fixture listener port below the automatic client-port pool')


async def child_checked(command, log_path, cwd=None):
    with log_path.open('w') as log:
        process = await asyncio.create_subprocess_exec(*map(str, command), stdout=log, stderr=log, cwd=cwd)
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


def block_text(block_id):
    return (f"({block_id['workchain']},{int(block_id['shard']) & ((1 << 64) - 1):016x},"
            f"{block_id['seqno']}):{base64.b64decode(block_id['root_hash']).hex()}:"
            f"{base64.b64decode(block_id['file_hash']).hex()}")


async def cpp_block(snapshot, node, block_id, directory):
    """Read native bytes without adding a Rust participant to the C++ control."""
    config = directory / 'lite-client.json'
    config.write_text(node.liteserver_config.to_json())
    data = directory / 'lite-data'
    data.mkdir()
    await child_checked([snapshot / 'build/lite-client/lite-client', '-C', config,
        '-r', '-D', data, '-t', '15', '-c', 'getblock ' + block_text(block_id)], directory / 'lite-client.log')
    expected = base64.b64decode(block_id['file_hash']).hex()
    matches = [p for p in data.rglob('*') if p.is_file() and digest(p) == expected]
    if len(matches) != 1:
        raise RuntimeError('Native LiteServer did not retain exactly one matching block body')
    return dict(id=block_id, boc=base64.b64encode(matches[0].read_bytes()).decode())


async def cpp_certificate(snapshot, node, zero, target, directory):
    config = directory / 'proof-client.json'
    config.write_text(node.liteserver_config.to_json())
    command = 'saveblkproofchain finality ' + block_text(zero) + ' ' + block_text(target)
    await child_checked([snapshot / 'build/lite-client/lite-client', '-C', config, '-r',
        '-t', '20', '-c', command], directory / 'proof-client.log', cwd=directory)
    return retained_cpp_certificate(directory, target)


def retained_cpp_certificate(directory, target):
    # The native client can return exit 0 after logging capture rejection.
    # Its exact-target completion receipt is mandatory; partial raw responses
    # alone do not mean that the requested proof was exported successfully.
    responses = sorted(directory.glob('finality-*.response.tl'))
    if not responses:
        raise RuntimeError('Native C++ LiteServer did not export finality proof responses')
    complete = directory / 'finality.complete'
    expected = f'Z01_CHAIN_CAPTURE_OK segments={len(responses)} target={block_text(target)}'
    if not complete.is_file() or complete.read_text().strip().upper() != expected.upper() \
            or {p.name for p in responses} != {f'finality-{i}.response.tl' for i in range(len(responses))}:
        raise RuntimeError('Native C++ finality capture lacks an exact-target completion receipt')
    return dict(kind='cpp_lite', name='cpp-0',
        capture_receipt=complete.read_text().strip(),
        responses=[base64.b64encode(path.read_bytes()).decode() for path in responses])


class NativeStateNotReady(RuntimeError):
    """The native peer explicitly reported local state/dependencies unavailable."""


def native_state_not_ready(log):
    clean = re.sub(r'\x1b\[[0-9;]*m', '', log)
    errors = re.findall(r'liteserver error: \[Error : (-?\d+) : ([^\r\n]+)', clean)
    def known(code, message):
        # Pinned C++ common/errorcode.h: notready=651. The existing Rust
        # ancestor-restoration miss currently has the narrower legacy 500 form.
        return int(code) == 651 or (int(code) == 500 and (
            message.startswith('LITE_SERVER_NOTREADY:') or
            message.startswith('LITE_SERVER_UNKNOWN: Cannot load handle for (')))
    return bool(errors) and all(known(code, message) for code, message in errors)


async def native_state(snapshot, config, name, block_id, directory):
    """Use the same pinned native client for C++ and Rust full-state responses."""
    directory.mkdir()
    config_path = directory / 'lite-client.json'
    config_path.write_text(config.to_json())
    data = directory / 'data'
    data.mkdir()
    try:
        await child_checked([snapshot / 'build/lite-client/lite-client', '-C', config_path,
            '-r', '-D', data, '-t', '15', '-c', 'getstate ' + block_text(block_id)],
            directory / 'client.log')
    except RuntimeError as error:
        if str(error).startswith('Program exited 1; see ') and (directory / 'client.log').is_file() and native_state_not_ready((directory / 'client.log').read_text()):
            raise NativeStateNotReady(str(error)) from error
        raise
    # The native client also saves its startup masterchain block. Select the
    # state receipt for the requested full identity instead of counting files.
    log = re.sub(r'\x1b\[[0-9;]*m', '', (directory / 'client.log').read_text())
    receipts = re.findall(r'obtained (\d+) state bytes for block ' + re.escape(block_text(block_id))
        + r'.*?(\d+) bytes saved into file ([^\r\n]+)', log, re.I | re.S)
    if len(receipts) != 1:
        raise RuntimeError(f'{name} did not retain exactly one requested native full-state receipt')
    obtained, saved, filename = receipts[0]
    body = Path(filename)
    if not body.resolve().is_relative_to(data.resolve()) or obtained != saved \
            or body.stat().st_size != int(saved) or digest(body).upper() != body.stem.upper():
        raise RuntimeError(f'{name} native full-state receipt does not match its saved body')
    return dict(name=name, id=block_id, file_hash=base64.b64encode(
        bytes.fromhex(digest(body))).decode(), boc=base64.b64encode(body.read_bytes()).decode())


async def prepare_rust(args, directory, i, network, global_config, tcp_used, udp_used):
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
    if args.verify_workchain or args.verify_certificates:
        config['lite_server_port'] = reserve_port(socket.SOCK_STREAM, tcp_used)
    write(directory / 'default_config.json', config)
    (directory / 'node-log.yml').write_text(
        "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\n"
        "root:\n  level: info\n  appenders: [console]\n")
    command = [args.validator_preparer, '--configs', directory,
        '--global-config', directory / 'global.json', '--zerostate', directory / 'zero' /
        (network.zerostate.masterchain.file_hash.hex() + '.boc'), '--member', i]
    if getattr(args, 'include_genesis_successor', False):
        command.append('--include-genesis-successor')
    await child_checked(command, directory.parent / f'prepare-{directory.name}.log')
    prepared = json.loads((directory / 'validator-prepared.json').read_text())
    if prepared['public_test_member'] != i or prepared['validator_id'] != hashlib.sha256(
            f'n6-validator-id-{i}'.encode()).hexdigest():
        raise RuntimeError('Prepared Rust identity differs from the reserved member')
    return address, prepared


async def run(args, root, snapshot, artifacts):
    sys.path.insert(0, str(snapshot / 'source/test/tostester/src'))
    from nacl.signing import SigningKey
    from tostester.install import Install
    from tostester.key import Key
    from tostester.network import Network, StartOptions, _write_model
    from tosapi import tos_api

    tcp_used = udp_used = set()
    network_dir = root / 'network'
    network_dir.mkdir()
    rust_nodes = []
    cpp_nodes = []
    endpoint_names, endpoints = [], []
    lite_configs = []
    async with Network(Install(snapshot / 'build', snapshot / 'source'), network_dir,
                       base_port=args.base_port) as network:
        profile = json.loads(args.genesis_profile.read_text())
        member_count = matrix_committee_size(profile, args.cpp_count)
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
        for i in range(member_count):
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
        write(root / 'frozen-profile.json', {**profile, 'expected_zerostate': zero,
            'expected_workchain_zerostate': shard_zero})
        if args.prepare_genesis_only:
            return dict(status='genesis_prepared_only', zerostate=zero, active_validators_started=False)
        await dht.run(StartOptions(threads=1, verbosity=3))
        for i, node in enumerate(members[:args.cpp_count]):
            address = f'127.0.0.1:{reserve_port(socket.SOCK_STREAM, tcp_used)}'
            await node.run(StartOptions(threads=2, verbosity=3, args=['--json-rpc-address', address]))
            cpp_nodes.append(node)
            endpoint_names.append(f'cpp-{i}')
            endpoints.append('http://' + address + '/jsonRPC')
            lite_configs.append(node.liteserver_config)
        global_config = root / 'config.global.json'
        _write_model(global_config, tos_api.Config_global(
            dht=tos_api.Dht_config_global(static_nodes=tos_api.Dht_nodes(nodes=[dht.signed_address]), k=3, a=3),
            validator=network.zerostate.as_validator_config()))
        if identity(json.loads(global_config.read_text())['validator']['zero_state']) != identity(zero):
            raise RuntimeError('Generated C++ global configuration differs from the frozen Genesis')
        expected_creators = {
            base64.b64encode(hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest()).decode():
                ('cpp' if i < args.cpp_count else 'rust', i)
            for i in range(member_count)
        }
        try:
            for i in range(args.cpp_count, member_count):
                directory = root / f'rust-{i}'
                address, prepared = await prepare_rust(args, directory, i, network, global_config, tcp_used, udp_used)
                log = (directory / 'node.log').open('w')
                try:
                    process = await asyncio.create_subprocess_exec(str(args.rust_node), '--configs',
                        str(directory), '--zerostate', str(directory / 'zero'), '--initial-sync-disabled',
                        cwd=directory, stdout=log, stderr=log,
                        env={**os.environ, 'TOKIO_WORKER_THREADS': '2'}, start_new_session=True)
                finally:
                    log.close()
                try:
                    start_ticks = Path(f'/proc/{process.pid}/stat').read_text().split()[21]
                except FileNotFoundError:
                    await process.wait()
                    raise RuntimeError(f'Rust {i} exited {process.returncode} during startup; see its node.log')
                rust_nodes.append(dict(index=i, directory=directory, process=process, start_ticks=start_ticks))
                endpoint_names.append(f'rust-{i}')
                endpoints.append('http://' + address + '/jsonRPC')
                if args.verify_workchain or args.verify_certificates:
                    client = json.loads((directory / 'lite_client_config.json').read_text())
                    lite_configs.append(tos_api.Liteclient_config_global(
                        liteservers=[tos_api.Liteserver_desc(id=tos_api.Pub_ed25519(
                            key=base64.b64decode(client['server_key']['pub_key'])),
                            ip=2130706433, port=int(client['server_address'].rsplit(':', 1)[1]))],
                        validator=network.zerostate.as_validator_config()))
                write(root / 'processes.json', dict(cpp={node.name: node.process_id for node in cpp_nodes},
                    rust={str(node['index']): dict(pid=node['process'].pid,
                        start_ticks=node['start_ticks'])
                        for node in rust_nodes}))
            write(root / 'rpc-endpoints.json', dict(zip(endpoint_names, endpoints)))
            if rust_nodes:
                first_prepared = json.loads((rust_nodes[0]['directory'] / 'validator-prepared.json').read_text())
            else:
                # This offline decoder validates the frozen committee; no Rust
                # validator process or network participant starts in this mode.
                _, first_prepared = await prepare_rust(args, root / 'committee-probe', 0,
                    network, global_config, tcp_used, udp_used)
            write(root / 'processes.json', dict(cpp={node.name: node.process_id for node in cpp_nodes},
                rust={str(node['index']): dict(pid=node['process'].pid,
                    start_ticks=node['start_ticks'])
                    for node in rust_nodes}))
            comparison_index = args.cpp_count if 0 < args.cpp_count < member_count else 1
            body_index = args.cpp_count if rust_nodes else 0
            master = next(s for s in first_prepared['sessions'] if s['masterchain'] and s['catchain_seqno'] == 0)
            weights = {m['validator_id']: m['weight'] for m in master['committee']}
            if len(weights) != member_count or set(weights) != {base64.b64decode(c).hex() for c in expected_creators}:
                raise RuntimeError('Authenticated committee differs from the declared reserved identities')
            total = sum(weights.values())
            cpp_weight = sum(weights[hashlib.sha256(f'n6-validator-id-{i}'.encode()).hexdigest()]
                             for i in range(args.cpp_count))
            write(root / 'quorum.json', dict(total_weight=total, quorum_weight=quorum_threshold(total),
                cpp_weight=cpp_weight, rust_weight=total - cpp_weight,
                cpp_alone_can_finalize=cpp_weight >= quorum_threshold(total)))
            observations = [{} for _ in endpoints]
            checked_keys, creators = set(), {}
            workchain_keys, workchain_creators = set(), {}
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
                    creators=list(creators), workchain_creators=list(workchain_creators),
                    common_checkpoints=len(common)))
                for key in common:
                    infos = [items[key] for items in observations]
                    if any(info['state_root_hash'] != infos[0]['state_root_hash'] for info in infos):
                        raise RuntimeError(f'Applied state roots differ at MC{key[2]}')
                    directory = root / 'checks' / str(key[2])
                    directory.mkdir(parents=True)
                    if rust_nodes:
                        block = await asyncio.to_thread(rpc, endpoints[body_index], 'getBlock',
                            {k: infos[0]['last'][k] for k in ['workchain', 'shard', 'seqno', 'root_hash', 'file_hash']})
                    else:
                        block = await cpp_block(snapshot, cpp_nodes[0], infos[0]['last'], directory)
                    sample = dict(zerostate=zero, reference=infos[0],
                        references=dict(zip(endpoint_names, infos)), comparison=infos[comparison_index],
                        comparison_endpoint=endpoint_names[comparison_index], block=block,
                        body_transport='native_rust_rpc' if rust_nodes else 'native_cpp_liteserver')
                    if member_count != 4:
                        sample['fixture_validator_count'] = member_count
                    if args.verify_certificates:
                        sample['masterchain_state'] = await native_state(snapshot, lite_configs[0],
                            endpoint_names[0], infos[0]['last'], directory / 'mc-state')
                        sample['governing_zerostate_boc'] = base64.b64encode(generated.file.read_bytes()).decode()
                        if rust_nodes:
                            certs = await asyncio.gather(*(asyncio.to_thread(rpc, url,
                                'getMasterchainBlockSignatures', {'seqno': key[2]})
                                for url in endpoints[args.cpp_count:]))
                            sample['certificates'] = [dict(kind='rpc', name=name, value=cert)
                                for name, cert in zip(endpoint_names[args.cpp_count:], certs)]
                        else:
                            sample['certificates'] = [await cpp_certificate(snapshot, cpp_nodes[0], zero,
                                infos[0]['last'], directory)]
                    write(directory / 'sample.json', sample)
                    await child_checked([args.block_checker, directory / 'sample.json',
                        directory / 'checked.json'], directory / 'checker.log')
                    checked = json.loads((directory / 'checked.json').read_text())
                    if args.verify_certificates:
                        check_committee_weights(checked, {i: 17 for i in range(member_count)},
                            lambda i: base64.b64encode(hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest()).decode())
                    if args.verify_workchain:
                        tops = [top for top in checked['shard_tops']
                            if int(top['workchain']) == 0 and int(top['shard']) == -(1 << 63)
                            and int(top['seqno']) > 0 and identity(top) not in workchain_keys]
                        if len(tops) > 1:
                            raise RuntimeError('Multiple full workchain-0 anchors in one masterchain block')
                        if tops:
                            top = tops[0]
                            wc_dir = directory / 'workchain'
                            wc_dir.mkdir()
                            if rust_nodes:
                                wc_block = await asyncio.to_thread(rpc, endpoints[body_index], 'getBlock',
                                    {k: top[k] for k in ['workchain', 'shard', 'seqno', 'root_hash', 'file_hash']})
                            else:
                                wc_block = await cpp_block(snapshot, cpp_nodes[0], top, wc_dir)
                            states = await asyncio.gather(*(native_state(snapshot, config, name, top,
                                wc_dir / name) for name, config in zip(endpoint_names, lite_configs)))
                            sample['workchain'] = dict(block=wc_block, states=states)
                            write(directory / 'sample.json', sample)
                            await child_checked([args.block_checker, directory / 'sample.json',
                                directory / 'workchain-checked.json'], directory / 'workchain-checker.log')
                            checked = json.loads((directory / 'workchain-checked.json').read_text())
                            wc_check = checked['workchain_check']
                            wc_creator = wc_check['created_by']
                            if wc_creator not in expected_creators:
                                raise RuntimeError('Anchored workchain block has an unexpected creator')
                            wc_language, wc_member = expected_creators[wc_creator]
                            wc_evidence = dict(member=wc_member, language=wc_language,
                                block_check=wc_check, masterchain_anchor=infos[0]['last'],
                                sample_directory=str(directory))
                            if wc_language == 'rust':
                                node = next(node for node in rust_nodes if node['index'] == wc_member)
                                text = (node['directory'] / 'node.log').read_text(errors='replace')
                                match = re.search(r'^\(0:8000000000000000, ' + str(top['seqno']) +
                                    r'\): ValidatorGroup::on_generate_slot: .*Collation successful$', text, re.M)
                                if not match:
                                    raise RuntimeError('Rust workchain creator lacks successful local collation evidence')
                                wc_evidence['local_collation'] = match.group(0)
                            workchain_keys.add(identity(top))
                            workchain_creators.setdefault(wc_creator, wc_evidence)
                            write(root / 'workchain-creators.json', workchain_creators)
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
                    if set(creators) == set(expected_creators) and (not args.verify_workchain
                            or set(workchain_creators) == set(expected_creators)):
                        for path, expected in artifacts.items():
                            if digest(Path(path)) != expected:
                                raise RuntimeError('An executable changed during matrix validation')
                        return dict(status=('all_four_creators_accepted_with_matching_states' if member_count == 4
                            else 'all_declared_creators_accepted_with_matching_states'),
                            validator_count=member_count,
                            cpp_count=args.cpp_count, rust_count=member_count - args.cpp_count,
                            control_kind=('all_cpp' if args.cpp_count == member_count else 'all_rust' if args.cpp_count == 0 else 'mixed'),
                            creators=creators, common_state_checkpoints=len(checked_keys),
                            final_certificates_required=args.verify_certificates,
                            workchain_states_required=args.verify_workchain,
                            workchain_creators=workchain_creators,
                            workchain_state_checkpoints=len(workchain_keys),
                            mixed_validator_qualified=False)
                await asyncio.sleep(0.1)
            raise TimeoutError(f'Not all {member_count} declared creators were accepted within {args.timeout} seconds')
        finally:
            codes = await asyncio.gather(*(stop_rust(node) for node in rust_nodes), return_exceptions=True)
            write(root / 'rust-shutdown.json', {str(node['index']):
                (str(code) if isinstance(code, BaseException) else code) for node, code in zip(rust_nodes, codes)})
            if any(code != 0 for code in codes) and sys.exception() is None:
                raise RuntimeError('At least one owned Rust process did not shut down normally')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--rust-node', type=Path, required=True)
    parser.add_argument('--validator-preparer', type=Path, required=True)
    parser.add_argument('--block-checker', type=Path, required=True)
    parser.add_argument('--rust-revision', required=True)
    parser.add_argument('--cpp-count', type=int, choices=range(7), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-port', type=int, default=55700)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--min-height', type=int, default=1)
    parser.add_argument('--genesis-profile', type=Path,
                        default=Path(__file__).with_name('testnet-v16.json'))
    parser.add_argument('--prepare-genesis-only', action='store_true')
    parser.add_argument('--verify-certificates', action='store_true')
    parser.add_argument('--verify-workchain', action='store_true')
    args = parser.parse_args()
    args.snapshot = args.snapshot.resolve()
    for name in ['rust_node', 'validator_preparer', 'block_checker']:
        setattr(args, name, getattr(args, name).resolve())
    manifest = json.loads((args.snapshot / 'manifest.json').read_text())
    args.genesis_profile = args.genesis_profile.resolve()
    profile = json.loads(args.genesis_profile.read_text())
    member_count = matrix_committee_size(profile, args.cpp_count)
    if member_count != 4 and not args.prepare_genesis_only and not (
            args.verify_certificates and args.verify_workchain):
        raise SystemExit('Full active three/six matrix requires certificates and workchain state checks')
    if member_count != 4 and not args.prepare_genesis_only and any(
            profile.get(key) is None for key in ['expected_zerostate', 'expected_workchain_zerostate']):
        raise SystemExit('Freeze both generated Genesis identities before starting the declared matrix')
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
    helper = Path(__file__).with_name('quorum_profile.py')
    artifacts[str(helper)] = digest(helper)
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
