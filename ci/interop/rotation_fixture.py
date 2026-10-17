#!/usr/bin/env python3
"""Check real MC/WC production and authenticated finality across committee replacement."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import time

sys.dont_write_bytecode = True
from mixed_matrix import (child_checked, cpp_block, cpp_certificate, digest, identity,
                          native_state, prepare_rust, reserve_port, rpc, stop_rust, write)


INITIAL = [0, 1, 2, 3]
SUCCESSOR = [0, 2, 4, 5]


def member_id(index):
    return base64.b64encode(hashlib.sha256(f'n6-validator-id-{index}'.encode()).digest()).decode()


def state_id(state, workchain):
    return {'@type': 'tos.blockIdExt', 'workchain': workchain, 'shard': str(-(1 << 63)),
            'seqno': 0, 'root_hash': base64.b64encode(state.root_hash).decode(),
            'file_hash': base64.b64encode(state.file_hash).decode()}


async def stop_rotation_node(node):
    started = time.monotonic()
    try:
        return await stop_rust(node)
    finally:
        node['shutdown_elapsed_seconds'] = time.monotonic() - started


async def start_rotation_node(binary, directory, log_name='node.log'):
    with (directory / log_name).open('w') as log:
        process = await asyncio.create_subprocess_exec(str(binary), '--configs', str(directory),
            '--zerostate', str(directory / 'zero'), '--initial-sync-disabled', cwd=directory,
            stdout=log, stderr=log, env={**os.environ, 'TOKIO_WORKER_THREADS': '2'},
            start_new_session=True)
    return {'process': process,
        'start_ticks': Path(f'/proc/{process.pid}/stat').read_text().split()[21]}


async def recover_rotation_member(args, root, nodes, endpoints, lite_configs, rust_nodes,
                                  zero, governing, checkpoint, artifacts):
    """Interrupt one owned successor, then reopen its existing data without preparation."""
    index = args.interrupt_rust_member
    node = next(node for node in rust_nodes if node['index'] == index)
    directory = root / 'recovery'; directory.mkdir()
    old_process = node['process']
    prepared = node['directory'] / 'validator-prepared.json'
    prepared_hash = digest(prepared)
    prior = await asyncio.gather(*(asyncio.to_thread(rpc, url, 'getMasterchainInfo') for url in endpoints))
    if any(identity(info['init']) != identity(zero) for info in prior):
        raise RuntimeError('Pre-interruption endpoint changed Genesis')
    receipt = {'member': index, 'before': checkpoint['block'],
        'pre_interruption_references': dict(enumerate(prior)),
        'old_process': {'pid': old_process.pid, 'start_ticks': node['start_ticks']},
        'prepared_sha256': prepared_hash, 'phase': 'interrupting'}
    write(directory / 'recovery.json', receipt)
    if old_process.returncode is not None:
        raise RuntimeError('Recovery member exited before the intended interruption')
    old_process.kill()
    interrupted_at = time.time()
    code = await asyncio.wait_for(old_process.wait(), 10)
    if code != -9:
        raise RuntimeError(f'Recovery interruption did not reap SIGKILL: {code}')
    receipt.update(interruption_returncode=code, interrupted_at_unix=interrupted_at, phase='waiting_for_survivors')
    write(directory / 'recovery.json', receipt)
    histories = [{} for _ in nodes]
    deadline = time.monotonic() + args.recovery_timeout

    async def common_checkpoint(indices, floor):
        while time.monotonic() < deadline:
            for live in rust_nodes:
                if live['index'] in indices and live['process'].returncode is not None:
                    raise RuntimeError(f"Live Rust recovery peer {live['index']} exited")
            replies = await asyncio.gather(*(asyncio.to_thread(rpc, endpoints[i],
                'getMasterchainInfo') for i in indices), return_exceptions=True)
            for i, value in zip(indices, replies):
                if isinstance(value, BaseException):continue
                if identity(value['init']) != identity(zero):
                    raise RuntimeError('Recovery endpoint changed Genesis')
                histories[i][identity(value['last'])] = value
                if len(histories[i]) > 512:del histories[i][next(iter(histories[i]))]
            common = set.intersection(*(set(histories[i]) for i in indices))
            newer = [key for key in common if key[2] > floor]
            if newer:
                key = max(newer, key=lambda key: key[2])
                infos = {i: histories[i][key] for i in indices}
                if len({info['state_root_hash'] for info in infos.values()}) != 1:
                    raise RuntimeError('Recovery peers disagree on the applied state')
                return infos
            await asyncio.sleep(0.2)
        raise TimeoutError('Interrupted member did not recover within the recovery deadline')

    async def check_checkpoint(infos, label, with_workchain):
        target = directory / label; target.mkdir()
        block_id = infos[0]['last']
        block = await cpp_block(args.snapshot, nodes[0], block_id, target)
        state = await native_state(args.snapshot, lite_configs[0], 'cpp-0', block_id, target / 'mc-state')
        proof = await cpp_certificate(args.snapshot, nodes[0], zero, block_id, target)
        sample = {'zerostate': zero, 'reference': infos[0], 'comparison': infos[next(i for i in infos if i != 0)],
            'all_references': {str(i): info for i, info in infos.items()},
            'block': block, 'masterchain_state': state, 'certificates': [proof],
            'governing_key_block': {**governing, 'certificates': [proof]}}
        write(target / 'sample.json', sample)
        await child_checked([args.block_checker, target / 'sample.json', target / 'checked.json'],
            target / 'checker.log')
        checked = json.loads((target / 'checked.json').read_text())
        if {m['validator_id'] for m in checked['configuration']['current']['members']} != {member_id(i) for i in SUCCESSOR}:
            raise RuntimeError('Recovery checkpoint changed the successor committee')
        if not checked['verified_governing_key_blocks'] or checked['key_block']:
            raise RuntimeError('Recovery checkpoint lacks successor finality')
        if with_workchain:
            tops = [top for top in checked['shard_tops'] if int(top['workchain']) == 0 and int(top['seqno']) > 0]
            if len(tops) != 1:raise RuntimeError('Recovery needs one produced full workchain')
            wc_dir = target / 'workchain'; wc_dir.mkdir()
            sample['references'] = {str(i): infos[i] for i in SUCCESSOR}
            sample['workchain'] = {'block': await cpp_block(args.snapshot, nodes[0], tops[0], wc_dir),
                'states': await asyncio.gather(*(native_state(args.snapshot, lite_configs[i],
                    str(i), tops[0], wc_dir / str(i)) for i in SUCCESSOR))}
            write(target / 'sample.json', sample)
            await child_checked([args.block_checker, target / 'sample.json', target / 'checked-with-workchain.json'],
                target / 'workchain-checker.log')
            checked = json.loads((target / 'checked-with-workchain.json').read_text())
        return checked

    floor = max(info['last']['seqno'] for info in prior)
    while True:
        survivor_infos = await common_checkpoint([i for i in range(6) if i != index], floor)
        floor = survivor_infos[0]['last']['seqno']
        survivor = await check_checkpoint(survivor_infos, f'survivors-{floor}', False)
        if survivor['gen_utime'] > interrupted_at:break
    receipt.update(phase='restarting_original_directory', survivor_checkpoint=survivor['block'])
    write(directory / 'recovery.json', receipt)
    for filename, expected in artifacts.items():
        if digest(Path(filename)) != expected:raise RuntimeError('An executable or profile changed before restart')
    if digest(prepared) != prepared_hash:raise RuntimeError('Prepared authority changed before restart')
    node.update(await start_rotation_node(args.rust_node, node['directory'], 'node-restart.log'))
    receipt['new_process'] = {'pid': node['process'].pid, 'start_ticks': node['start_ticks']}
    receipt['phase'] = 'waiting_for_recovered_leadership'
    write(directory / 'recovery.json', receipt)
    # Clear all pre-interruption observations; acceptance needs fresh RPCs from every process.
    histories = [{} for _ in nodes]
    floor = survivor['block']['seqno']
    minimum_wc = max((int(top['seqno']) for top in survivor['shard_tops'] if int(top['workchain']) == 0), default=0)
    leaders = {}
    while len(leaders) < 2:
        infos = await common_checkpoint(list(range(6)), floor)
        floor = infos[0]['last']['seqno']
        checked = await check_checkpoint(infos, str(floor), True)
        for chain, evidence, workchain in [('masterchain', checked, -1), ('workchain', checked['workchain_check'], 0)]:
            if evidence['created_by'] != member_id(index):continue
            if workchain == 0 and evidence['block']['seqno'] <= minimum_wc:continue
            match = re.search(r'^\(' + str(workchain) + r':8000000000000000, ' +
                str(evidence['block']['seqno']) + r'\): ValidatorGroup::on_generate_slot: .*Collation successful$',
                (node['directory'] / 'node-restart.log').read_text(errors='replace'), re.M)
            if not match:raise RuntimeError('Recovered creator lacks post-restart local collation evidence')
            leaders.setdefault(chain, {'block': evidence['block'], 'sample_directory': str(directory / str(floor)),
                'local_collation': match.group(0)})
        receipt.update(leaders=leaders, last_checkpoint=checked['block'])
        write(directory / 'recovery.json', receipt)
    if digest(prepared) != prepared_hash:raise RuntimeError('Recovery changed prepared authority')
    receipt.update(phase='recovered', all_six_applied_states_match=True,
        successor_finality_checked=True, workchain_states_match=True, manual_database_repair=False)
    write(directory / 'recovery.json', receipt)
    return receipt


def install_successor(module, nodes, profile):
    """Add an explicit future set before the native config account is created.

    Only the isolated generated Fift input changes. The snapshot and production
    configuration contract remain byte-for-byte fixed. Its ordinary tock moves
    Param36 to 34 and the previous 34 to 32 at the declared activation time.
    This predeclared Genesis successor is not an election rehearsal.
    """
    original = module.run_fift

    def generate(install, code, directory, **kwargs):
        anchor = '\nconfig.new_consensus_params_all!\n'
        if code.count(anchor) != 1:
            raise RuntimeError('Pinned Genesis template insertion point differs')
        lines = ['dictnew 0 validator-dict 2!', 'validators-weight 0!']
        for index in SUCCESSOR:
            filename = f'rotation-validator-{index}.boc'
            (directory / filename).write_bytes(module._pq_validator_descriptor(
                nodes[index].pq_initial_validator, 17).to_boc())
            lines.append(f'17 "{filename}" file>B B>boc register-validator')
        since = profile['genesis_time'] + profile['activation_delay']
        until = since + profile['successor_valid_for']
        lines.append(f'<b x{{12}} s, {since} 32 u, {until} 32 u, '
                     '4 16 u, 4 16 u, 68 64 u, validator-dict @ first dict, b> 36 config!')
        original(install, code.replace(anchor, anchor + '\n'.join(lines) + '\n'), directory, **kwargs)

    module.run_fift = generate
    return original


async def run(args, profile, root, artifacts):
    sys.path.insert(0, str(args.snapshot / 'source/test/tostester/src'))
    from nacl.signing import SigningKey
    from tostester.install import Install
    from tostester.key import Key
    from tostester.network import Network, StartOptions, _write_model
    from tosapi import tos_api
    import tostester.zerostate as genesis_module

    used, endpoints, nodes = set(), [], []
    rust_nodes, cpp_started, lite_configs = [], [], []
    endpoint_names = [('rust' if args.rust_node and i in [2, 3, 5] else 'cpp') + f'-{i}' for i in range(6)]
    (root / 'network').mkdir()
    async with Network(Install(args.snapshot / 'build', args.snapshot / 'source'),
                       root / 'network', base_port=args.base_port) as network:
        config = network.config
        config.global_id, config.global_version = profile['global_id'], 16
        config.genesis_time = profile['genesis_time']
        config.genesis_wallet_seed = hashlib.sha256(profile['wallet_seed_label'].encode()).digest()
        config.bootstrap_validator_set_valid_for = profile['activation_delay']
        config.shard_validators = 4
        for consensus in [config.mc_consensus, config.shard_consensus]:
            for key, value in profile['consensus'].items():
                if not hasattr(consensus, key):
                    raise RuntimeError(f'Unknown consensus profile field {key}')
                setattr(consensus, key, value)
        dht = network.create_dht_node()
        for index in range(6):
            key = Key(SigningKey(hashlib.sha256(f'n6-validator-transport-{index}'.encode()).digest()))
            node = network.create_full_node(validator_key=key)
            provision = node.make_initial_pq_validator if index in INITIAL else node.make_noninitial_pq_validator
            provision(hashlib.sha256(f'n6-validator-id-{index}'.encode()).digest(),
                      hashlib.sha256(f'n6-validator-seed-{index}'.encode()).digest())
            node.announce_to(dht)
            nodes.append(node)
        original = install_successor(genesis_module, nodes, profile)
        try:
            genesis = network._get_or_generate_zerostate()
        finally:
            genesis_module.run_fift = original
        zero = state_id(genesis.masterchain, -1)
        shard_zero = state_id(genesis.shardchain, 0)
        frozen = {**profile, 'expected_zerostate': zero, 'expected_workchain_zerostate': shard_zero}
        write(root / 'frozen-profile.json', frozen)
        write(root / 'genesis.json', {'zerostate': zero, 'workchain_zerostate': shard_zero,
            'initial_members': INITIAL, 'successor_members': SUCCESSOR,
            'activate_at': profile['genesis_time'] + profile['activation_delay']})
        for key, generated in [('expected_zerostate', zero), ('expected_workchain_zerostate', shard_zero)]:
            if profile.get(key) is not None and identity(profile[key]) != identity(generated):
                raise RuntimeError(f'Generated rotation Genesis differs from frozen {key}')
        if args.prepare_genesis_only:
            return {'status': 'rotation_genesis_prepared', 'validators_started': False}
        if any(profile.get(key) is None for key in ['expected_zerostate', 'expected_workchain_zerostate']):
            raise RuntimeError('Prepare and freeze the rotation profile before starting validators')
        activation = profile['genesis_time'] + profile['activation_delay']
        if activation - time.time() < 20:
            raise RuntimeError('Insufficient time for a real pre-rotation checkpoint')
        await dht.run(StartOptions(threads=1, verbosity=3))
        try:
            global_config = root / 'config.global.json'
            _write_model(global_config, tos_api.Config_global(
                dht=tos_api.Dht_config_global(static_nodes=tos_api.Dht_nodes(nodes=[dht.signed_address]), k=3, a=3),
                validator=genesis.as_validator_config()))
            for index, node in enumerate(nodes):
                if args.rust_node and index in [2, 3, 5]:
                    directory = root / f'rust-{index}'
                    address, prepared = await prepare_rust(args, directory, index, network,
                        global_config, used, used)
                    rust_nodes.append(dict(index=index, directory=directory,
                        **await start_rotation_node(args.rust_node, directory)))
                    client = json.loads((directory / 'lite_client_config.json').read_text())
                    lite_configs.append(tos_api.Liteclient_config_global(
                        liteservers=[tos_api.Liteserver_desc(id=tos_api.Pub_ed25519(
                            key=base64.b64decode(client['server_key']['pub_key'])), ip=2130706433,
                            port=int(client['server_address'].rsplit(':', 1)[1]))],
                        validator=genesis.as_validator_config()))
                else:
                    address = f'127.0.0.1:{reserve_port(socket.SOCK_STREAM, used)}'
                    await node.run(StartOptions(threads=2, verbosity=3, args=['--json-rpc-address', address]))
                    cpp_started.append((index, node))
                    lite_configs.append(node.liteserver_config)
                endpoints.append('http://' + address + '/jsonRPC')
                write(root / 'processes.json', {'cpp': {str(i): n.process_id for i, n in cpp_started},
                    'rust': {str(n['index']): {'pid': n['process'].pid, 'start_ticks': n['start_ticks']} for n in rust_nodes}})
            write(root / 'rpc-endpoints.json', dict(zip(endpoint_names, endpoints)))
            histories = [{} for _ in nodes]
            governing_witnesses = {}
            seen = set()
            epochs = {phase: {'mc_creators': {}, 'wc_creators': {}} for phase in ['before', 'after']}
            baseline_wc_cc = 0
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                for node in rust_nodes:
                    if node['process'].returncode is not None:
                        raise RuntimeError(f"Rust {node['index']} exited {node['process'].returncode}")
                replies = await asyncio.gather(*(asyncio.to_thread(rpc, url, 'getMasterchainInfo')
                    for url in endpoints), return_exceptions=True)
                for index, value in enumerate(replies):
                    if isinstance(value, BaseException):
                        continue
                    if identity(value['init']) != identity(zero):
                        raise RuntimeError('C++ endpoint moved to another Genesis')
                    histories[index][identity(value['last'])] = value
                    if len(histories[index]) > 512:
                        del histories[index][next(iter(histories[index]))]
                common = set.intersection(*(set(history) for history in histories))
                common = sorted((key for key in common if key[2] > 0 and key not in seen),
                                key=lambda key: key[2], reverse=True)
                write(root / 'status.json', {'status': 'waiting_for_membership_rotation',
                    'heights': [v['last']['seqno'] if not isinstance(v, BaseException) else None for v in replies],
                    'epochs': epochs})
                for key in common:
                    infos = [history[key] for history in histories]
                    if any(value['state_root_hash'] != infos[0]['state_root_hash'] for value in infos):
                        raise RuntimeError('C++ states differ at a common rotation checkpoint')
                    directory = root / 'checks' / str(key[2]); directory.mkdir(parents=True)
                    block = await cpp_block(args.snapshot, nodes[0], infos[0]['last'], directory)
                    state = await native_state(args.snapshot, nodes[0].liteserver_config, 'cpp-0',
                        infos[0]['last'], directory / 'mc-state')
                    sample = {'zerostate': zero, 'reference': infos[0], 'comparison': infos[2],
                        'all_references': dict(zip(endpoint_names, infos)),
                        'block': block, 'masterchain_state': state}
                    write(directory / 'sample.json', sample)
                    await child_checked([args.block_checker, directory / 'sample.json', directory / 'checked.json'],
                        directory / 'checker.log')
                    checked = json.loads((directory / 'checked.json').read_text())
                    members = {m['validator_id'] for m in checked['configuration']['current']['members']}
                    if members == {member_id(i) for i in INITIAL}:
                        phase, committee = 'before', INITIAL
                    elif members == {member_id(i) for i in SUCCESSOR}:
                        phase, committee = 'after', SUCCESSOR
                    else:
                        raise RuntimeError('Authenticated C++ state has an unexpected current committee')
                    seen.add(key)
                    if checked['key_block']:
                        if checked['prev_key_block_seqno'] != 0:
                            raise RuntimeError('This one-successor fixture encountered an additional key-block epoch')
                        sample['governing_zerostate_boc'] = base64.b64encode(genesis.masterchain.file.read_bytes()).decode()
                        sample['certificates'] = [await cpp_certificate(args.snapshot, nodes[0], zero,
                            infos[0]['last'], directory)]
                        write(directory / 'sample.json', sample)
                        await child_checked([args.block_checker, directory / 'sample.json',
                            directory / 'key-block-certified.json'], directory / 'key-block-checker.log')
                        checked = json.loads((directory / 'key-block-certified.json').read_text())
                        write(directory / 'transition.json', {'phase': phase, 'checked': checked})
                        continue  # A transition block is still signed by its preceding set.
                    if phase == 'after' and (checked['gen_utime'] < activation or checked['prev_key_block_seqno'] == 0):
                        raise RuntimeError('Successor sample lacks an actual key-block transition')
                    sample['references'] = {endpoint_names[i]: infos[i] for i in committee}
                    proof = await cpp_certificate(args.snapshot, nodes[0], zero, infos[0]['last'], directory)
                    if checked['prev_key_block_seqno'] == 0:
                        sample['governing_zerostate_boc'] = base64.b64encode(genesis.masterchain.file.read_bytes()).decode()
                        sample['certificates'] = [proof]
                    else:
                        key_seqno = checked['prev_key_block_seqno']
                        if key_seqno not in governing_witnesses:
                            key_id = await asyncio.to_thread(rpc, endpoints[0], 'lookupBlock',
                                {'workchain': -1, 'shard': str(-(1 << 63)), 'seqno': key_seqno})
                            gov_dir = root / 'governing' / str(key_seqno); gov_dir.mkdir(parents=True)
                            key_body = await cpp_block(args.snapshot, nodes[0], key_id, gov_dir)
                            key_state = await native_state(args.snapshot, lite_configs[0], 'cpp-0',
                                key_id, gov_dir / 'state')
                            governing_witnesses[key_seqno] = {'zerostate': zero, 'block': key_body,
                                'masterchain_state': key_state,
                                'governing_zerostate_boc': base64.b64encode(genesis.masterchain.file.read_bytes()).decode()}
                            write(gov_dir / 'bodies.json', governing_witnesses[key_seqno])
                        sample['certificates'] = [proof]
                        sample['governing_key_block'] = {**governing_witnesses[key_seqno], 'certificates': [proof]}
                    tops = [top for top in checked['shard_tops'] if int(top['workchain']) == 0 and int(top['seqno']) > 0]
                    if tops:
                        top = tops[0]; wc_dir = directory / 'workchain'; wc_dir.mkdir()
                        wc_block = await cpp_block(args.snapshot, nodes[0], top, wc_dir)
                        states = await asyncio.gather(*(native_state(args.snapshot, lite_configs[i],
                            endpoint_names[i], top, wc_dir / endpoint_names[i]) for i in committee))
                        sample['workchain'] = {'block': wc_block, 'states': states}
                    write(directory / 'sample.json', sample)
                    await child_checked([args.block_checker, directory / 'sample.json', directory / 'epoch-checked.json'],
                        directory / 'epoch-checker.log')
                    checked = json.loads((directory / 'epoch-checked.json').read_text())
                    if phase == 'after' and not checked['verified_governing_key_blocks']:
                        raise RuntimeError('Successor sample lacks independently verified governing history')
                    if checked['created_by'] not in {member_id(i) for i in committee}:
                        raise RuntimeError('Non-transition block creator is absent from the current committee')
                    evidence = {'check': checked, 'sample_directory': str(directory)}
                    mc_member = next(i for i in committee if member_id(i) == checked['created_by'])
                    if args.rust_node and mc_member in [2, 3, 5]:
                        node = next(n for n in rust_nodes if n['index'] == mc_member)
                        match = re.search(r'^\(-1:8000000000000000, ' + str(key[2]) +
                            r'\): ValidatorGroup::on_generate_slot: .*Collation successful$',
                            (node['directory'] / 'node.log').read_text(errors='replace'), re.M)
                        if not match:raise RuntimeError('Rust MC creator lacks local collation evidence')
                        evidence['local_collation'] = match.group(0)
                    epochs[phase]['mc_creators'].setdefault(checked['created_by'], evidence)
                    wc = checked['workchain_check']
                    if wc is not None:
                        if phase == 'before': baseline_wc_cc = max(baseline_wc_cc, wc['gen_catchain_seqno'])
                        eligible = phase == 'before' or (wc['gen_utime'] >= activation
                            and wc['gen_catchain_seqno'] > baseline_wc_cc)
                        if eligible and wc['created_by'] in {member_id(i) for i in committee}:
                            evidence = {'check': wc, 'masterchain_anchor': infos[0]['last'],
                                'sample_directory': str(directory)}
                            wc_member = next(i for i in committee if member_id(i) == wc['created_by'])
                            if args.rust_node and wc_member in [2, 3, 5]:
                                node = next(n for n in rust_nodes if n['index'] == wc_member)
                                match = re.search(r'^\(0:8000000000000000, ' + str(wc['block']['seqno']) +
                                    r'\): ValidatorGroup::on_generate_slot: .*Collation successful$',
                                    (node['directory'] / 'node.log').read_text(errors='replace'), re.M)
                                if not match:raise RuntimeError('Rust WC creator lacks local collation evidence')
                                evidence['local_collation'] = match.group(0)
                            epochs[phase]['wc_creators'].setdefault(wc['created_by'], evidence)
                    write(root / 'epochs.json', epochs)
                    if all(len(epoch[k]) == 4 for epoch in epochs.values() for k in ['mc_creators', 'wc_creators']):
                        recovery = None
                        if args.interrupt_rust_member is not None:
                            recovery = await recover_rotation_member(args, root, nodes, endpoints,
                                lite_configs, rust_nodes, zero, governing_witnesses[checked['prev_key_block_seqno']],
                                checked, artifacts)
                        for filename, expected in artifacts.items():
                            if digest(Path(filename)) != expected: raise RuntimeError('An executable or profile changed')
                        return {'status': ('mixed_membership_rotation_observed' if args.rust_node
                                          else 'cpp_membership_rotation_observed'), 'epochs': epochs,
                            'all_six_applied_mc_states_match': True, 'independent_post_rotation_finality_qualified': True,
                            'mixed_rotation_qualified': bool(args.rust_node), 'election_rehearsal': False,
                            'recovery': recovery}
                await asyncio.sleep(0.2)
            raise TimeoutError('C++ rotation did not satisfy both MC/WC creator epochs')
        finally:
            codes = await asyncio.gather(*(stop_rotation_node(node) for node in rust_nodes), return_exceptions=True)
            write(root / 'rust-shutdown.json', {str(node['index']):
                (str(code) if isinstance(code, BaseException) else code)
                for node, code in zip(rust_nodes, codes)})
            write(root / 'rust-shutdown-timing.json', {str(node['index']):
                {'elapsed_seconds': node['shutdown_elapsed_seconds'], 'normal_exit_limit_seconds': 20}
                for node in rust_nodes})
            if any(code != 0 for code in codes) and sys.exception() is None:
                raise RuntimeError('Owned Rust rotation nodes did not stop normally')



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--block-checker', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-port', type=int, default=55900)
    parser.add_argument('--timeout', type=float, default=240)
    parser.add_argument('--prepare-genesis-only', action='store_true')
    parser.add_argument('--rust-node', type=Path)
    parser.add_argument('--validator-preparer', type=Path)
    parser.add_argument('--interrupt-rust-member', type=int, choices=[2, 5])
    parser.add_argument('--recovery-timeout', type=float, default=180)
    args = parser.parse_args()
    if bool(args.rust_node) != bool(args.validator_preparer):
        raise SystemExit('Mixed rotation requires both the Rust node and offline preparer')
    if args.interrupt_rust_member is not None and (not args.rust_node or args.prepare_genesis_only):
        raise SystemExit('Recovery requires a live mixed rotation fixture')
    if not 0 < args.recovery_timeout <= 600:
        raise SystemExit('Recovery timeout must be positive and at most 600 seconds')
    args.verify_workchain = args.include_genesis_successor = True
    if args.rust_node:
        args.rust_node, args.validator_preparer = args.rust_node.resolve(), args.validator_preparer.resolve()
    for name in ['snapshot', 'block_checker', 'profile', 'output']:
        setattr(args, name, getattr(args, name).resolve())
    profile = json.loads(args.profile.read_text())
    if profile['schema'] != 1 or profile['global_version'] != 16 or profile['initial_members'] != INITIAL \
            or profile['successor_members'] != SUCCESSOR:
        raise SystemExit('Unsupported explicit rotation profile')
    if any(type(profile.get(key)) is not int for key in
           ['global_id', 'genesis_time', 'activation_delay', 'successor_valid_for']):
        raise SystemExit('Rotation times and network ID must be explicit integers')
    if profile['global_id'] != 4 or not 90 <= profile['activation_delay'] <= 3600 \
            or profile['successor_valid_for'] <= 600 or profile['genesis_time'] < 0 \
            or profile['genesis_time'] + profile['activation_delay'] + profile['successor_valid_for'] > 0xffffffff:
        raise SystemExit('Unsupported bounded isolated rotation schedule')
    if profile['consensus']['protocol_version'] != 2 or not profile['consensus']['use_quic']:
        raise SystemExit('Rotation fixture requires the explicit native protocol-2 QUIC profile')
    manifest = json.loads((args.snapshot / 'manifest.json').read_text())
    if manifest['cpp_source_commit'] != profile['cpp_revision'] \
            or profile['cpp_revision'] != '8f083dc06bff16705710a01de15eb3123d5d696b':
        raise SystemExit('Rotation requires the pinned C++ baseline')
    artifacts = {str(args.block_checker): digest(args.block_checker), str(args.profile): digest(args.profile)}
    if args.rust_node:
        artifacts.update({str(path): digest(path) for path in [args.rust_node, args.validator_preparer]})
    for item in manifest['binaries']:
        path = args.snapshot / 'build' / item['path']
        if digest(path) != item['sha256']:raise SystemExit(f'C++ executable changed: {path}')
        artifacts[str(path)] = item['sha256']
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / 'source.json', {'snapshot': manifest, 'artifacts': artifacts,
        'profile': profile, 'command': sys.argv, 'driver_sha256': digest(Path(__file__))})
    try:
        result = asyncio.run(run(args, profile, args.output, artifacts))
    except BaseException as error:
        write(args.output / 'result.json', {'status': 'failed', 'error_type': type(error).__name__, 'error': str(error)})
        raise
    else:
        write(args.output / 'result.json', result)


if __name__ == '__main__':
    main()
