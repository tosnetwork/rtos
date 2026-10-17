"""Owned-node pause at exactly the pinned C++ weighted quorum; same-PID recovery."""
import asyncio
import json
import os
from pathlib import Path
import re
import signal
import time

from mixed_matrix import child_checked, cpp_block, cpp_certificate, digest, identity, native_state, rpc, write
from network_faults import require_namespace
from quorum_profile import check_committee_weights, epoch_weights, quorum_threshold


async def exercise_weighted_quorum(args, root, nodes, endpoints, lite_configs, rust_nodes,
                                   zero, governing, checkpoint, artifacts, profile):
    from rotation_fixture import SUCCESSOR, member_id, recovery_workchain_states
    require_namespace()
    directory = root / 'weighted-quorum'; directory.mkdir()
    weights = epoch_weights(profile, 'successor_weights', SUCCESSOR)
    total = sum(weights.values()); threshold = quorum_threshold(total)
    paused = profile['weighted_quorum_pause']
    live = [i for i in range(6) if i not in paused]
    survivors = [i for i in SUCCESSOR if i not in paused]
    if survivors != [4, 5] or sum(weights[i] for i in survivors) != threshold:
        raise RuntimeError('Weighted pause must retain the declared exact-quorum pair')
    rust_by_index = {n['index']: n for n in rust_nodes}
    processes = {}
    for i, node in enumerate(nodes):
        pid = rust_by_index[i]['process'].pid if i in rust_by_index else node.process_id
        processes[str(i)] = {'pid': pid, 'start_ticks': Path(f'/proc/{pid}/stat').read_text().split()[21]}

    def same_processes():
        for item in processes.values():
            path = Path(f"/proc/{item['pid']}/stat")
            if not path.exists() or path.read_text().split()[21] != item['start_ticks']:
                raise RuntimeError('Weighted quorum changed an original validator process')

    receipt = {'phase': 'pausing', 'before': checkpoint['block'], 'processes': processes,
        'paused_members': paused, 'survivor_members': survivors, 'weights': weights,
        'total_weight': total, 'quorum_weight': threshold,
        'strict_greater_threshold_for_comparison_only': total * 2 // 3 + 1,
        'same_processes': True, 'manual_database_repair': False, 'deadline_seconds': args.recovery_timeout,
        'exact_quorum_chain': 'masterchain', 'workchain_scope': 'full anchored states after all active members resume'}
    write(directory / 'receipt.json', receipt)
    started = time.monotonic(); deadline = started + args.recovery_timeout
    histories = [{} for _ in nodes]

    async def common(indices, floor):
        while time.monotonic() < deadline:
            same_processes()
            replies = await asyncio.gather(*(asyncio.to_thread(rpc, endpoints[i], 'getMasterchainInfo')
                for i in indices), return_exceptions=True)
            for i, value in zip(indices, replies):
                if isinstance(value, BaseException): continue
                if identity(value['init']) != identity(zero):
                    raise RuntimeError('Weighted quorum endpoint changed Genesis')
                histories[i][identity(value['last'])] = value
                if len(histories[i]) > 512: del histories[i][next(iter(histories[i]))]
            keys = set.intersection(*(set(histories[i]) for i in indices))
            keys = [key for key in keys if key[2] > floor]
            if keys:
                key = max(keys, key=lambda key: key[2]); infos = {i: histories[i][key] for i in indices}
                if len({value['state_root_hash'] for value in infos.values()}) != 1:
                    raise RuntimeError('Weighted quorum peers disagree on applied state')
                return infos
            await asyncio.sleep(.2)
        raise TimeoutError('Weighted quorum did not qualify within the original recovery deadline')

    async def check(infos, label, with_wc):
        target = directory / label; target.mkdir()
        anchor = 4  # active C++ survivor in both all-C++ and mixed variants
        block_id = infos[anchor]['last']
        proof = await cpp_certificate(args.snapshot, nodes[anchor], zero, block_id, target)
        proof['name'] = 'cpp-4'
        sample = {'zerostate': zero, 'reference': infos[anchor],
            'comparison': infos[next(i for i in infos if i != anchor)],
            'all_references': {str(i): v for i, v in infos.items()},
            'block': await cpp_block(args.snapshot, nodes[anchor], block_id, target),
            'masterchain_state': await native_state(args.snapshot, lite_configs[anchor], 'cpp-4', block_id, target / 'mc-state'),
            'certificates': [proof], 'governing_key_block': {**governing, 'certificates': [proof]}}
        write(target / 'sample.json', sample)
        await child_checked([args.block_checker, target / 'sample.json', target / 'checked.json'], target / 'checker.log')
        checked = json.loads((target / 'checked.json').read_text())
        check_committee_weights(checked, weights, member_id)
        if checked['key_block'] or not checked['verified_governing_key_blocks']:
            raise RuntimeError('Weighted sample lacks successor finality')
        if with_wc:
            tops = [top for top in checked['shard_tops'] if top['workchain'] == 0 and top['seqno'] > 0]
            if len(tops) != 1: raise RuntimeError('Weighted recovery requires one full workchain')
            wc = target / 'workchain'; wc.mkdir()
            sample['references'] = {str(i): infos[i] for i in SUCCESSOR}
            sample['workchain'] = {
                'block': await cpp_block(args.snapshot, nodes[anchor], tops[0], wc),
                'states': await recovery_workchain_states(args.snapshot, lite_configs, SUCCESSOR, tops[0], wc, deadline)}
            write(target / 'sample.json', sample)
            await child_checked([args.block_checker, target / 'sample.json', target / 'checked-with-workchain.json'], target / 'workchain-checker.log')
            checked = json.loads((target / 'checked-with-workchain.json').read_text())
        return checked

    stopped = []
    try:
        same_processes()
        for i in paused:
            os.kill(processes[str(i)]['pid'], signal.SIGSTOP); stopped.append(i)
        receipt['paused_at_unix'] = time.time()
        until = min(deadline, time.monotonic() + 1)
        while True:
            states = {str(i): Path(f"/proc/{processes[str(i)]['pid']}/stat").read_text().split()[2] for i in paused}
            if all(state in ['T', 't'] for state in states.values()): break
            if time.monotonic() >= until: raise TimeoutError('Owned processes did not enter stopped state')
            await asyncio.sleep(.01)
        receipt.update(phase='paused', observed_process_states=states); write(directory / 'receipt.json', receipt)
        floor = checkpoint['block']['seqno']
        while True:
            infos = await common(live, floor); floor = infos[4]['last']['seqno']
            checked = await check(infos, f'survivors-{floor}', False)
            if checked['gen_utime'] <= receipt['paused_at_unix']: continue
            expected = {member_id(i) for i in survivors}
            certificates = checked['verified_final_certificates']
            if not certificates or any(set(c['validator_ids']) != expected or c['verified_weight'] != threshold for c in certificates):
                raise RuntimeError('Fresh survivor certificate is not the exact declared weighted pair')
            receipt.update(survivor_checkpoint=checked['block'], survivor_sample=str(directory / f'survivors-{floor}'),
                survivor_certificates=certificates)
            break
    finally:
        for i in stopped:
            item = processes[str(i)]; path = Path(f"/proc/{item['pid']}/stat")
            if path.exists() and path.read_text().split()[21] == item['start_ticks']:
                os.kill(item['pid'], signal.SIGCONT)
        receipt['resumed_at_unix'] = time.time(); write(directory / 'receipt.json', receipt)

    histories = [{} for _ in nodes]
    votes, leaders = {}, {str(i): {} for i in paused}
    floor = receipt['survivor_checkpoint']['seqno']
    while len(votes) != len(paused) or any(len(v) != 2 for v in leaders.values()):
        infos = await common(list(range(6)), floor); floor = infos[4]['last']['seqno']
        checked = await check(infos, str(floor), True)
        for i in paused:
            signer = member_id(i)
            if checked['gen_utime'] > receipt['resumed_at_unix'] and any(signer in c['validator_ids'] for c in checked['verified_final_certificates']):
                votes.setdefault(str(i), {'block': checked['block'], 'sample_directory': str(directory / str(floor))})
            for chain, evidence, workchain in [('masterchain', checked, -1), ('workchain', checked['workchain_check'], 0)]:
                if evidence['created_by'] != signer or evidence['gen_utime'] <= receipt['resumed_at_unix']: continue
                item = {'block': evidence['block'], 'sample_directory': str(directory / str(floor))}
                if i in rust_by_index:
                    text = (rust_by_index[i]['directory'] / 'node.log').read_text(errors='replace')
                    match = re.search(r'^\(' + str(workchain) + r':8000000000000000, ' + str(evidence['block']['seqno']) + r'\): ValidatorGroup::on_generate_slot: .*Collation successful$', text, re.M)
                    if not match: raise RuntimeError('Recovered Rust creator lacks local collation evidence')
                    item['local_collation'] = match.group(0)
                leaders[str(i)].setdefault(chain, item)
        receipt.update(phase='waiting_for_recovered_members', votes=votes, leaders=leaders, last_checkpoint=checked['block'])
        write(directory / 'receipt.json', receipt)
    same_processes()
    if any(digest(Path(name)) != expected for name, expected in artifacts.items()):
        raise RuntimeError('Weighted quorum executable or profile changed')
    receipt.update(phase='recovered', elapsed_seconds=time.monotonic() - started,
        all_six_applied_states_match=True, workchain_states_match=True, successor_finality_checked=True,
        completed_at_unix=time.time())
    if receipt['elapsed_seconds'] > args.recovery_timeout:
        raise TimeoutError('Weighted quorum receipt exceeded the original deadline')
    write(directory / 'receipt.json', receipt)
    return receipt
