"""Bounded availability faults on owned three/six-member full committees."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time

from mixed_matrix import child_checked, cpp_block, cpp_certificate, digest, identity, native_state, rpc, write
from network_faults import require_namespace
from quorum_profile import check_committee_weights, matrix_committee_size, matrix_threshold_plan, quorum_threshold


async def exercise_threshold_fault(args, root, nodes, endpoints, lite_configs, rust_nodes,
                                   zero, genesis_boc, checkpoint, artifacts, profile, deadline):
    from rotation_fixture import recovery_workchain_states
    namespace = require_namespace()
    count = matrix_committee_size(profile, args.cpp_count)
    plan = matrix_threshold_plan(profile, args.cpp_count)
    directory = root / 'threshold-fault'; directory.mkdir()
    rust = {n['index']: n for n in rust_nodes}
    weights = {i: 17 for i in range(count)}
    member_id = lambda i: base64.b64encode(hashlib.sha256(f'n6-validator-id-{i}'.encode()).digest()).decode()
    quorum = quorum_threshold(17 * count)
    survivors = [i for i in range(count) if i not in plan['pause_at_quorum']]
    below = [i for i in survivors if i not in plan['pause_below_quorum']]
    if sum(weights[i] for i in survivors) != quorum or sum(weights[i] for i in below) >= quorum:
        raise RuntimeError('Declared availability stages do not straddle the pinned CPP quorum')
    processes = {}
    for i, node in enumerate(nodes):
        pid = rust[i]['process'].pid if i in rust else node.process_id
        processes[str(i)] = {'pid': pid, 'start_ticks': Path(f'/proc/{pid}/stat').read_text().split()[21]}
    started = time.monotonic()
    receipt = {'phase': 'starting', 'plan': plan, 'namespace': namespace, 'processes': processes,
        'before': checkpoint['block'], 'validator_count': count, 'total_weight': count * 17,
        'quorum_weight': quorum, 'survivor_members': survivors, 'below_quorum_members': below,
        'below_quorum_weight': len(below) * 17, 'available_budget_seconds': deadline - started,
        'same_processes': True, 'manual_database_repair': False,
        'negative_scope': 'no observed finalized MC head advance during the declared bounded window',
        'workchain_scope': 'complete state on every active endpoint, block update and authenticated MC anchor'}
    stopped = set()
    histories = [{} for _ in nodes]

    def audit():
        states = {}
        for i, item in processes.items():
            path = Path(f"/proc/{item['pid']}/stat")
            if not path.exists(): raise RuntimeError('Original validator process disappeared')
            stat = path.read_text().split()
            if stat[21] != item['start_ticks'] or stat[2] == 'Z':
                raise RuntimeError('Original validator process changed or exited')
            states[i] = stat[2]
            if int(i) in stopped and stat[2] not in ('T', 't'):
                raise RuntimeError('An owned paused validator resumed unexpectedly')
        return states

    def budget():
        if time.monotonic() >= deadline:
            raise TimeoutError('Threshold sequence exceeded the original matrix deadline')

    async def pause(indices):
        audit(); new = []
        for i in indices:
            os.kill(processes[str(i)]['pid'], signal.SIGSTOP); new.append(i); stopped.add(i)
        until = min(deadline, time.monotonic() + 1)
        while True:
            states = {str(i): Path(f"/proc/{processes[str(i)]['pid']}/stat").read_text().split()[2] for i in new}
            if all(state in ('T', 't') for state in states.values()): break
            if time.monotonic() >= until: raise TimeoutError('Owned validator did not stop')
            await asyncio.sleep(.01)
        stopped.update(new)
        return audit()

    async def common(indices, floor):
        while True:
            budget(); audit()
            values = await asyncio.gather(*(asyncio.to_thread(rpc, endpoints[i], 'getMasterchainInfo')
                for i in indices), return_exceptions=True)
            for i, value in zip(indices, values):
                if isinstance(value, BaseException): continue
                if identity(value['init']) != identity(zero): raise RuntimeError('Endpoint changed Genesis')
                histories[i][identity(value['last'])] = value
                if len(histories[i]) > 512: del histories[i][next(iter(histories[i]))]
            common_keys = set.intersection(*(set(histories[i]) for i in indices))
            keys = [key for key in common_keys if key[2] > floor]
            if keys:
                key = max(keys, key=lambda key: key[2]); infos = {i: histories[i][key] for i in indices}
                if len({info['state_root_hash'] for info in infos.values()}) != 1:
                    raise RuntimeError('Applied states differ across live endpoints')
                return infos
            await asyncio.sleep(.2)

    async def check(infos, label, with_wc):
        budget(); target = directory / label; target.mkdir()
        block_id = infos[0]['last']
        proof = await cpp_certificate(args.snapshot, nodes[0], zero, block_id, target)
        sample = {'fixture_validator_count': count, 'zerostate': zero, 'reference': infos[0],
            'comparison': infos[next(i for i in infos if i != 0)],
            'all_references': {str(i): v for i, v in infos.items()},
            'block': await cpp_block(args.snapshot, nodes[0], block_id, target),
            'masterchain_state': await native_state(args.snapshot, lite_configs[0], '0', block_id, target / 'mc-state'),
            'certificates': [proof], 'governing_zerostate_boc': genesis_boc}
        write(target / 'sample.json', sample)
        await child_checked([args.block_checker, target / 'sample.json', target / 'checked.json'], target / 'checker.log')
        checked = json.loads((target / 'checked.json').read_text())
        check_committee_weights(checked, weights, member_id)
        if with_wc:
            tops = [top for top in checked['shard_tops'] if top['workchain'] == 0 and top['seqno'] > 0]
            if len(tops) != 1: raise RuntimeError('Expected one full workchain anchor')
            wc = target / 'workchain'; wc.mkdir()
            sample['references'] = {str(i): infos[i] for i in range(count)}
            sample['workchain'] = {'block': await cpp_block(args.snapshot, nodes[0], tops[0], wc),
                'states': await recovery_workchain_states(args.snapshot, lite_configs, range(count), tops[0], wc, deadline)}
            write(target / 'sample.json', sample)
            await child_checked([args.block_checker, target / 'sample.json', target / 'checked-with-workchain.json'], target / 'workchain-checker.log')
            checked = json.loads((target / 'checked-with-workchain.json').read_text())
        budget()
        return checked

    async def heads(indices):
        budget(); audit()
        values = await asyncio.gather(*(asyncio.to_thread(rpc, endpoints[i], 'getMasterchainInfo') for i in indices))
        if any(identity(v['init']) != identity(zero) for v in values): raise RuntimeError('Negative observation changed Genesis')
        return {str(i): v for i, v in zip(indices, values)}

    write(directory / 'receipt.json', receipt)
    try:
        budget()
        receipt['quorum_stop_states'] = await pause(plan['pause_at_quorum'])
        receipt['quorum_paused_at_unix'] = time.time()
        floor = checkpoint['block']['seqno']
        while True:
            infos = await common(survivors, floor); floor = infos[0]['last']['seqno']
            checked = await check(infos, f'exact-{floor}', False)
            if checked['gen_utime'] <= receipt['quorum_paused_at_unix']: continue
            expected = {member_id(i) for i in survivors}
            certs = checked['verified_final_certificates']
            if not certs or any(set(c['validator_ids']) != expected or c['verified_weight'] != quorum for c in certs):
                raise RuntimeError('Fresh exact-threshold certificate lacks the declared necessary members')
            receipt.update(phase='exact_quorum_verified', survivor_checkpoint=checked['block'],
                survivor_certificates=certs, survivor_sample=f'exact-{floor}')
            write(directory / 'receipt.json', receipt); break
        receipt['below_stop_states'] = await pause(plan['pause_below_quorum'])
        receipt['below_paused_at_unix'] = time.time()
        settle_end = time.monotonic() + plan['settle_seconds']
        while time.monotonic() < settle_end:
            budget(); audit(); await asyncio.sleep(.1)
        baseline = await heads(below)
        if len({identity(v['last']) for v in baseline.values()}) != 1 or len({v['state_root_hash'] for v in baseline.values()}) != 1:
            raise RuntimeError('Below-quorum observers did not converge before the fixed observation')
        if any(v['last']['seqno'] < receipt['survivor_checkpoint']['seqno'] for v in baseline.values()):
            raise RuntimeError('Below-quorum observation regressed behind the certified checkpoint')
        observation_started = time.monotonic(); end = observation_started + plan['observe_seconds']; observations = []
        receipt.update(phase='observing_below_quorum', below_baseline=baseline)
        write(directory / 'receipt.json', receipt)
        while time.monotonic() < end:
            values = await heads(below)
            if any(identity(value['last']) != identity(baseline[i]['last']) or value['state_root_hash'] != baseline[i]['state_root_hash'] for i, value in values.items()):
                raise RuntimeError('A below-quorum finalized head advanced during the declared observation')
            observations.append({'elapsed_seconds': time.monotonic() - observation_started,
                'references': values, 'process_states': audit()})
            write(directory / 'negative-observation.json', observations)
            await asyncio.sleep(.2)
        budget()
        final_heads = await heads(below)
        if any(identity(v['last']) != identity(baseline[i]['last']) or v['state_root_hash'] != baseline[i]['state_root_hash'] for i, v in final_heads.items()):
            raise RuntimeError('Below-quorum finalized head changed at the observation boundary')
        receipt.update(phase='below_quorum_observed', observation_elapsed_seconds=time.monotonic()-observation_started,
            observation_count=len(observations), below_final_references=final_heads)
        write(directory / 'receipt.json', receipt)
    finally:
        for i in sorted(stopped):
            item = processes[str(i)]; path = Path(f"/proc/{item['pid']}/stat")
            if path.exists() and path.read_text().split()[21] == item['start_ticks']:
                os.kill(item['pid'], signal.SIGCONT)
        stopped.clear()
        receipt['resumed_at_unix'] = time.time(); write(directory / 'receipt.json', receipt)
    histories = [{} for _ in nodes]
    restored = sorted(set(plan['pause_at_quorum'] + plan['pause_below_quorum']))
    votes, leaders = {}, {str(i): {} for i in restored}
    floor = max(v['last']['seqno'] for v in receipt['below_final_references'].values())
    while len(votes) != len(restored) or any(len(v) != 2 for v in leaders.values()):
        infos = await common(list(range(count)), floor); floor = infos[0]['last']['seqno']
        checked = await check(infos, f'restored-{floor}', True)
        for i in restored:
            signer = member_id(i)
            if checked['gen_utime'] > receipt['resumed_at_unix'] and any(signer in c['validator_ids'] for c in checked['verified_final_certificates']):
                votes.setdefault(str(i), {'block': checked['block'], 'sample': f'restored-{floor}'})
            for chain, evidence, wc in [('masterchain', checked, -1), ('workchain', checked['workchain_check'], 0)]:
                if evidence['created_by'] != signer or evidence['gen_utime'] <= receipt['resumed_at_unix']: continue
                item = {'block': evidence['block'], 'sample': f'restored-{floor}'}
                if i in rust:
                    text = (rust[i]['directory'] / 'node.log').read_text(errors='replace')
                    match = re.search(r'^\(' + str(wc) + r':8000000000000000, ' + str(evidence['block']['seqno']) + r'\): ValidatorGroup::on_generate_slot: .*Collation successful$', text, re.M)
                    if not match: raise RuntimeError('Restored Rust creator lacks local collation evidence')
                    item['local_collation'] = match.group(0)
                leaders[str(i)].setdefault(chain, item)
        receipt.update(phase='waiting_for_restored_members', votes=votes, leaders=leaders, final_checkpoint=checked['block'])
        write(directory / 'receipt.json', receipt)
    audit(); budget()
    if any(digest(Path(name)) != expected for name, expected in artifacts.items()):
        raise RuntimeError('Threshold fixture artifact changed during validation')
    receipt.update(phase='recovered', elapsed_seconds=time.monotonic()-started,
        all_declared_mc_states_match=True, all_declared_wc_states_match=True, completed_at_unix=time.time())
    write(directory / 'receipt.json', receipt)
    return receipt
