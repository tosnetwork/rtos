"""Recover missed creator samples through authenticated full-WC ancestry."""
import asyncio
import copy
import json
import time

from mixed_matrix import child_checked, cpp_block, identity, native_state, write


def eligible_workchain(wc, phase, activation, baseline_wc_cc):
    return phase == 'before' or (wc['gen_utime'] >= activation
        and wc['gen_catchain_seqno'] > baseline_wc_cc)


async def collect_workchain_history(args, nodes, lite_configs, endpoint_names, committee,
        sample, checked, directory, deadline, missing, phase, activation, baseline_wc_cc, cache):
    """Return full checked historical samples, never just a parent-ID observation.

    The cache retains the exact original evidence path for previously checked
    bodies; it never manufactures a new checkpoint from a cached result.
    """
    missing = set(missing)
    cursor = checked.get('workchain_check')
    if not missing or cursor is None:
        return []
    if 'previous_block' not in cursor:
        raise RuntimeError('Historical WC sampling needs an ancestry-capable native checker')
    body = sample['workchain']['block']
    cache[(phase, identity(cursor['block']))] = (cursor, directory, body)
    chain = []
    results = []

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError('Historical WC sampling exceeded the original rotation deadline')
        return budget

    for _ in range(64):
        remaining()
        parent = cursor['previous_block']
        if int(parent['seqno']) == 0:
            break
        chain.append(body)
        key = (phase, identity(parent))
        if key in cache:
            cursor, target, body = cache[key]
        else:
            target = directory / ('wc-history-' + str(parent['seqno']))
            target.mkdir()
            body = await asyncio.wait_for(cpp_block(args.snapshot, nodes[0], parent, target), remaining())
            states = await asyncio.wait_for(asyncio.gather(*(native_state(args.snapshot, lite_configs[i],
                endpoint_names[i], parent, target / endpoint_names[i]) for i in committee)), remaining())
            request = copy.deepcopy(sample)
            request['workchain'] = {'block':body, 'states':states, 'anchor_chain':copy.deepcopy(chain)}
            write(target / 'sample.json', request)
            await asyncio.wait_for(child_checked([args.block_checker, target / 'sample.json',
                target / 'checked.json'], target / 'checker.log'), remaining())
            full = json.loads((target / 'checked.json').read_text())
            cursor = full['workchain_check']
            if identity(full['block']) != identity(checked['block']) \
                    or identity(cursor['block']) != identity(parent) \
                    or cursor['masterchain_anchor_links'] != len(chain) \
                    or not cursor['all_four_states_match_block_update']:
                raise RuntimeError('Historical WC native result differs from the exact checkpoint')
            cache[key] = (cursor, target, body)
        if not eligible_workchain(cursor, phase, activation, baseline_wc_cc):
            break
        if cursor['created_by'] in missing:
            results.append((cursor, target))
            missing.remove(cursor['created_by'])
            if not missing:
                break
    return results
