#!/usr/bin/env python3
"""Exercise native historical-WC checks using two adjacent real checkpoints.

Both input samples must already carry native blocks, certificates and full states.
No network, key material, or live database is required.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def exercise(checker, anchor_sample, target_sample, output, baseline=None):
    output.mkdir(parents=True, exist_ok=False)
    anchor = json.loads(anchor_sample.read_text())
    target = json.loads(target_sample.read_text())
    positive = copy.deepcopy(anchor)
    positive['workchain'] = copy.deepcopy(target['workchain'])
    positive['workchain']['anchor_chain'] = [anchor['workchain']['block']]
    cases = []

    def run(name, sample, binary, succeeds, reason=None):
        request = output / (name + '.json')
        request.write_text(json.dumps(sample, indent=2) + '\n')
        result = output / (name + '-checked.json')
        process = subprocess.run([str(binary), str(request), str(result)], capture_output=True, text=True)
        (output / (name + '.log')).write_text(process.stdout + process.stderr)
        assert (process.returncode == 0) == succeeds, (name, process.stderr)
        if reason:
            assert reason in process.stderr, (name, process.stderr)
        if succeeds:
            checked = json.loads(result.read_text())['workchain_check']
            assert checked['all_four_states_match_block_update'] is True
            assert checked['masterchain_anchor_links'] == (1 if name == 'historical-positive' else 0)
            assert checked['previous_block']['seqno'] + 1 == checked['block']['seqno']
        cases.append(dict(name=name, returncode=process.returncode, expected_pass=succeeds, reason=reason))

    if baseline:
        run('old-causal-red', positive, baseline, False, 'not anchored')
    run('historical-positive', positive, checker, True)
    sample = copy.deepcopy(positive)
    sample['workchain'].pop('anchor_chain')
    run('missing-chain', sample, checker, False, 'not anchored')
    sample = copy.deepcopy(positive)
    sample['workchain']['anchor_chain'][0]['boc'] = target['workchain']['block']['boc']
    run('wrong-anchor-body', sample, checker, False, 'anchor file hash differs')
    sample = copy.deepcopy(positive)
    sample['workchain']['anchor_chain'] *= 2
    run('duplicate-link', sample, checker, False, 'link identity or order differs')
    sample = copy.deepcopy(positive)
    sample['workchain']['anchor_chain'] *= 65
    run('over-bound', sample, checker, False, 'exceeds fixture bound')
    sample = copy.deepcopy(positive)
    sample['workchain']['states'].pop()
    run('missing-endpoint-state', sample, checker, False, 'exactly one workchain state')
    sample = copy.deepcopy(positive)
    sample['workchain']['block']['id']['file_hash'] = anchor['workchain']['block']['id']['file_hash']
    run('wrong-exact-target', sample, checker, False, 'does not reach the exact target')
    sample = copy.deepcopy(positive)
    sample['workchain']['anchor_chain'] = 'invalid'
    run('nonarray-chain', sample, checker, False, 'chain array required')
    run('direct-top', anchor, checker, True)
    summary = dict(checker_sha256=hashlib.sha256(checker.read_bytes()).hexdigest(), cases=cases)
    (output / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', required=True, type=Path)
    parser.add_argument('--anchor-sample', required=True, type=Path)
    parser.add_argument('--target-sample', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--baseline-checker', type=Path)
    args = parser.parse_args()
    result = exercise(args.checker, args.anchor_sample, args.target_sample, args.output, args.baseline_checker)
    print('Historical WC native cases passed:', len(result['cases']))
