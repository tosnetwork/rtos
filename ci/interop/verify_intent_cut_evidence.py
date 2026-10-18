#!/usr/bin/env python3
"""Bind an actual owned intent cut to its unchanged normal recovery proof.

This complements functional/native verification; it creates no replay input and
cannot qualify the broader fault matrix or local candidate fallback mechanism.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

POINTS = ('before-write', 'after-partial-write', 'after-fsync')
MODES = ('sync-eio', 'write-enospc')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_written_prefix(raw, intended, point):
    require(bool(intended), 'empty intended record')
    if point == 'before-write':
        require(raw == b'', 'before-write bytes are not empty')
    elif point == 'after-partial-write':
        require(0 < len(raw) == len(intended) // 2 < len(intended), 'partial byte count differs')
        require(intended.startswith(raw), 'partial bytes differ from exact intended prefix')
    elif point == 'after-fsync':
        require(raw == intended, 'synced bytes differ from intended record')
    else:
        raise ValueError('unsupported cut point')


def verify(evidence, *, genesis, mode, point):
    require(mode in MODES and point in POINTS, 'unsupported declared mode/point')
    evidence = Path(evidence)
    read = lambda path: json.loads(path.read_text())
    archive = evidence / 'source-ack-recovery'
    recovery = read(archive / 'recovery/recovery.json')
    functional = read(evidence / 'functional-observations.json')
    require(functional['genesis'] == genesis, 'functional case differs')
    require(functional['independent_functional_recovery_gate_passed'], 'functional gate not passed')
    metas = list((evidence / 'builds').glob('expired-member-ack-empty-intent*-source.json'))
    require(len(metas) == 1, 'ambiguous fixture metadata')
    metadata = read(metas[0])
    require(int(metadata['genesis']) == genesis, 'fixture case differs')
    require(metadata['compiled_product_commit'] == functional['source_commit'], 'node commit differs')
    require(metadata['commit'] == functional['fixture_commit'], 'fixture commit differs')
    phases = recovery['original_recovery_acceptance']
    combined, fault = phases['source_ack_partition_restart'], phases['source_ack_fault']
    cut = combined['intent_cut']
    command = read(archive / 'source.json')['command']
    runtime = Path(command[command.index('--output') + 1])
    require(command[command.index('--source-ack-intent-cut-point') + 1] == point
            and '--source-ack-intent-stop' in command, 'command cut differs')
    require(command[command.index('--source-ack-fault') + 1] == fault['mode'] == mode
            and combined['source_ack_fault'] == mode, 'command/receipt mode differs')
    require((fault['temporary_bytes'] > 0) if mode == 'sync-eio'
            else fault['temporary_bytes'] == 0, 'ACK temporary bytes differ from declared failure')
    require(cut['point'] == point and cut['stopped_state_verified'], 'cut/stop differs')
    require(all(cut[k] for k in ['preserved_after_interruption', 'preserved_before_restart',
                                'normal_replay_completed']), 'cut not preserved or normally replayed')
    require(cut['pid'] == recovery['old_process']['pid'], 'cut process differs')
    temporary, pending = Path(cut['path']), Path(fault['pending_directory'])
    require(temporary.is_absolute() and '..' not in temporary.parts, 'noncanonical cut path')
    require(temporary.parent == pending.parent / 'finality-intents', 'cut namespace differs')
    require(temporary.is_relative_to(runtime / 'rust-5/node_db/catchains/consensus/v2'),
            'cut outside owned node')
    raw = (evidence / 'source-ack-partition/intent-before.json').read_bytes()
    intended = (evidence / 'source-ack-partition/intent-original-record.json').read_bytes()
    require(len(raw) == cut['bytes'] and digest(raw) == cut['sha256'], 'written byte fingerprint differs')
    require(len(intended) == cut['intended_bytes'] and digest(intended) == cut['intended_sha256'],
            'intended byte fingerprint differs')
    if point != 'after-fsync':
        require(intended == (evidence / 'source-ack-partition/intent-intended.json').read_bytes(),
                'observation-only intended backup differs')
    verify_written_prefix(raw, intended, point)
    record = json.loads(intended)
    require(record['schema'] == 1 and record['session_id'] == fault['session'], 'record domain differs')
    require(type(record['slot']) is int and 0 <= record['slot'] <= 0xffffffff, 'invalid slot')
    require(re.fullmatch('[0-9a-f]{64}', record['candidate_hash']), 'invalid candidate hash')
    require(temporary.name == f"{record['slot']}-{record['candidate_hash']}.tmp", 'noncanonical filename')
    require(cut['slot'] == record['slot'] and cut['candidate_hash'] == record['candidate_hash'],
            'cut identity differs')
    marker = (evidence / 'source-ack-partition/intent-stop.marker').read_text()
    require(marker == f"intent {point} pid={cut['pid']}: {temporary}\n", 'native stop marker differs')
    status = (evidence / 'source-ack-partition/intent-stopped-process.txt').read_text().splitlines()
    require(any(line.startswith('State:') and line.split()[1] == 'T' for line in status), 'process not stopped')
    require(any(line.startswith('Pid:') and int(line.split()[1]) == cut['pid'] for line in status),
            'stopped PID differs')
    completed = (evidence / 'source-ack-partition/intent-completed.json').read_bytes()
    require(digest(completed) == cut['completed_sha256']
            and json.loads(completed) == {'schema': 1, 'record': record}, 'normal completion differs')
    require(not temporary.exists() and not temporary.with_suffix('.json').exists(), 'intent still pending')
    live = temporary.parent / 'completed-v1' / temporary.with_suffix('.complete').name
    require(live.read_bytes() == completed, 'live completed proof differs')
    require(fault['native_error_observed_at_unix'] <= cut['observed_at_unix']
            <= recovery['interrupted_at_unix'], 'failure/cut/interruption order differs')
    require(combined['original_source_ack_recovered'] and combined['source_fault_removed_before_restart']
            and not combined['manual_database_repair'], 'original recovery differs')
    for receipt in phases.values():
        require(0 < receipt['elapsed_seconds'] <= receipt['recovery_limit_seconds'] == 180,
                'original deadline exceeded')
        require(receipt['budget_started_at_unix'] == fault['budget_started_at_unix'],
                'original budget changed')
    require(recovery['original_recovery_verified_at_unix']
            <= recovery['followup_intent_frontier']['budget_started_at_unix'], 'followup preceded acceptance')
    return {'genesis': genesis, 'product': functional['source_commit'],
            'fixture': functional['fixture_commit'], 'status': 'intent_cut_and_normal_replay_verified',
            'source_ack_mode': mode, 'point': point, 'written_bytes': len(raw),
            'intended_bytes': len(intended), 'pid': cut['pid'], 'slot': cut['slot'],
            'candidate_hash': cut['candidate_hash'], 'normal_replay_completed': True,
            'proof_sha256': digest(completed), 'original_budget_seconds': 180,
            'original_combined_elapsed_seconds': combined['elapsed_seconds'],
            'original_budget_extended': False, 'manual_database_repair': False,
            'broad_task_complete': False,
            'scope': 'Exact declared cut bytes and normal proof under original deadline. '
                     'Intended backup is observation only; native/functional checks remain separate.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--genesis', type=int, required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--point', choices=POINTS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.evidence, genesis=args.genesis, mode=args.mode, point=args.point)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f"Verified {args.genesis} {args.mode}/{args.point}: "
          f"{result['written_bytes']}/{result['intended_bytes']} bytes and exact normal completion.")


if __name__ == '__main__':
    main()
