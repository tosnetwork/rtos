#!/usr/bin/env python3
"""Compare an independently started Rust node with existing local C++ nodes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

active_output = None


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(block):
    return (int(block['workchain']), int(block['shard']), int(block['seqno']),
            block['root_hash'], block['file_hash'])


def rpc(url, method, params=None):
    body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params or {})).encode()
    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.load(response)
    if value.get('error') or value.get('ok') is False or 'result' not in value:
        raise RuntimeError(f'{method} failed at {url}: {value}')
    return value['result']


def reference(urls, zero, timeout):
    deadline = time.monotonic() + timeout
    while True:
        observations = [rpc(url, 'getMasterchainInfo') for url in urls]
        if any(identity(item['init']) != identity(zero) for item in observations):
            raise RuntimeError('C++ reference does not match the configured zerostate')
        if (all(identity(item['last']) == identity(observations[0]['last']) and
                item['state_root_hash'] == observations[0]['state_root_hash'] for item in observations)
                and int(observations[0]['last']['seqno']) > 0):
            return observations
        if time.monotonic() >= deadline:
            raise TimeoutError('C++ reference nodes did not agree on a produced block/state checkpoint')
        time.sleep(0.2)


def main():
    global active_output
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--global-config', type=Path, required=True)
    parser.add_argument('--cpp-rpc', action='append', required=True)
    parser.add_argument('--rust-node', type=Path, required=True)
    parser.add_argument('--block-checker', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if len(set(args.cpp_rpc)) < 2:
        parser.error('provide at least two distinct C++ observer RPC endpoints')
    if not args.prepare_only and args.block_checker is None:
        parser.error('--block-checker is required for the actual comparison')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    active_output = root
    rust = root / 'rust'
    rust.mkdir()
    config_bytes = args.global_config.read_bytes()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    config = json.loads(config_bytes)
    zero = config['validator']['zero_state']
    if identity(zero)[:3] != (-1, -(2**63), 0):
        raise ValueError('global config must pin a masterchain zerostate')
    (rust / 'global.json').write_bytes(config_bytes)
    sources = dict(global_config=str(args.global_config.resolve()), global_config_sha256=config_hash,
                   zerostate=zero, cpp_rpc=args.cpp_rpc, rust_binary=str(args.rust_node.resolve()),
                   rust_binary_sha256=digest(args.rust_node), driver_sha256=digest(Path(__file__)))
    if args.block_checker is not None:
        sources.update(block_checker=str(args.block_checker.resolve()), block_checker_sha256=digest(args.block_checker))
    (root / 'source.json').write_text(json.dumps(sources, indent=2) + '\n')
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
    sockets.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    try:
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        default = dict(log_config_name='node-log.yml', ton_global_config_name='global.json',
                       internal_db_path=str(rust / 'node_db'), boot_from_zerostate=True,
                       restore_db=True, archival_mode=None,
                       json_rpc_server={'address': '127.0.0.1:' + str(sockets[2].getsockname()[1])},
                       ip_address='127.0.0.1:' + str(sockets[0].getsockname()[1]),
                       ip_address_quic='127.0.0.1:' + str(sockets[1].getsockname()[1]))
        (rust / 'default_config.json').write_text(json.dumps(default, indent=2) + '\n')
    finally:
        for sock in sockets:
            sock.close()
    (rust / 'node-log.yml').write_text(
        "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\n"
        "root:\n  level: info\n  appenders: [console]\n")
    observations = reference(args.cpp_rpc, zero, min(args.timeout, 30))
    checkpoint = observations[0]
    (root / 'reference.json').write_text(json.dumps(observations, indent=2) + '\n')
    result = dict(status='prepared', checkpoint=checkpoint['last'], active_signing_qualified=False)
    (root / 'status.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.prepare_only:
        print(json.dumps(result))
        return
    process = None
    rust_rpc = 'http://' + default['json_rpc_server']['address'] + '/jsonRPC'
    checkpoints = {identity(checkpoint['last']): observations}
    try:
        if not (rust / 'config.json').exists():
            # The node creates config.json from default_config.json and exits.
            with (rust / 'node-generate.log').open('w') as log:
                subprocess.run([str(args.rust_node.resolve()), '--configs', str(rust)], cwd=rust,
                               stdout=log, stderr=log, check=True, timeout=60)
        with (rust / 'node.log').open('w') as log:
            command = [str(args.rust_node.resolve()), '--configs', str(rust), '--initial-sync-disabled']
            process = subprocess.Popen(command, cwd=rust, stdout=log, stderr=log,
                env={**os.environ, 'TOKIO_WORKER_THREADS': '2'}, start_new_session=True)
            (root / 'process.json').write_text(json.dumps(dict(pid=process.pid, command=command,
                start_ticks=Path(f'/proc/{process.pid}/stat').read_text().split()[21])) + '\n')
            floor = int(checkpoint['last']['seqno']) + 2
            deadline = time.monotonic() + args.timeout
            while True:
                if digest(args.global_config) != config_hash:
                    raise RuntimeError('source global config changed; prepare a fresh comparison')
                if process.poll() is not None:
                    raise RuntimeError(f'Rust exited {process.returncode}; see rust/node.log')
                if time.monotonic() >= deadline:
                    raise TimeoutError(f'Rust did not match a C++ block/state checkpoint at or beyond MC{floor}')
                try:
                    current = [rpc(url, 'getMasterchainInfo') for url in args.cpp_rpc]
                    rust_info = rpc(rust_rpc, 'getMasterchainInfo')
                except (OSError, RuntimeError) as error:
                    result.update(status='running', last_rpc_error=str(error), observed_unix=time.time())
                    (root / 'status.json').write_text(json.dumps(result, indent=2) + '\n')
                    time.sleep(0.5)
                    continue
                if any(identity(item['init']) != identity(zero) for item in [*current, rust_info]):
                    raise RuntimeError('a running node advertises a different zerostate identity')
                if all(identity(item['last']) == identity(current[0]['last']) and
                       item['state_root_hash'] == current[0]['state_root_hash'] for item in current):
                    checkpoints[identity(current[0]['last'])] = current
                if len(checkpoints) > 1024:
                    del checkpoints[next(iter(checkpoints))]
                height = int(rust_info['last']['seqno'])
                key = identity(rust_info['last'])
                result.update(status='running', rust_observed_height=height, observed_unix=time.time())
                (root / 'status.json').write_text(json.dumps(result, indent=2) + '\n')
                if height >= floor and key in checkpoints:
                    reference_sample = checkpoints[key]
                    block = rpc(rust_rpc, 'getBlock', {k: rust_info['last'][k]
                        for k in ['workchain', 'shard', 'seqno', 'root_hash', 'file_hash']})
                    sample = dict(zerostate=zero, reference=reference_sample[0], references=reference_sample,
                                  rust=rust_info, block=block)
                    (root / 'sample.json').write_text(json.dumps(sample, indent=2) + '\n')
                    with (root / 'block-check.log').open('w') as checked:
                        subprocess.run([str(args.block_checker.resolve()), str(root / 'sample.json'),
                                        str(root / 'block-check.json')], check=True, timeout=60,
                                       stdout=checked, stderr=subprocess.STDOUT)
                    break
                time.sleep(0.5)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    inspected = json.loads((root / 'block-check.json').read_text())
    if inspected['status'] != 'block_and_state_match':
        raise RuntimeError('block and state check did not confirm the checkpoint')
    for url in args.cpp_rpc:
        item = rpc(url, 'lookupBlock', {k: inspected['block'][k] for k in ['workchain', 'shard', 'seqno']})
        if identity(item) != identity(inspected['block']):
            raise RuntimeError('C++ no longer agrees with the matched block identity')
    if digest(args.global_config) != config_hash:
        raise RuntimeError('source global config changed during comparison')
    if digest(args.rust_node) != sources['rust_binary_sha256'] or digest(args.block_checker) != sources['block_checker_sha256']:
        raise RuntimeError('a Rust program changed during comparison')
    result.update(status='block_and_state_checkpoint_match', block_check=inspected,
                  shutdown_returncode=process.returncode, cpp_checkpoint_identity_matches=True,
                  mixed_validator_qualified=False)
    (root / 'status.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    try:
        main()
    except BaseException as error:
        # Each run has a fresh directory. Preserve the failure beside its logs.
        if active_output is not None:
            failure = json.dumps(dict(status='failed', error_type=type(error).__name__, error=str(error)), indent=2) + '\n'
            (active_output / 'failure.json').write_text(failure)
            (active_output / 'status.json').write_text(failure)
        raise
