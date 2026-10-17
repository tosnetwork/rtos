#!/usr/bin/env python3
"""Real packet faults confined to a newly created user and network namespace."""
import json
import os
from pathlib import Path
import subprocess
import time

MARK = '0x52540202'
MODES = {
    'partition': ['loss', '100%'],
    'loss': ['loss', '20%'],
    'reorder': ['delay', '100ms', 'reorder', '100%', 'gap', '5'],
    'duplicate': ['duplicate', '100%'],
}


def require_namespace():
    parent = os.environ.get('RTOS_FIXTURE_PARENT_NETNS')
    parent_user = os.environ.get('RTOS_FIXTURE_PARENT_USERNS')
    current = os.readlink('/proc/self/ns/net')
    user = os.readlink('/proc/self/ns/user')
    if not parent or not parent_user or current == parent or user == parent_user or os.geteuid() != 0:
        raise RuntimeError('Packet faults require a fresh user and network namespace; host changes refused')
    return {'network': current, 'user': user, 'parent_network': parent, 'parent_user': parent_user}


def marked_environment(library):
    require_namespace()
    if os.environ.get('LD_PRELOAD'):
        raise RuntimeError('Fixture refuses to replace an existing preload environment')
    return {**os.environ, 'LD_PRELOAD': str(library), 'RTOS_FIXTURE_SOCKET_MARK': MARK}


class PacketMarks:
    """Install before nodes connect, so existing reverse flows are tagged too."""
    def __init__(self, directory):
        self.namespace = require_namespace()
        self.directory = directory
        self.directory.mkdir()
        self.rules = []
        self.commands = []

    def command(self, *args):
        result = subprocess.run(args, check=True, capture_output=True, text=True)
        self.commands.append({'argv': list(args), 'stdout': result.stdout})
        (self.directory / 'routing.json').write_text(json.dumps({
            'namespace': self.namespace, 'commands': self.commands}, indent=2) + '\n')
        return result.stdout

    def prepare(self):
        if self.command('iptables', '-t', 'mangle', '-S', 'OUTPUT').strip() != '-P OUTPUT ACCEPT':
            raise RuntimeError('Expected a fresh namespace with no output routing rules')
        try:
            for args in [
                ['-m', 'mark', '--mark', MARK, '-j', 'CONNMARK', '--save-mark'],
                ['-j', 'CONNMARK', '--restore-mark'],
            ]:
                self.command('iptables', '-t', 'mangle', '-A', 'OUTPUT', *args)
                self.rules.append(args)
        except BaseException:
            self.close()
            raise

    def close(self):
        for args in reversed(self.rules):
            self.command('iptables', '-t', 'mangle', '-D', 'OUTPUT', *args)
        self.rules.clear()


class PacketFault:
    def __init__(self, directory, mode, ports):
        self.namespace = require_namespace()
        self.directory = directory
        self.directory.mkdir()
        self.mode = mode
        self.ports = sorted(set(ports))
        if mode not in MODES or not self.ports or any(not 0 < p < 65536 for p in self.ports):
            raise ValueError('Explicit fixture mode and listening ports required')
        self.commands = []
        self.owned = False
        self.rules = []

    def command(self, *args):
        completed = subprocess.run(args, check=True, capture_output=True, text=True)
        self.commands.append({'argv': list(args), 'stdout': completed.stdout})
        self.save()
        return completed.stdout

    def save(self):
        (self.directory / 'injection.json').write_text(json.dumps({
            'namespace': self.namespace, 'mode': self.mode, 'socket_mark': MARK,
            'listening_ports': self.ports, 'commands': self.commands,
            'owned_qdisc': self.owned}, indent=2) + '\n')

    def arm(self):
        existing = json.loads(self.command('tc', '-j', 'qdisc', 'show', 'dev', 'lo'))
        if any(q['kind'] != 'noqueue' for q in existing):
            raise RuntimeError('Unexpected existing loopback qdisc; refusing replacement')
        try:
            self.command('tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'handle', '1:',
                         'prio', 'bands', '3', 'priomap', *(['0'] * 16))
            self.owned = True
            self.command('tc', 'qdisc', 'add', 'dev', 'lo', 'parent', '1:3', 'handle', '30:',
                         'netem', *MODES[self.mode])
            # Socket marks cover outgoing connections, including ephemeral TCP
            # ports. Conntrack restores marks on reverse traffic. Listening-port
            # rules also catch the first incoming packet of a new connection.
            self.command('tc', 'filter', 'add', 'dev', 'lo', 'protocol', 'all', 'parent', '1:',
                         'prio', '1', 'handle', MARK, 'fw', 'flowid', '1:3')
            for number, port in enumerate(self.ports):
                for offset, direction in enumerate(['sport', 'dport']):
                    self.command('tc', 'filter', 'add', 'dev', 'lo', 'protocol', 'ip', 'parent', '1:',
                                 'prio', str(10 + number * 2 + offset), 'u32', 'match', 'ip',
                                 direction, str(port), '0xffff', 'flowid', '1:3')
            self.armed_at = time.time()
            self.save()
        except BaseException:
            self.restore()
            raise

    def statistics(self):
        values = json.loads(self.command('tc', '-s', '-j', 'qdisc', 'show', 'dev', 'lo'))
        (self.directory / 'statistics.json').write_text(json.dumps(values, indent=2) + '\n')
        return next(q for q in values if q['kind'] == 'netem' and q['handle'] == '30:')

    def restore(self):
        try:
            if self.owned:
                current = json.loads(self.command('tc', '-j', 'qdisc', 'show', 'dev', 'lo'))
                if not any(q.get('root') and q['kind'] == 'prio' and q['handle'] == '1:' for q in current):
                    raise RuntimeError('Owned fixture qdisc changed; refusing unrelated deletion')
                self.command('tc', 'qdisc', 'del', 'dev', 'lo', 'root', 'handle', '1:')
                self.owned = False
        finally:
            self.save()
