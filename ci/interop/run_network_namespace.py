#!/usr/bin/env python3
"""Run an isolated local fixture with no host networking or host network privileges."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    arguments = sys.argv[1:]
    if arguments and arguments[0] == '--inside':
        from network_faults import require_namespace
        require_namespace()
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        arguments = arguments[1:]
        if not arguments:
            raise SystemExit('Fixture command required')
        os.execvpe(arguments[0], arguments, os.environ)
    if not arguments:
        raise SystemExit('Fixture command required')
    env = {**os.environ, 'RTOS_FIXTURE_PARENT_NETNS': os.readlink('/proc/self/ns/net'),
           'RTOS_FIXTURE_PARENT_USERNS': os.readlink('/proc/self/ns/user'),
           'PYTHONDONTWRITEBYTECODE': '1'}
    raise SystemExit(subprocess.run(['unshare', '--user', '--map-root-user', '--net', '--',
        sys.executable, str(Path(__file__).resolve()), '--inside', *arguments], env=env).returncode)


if __name__ == '__main__':
    main()
