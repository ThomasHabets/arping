#!/usr/bin/env python3
"""Inject failures into the actual binary in the tests/run namespaces."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def check_failure(library, fault, options, after=0, status=1, output=''):
    sender = ([] if os.environ.get('ARPING_ROOTLESS') == 'yes'
              else ['ip', 'netns', 'exec', 'arping_test0'])
    result = subprocess.run(
        sender + ['env', f'LD_PRELOAD={library}', f'ARPING_TEST_FAIL={fault}',
                  f'ARPING_TEST_FAIL_AFTER={after}', './src/arping', '-Z',
                  '-i', 'veth0', '-W', '0.01', '-c', '2'] + options,
        capture_output=True, text=True, timeout=5)
    expected = f'injected {fault} failure'
    if (result.returncode != status or expected not in result.stderr
            or output not in result.stdout):
        raise AssertionError(
            f'{fault}, {options}, after={after}: exit {result.returncode}; '
            f'output {result.stdout!r}; stderr {result.stderr!r}')
    print(f'PASS: {fault}, {options}, after={after}')


def main():
    with tempfile.TemporaryDirectory(prefix='arping-faults-') as directory:
        library = str(Path(directory) / 'faults.so')
        subprocess.run(
            shlex.split(os.environ.get('CC', 'cc'))
            + ['-Wall', '-Wextra', '-shared', '-fPIC', 'tests/faults.c',
               '-o', library, '-ldl'], check=True)
        ip = ['-P', '192.0.2.102']
        mac = ['-T', '192.0.2.102', 'ff:ff:ff:ff:ff:ff']
        cases = [
            ('libnet_build_arp', ip),
            ('libnet_build_icmpv4_echo', mac),
            ('libnet_build_ipv4', mac),
            ('libnet_build_ethernet', ip),
            ('libnet_build_ethernet', mac),
            ('libnet_build_802_1q', ['-V', '7'] + ip),
            ('libnet_build_802_1q', ['-V', '7'] + mac),
        ]
        for fault, options in cases:
            for after in (0, 1):
                check_failure(library, fault, options, after)
        check_failure(library, 'select', ['-d', '-q', '192.0.2.102'])
        check_failure(library, 'select-after-reply', ['-W', '0.1', '192.0.2.101'],
                      output='index=0 time=')
        check_failure(library, 'select-eintr', ['-W', '0.1', '192.0.2.101'], status=0,
                      output='2 packets received')


if __name__ == '__main__':
    main()
