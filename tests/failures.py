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
    statistics = (f'{after} packets transmitted, 0 packets received'
                  if fault.startswith('libnet_build_') else output)
    fatal_clock = fault.startswith('clock') and fault != 'clock-fallback'
    if (result.returncode != status or expected not in result.stderr
            or statistics not in result.stdout
            or ('-q' in options and result.stdout)
            or (fatal_clock and ('statistics' in result.stdout
                                 or 'gettimeofday():' not in result.stderr))):
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
        check_failure(library, 'select', ['-d', '192.0.2.102'],
                      output='1 packets transmitted, 0 packets received')
        check_failure(library, 'select', ['-d', '-q', '192.0.2.102'])
        check_failure(library, 'select-after-reply', ['-W', '0.1', '192.0.2.101'],
                      output='1 packets transmitted, 1 packets received')
        check_failure(library, 'select-eintr', ['-W', '0.1', '192.0.2.101'], status=0,
                      output='2 packets transmitted, 2 packets received')

        for fault in ('pcap-fd', 'pcap-fd-limit'):
            check_failure(library, fault, ['-d', '192.0.2.102'],
                          output='1 packets transmitted, 0 packets received')
        check_failure(library, 'pcap-dispatch', ['-W', '0.1', '192.0.2.101'],
                      output='1 packets transmitted, 1 packets received')
        check_failure(library, 'clock', ['-P', '-vv', '192.0.2.102'])
        check_failure(library, 'clock', ip)
        check_failure(library, 'clock', mac)
        check_failure(library, 'clock', ['-w', '1'] + ip)
        check_failure(library, 'clock', ['-q'] + ip)
        check_failure(library, 'clock', ['192.0.2.102'], after=1)
        check_failure(library, 'clock', ['192.0.2.102'], after=2)
        check_failure(library, 'clock', ['-w', '1'] + ip, after=1)
        check_failure(library, 'clock', ['-w', '1'] + ip, after=3)
        check_failure(library, 'clock-on-reply', ['-W', '0.1', '192.0.2.101'])
        check_failure(library, 'clock-after-reply', ['-W', '0.1', '192.0.2.101'])
        check_failure(library, 'clock-fallback', ip, status=0,
                      output='2 packets transmitted, 0 packets received')
        unicast_mac = ['-W', '0.1', '-T', '192.0.2.101', '00:01:02:33:44:01']
        check_failure(library, 'clock-on-reply', unicast_mac)
        check_failure(library, 'clock-fallback', unicast_mac, status=0,
                      output='2 packets transmitted, 2 packets received')


if __name__ == '__main__':
    main()
