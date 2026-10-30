#!/usr/bin/env python3
"""Exercise failures and argument validation in the tests/run namespaces."""

import os
from pathlib import Path
import shlex
import select
import signal
import subprocess
import tempfile
import time


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
    fatal_clock = (fault == 'wall-clock'
                   or (fault.startswith('clock') and (fault != 'clock-fallback'
                                                       or after > 0)))
    clock_error = ('gettimeofday():' if fault == 'wall-clock'
                   or (fault == 'clock' and after == 0)
                   else 'clock_gettime():')
    if (result.returncode != status or expected not in result.stderr
            or statistics not in result.stdout
            or ('-q' in options and result.stdout)
            or (fatal_clock and ('statistics' in result.stdout
                                 or clock_error not in result.stderr))):
        raise AssertionError(
            f'{fault}, {options}, after={after}: exit {result.returncode}; '
            f'output {result.stdout!r}; stderr {result.stderr!r}')
    print(f'PASS: {fault}, {options}, after={after}')


def check_group(value, status):
    sender = ([] if os.environ.get('ARPING_ROOTLESS') == 'yes'
              else ['ip', 'netns', 'exec', 'arping_test0'])
    result = subprocess.run(
        sender + ['./src/arping', '-Z', '-i', 'veth0', '-P', '-c', '0',
                  '-g', value, '192.0.2.102'],
        capture_output=True, text=True, timeout=5)
    if (result.returncode != status or (status and not result.stderr)
            or (not status and '0 packets transmitted' not in result.stdout)):
        raise AssertionError(
            f'group {value}: exit {result.returncode}, want {status}; '
            f'output {result.stdout!r}; stderr {result.stderr!r}')
    print(f'PASS: group {value}, exit={status}')


def check_capture_time(library, options, timestamp_type='host', sandbox='-Z'):
    sender = ([] if os.environ.get('ARPING_ROOTLESS') == 'yes'
              else ['ip', 'netns', 'exec', 'arping_test0'])
    result = subprocess.run(
        sender + ['env', f'LD_PRELOAD={library}', 'ARPING_TEST_FAIL=capture-time',
                  './src/arping', sandbox, '-i', 'veth0', '-m', timestamp_type,
                  '-c', '2', '-W', '0.01', '-w', '1'] + options,
        capture_output=True, text=True, timeout=5)
    # The capture and send timestamps are fixed, while callbacks are delayed.
    # Check both per-reply output and statistics, including microsecond scaling.
    expected = 'rtt min/avg/max/std-dev = 1234.567/1234.567/1234.567/0.000 ms'
    if (result.returncode or expected not in result.stdout
            or result.stdout.count('time=1.235 sec') != 2
            or '2 packets transmitted, 2 packets received' not in result.stdout):
        raise AssertionError(
            f'capture timestamps, {timestamp_type}, {sandbox}, {options}: '
            f'exit {result.returncode}; output {result.stdout!r}; '
            f'stderr {result.stderr!r}')
    print(f'PASS: capture timestamps, {timestamp_type}, {sandbox}, {options}')


def check_unsynchronized_type(timestamp_type):
    sender = ([] if os.environ.get('ARPING_ROOTLESS') == 'yes'
              else ['ip', 'netns', 'exec', 'arping_test0'])
    result = subprocess.run(
        sender + ['./src/arping', '-Z', '-i', 'veth0', '-m', timestamp_type,
                  '-P', '-c', '0', '192.0.2.102'],
        capture_output=True, text=True, timeout=5)
    # Older libpcap versions might not know these names at all.
    if (result.returncode != 1
            or not any(message in result.stderr for message in
                       ('not synchronized', 'Unknown timestamp type'))):
        raise AssertionError(
            f'unsynchronized type {timestamp_type}: exit {result.returncode}; '
            f'stderr {result.stderr!r}')
    print(f'PASS: reject unsynchronized timestamp type {timestamp_type}')


def check_interrupt(library, options, sandbox):
    sender = ([] if os.environ.get('ARPING_ROOTLESS') == 'yes'
              else ['ip', 'netns', 'exec', 'arping_test0'])
    read_fd, write_fd = os.pipe()
    # The first packet wait consumes our outgoing probe on Linux. Interrupt
    # the next wait, when select would otherwise sleep on an empty capture fd.
    after = 0 if '-P' in options else 1
    process = subprocess.Popen(
        sender + ['env', f'LD_PRELOAD={library}', 'ARPING_TEST_FAIL=wait-sigint',
                  f'ARPING_TEST_FAIL_AFTER={after}',
                  f'ARPING_TEST_INTERRUPT_FD={read_fd}', './src/arping', sandbox,
                  '-i', 'veth0', '-c', '1', '-W', '10'] + options,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(read_fd,))
    os.close(read_fd)
    stderr = b''
    try:
        deadline = time.monotonic() + 3
        while b'injected wait-sigint failure' not in stderr:
            wait = deadline - time.monotonic()
            if wait <= 0 or not select.select([process.stderr], [], [], wait)[0]:
                raise AssertionError('interrupt hook did not become ready')
            chunk = os.read(process.stderr.fileno(), 4096)
            if not chunk:
                raise AssertionError(f'interrupt hook exited early: {stderr!r}')
            stderr += chunk
        os.kill(process.pid, signal.SIGINT)
        os.write(write_fd, b'1')
        stdout, remaining_stderr = process.communicate(timeout=2)
        stderr += remaining_stderr
        expected_status = 0 if '-P' in options else 1
        if (process.returncode != expected_status or b'Timeout' in stdout
                or ('-q' in options and stdout)
                or ('-q' not in options
                    and b'1 packets transmitted, 0 packets received' not in stdout)):
            raise AssertionError(
                f'interrupt, {sandbox}, {options}: exit {process.returncode}; '
                f'output {stdout!r}; stderr {stderr!r}')
        print(f'PASS: interrupt before wait, {sandbox}, {options}')
    finally:
        os.close(write_fd)
        if process.poll() is None:
            process.kill()
        process.communicate()


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
        check_failure(library, 'pselect', ['-d', '192.0.2.102'],
                      output='1 packets transmitted, 0 packets received')
        check_failure(library, 'pselect', ['-d', '-q', '192.0.2.102'])
        check_failure(library, 'pselect', ip,
                      output='1 packets transmitted, 0 packets received')
        check_failure(library, 'pselect-after-reply', ['-W', '0.1', '192.0.2.101'],
                      output='1 packets transmitted, 1 packets received')
        check_failure(library, 'pselect-eintr', ['-W', '0.1', '192.0.2.101'], status=0,
                      output='2 packets transmitted, 2 packets received')
        for options in (['192.0.2.102'], ['-q', '192.0.2.102'],
                        ['-P', '192.0.2.102'], mac):
            for sandbox in ('-Z', '-z'):
                check_interrupt(library, options, sandbox)

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
        # A late monotonic failure must not mix uptime with Unix time,
        # even when gettimeofday would succeed.
        check_failure(library, 'clock-fallback', ['-w', '1'] + ip, after=1)
        check_failure(library, 'clock-fallback', ['192.0.2.101'], after=1)
        check_failure(library, 'clock-fallback', unicast_mac, after=1)
        for options in (['192.0.2.101'], unicast_mac):
            for sandbox in ('-Z', '-z'):
                check_capture_time(library, options, sandbox=sandbox)
            # Unsupported synchronized types fall back to default capture
            # timestamps, which must still be used for RTT measurements.
            check_capture_time(library, options, timestamp_type='host_hiprec')
            check_failure(library, 'wall-clock', ['-m', 'host'] + options)
    for timestamp_type in ('adapter_unsynced', 'host_hiprec_unsynced'):
        check_unsynchronized_type(timestamp_type)
    # Values above 32-bit ULONG_MAX must not wrap into another group ID.
    for value in ('4294967296', '4294967297', '18446744073709551615'):
        check_group(value, 1)
    for value in ('0', '1', '2147483647'):
        check_group(value, 0)


if __name__ == '__main__':
    main()
