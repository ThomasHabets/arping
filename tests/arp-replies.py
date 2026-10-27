#!/usr/bin/env python3
"""Exercise ARP reply fields using the namespaces created by tests/run."""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def respond():
    replies = json.loads(sys.stdin.readline())
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('veth1', 0))
        sock.settimeout(5)
        print('ready', flush=True)
        while True:
            packet = sock.recv(2048)
            if (len(packet) >= 42 and packet[12:14] == b'\x08\x06'
                    and packet[20:22] == b'\x00\x01'
                    and packet[38:42] == socket.inet_aton('192.0.2.102')):
                break
        for reply in replies:
            ethernet_sender, arp_sender = reply[:2]
            target_ip = (socket.inet_aton(reply[2]) if len(reply) == 3
                         else packet[28:32])
            ethernet = (packet[6:12] + bytes.fromhex(ethernet_sender)
                        + b'\x08\x06')
            arp = (struct.pack('!HHBBH', 1, 0x800, 6, 4, 2)
                   + bytes.fromhex(arp_sender) + packet[38:42]
                   + packet[22:28] + target_ip)
            sock.send(ethernet + arp + b'\0' * 18)


def check_reply(name, replies, options, expected, status=0, prefix=False):
    if os.environ.get('ARPING_ROOTLESS') == 'yes':
        sender = []
        peer = ['nsenter', '-t', os.environ['ARPING_PEER_PID'], '-n']
    else:
        sender = ['ip', 'netns', 'exec', 'arping_test0']
        peer = ['ip', 'netns', 'exec', 'arping_test1']
    responder = subprocess.Popen(
        peer + [sys.executable, str(Path(__file__).resolve()), '--respond'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        responder.stdin.write(json.dumps(replies) + '\n')
        responder.stdin.flush()
        if responder.stdout.readline().strip() != 'ready':
            raise RuntimeError('ARP responder did not start')
        result = subprocess.run(
            sender + ['./src/arping', '-i', 'veth0', '-c', '1', '-W', '0.05']
            + options + ['192.0.2.102'], capture_output=True, text=True,
            timeout=5)
        responder.wait(timeout=5)
        if responder.returncode:
            raise RuntimeError(responder.stderr.read())
        matches = (result.stdout.startswith(expected) if prefix
                   else result.stdout == expected)
        if result.returncode != status or not matches:
            raise AssertionError(
                f'{name}: exit {result.returncode}, want {status}; '
                f'output {result.stdout!r}, want {expected!r}; '
                f'stderr {result.stderr!r}')
        print(f'PASS: {name}')
    finally:
        if responder.poll() is None:
            responder.kill()
        responder.communicate()


def main():
    ethernet = '000102334401'
    owner = '0200000000aa'
    other_owner = '0200000000bb'
    mac = '00:01:02:33:44:01'
    both = mac + ' (ARP: 02:00:00:00:00:aa)'
    check_reply('matching ARP and Ethernet senders', [(ethernet, ethernet)],
                ['-r'], mac + '\n')
    check_reply('different ARP sender in normal output', [(ethernet, owner)],
                [], 'ARPING 192.0.2.102\n60 bytes from ' + both
                + ' (192.0.2.102): index=0 time=', prefix=True)
    check_reply('different ARP sender in raw output', [(ethernet, owner)],
                ['-r'], '02:00:00:00:00:aa\n')
    check_reply('different ARP sender in combined raw output',
                [(ethernet, owner)], ['-r', '-R'],
                '02:00:00:00:00:aa 192.0.2.102\n')
    check_reply('IP-only output', [(ethernet, owner)],
                ['-R'], '192.0.2.102\n')
    check_reply('different owners sharing an Ethernet sender',
                [(ethernet, owner), (ethernet, other_owner)], ['-d', '-q'],
                '', status=1)
    check_reply('same owner with different Ethernet senders',
                [(ethernet, owner), ('020000000002', owner)], ['-d', '-q'], '')
    check_reply('wrong target IP cannot satisfy the reply limit',
                [(ethernet, ethernet, '192.0.2.99')], ['-q', '-C', '1'],
                '', status=1)
    check_reply('wrong target IP with an explicit source',
                [(ethernet, ethernet, '192.0.2.100')],
                ['-q', '-S', '198.51.100.1'], '', status=1)
    check_reply('matching explicit source IP', [(ethernet, ethernet)],
                ['-q', '-S', '198.51.100.1'], '')
    check_reply('matching zero source IP', [(ethernet, ethernet)],
                ['-q', '-0'], '')
    check_reply('promiscuous mode rejects another target IP',
                [(ethernet, ethernet, '192.0.2.99')], ['-q', '-p'],
                '', status=1)
    check_reply('promiscuous mode accepts the matching target IP',
                [(ethernet, ethernet)], ['-q', '-p'], '')


if __name__ == '__main__':
    if sys.argv[1:] == ['--respond']:
        respond()
    else:
        main()
