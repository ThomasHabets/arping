#!/usr/bin/env python3
"""Exercise reply fields using the namespaces created by tests/run."""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def respond_mac(sock, packet, replies, fields):
    header_size = (packet[14] & 15) * 4
    length = struct.unpack('!H', packet[16:18])[0]
    icmp = bytearray(packet[14 + header_size:14 + length])
    icmp += b'\x01' * fields.get('extra_payload', 0)
    options = b'\x01' * fields.get('ip_options', 0)
    reply_header_size = 20 + len(options)
    ip_length = fields.get('ip_length', reply_header_size + len(icmp))
    ip_length -= fields.get('trim_ip', 0)
    icmp[0] = 0
    icmp[2:4] = b'\0\0'
    icmp[2:4] = struct.pack('!H', checksum(
        bytes(icmp[:max(0, ip_length - reply_header_size)])))
    for sender, ip in replies:
        ethernet = packet[6:12] + bytes.fromhex(sender) + b'\x08\x00'
        destination = (socket.inet_aton(fields['destination'])
                       if 'destination' in fields else packet[26:30])
        header = struct.pack('!BBHHHBBH4s4s', 0x40 | (reply_header_size // 4),
                             0, ip_length, 1, fields.get('fragment', 0), 64, 1, 0,
                             socket.inet_aton(ip), destination) + options
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        sock.send(ethernet + header + icmp + b'\0' * fields.get('padding', 0))


def respond():
    config = json.loads(sys.stdin.readline())
    replies = config['replies']
    mac_ping = config['mac_ping']
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('veth1', 0))
        sock.settimeout(5)
        print('ready', flush=True)
        while True:
            packet = sock.recv(2048)
            if (mac_ping and len(packet) >= 42
                    and packet[12:14] == b'\x08\x00' and packet[23] == 1
                    and packet[30:34] == socket.inet_aton('192.0.2.102')
                    and packet[14 + (packet[14] & 15) * 4] == 8):
                respond_mac(sock, packet, replies, config['mac_fields'])
                return
            if (not mac_ping and len(packet) >= 42
                    and packet[12:14] == b'\x08\x06'
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


def check_reply(name, replies, options, expected, status=0, prefix=False,
                mac_ping=False, mac_fields=None):
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
        responder.stdin.write(json.dumps({'replies': replies,
                                         'mac_ping': mac_ping,
                                         'mac_fields': mac_fields or {}}) + '\n')
        responder.stdin.flush()
        if responder.stdout.readline().strip() != 'ready':
            raise RuntimeError('ARP responder did not start')
        target = (['-T', '192.0.2.102', 'ff:ff:ff:ff:ff:ff'] if mac_ping
                  else ['192.0.2.102'])
        result = subprocess.run(
            sender + ['./src/arping', '-i', 'veth0', '-c', '1', '-W', '0.05']
            + options + target, capture_output=True, text=True,
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
    for options in (['-r', '-R', '-r'], ['-R', '-r', '-R'],
                    ['-r', '-r', '-R', '-R'], ['-rRrR']):
        check_reply(f'repeated combined raw flags {options}', [(ethernet, owner)],
                    options, '02:00:00:00:00:aa 192.0.2.102\n')
        check_reply(f'repeated combined MAC-ping raw flags {options}',
                    [(owner, '192.0.2.102')], options,
                    '02:00:00:00:00:aa 192.0.2.102\n', mac_ping=True)
    check_reply('repeated MAC-only output', [(ethernet, owner)],
                ['-r', '-r'], '02:00:00:00:00:aa\n')
    check_reply('repeated IP-only output', [(ethernet, owner)],
                ['-R', '-R'], '192.0.2.102\n')
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
    same_mac = [(owner, '192.0.2.102'), (owner, '192.0.2.103')]
    different_macs = [(owner, '192.0.2.102'), (other_owner, '192.0.2.103')]
    check_reply('MAC ping detects distinct senders', different_macs,
                ['-d', '-r'], '192.0.2.102\n192.0.2.103\n', status=1,
                mac_ping=True)
    check_reply('MAC ping permits multiple IPs from one MAC', same_mac,
                ['-d', '-r'], '192.0.2.102\n192.0.2.103\n', mac_ping=True)
    check_reply('MAC ping accepts distinct senders without -d', different_macs,
                ['-r'], '192.0.2.102\n192.0.2.103\n', mac_ping=True)
    check_reply('MAC duplicate check honors the reply limit', different_macs,
                ['-d', '-C', '1', '-r'], '192.0.2.102\n', mac_ping=True)
    check_reply('MAC duplicate check without replies', [], ['-d', '-q'], '',
                mac_ping=True)
    reply = [(owner, '192.0.2.102')]
    for fragment in (0x2000, 1, 0x2001, 0x1fff):
        check_reply(f'MAC ping rejects IPv4 fragment {fragment:#x}', reply,
                    ['-q', '-C', '1'], '', status=1, mac_ping=True,
                    mac_fields={'fragment': fragment, 'extra_payload': 4})
    check_reply('MAC ping accepts an unfragmented packet with DF set', reply,
                ['-q', '-C', '1'], '', mac_ping=True,
                mac_fields={'fragment': 0x4000})
    for name, fields in [
        ('cookie only in Ethernet padding', {'ip_length': 28}),
        ('short cookie with padding', {'trim_ip': 1}),
        ('IP length smaller than the header', {'ip_length': 16}),
        ('IP length larger than the captured packet', {'ip_length': 65535}),
        ('cookie in padding after IP options', {'ip_options': 4, 'ip_length': 32}),
    ]:
        check_reply(name, reply, ['-q', '-C', '1'], '', status=1,
                    mac_ping=True, mac_fields=fields)
    for fields in ({'padding': 16}, {'ip_options': 4}, {'ip_options': 40}):
        check_reply(f'valid MAC reply with {fields}', reply, ['-q'], '',
                    mac_ping=True, mac_fields=fields)
    for options in (['-q'], ['-q', '-p'], ['-q', '-S', '198.51.100.1']):
        check_reply(f'MAC reply to another IPv4 host with {options}', reply,
                    options, '', status=1, mac_ping=True,
                    mac_fields={'destination': '192.0.2.99'})
    check_reply('MAC reply to the interface IP instead of explicit source',
                reply, ['-q', '-S', '198.51.100.1'], '', status=1,
                mac_ping=True, mac_fields={'destination': '192.0.2.100'})
    for options in (['-q', '-S', '198.51.100.1'], ['-q', '-0'], ['-q', '-p']):
        check_reply(f'MAC reply to the matching source with {options}', reply,
                    options, '', mac_ping=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--respond']:
        respond()
    else:
        main()
