# ARP Ping

By Thomas Habets <thomas@habets.se>

* <http://www.habets.pp.se/synscan/>
* <http://github.com/ThomasHabets/arping>
* `git clone https://github.com/ThomasHabets/arping.git`

## Introduction

Arping is a util to find out if a specific IP address on the LAN is 'taken'
and what MAC address owns it. Sure, you *could* just use 'ping' to find out if
it's taken and even if the computer blocks ping (and everything else) you still
get an entry in your ARP cache. But what if you aren't on a routable net? Or
the host blocks ping (all ICMP even)? Then you're screwed. Or you use arping.

## Why it's not stupid

Say you have a block of N real IANA-assigned IP-addresses. You want to debug
the net and you don't know which IP addresses are taken. You can't ping anyone
before you take the IP, and you can't pick an IP before you know which are
already taken. Catch 22. But with arping you can 'ping' the IP and if you get
no response, the IP is available.

## Example uses

If some box is dumping non-IP (like IPX) garbage and you don't know which box
it is, you can ping by MAC to get the IP and fix the problem.

If you are on someone else's net and want to 'borrow' a real IP address instead
of using one of those 10.x.x.x-addresses the DHCP hands out you probably want
to know which ones are taken, or people will get mad (a friend of mine got a
call on his cellphone about 15 seconds after he accidentally 'stole' an IP,
oops).

## Compiling / installing

See INSTALL file.

### Portability

First class platforms, tested by CI in GitHub Actions and/or main development
machine:

* Latest Debian stable amd64
* Latest Ubuntu amd64
* Ubuntu 24.04 aarch64
* Latest OpenBSD amd64
* Latest MacOS X aarch64
* FreeBSD amd64
* NetBSD amd64
* DragonFly BSD amd64
* OmniOS r151054 amd64

Systems that it should still work on, but I don't personally regularly test:

* Debian Alpha
* IRIX 6.5 mips (last test 2009-09-27)
* OpenBSD sparc64 (last test: 2009-10-02)
* Solaris

Features arping depends on:
* POSIX.1-2001, for `pselect()`. If needed, the code changes to fall back would
  be minimal.
* C99, for declaring variables in the middle of a block.

## Mailing list

<https://groups.google.com/g/synscan>

## How it does it

See 'Technical' at the bottom of this file.

## FAQ

### Q: Where is Arping 1.x? I use libnet 1.0.x so I need that!

Arping 1 has finally been removed from the Arping 2.x tarball in 2.09.
Arping 1.x currently only lives in the Arping packages 2.08 and lower. If
features are to be added or bugs fixed it will show up again as a separate
package forked from Arping 2.08.

For now just get arping-2.08.tar.gz and use that.

### Q: Where's the Windows version? A compiled .exe would be nice.

I don't have a windows box, so the .exe I'm providing was NOT compiled
by me. If something is strange about it tell me, but there won't be much
I can do about it.
That being said:

<http://www.habets.pp.se/synscan/files/arping-for-windows-not-compiled-by-me.exe>

### Q: After compiling arping without any problem, i test it first with localhost... but it doesn't respond. Isn't that strange?

Not really, as you can see by typing 'ifconfig' the lo (local) interface
does not have a MAC address. It's not a physical device! MAC addresses are
there to differentiate computers on a shared medium (the aether, or ether)
and since packets to localhost does not go over any wire there is no need
to identify which box is talking to which. There is only one.

### Q: Arping can't ping anything!

Check which interface is active with `-v`. If it's the wrong one, use `-i`
to set it right.

### Q: Arping finds some hosts, but not others. why?   BTW, I have several NICs.

You have to choose interface with the `-i` switch if the default is wrong for
you.

### Q: I tried to ping my own MAC address, but it doesn't work.

A sane OS will think it's suspicious if you send packets to yourself over
the wire and will ignore them.

And why would you want to lookup the IP or MAC of yourself? ifconfig
can tell you that.

### Q: I can't ping any/some MAC address on my LAN.

Arping when pinging a MAC relies on the host to answer a broadcast ping
(icmp echo request) properly (IIRC: not the windows way). If you want a
host to pop up on MAC ping, you have to config it to respond to broadcast
pings.
(for linux, make sure `/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts` is 0)

or

-T <IP/host> allows you to restrict the arping to a limited subnet, which
may or may not work for you. For example if the box 00:01:02:03:04:05 is on
192.168.0.0/24 then the broadcast probably is 192.168.0.255, so try:

```
# arping -T 192.168.0.255 00:01:02:03:04:05
```

### Q: ./configure says I need libnet and/or libpcap

Arping depends on libnet 1.1 or newer, and libpcap. Get libnet from
<https://github.com/libnet/libnet> and libpcap from <http://www.tcpdump.org>.
Or more likely they were both included in your Linux distribution.

The original libnet site
was <http://packetfactory.openwall.net/projects/libnet/>, but is not updated.

### Q: I get `libnet_get_ipaddr(): no error` when I run arping with IP (src or dst) 255.255.255.255.

Use the `-b`/`-B` switches. Libnet sucks (ha ha only serious) and returns -1 for
error == int32 encoded 255.255.255.255.

### Q: I used to be able to use `-S 255.255.255.255`, now it fails. What's going on? (or: Why can't I arping 255.255.255.255?)

Argh! Why would you want to? Anyway, this one is due to libnets resolving,
and my unwillingness to reimplement it (in a portable manner, ugh).

`-S 255.255.255.255` can be replaced with `-b`, and pinging broadcast (why you
would do that eludes me) `-B`.

To be extra perverted, try: `./arping -b -B`

### Q: The roundtrip times are off, sometimes by milliseconds!

I know.

#### Short answer

'ping' does the same thing. (ping from iputils-ss010824 anyway)

#### Long answer

I can't (portably anyway) do anything other than queue a packet
to the network. That means I don't know exactly when it arrived. Also,
I can't tell when a packet arrives on the wire, only when arping gets
it from the kernel. Just make sure neither the network (whole segment
if you are hubbed, just your NIC if you are switched) nor your box is
loaded when you care about timing, and/or run arping with higher
priority.

```
nice -n -15 arping 1.2.3.4
schedtool -R -p 1 -e arping 1.2.3.4
```

But if you find way to get more exact timing portably (or just for one
OS really), let me know.

### Q: Is it OK to make arping suid root?

Be my guest, but I'd recommend restricting execution of arping to trusted users.
Arping tries to drop all possible privileges as early as possible, but this is a
network debugging tool, which generates low-level network packets that ordinary
users have absolutely no business generating.

If you are honestly debugging the network then I don't see why you aren't
root already.

That being said, on Linux you can add the `CAP_NET_RAW` capability to arping
limiting the damage if arping were to be compromised:

```
  sudo setcap cap_net_raw+ep  /usr/local/sbin/arping
```

This requires a libnet 1.1.5 or higher, which does not explicitly check for
uid 0.

For older versions of Libnet you can try applying this patch:
  <http://github.com/ThomasHabets/libnet/commit/aaa383b5c816107082508b7646929a9479b81645>

### Q: What's this -A switch all about, I don't understand it.

Normally arping packets are sent out to some kind of broadcast (MAC or IPv4
broadcast) and hosts reply with source address == their address.

If `-A` is given, only packets coming in with a *source* address equal
to the *destination* address in the query is accepted.

If you don't understand, don't worry. You won't need it. But for an
example use, see the arping-scan-net.sh script.

## License

It's GPLv2, see the LICENSE file.

## Technical

Yes, I've finally bothered to write how it works.
tcpdumps were taken with `tcpdump -vven 'arp or icmp'`.

The source box is 192.168.0.2/0:10:5a:3e:c5:b4 and the target box is
192.168.0.1/0:60:93:34:91:99.

### For pinging IP addresses

When a host wants to send an IP packet to another host, it sends out an ARP
packet asking what MAC the destination IP address has, a so-called 'who-has'
packet. This is then answered by another ARP packet, the 'is-at' packet.

```
18:16:07.179699 0:10:5a:3e:c5:b4 ff:ff:ff:ff:ff:ff 0806 42:
                arp who-has 192.168.0.1 tell 192.168.0.2
```

This is the packet generated by arping.
An Ethernet frame from my 3com card to the broadcast address carrying an arp
packet asking what MAC 192.168.0.1 has (who-has).

```
18:16:07.180221 0:60:93:34:91:99 0:10:5a:3e:c5:b4 0806 60:
                arp reply 192.168.0.1 is-at 0:60:93:34:91:99
```

The answer, that 192.168.0.1 has MAC 0:60:93:34:91:99 (is-at).

### For pinging MAC addresses

A broadcast ping (255.255.255.255, or any address supplied with `-T`, see below)
is sent out on the Ethernet, but in an Ethernet frame addressed to the target
MAC only.

```
18:20:09.627321 0:10:5a:3e:c5:b4 0:60:93:34:91:99 0800 42:
                192.168.0.2 > 255.255.255.255: icmp: echo request
                (ttl 48, id 17767, len 28)
```

This is the packet generated by arping.
Ethernet frame from my 3com NIC to the destination MAC, carrying a broadcast
ping.

```
18:20:09.628432 0:60:93:34:91:99 0:10:5a:3e:c5:b4 0800 60:
                192.168.0.1 > 192.168.0.2: icmp: echo reply
                (ttl 255, id 7593, len 28)
```

The answer, including the source address of the target host. Note that this
is not how every OS responds to a broadcast ping (if at all). Some answer with
a source address equal to the broadcast address, and others don't' answer at
all.

This is why pinging a raw MAC doesn't always work, and you may need to play
with -T to get it to answer correctly (or at all). You can always brute-force
if you can't even find a broadcast that the box will answer correctly to.

```
for d in $(seq 0 255); do
    sudo arping -q -c 1 -T $a.$b.$c.$d 0:60:93:34:91:99
    if [ $? = 0 ]; then
      echo "Got answer with address: 192.168.0.$d"
    fi
done
```

Note that this script will take 1 second per IP since that is how long arping
waits, so scanning a C-class net will take 256 seconds. If you have a bigger
net, then write a program that will run several arpings at the same time to
go through more in less time, or check out arping-scan-net.sh, which is a
more capable script for scanning, but you need to edit it since the address
range it searches is hard-coded.

I may add this to arping some day, but don't hold your breath.

-----------------------------------------------------------------------
Send questions/suggestions/patches/rants/money/envy to thomas@habets.se
