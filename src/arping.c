/** arping/src/arping.c
 *
 * arping
 *
 * By Thomas Habets <thomas@habets.pp.se>
 *
 * ARP 'ping' utility
 *
 * Broadcasts a who-has ARP packet on the network and prints answers.
 * *VERY* useful when you are trying to pick an unused IP for a net that
 * you don't yet have routing to. Then again, if you have no idea what I'm
 * talking about then you prolly don't need it.
 *
 * Also finds out IP of specified MAC
 *
 */
/*
 *  Copyright (C) 2000-2010 Thomas Habets <thomas@habets.pp.se>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_LIBNET_H
#include <libnet.h>
#endif

#if HAVE_WIN32_LIBNET_H
#include <win32/libnet.h>
#endif

#if HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
#include <pcap.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#ifndef WIN32
#define WIN32 0
#endif

/**
 * OS-specific interface finding using routing table. See findif_*.c
 */
const char *
arping_lookupdev(const char *ifname,
                 uint32_t srcip,
                 uint32_t dstip,
                 char *ebuf);

static const char *version = VERSION; /* from autoconf */

static libnet_t *libnet = 0;

static struct timeval lastpacketsent;

uint32_t srcip, dstip;

static int beep = 0;
static int reverse_beep = 0;
static int verbose = 0;
static int alsototal = 0;
/*static int pingmac = 0; */
static int finddup = 0;
static int dupfound = 0;
static unsigned int numsent = 0;
static unsigned int numrecvd = 0;
static unsigned int numdots = 0;
static int addr_must_be_same = 0;
/* RAWRAW is RAW|RRAW */
static enum { NORMAL, QUIET, RAW, RRAW, RAWRAW, DOT } display = NORMAL;
static char *target = "huh? bug in arping?";
static uint8_t ethnull[ETH_ALEN];
static uint8_t ethxmas[ETH_ALEN];
static char srcmac[ETH_ALEN];
static char dstmac[ETH_ALEN];
static char lastreplymac[ETH_ALEN];

/* doesn't need to be volatile */
volatile int time_to_die = 0;

/**
 *
 */
static void
count_missing_dots()
{
        while (numsent > numdots) {
                putchar('.');
                numdots++;
        }
}

/**
 *
 */	
void
do_libnet_init(const char *ifname)
{
	char ebuf[LIBNET_ERRBUF_SIZE];
	if (verbose > 1) {
		printf("libnet_init(%s)\n", ifname?ifname:"<null>");
	}
	if (libnet) {
		/* prolly going to switch interface from temp to real */
		libnet_destroy(libnet);
		libnet = 0;
	}

        /* try libnet_init() even though we aren't root. We may have
         * a capability or something */
	if (!(libnet = libnet_init(LIBNET_LINK,
				   (char*)ifname,
				   ebuf))) {
		fprintf(stderr, "arping: %s\n", ebuf);
                if (getuid() && geteuid()) {
                        fprintf(stderr,
                                "arping: you may need to run as root\n");
                }
		exit(1);
	}
}

/**
 *
 */
const char *
arping_lookupdev_default(const char *ifname,
			 uint32_t srcip, uint32_t dstip,
			 char *ebuf)
{
#if WIN32
	WCHAR buf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
	WCHAR* ret = (WCHAR*)pcap_lookupdev((char*)buf);
	if (ret != NULL) {
		wcstombs(ebuf, ret, LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE);
		return ebuf;
	}
	return NULL;
#else
	return pcap_lookupdev(ebuf);
#endif
}

#if WIN32
static BOOL WINAPI arping_console_ctrl_handler(DWORD dwCtrlType)
{
	if(verbose) {
		printf("arping_console_ctrl_handler( %d )\n", (int)dwCtrlType);
	}
	time_to_die = 1;

#if 0
	/* if SetConsoleCtrlHandler() does what I think, this isn't needed */
	if (display == NORMAL) {
		printf("\n--- %s statistics ---\n"
		       "%d packets transmitted, %d packets received, %3.0f%% "
		       "unanswered\n",target,numsent,numrecvd,
		       100.0 - 100.0 * (float)(numrecvd)/(float)numsent);
        }
#endif
	return TRUE;
}
#endif


/**
 *
 */
static void sigint(int i)
{
	time_to_die = 1;
}

/**
 *
 */
static void
extended_usage()
{
	printf("\nOptions:\n");
	printf("\n"
	       "    -0     Use this option to ping with source IP address 0.0.0.0. Use this\n"
	       "           when you haven't configured your interface yet.  Note that  this\n"
	       "           may  get  the  MAC-ping  unanswered.   This  is  an alias for -S\n"
	       "           0.0.0.0.\n"
	       "    -a     Audiable ping.\n"
	       "    -A     Only count addresses matching  requested  address  (This  *WILL*\n"
	       "           break  most things you do. Only useful if you are arpinging many\n"
	       "           hosts at once. See arping-scan-net.sh for an example).\n"
	       "    -b     Like -0 but source broadcast source  address  (255.255.255.255).\n"
	       "           Note that this may get the arping unanswered since it's not nor-\n"
	       "           mal behavior for a host.\n"
	       "    -B     Use instead of host if you want to address 255.255.255.255.\n"
	       "    -c count\n"
	       "           Only send count requests.\n"
	       "    -d     Find duplicate replies. Exit with 1 if there are "
               "answers from\n"
               "           two different MAC addresses.\n"
	       "    -D     Display answers as dots and missing packets as exclamation points.\n"
               "    -e     Like -a but beep when there is no reply.\n"
	       "    -F     Don't try to be smart about the interface name.  (even  if  this\n"
	       "           switch is not given, -i overrides smartness)\n"
	       "    -h     Displays a help message and exits.\n"
	       "    -i interface\n"
	       "           Use the specified interface.\n"
	       "    -q     Does not display messages, except error messages.\n"
	       "    -r     Raw output: only the MAC/IP address is displayed for each reply.\n"
	       "    -R     Raw output: Like -r but shows \"the other one\", can  be  combined\n"
	       "           with -r.\n"
	       "    -s MAC Set source MAC address. You may need to use -p with this.\n"
	       "    -S IP  Like  -b and -0 but with set source address.  Note that this may\n"
	       "       	   get the arping unanswered if the target does not have routing to\n"
	       "           the  IP.  If you don't own the IP you are using, you may need to\n"
	       "           turn on promiscious mode on the interface (with -p).  With  this\n"
	       "           switch  you can find out what IP-address a host has without tak-\n"
	       "           ing an IP-address yourself.\n"
	       "    -t MAC Set target MAC address to use when pinging IP address.\n"
	       "    -T IP  Use -T as target address when pinging MACs that won't respond to\n"
	       "           a broadcast ping but perhaps to a directed broadcast.\n"
	       "           Example:\n"
	       "           To check the address of MAC-A, use knowledge of MAC-B and  IP-B.\n"
	       "           $ arping -S <IP-B> -s <MAC-B> -p <MAC-A>\n"
	       "    -p     Turn  on  promiscious  mode  on interface, use this if you don't\n"
	       "           \"own\" the MAC address you are using.\n"
	       "    -u     Show index=received/sent instead  of  just  index=received  when\n"
	       "           pinging MACs.\n"
	       "    -v     Verbose output. Use twice for more messages.\n"
	       "    -w     Time to wait between pings, in microseconds.\n");
        printf("Report bugs to: thomas@habets.pp.se\n"
               "Arping home page: <http://www.habets.pp.se/synscan/>\n"
               "Development repo: http://github.com/ThomasHabets/arping\n");
}

/**
 *
 */
static void
standard_usage()
{
	printf("ARPing %s, by Thomas Habets <thomas@habets.pp.se>\n",
	       version);
        printf("usage: arping [ -0aAbdDeFpqrRuv ] [ -w <us> ] "
               "[ -S <host/ip> ]\n"
               "              "
               "[ -T <host/ip ] "
               "[ -s <MAC> ] [ -t <MAC> ] [ -c <count> ]\n"
               "              "
               "[ -i <interface> ] "
               "<host/ip/MAC | -B>\n");
}

/**
 *
 */
static void
usage(int ret)
{
        standard_usage();
        if (WIN32) {
                extended_usage();
        } else {
                printf("For complete usage info, use --help"
                       " or check the manpage.\n");
        }
	exit(ret);
}

/**
 * It was unclear from msdn.microsoft.com if their scanf() supported
 * [0-9a-fA-F], so I'll stay away from it.
 */
static int is_mac_addr(const char *p)
{
	/* cisco-style */
	if (3*5-1 == strlen(p)) {
		unsigned int c;
		for (c = 0; c < strlen(p); c++) {
			if ((c % 5) == 4) {
				if ('.' != p[c]) {
					goto checkcolon;
				}
			} else {
				if (!isxdigit(p[c])) {
					goto checkcolon;
				}
			}
		}
		return 1;
	}
	/* windows-style */
	if (6*3-1 == strlen(p)) {
		unsigned int c;
		for (c = 0; c < strlen(p); c++) {
			if ((c % 3) == 2) {
				if ('-' != p[c]) {
					goto checkcolon;
				}
			} else {
				if (!isxdigit(p[c])) {
					goto checkcolon;
				}
			}
		}
		return 1;
	}

 checkcolon:
	/* unix */
	return strchr(p, ':') ? 1 : 0;
}

/**
 * lots of parms since C arrays suck
 */
static int get_mac_addr(const char *in,
			unsigned int *n0,
			unsigned int *n1,
			unsigned int *n2,
			unsigned int *n3,
			unsigned int *n4,
			unsigned int *n5)
{
	if (6 == sscanf(in, "%x:%x:%x:%x:%x:%x",n0,n1,n2,n3,n4,n5)) {
		return 1;
	} else if(6 == sscanf(in, "%2x%x.%2x%x.%2x%x",n0,n1,n2,n3,n4,n5)) {
		return 1;
	} else if(6 == sscanf(in, "%x-%x-%x-%x-%x-%x",n0,n1,n2,n3,n4,n5)) {
		return 1;
	}
	return 0;
}

/**
 * as always, the answer is 42
 *
 * in this case the question is how many bytes buf needs to be.
 * Assuming a 33 byte max %d
 *
 * Still, I'm using at least 128bytes below
 *
 * (because snprintf() sadly isn't as portable, that's why)
 */
static char *tv2str(const struct timeval *tv, const struct timeval *tv2,
		    char *buf)
{
	double f,f2;
	int exp = 0;

	f = tv->tv_sec + (double)tv->tv_usec / 1000000;
	f2 = tv2->tv_sec + (double)tv2->tv_usec / 1000000;
	f = (f2 - f) * 1000000;
	while (f > 1000) {
		exp+= 3;
		f /= 1000;
	}
	switch (exp) {
	case 0:
		sprintf(buf, "%.3f usec", f);
		break;
	case 3:
		sprintf(buf, "%.3f msec", f);
		break;
	case 6:
		sprintf(buf, "%.3f sec", f);
		break;
	case 9:
		sprintf(buf, "%.3f sec", f*1000);
		break;
        default:
		/* huh, uh, huhuh */
		sprintf(buf, "%.3fe%d sec", f, exp-6);
	}
	return buf;
}



/** Send directed IPv4 ICMP echo request.
 *
 * \param srcmac  Source MAC. From -s switch or autodetected
 * \param dstmac  Destination/target MAC. Target command line.
 * \param srcip   From -S switch or autodetected
 * \param dstip   From -D switch, or 255.255.255.255
 * \param id      IP id
 * \param seq     Ping seq
 */
static void
pingmac_send(uint8_t *srcmac, uint8_t *dstmac,
	     uint32_t srcip, uint32_t dstip,
	     uint16_t id, uint16_t seq)
{
	static libnet_ptag_t icmp = 0, ipv4 = 0,eth=0;
	int c;

	if (-1 == (icmp = libnet_build_icmpv4_echo(ICMP_ECHO, /* type */
						   0, /* code */
						   0, /* checksum */
						   id, /* id */
						   seq, /* seq */
						   NULL, /* payload */
						   0, /* payload len */
						   libnet,
						   icmp))) {
		fprintf(stderr, "libnet_build_icmpv4_echo(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}

	if (-1==(ipv4 = libnet_build_ipv4(LIBNET_IPV4_H
					  + LIBNET_ICMPV4_ECHO_H + 0,
					  0, /* ToS */
					  id, /* id */
					  0, /* frag */
					  64, /* ttl */
					  IPPROTO_ICMP,
					  0, /* checksum */
					  srcip,
					  dstip,
					  NULL, /* payload */
					  0,
					  libnet,
					  ipv4))) {
		fprintf(stderr, "libnet_build_ipv4(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if (-1 == (eth = libnet_build_ethernet(dstmac,
					       srcmac,
					       ETHERTYPE_IP,
					       NULL,
					       0,
					       libnet,
					       eth))) {
		fprintf(stderr, "libnet_build_ethernet(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if(verbose>1) {
		if (-1 == gettimeofday(&lastpacketsent, NULL)) {
			fprintf(stderr, "arping: gettimeofday(): %s\n",
				strerror(errno));
			sigint(0);
		}
		printf("arping: sending packet at time %d %d\n",
		       lastpacketsent.tv_sec,
		       lastpacketsent.tv_usec);
	}
	if (-1 == (c = libnet_write(libnet))) {
		fprintf(stderr, "arping: libnet_write(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if (-1 == gettimeofday(&lastpacketsent, NULL)) {
		fprintf(stderr, "arping: gettimeofday(): %s\n",
			strerror(errno));
		sigint(0);
	}
	numsent++;
}

/** Send ARP who-has.
 *
 * \param srcmac   -s or autodetected
 * \param dstmac   -t or ff:ff:ff:ff:ff:ff
 * \param srcip    -S or autodetected
 * \param dstip    -T or or cmdline
 *
 */
static void
pingip_send(uint8_t *srcmac, uint8_t *dstmac,
	    uint32_t srcip, uint32_t dstip)
{
	static libnet_ptag_t arp=0,eth=0;
	if (-1 == (arp = libnet_build_arp(ARPHRD_ETHER,
					  ETHERTYPE_IP,
					  ETH_ALEN,
					  IP_ALEN,
					  ARPOP_REQUEST,
					  srcmac,
					  (uint8_t*)&srcip,
					  ethnull,
					  (uint8_t*)&dstip,
					  NULL,
					  0,
					  libnet,
					  arp))) {
		fprintf(stderr, "arping: libnet_build_arp(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if (-1 == (eth = libnet_build_ethernet(dstmac,
					       srcmac,
					       ETHERTYPE_ARP,
					       NULL,
					       0,
					       libnet,
					       eth))) {
		fprintf(stderr, "arping: libnet_build_ethernet(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if(verbose>1) {
		if (-1 == gettimeofday(&lastpacketsent, NULL)) {
			fprintf(stderr, "arping: gettimeofday(): %s\n",
				strerror(errno));
			sigint(0);
		}
		printf("arping: sending packet at time %d %d\n",
		       lastpacketsent.tv_sec,
		       lastpacketsent.tv_usec);
	}
	if (-1 == libnet_write(libnet)) {
		fprintf(stderr, "arping: libnet_write(): %s\n", 
			libnet_geterror(libnet));
		sigint(0);
	}
	if (-1 == gettimeofday(&lastpacketsent, NULL)) {
		fprintf(stderr, "arping: gettimeofday(): %s\n",
			strerror(errno));
		sigint(0);
	}
	numsent++;
}

/** handle incoming packet when pinging an IP address.
 *
 * \param h       packet metadata
 * \param packet  packet data
 */
static void
pingip_recv(const char *unused, struct pcap_pkthdr *h,
	    uint8_t *packet)
{
	struct libnet_802_3_hdr *heth;
	struct libnet_arp_hdr *harp;
	struct timeval arrival;
	int c;

	if(verbose>2) {
		printf("arping: received response for ip ping\n");
	}

	if (-1 == gettimeofday(&arrival, NULL)) {
		fprintf(stderr, "arping: gettimeofday(): %s\n",
			strerror(errno));
		sigint(0);
	}
	heth = (void*)packet;
	harp = (void*)((char*)heth + LIBNET_ETH_H);

	if ((htons(harp->ar_op) == ARPOP_REPLY)
	    && (htons(harp->ar_pro) == ETHERTYPE_IP)
	    && (htons(harp->ar_hrd) == ARPHRD_ETHER)) {
		uint32_t ip;
		memcpy(&ip, (char*)harp + harp->ar_hln
		       + LIBNET_ARP_H,4);
		if (addr_must_be_same
		    && (memcmp((u_char*)harp+sizeof(struct libnet_arp_hdr),
			       dstmac, ETH_ALEN))) {
			return;
		}
		if (dstip == ip) {
			switch(display) {
			case DOT:
				numdots++;
				count_missing_dots();
				putchar('!');
				break;
			case NORMAL: {
				char buf[128];
				printf("%d bytes from ", h->len);
				for (c = 0; c < 6; c++) {
					printf("%.2x%c", heth->_802_3_shost[c],
					       (c<5)?':':' ');
				}
				
				printf("(%s): index=%d",
				       libnet_addr2name4(ip,0),
				       numrecvd);
				if (alsototal) {
					printf("/%u", numsent-1);
				}
				printf(" time=%s",
				       tv2str(&lastpacketsent,
					      &arrival,buf));
				break; }
			case QUIET:
				break;
			case RAWRAW:
				for (c = 0; c < 6; c++) {
					printf("%.2x%c", heth->_802_3_shost[c],
					       (c<5)?':':' ');
				}
				printf("%s", libnet_addr2name4(ip,0));
				break;
			case RRAW:
				printf("%s", libnet_addr2name4(ip,0));
				break;
			case RAW:
				for (c = 0; c < 6; c++) {
					printf("%.2x%s", heth->_802_3_shost[c],
					       (c<5)?":":"");
				}
				break;
			default:
				fprintf(stderr, "arping: can't happen!\n");
			}

                        switch (display) {
                        case QUIET:
                        case DOT:
                                break;
                        default:
                                if (beep) {
                                        printf("\a");
                                }
                                printf("\n");
                        }
                        if (numrecvd) {
                                if (memcmp(lastreplymac,
                                           heth->_802_3_shost, ETH_ALEN)) {
                                        dupfound = 1;
                                }
                        }
                        memcpy(lastreplymac, heth->_802_3_shost, ETH_ALEN);

			numrecvd++;
		}
	}
}

/** handle incoming packet when pinging an MAC address.
 *
 * \param h       packet metadata
 * \param packet  packet data
 */
static void
pingmac_recv(const char *unused, struct pcap_pkthdr *h,
	     uint8_t *packet)
{
	struct libnet_802_3_hdr *heth;
	struct libnet_ipv4_hdr *hip;
	struct libnet_icmpv4_hdr *hicmp;
	struct timeval arrival;
	int c;

	if(verbose>2) {
		printf("arping: received response for mac ping\n");
	}

	if (-1 == gettimeofday(&arrival, NULL)) {
		fprintf(stderr, "arping: gettimeofday(): %s\n",
			strerror(errno));
		sigint(0);
	}

	heth = (void*)packet;
	hip = (void*)((char*)heth + LIBNET_ETH_H);
	hicmp = (void*)((char*)hip + LIBNET_IPV4_H);

	if ((htons(hicmp->icmp_type) == ICMP_ECHOREPLY)
	    && ((!memcmp(heth->_802_3_shost, dstmac,ETH_ALEN)
		 || !memcmp(dstmac, ethxmas, ETH_ALEN)))
	    && !memcmp(heth->_802_3_dhost, srcmac, ETH_ALEN)) {
		if (addr_must_be_same) {
			uint32_t tmp;
			memcpy(&tmp, &hip->ip_src, 4);
			if (dstip != tmp) {
				return;
			}
		}
		switch(display) {
		case QUIET:
			break;
		case NORMAL: {
			char buf[128];
			printf("%d bytes from %s (",h->len,
			       libnet_addr2name4(*(int*)&hip->ip_src, 0));
			for (c = 0; c < 6; c++) {
				printf("%.2x%c", heth->_802_3_shost[c],
				       (c<5)?':':')');
			}
			printf(": icmp_seq=%d time=%s",
			       htons(hicmp->icmp_seq),tv2str(&lastpacketsent,
						      &arrival,buf));
			break; }
		case RAW:
			printf("%s",
			       libnet_addr2name4(hip->ip_src.s_addr, 0));
			break;
		case RRAW:
			for (c = 0; c < 6; c++) {
				printf("%.2x%s", heth->_802_3_shost[c],
				       (c<5)?":":"");
			}
			break;
		case RAWRAW:
			for (c = 0; c < 6; c++) {
				printf("%.2x%c", heth->_802_3_shost[c],
				       (c<5)?':':' ');
			}
			printf("%s",
			       libnet_addr2name4(hip->ip_src.s_addr, 0));
			break;
		default:
			fprintf(stderr, "arping: can't-happen-bug\n");
			sigint(0);
		}
		if (display != QUIET) {
			printf(beep?"\a\n":"\n");
		}
		numrecvd++;
	}
}


#if WIN32
/**
 * untested for a long time. Maybe since arping 2.05 or so.
 */
static void
ping_recv_win32(pcap_t *pcap,uint32_t packetwait, pcap_handler func)
{
       struct timeval tv,tv2;
       char done = 0;
       /* windows won't let us do select() */
       if (-1 == gettimeofday(&tv2,NULL)) {
	       fprintf(stderr, "arping: gettimeofday(): %s\n",
		       strerror(errno));
               sigint(0);
       }
       while (!done && !time_to_die) {
	       struct pcap_pkthdr *pkt_header;
	       u_char *pkt_data;
	       if (pcap_next_ex(pcap, &pkt_header, &pkt_data) == 1) {
		       func(pcap, pkt_header, pkt_data);
	       }
	       if (-1 == gettimeofday(&tv,NULL)) {
		       fprintf(stderr, "arping: "
			       "gettimeofday(): %s\n",
			       strerror(errno));
		       sigint(0);
	       }
               /*
                * setup next timeval, not very exact
                */
               tv.tv_sec  = (packetwait / 1000000)
		       - (tv.tv_sec - tv2.tv_sec);
	       tv.tv_usec = (packetwait % 1000000)
		       - (tv.tv_usec - tv2.tv_usec);
	       while (tv.tv_usec < 0) {
		       tv.tv_sec--;
		       tv.tv_usec += 1000000;
	       }
	       usleep(10);
	       if (tv.tv_sec < 0) {
		       done=1;
	       }
       }
}
#endif

/**
 * while negative microseconds, take from whole seconds.
 * help function for measuring deltas.
 */
static void
fixup_timeval(struct timeval *tv)
{
	while (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}

/**
 * idiot-proof gettimeofday() wrapper
 */
static void
gettv(struct timeval *tv)
{
	if (-1 == gettimeofday(tv,NULL)) {
		fprintf(stderr, "arping: "
			"gettimeofday(): %s\n",
			strerror(errno));
		sigint(0);
	}
}


/**
 * 
 */
static void
ping_recv_unix(pcap_t *pcap,uint32_t packetwait, pcap_handler func)
{
       struct timeval tv;
       struct timeval endtime;
       char done = 0;

       gettv(&tv);
       endtime.tv_sec = tv.tv_sec + (packetwait / 1000000);
       endtime.tv_usec = tv.tv_usec + (packetwait % 1000000);
       fixup_timeval(&endtime);

       int fd;

       fd = pcap_get_selectable_fd(pcap);

       for (;!done;) {
	       int trydispatch = 0;

	       gettv(&tv);
	       tv.tv_sec = endtime.tv_sec - tv.tv_sec;
	       tv.tv_usec = endtime.tv_usec - tv.tv_usec;
	       fixup_timeval(&tv);
	       if (tv.tv_sec < 0) {
		       tv.tv_sec = 0;
		       tv.tv_usec = 1;
		       done = 1;
	       }
	       if (time_to_die) {
		       return;
	       }

	       /* try to wait for data */
	       {
		       struct pollfd p;
		       int r;
		       p.fd = fd;
		       p.events = POLLIN | POLLPRI;

		       r = poll(&p, 1, tv.tv_sec * 1000 + tv.tv_usec / 1000);
		       switch (r) {
		       case 0: /* timeout */
			       done = 1;
			       break;
		       case -1: /* error */
			       if (errno != EINTR) {
				       done = 1;
				       sigint(0);
				       fprintf(stderr,
					       "arping: poll() failed: %s\n",
					       strerror(errno));
			       }
			       break;
		       default: /* data returned */
			       trydispatch = 1;
			       break;
		       }
	       }

	       if (trydispatch) {
		       int ret;
		       if (1 != (ret = pcap_dispatch(pcap, 1,
						     func,
						     NULL))) {
			       /* rest, so we don't take 100% CPU... mostly
                                  hmm... does usleep() exist everywhere? */
			       usleep(1);

			       /* weird is normal on bsd :) */
			       if (verbose > 3) {
				       fprintf(stderr,
					       "arping: poll says ok, "
					       "pcap_dispatch=%d!\n",
					       ret);
			       }
		       }
	       }
       }
}

/**
 * 
 */
static void
ping_recv(pcap_t *pcap,uint32_t packetwait, pcap_handler func)
{
       if(verbose>3) {
               printf("arping: receiving packets...\n");
       }

#if WIN32
       ping_recv_win32(pcap,packetwait,func);
#else
       ping_recv_unix(pcap,packetwait,func);
#endif
}

/**
 *
 */
int main(int argc, char **argv)
{
	char ebuf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
	char *cp;
	int promisc = 0;
	int srcip_given = 0;
	int srcmac_given = 0;
	int dstip_given = 0;
	const char *ifname = NULL;
	char *parm;
	int c;
	unsigned int maxcount = -1;
	int dont_use_arping_lookupdev=0;
	struct bpf_program bp;
	pcap_t *pcap;
	static enum { NONE, PINGMAC, PINGIP } mode = NONE;
	unsigned int packetwait = 1000000;

        for (c = 1; c < argc; c++) {
                if (!strcmp(argv[c], "--help")) {
                        standard_usage();
                        extended_usage();
                        exit(0);
                }
        }

	memset(ethnull, 0, ETH_ALEN);

	srcip = 0;
	dstip = 0xffffffff;
	memset(dstmac, 0xff, ETH_ALEN);
	memset(ethxmas, 0xff, ETH_ALEN);

	while (EOF!=(c=getopt(argc,argv,"0aAbBc:dDeFhi:I:pqrRs:S:t:T:uvw:"))) {
		switch(c) {
		case '0':
			srcip = 0;
			srcip_given = 1;
			break;
		case 'a':
			beep = 1;
			break;
		case 'A':
			addr_must_be_same = 1;
			break;
		case 'b':
			srcip = 0xffffffff;
			srcip_given = 1;
			break;
		case 'B':
			dstip = 0xffffffff;
			dstip_given = 1;
			break;
		case 'c':
			maxcount = atoi(optarg);
			break;
		case 'd':
			finddup = 1;
			break;
		case 'D':
			display = DOT;
			break;
                case 'e':
                        reverse_beep = 1;
                        break;
		case 'F':
			dont_use_arping_lookupdev=1;
			break;
		case 'h':
			usage(0);
		case 'i':
			if (strchr(optarg, ':')) {
				fprintf(stderr, "arping: If you're trying to "
					"feed me an interface alias then you "
					"don't really\nknow what this programs"
					" does, do you?\nUse -I if you really"
					" mean it (undocumented on "
					"purpose)\n");
				exit(1);
			}
		case 'I': /* FALL THROUGH */
			ifname = optarg;
			break;
		case 'p':
			promisc = 1;
			break;
		case 'q':
			display = QUIET;
			break;
		case 'r':
			display = (display==RRAW)?RAWRAW:RAW;
			break;
		case 'R':
			display = (display==RAW)?RAWRAW:RRAW;
			break;
		case 's': { /* spoof source MAC */
			unsigned int n[6];
			if (!get_mac_addr(optarg,
					  &n[0],&n[1],&n[2],
					  &n[3],&n[4],&n[5])){
				fprintf(stderr, "arping: Weird MAC addr %s\n",
					optarg);
				exit(1);
			}
			for (c = 0; c < 6; c++) {
				srcmac[c] = n[c] & 0xff;
			}
			srcmac_given = 1;
			break;
		}
		case 'S': /* set source IP, may be null for don't-know */
			do_libnet_init(ifname);
			if (-1 == (srcip = libnet_name2addr4(libnet,
							     optarg,
							     LIBNET_RESOLVE))){
				fprintf(stderr, "arping: Can't resolve %s, or "
					"%s is broadcast. If it is, use -b"
					" instead of -S\n", optarg,optarg);
				exit(1);
			}
			srcip_given = 1;
			break;
		case 't': { /* set taget mac */
			unsigned int n[6];
			if (mode == PINGMAC) {
				fprintf(stderr, "arping: -t can only be used "
					"in IP ping mode\n");
				exit(1);
			}
			if (!get_mac_addr(optarg,
					  &n[0],&n[1],&n[2],
					  &n[3],&n[4],&n[5])){
				fprintf(stderr, "Illegal MAC addr %s\n",
					optarg);
				exit(1);
			}
			for (c = 0; c < 6; c++) {
				dstmac[c] = n[c] & 0xff;
			}
			mode = PINGIP;
			break;
		}
		case 'T': /* set destination IP */
			if (mode == PINGIP) {
				fprintf(stderr, "arping: -T can only be used "
					"in MAC ping mode\n");
				exit(1);
			}
			do_libnet_init(ifname);
			if (-1 == (dstip = libnet_name2addr4(libnet,
							     optarg,
							     LIBNET_RESOLVE))){
				fprintf(stderr,"arping: Can't resolve %s, or "
					"%s is broadcast. If it is, use -B "
					"instead of -T\n",optarg,optarg);
				exit(1);
			}
			mode = PINGMAC;
			break;
		case 'u':
			alsototal = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			packetwait = (unsigned)atoi(optarg);
			break;
		default:
			usage(1);
		}
	}

        if (display == DOT) {
                setvbuf(stdout, NULL, _IONBF, 0);
        }

        if (finddup && maxcount == -1) {
                maxcount = 3;
        }

	parm = (optind < argc) ? argv[optind] : NULL;

        /* default to own IP address when doing -d */
        if (finddup && !parm) {
                dstip_given = 1;
                do_libnet_init(ifname);
                dstip = libnet_get_ipaddr4(libnet);
                if (verbose) {
                        printf("defaulting to checking dup for %s\n",
                               libnet_addr2name4(dstip, 0));
                }
        }

	/*
	 * Handle dstip_given instead of ip address after parms (-B really)
	 */
	if (mode == NONE) {
		if (optind + 1 == argc) {
			mode = is_mac_addr(parm)?PINGMAC:PINGIP;
		} else if (dstip_given) {
			mode = PINGIP;
			do_libnet_init(ifname);
			parm = strdup(libnet_addr2name4(dstip,0));
			if (!parm) {
				fprintf(stderr, "arping: out of mem\n");
				exit(1);
			}
		}
	}

	if (!parm) {
		usage(1);
	}

	/*
	 *
	 */
	if (mode == NONE) {
		usage(1);
	}

	/*
	 * libnet init (may be done already for resolving)
	 */
	do_libnet_init(ifname);
	
	/*
	 * Make sure dstip and parm like eachother
	 */
	if (mode == PINGIP && (!dstip_given)) {
		if (is_mac_addr(parm)) {
			fprintf(stderr, "arping: Options given only apply to "
				"IP ping, but MAC address given as argument"
				"\n");
			exit(1);
		}
		if (-1 == (dstip = libnet_name2addr4(libnet,
						     parm,
						     LIBNET_RESOLVE))) {
			fprintf(stderr, "arping: Can't resolve %s\n", parm);
			exit(1);
		}
		parm = strdup(libnet_addr2name4(dstip,0));
	}

	/*
	 * parse parm into dstmac
	 */
	if (mode == PINGMAC) {
		unsigned int n[6];
		if (optind + 1 != argc) {
			usage(1);
		}
		if (!is_mac_addr(parm)) {
			fprintf(stderr, "arping: Options given only apply to "
				"MAC ping, but no MAC address given as "
				"argument\n");
			exit(1);
		}
		if (!get_mac_addr(argv[optind],
				  &n[0],&n[1],&n[2],
				  &n[3],&n[4],&n[5])) {
			fprintf(stderr, "arping: Illegal mac addr %s\n",
				argv[optind]);
			return 1;
		}
		for (c = 0; c < 6; c++) {
			dstmac[c] = n[c] & 0xff;
		}
	}	

	target = parm;
	/*
	 * Argument processing done, parameters considered sane below
	 */

	/*
	 * Get some good iface.
	 */
	if (!ifname) {
		if (dont_use_arping_lookupdev) {
			ifname = arping_lookupdev_default(ifname,
							  srcip,dstip,ebuf);
		} else {
			ifname = arping_lookupdev(ifname,srcip,dstip,ebuf);
		}
		if (!ifname) {
			fprintf(stderr, "arping: arping_lookupdev(): %s\n",
				ebuf);
			exit(1);
		}
		/* FIXME: check for other probably-not interfaces */
		if (!strcmp(ifname, "ipsec")
		    || !strcmp(ifname,"lo")) {
			fprintf(stderr, "arping: Um.. %s looks like the wrong "
				"interface to use. Is it? "
				"(-i switch)\n", ifname);
			fprintf(stderr, "arping: using it anyway this time\n");
		}
	}

	/*
	 * Init libnet again, because we now know the interface name.
	 * We should know it by know at least
	 */
	do_libnet_init(ifname);

	/*
	 * pcap init
	 */
	if (!(pcap = pcap_open_live((char*)ifname, 100, promisc, 10, ebuf))) {
		fprintf(stderr, "arping: pcap_open_live(): %s\n",ebuf);
		exit(1);
	}
	if (pcap_setnonblock(pcap, 1, ebuf)) {
		fprintf(stderr, "arping: pcap_set_nonblock(): %s\n", ebuf);
		exit(1);
	}
	if (verbose) {
		printf("pcap_get_selectable(): %d\n",
		       pcap_get_selectable_fd(pcap));
	}

#if HAVE_NET_BPF_H
	{
		uint32_t on = 1;
		if (0 < (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE,
			       &on))) {
			fprintf(stderr, "arping: ioctl(fd,BIOCIMMEDIATE, 1) "
				"failed, continuing anyway, YMMV: %s\n",
				strerror(errno));
		}
	}
#endif

	if (mode == PINGIP) {
		/* FIXME: better filter with addresses? */
		if (-1 == pcap_compile(pcap, &bp, "arp", 0,-1)) {
			fprintf(stderr, "arping: pcap_compile(): error\n");
			exit(1);
		}
	} else { /* ping mac */
		/* FIXME: better filter with addresses? */
		if (-1 == pcap_compile(pcap, &bp, "icmp", 0,-1)) {
			fprintf(stderr, "arping: pcap_compile(): error\n");
			exit(1);
		}
	}
	if (-1 == pcap_setfilter(pcap, &bp)) {
		fprintf(stderr, "arping: pcap_setfilter(): error\n");
		exit(1);
	}

	/*
	 * final init
	 */
	if (!srcmac_given) {
		if (!(cp = (char*)libnet_get_hwaddr(libnet))) {
			fprintf(stderr, "arping: libnet_get_hwaddr(): %s\n",
				libnet_geterror(libnet));
			exit(1);
		}
		memcpy(srcmac, cp, ETH_ALEN);
	}
	if (!srcip_given) {
		if (-1 == (srcip = libnet_get_ipaddr4(libnet))) {
			fprintf(stderr, "arping: libnet_get_ipaddr4(libnet): "
				"%s\n", libnet_geterror(libnet));
			exit(1);
		}
	}
#if WIN32
	/* SetConsoleCtrlHandler(NULL, TRUE); */
	SetConsoleCtrlHandler(arping_console_ctrl_handler, TRUE);
#else
	signal(SIGINT, sigint);
#endif

	if (verbose) {
		printf("This box:   Interface: %s  IP: %s   MAC address: ",
		       ifname, libnet_addr2name4(libnet_get_ipaddr4(libnet),
						 0));
		for (c = 0; c < ETH_ALEN - 1; c++) {
			printf("%.2x:", (uint8_t)srcmac[c]);
		}
		printf("%.2x\n", (uint8_t)srcmac[ETH_ALEN - 1]);
	}


	if (display == NORMAL) {
		printf("ARPING %s\n", parm);
	}

	/*
	 * let's roll
	 */
	if (mode == PINGIP) {
		unsigned int c;
                unsigned int r;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingip_send(srcmac, dstmac, srcip, dstip);
                        r = numrecvd;
			ping_recv(pcap,packetwait,
				  (pcap_handler)pingip_recv);
                        if (reverse_beep && !time_to_die && (r == numrecvd)) {
                                printf("\a");
                                fflush(stdout);
                        }
		}
	} else { /* PINGMAC */
		unsigned int c;
                unsigned int r;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingmac_send(srcmac, dstmac, srcip, dstip, rand(), c);
                        r = numrecvd;
			ping_recv(pcap,packetwait,
				  (pcap_handler)pingmac_recv);
                        if (reverse_beep && !time_to_die && (r == numrecvd)) {
                                printf("\a");
                                fflush(stdout);
                        }
		}
	}
        if (display == DOT) {
                count_missing_dots();
                printf("\t%3.0f%% packet loss\n",
                       100.0 - 100.0 * (float)(numrecvd)/(float)numsent);
        } else if (display == NORMAL) {
                float succ;
                succ = 100.0 - 100.0 * (float)(numrecvd)/(float)numsent;
                printf("\n--- %s statistics ---\n"
                       "%d packets transmitted, "
                       "%d packets received, "
                       "%3.0f%% "
                       "unanswered (%d extra)\n",
                       target,numsent,numrecvd,
                       (succ < 0.0) ? 0.0 : succ,
                       (succ < 0.0) ? (numrecvd - numsent): 0); 
	}

        if (finddup) {
                return dupfound;
        } else {
                return !numrecvd;
        }
}
