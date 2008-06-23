/*
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
 * $Id: arping.c 2052 2008-06-23 07:22:30Z marvin $
 */
/*
 *  Copyright (C) 2000-2008 Thomas Habets <thomas@habets.pp.se>
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
//#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
// NOTE: try un-commenting this
//#include <stdint.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
#endif

#ifdef WIN32
#include <win32/libnet.h>
#endif
#include <pcap.h>

#if defined(WIN32)
#define HAVE_ESIZE_TYPES 1
#include "win32.h"
#include "win32/getopt.h"
#endif

#if !defined(linux)
#define HAVE_WEIRD_BSD 1
#define FINDIF 1
#endif
 
#if defined(linux)
#define HAVE_ESIZE_TYPES 1
#define FINDIF 1
#endif

#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif

#ifndef HAVE_ESIZE_TYPES
/*
 * let's hope we at least have these
 * FIXME: bleh, this is not auto-detected, so fix it with os-dependent stuff
 * like we have above for linux
 * But this broken thing compiled on my solaris, openbsd and linux-boxes so
 * it kinda works.
 */
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

const float version = 2.06f;

static libnet_t *libnet = 0;

static struct timeval lastpacketsent;

static u_int32_t srcip,dstip;

static int beep = 0;
static int verbose = 0;
static int alsototal = 0;
/*static int pingmac = 0; */
static int finddup = 0;
static unsigned int numsent = 0;
static unsigned int numrecvd = 0;
static int addr_must_be_same = 0;
// RAWRAW is RAW|RRAW
static enum { NORMAL,QUIET,RAW,RRAW,RAWRAW } display = NORMAL;
static char *target = "huh? bug in arping?";
static u_int8_t ethnull[ETH_ALEN];
static u_int8_t ethxmas[ETH_ALEN];
static char srcmac[ETH_ALEN];
static char dstmac[ETH_ALEN];

volatile int time_to_die = 0;


/*
 *
 */	
static void do_libnet_init(const char *ifname)
{
	char ebuf[LIBNET_ERRBUF_SIZE];
	if (verbose > 1) {
		printf("libnet_init(%s)\n", ifname);
	}
	if (libnet) {
		/* prolly going to switch interface from temp to real */
		libnet_destroy(libnet);
		libnet = 0;
	}
	if (getuid() && geteuid()) {
		fprintf(stderr, "arping: must run as root\n");
		exit(1);
	}

	if (!(libnet = libnet_init(LIBNET_LINK,
				   (char*)ifname,
				   ebuf))) {
		fprintf(stderr, "arping: libnet_init(): %s\n", ebuf);
		exit(1);
	}
}

/*
 *
 */
static const char *
arping_lookupdev_default(const char *ifname,
			 u_int32_t srcip, u_int32_t dstip,
			 char *ebuf)
{
#ifdef WIN32
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

#if defined(FINDIF) && defined(linux)
/*
 *
 */
static const char *arping_lookupdev(const char *ifname,
				    u_int32_t srcip,
				    u_int32_t dstip,
				    char *ebuf)
{
	FILE *f;
	static char buf[1024];
	char buf1[1024];
	char buf2[1024];
	char *p,*p2;
	int n;

	do_libnet_init(ifname);
	libnet_addr2name4_r(dstip,0,buf2);
	libnet_addr2name4_r(srcip,0,buf1);

	/*
	 * Construct and run command
	 */
	snprintf(buf, 1023, "/sbin/ip route get %s from %s 2>&1",
		 buf2,buf1);
	if (!(f = popen(buf, "r"))) {
		goto failed;
	}
	if (0>(n = fread(buf, 1, sizeof(buf)-1, f))) {
		pclose(f);
		goto failed;
	}
	buf[n] = 0;
	if (-1 == pclose(f)) {
		perror("arping: pclose()");
		goto failed;
	}

	/*
	 * Parse out device
	 */
	p = strstr(buf, "dev ");
	if (!p) {
		goto failed;
	}

	p+=4;

	p2 = strchr(p, ' ');
	if (!p2) {
		goto failed;
	}
	*p2 = 0;
	return p;
 failed:
	return arping_lookupdev_default(ifname,srcip,dstip,ebuf);
}
#elif defined(FINDIF) && defined(HAVE_WEIRD_BSD)
static
const char *
arping_lookupdev(const char *ifname,
		 u_int32_t srcip, u_int32_t dstip, char *ebuf)
{
	FILE *f;
	static char buf[10240];
	char buf1[1024];
	char *p,*p2;
	int n;

	do_libnet_init(ifname);
	libnet_addr2name4_r(dstip,0,buf1);
	//libnet_addr2name4_r(srcip,0,buf1);

	/*
	 * Construct and run command
	 */
	snprintf(buf, 1023, "/sbin/route -n get %s 2>&1",
		 buf1);
	if (!(f = popen(buf, "r"))) {
		goto failed;
	}
	if (0 > (n = fread(buf, 1, sizeof(buf)-1, f))) {
		pclose(f);
		goto failed;
	}
	buf[n] = 0;
	if (-1 == pclose(f)) {
		perror("arping: pclose()");
		goto failed;
	}

	/*
	 * Parse out device
	 */
	p = strstr(buf, "interface: ");
	if (!p) {
		goto failed;
	}

	p+=11;

	p2 = strchr(p, '\n');
	if (!p2) {
		goto failed;
	}
	*p2 = 0;
	return p;
 failed:
	return arping_lookupdev_default(srcip,dstip,ebuf);
}
#else
/*
 *
 */
static const char *arping_lookupdev(const char *ifname,
				    u_int32_t srcip, u_int32_t dstip,
				    char *ebuf)
{
	return arping_lookupdev_default(ifname,srcip,dstip,ebuf);
}
#endif


#ifdef WIN32
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


/*
 *
 */
static void sigint(int i)
{
	time_to_die = 1;
}

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
	       "    -d     Find duplicate replies.\n"
	       "    -F     Don't try to be smart about the interface name.  (even  if  this\n"
	       "           switch is not given, -i overrides smartness.\n"
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
	       "    -w     (arping 2.x only) Time to wait between pings, in microseconds.\n");
}

/*
 *
 */
static void usage(int ret)
{
	printf("ARPing %1.2f, by Thomas Habets <thomas@habets.pp.se>\n",
	       version);
	printf("usage: arping [ -0aAbdFpqrRuv ] [ -w <us> ] [ -S <host/ip> ] "
	       "[ -T <host/ip ]\n"
	       "              [ -s <MAC> ] [ -t <MAC> ] [ -c <count> ] "
	       "[ -i <interface> ]\n"
	       "              <host/ip/MAC | -B>\n");
#ifdef WIN32
	extended_usage();
#endif
	exit(ret);
}

/*
 * It was unclear from msdn.microsoft.com if their scanf() supported
 * [0-9a-fA-F], so I'll stay away from it.
 */
static int is_mac_addr(const char *p)
{
	/* cisco-style */
	if (3*5-1 == strlen(p)) {
		int c;
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
		int c;
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

/*
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

/*
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
		// huh, uh, huhuh
		sprintf(buf, "%.3fe%d sec", f, exp-6);
	}
	return buf;
}



/*
 *
 */
static void pingmac_send(u_int8_t *srcmac, u_int8_t *dstmac,
			 u_int32_t srcip, u_int32_t dstip,
			 u_int16_t id, u_int16_t seq)
{
	static libnet_ptag_t icmp = 0, ipv4 = 0,eth=0;
	int c;

	if (-1 == (icmp = libnet_build_icmpv4_echo(ICMP_ECHO, // type
						   0, // code
						   0, // checksum
						   id, // id
						   seq, // seq
						   NULL, // payload
						   0, // payload len
						   libnet,
						   icmp))) {
		fprintf(stderr, "libnet_build_icmpv4_echo(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}

	if (-1==(ipv4 = libnet_build_ipv4(LIBNET_IPV4_H
					  + LIBNET_ICMPV4_ECHO_H + 0,
					  0, // ToS
					  id, // id
					  0, // frag
					  64, // ttl
					  IPPROTO_ICMP,
					  0, // checksum
					  srcip,
					  dstip,
					  NULL, // payload
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
		printf("arping: sending packet\n");
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

/*
 *
 */
static void pingip_send(u_int8_t *srcmac, u_int8_t *dstmac,
			u_int32_t srcip, u_int32_t dstip)
{
	static libnet_ptag_t arp=0,eth=0;
	if (-1 == (arp = libnet_build_arp(ARPHRD_ETHER,
					  ETHERTYPE_IP,
					  ETH_ALEN,
					  IP_ALEN,
					  ARPOP_REQUEST,
					  srcmac,
					  (u_int8_t*)&srcip,
					  ethnull,
					  (u_int8_t*)&dstip,
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
		printf("arping: sending packet\n");
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

/*
 *
 */
static void pingip_recv(const char *unused, struct pcap_pkthdr *h,
			u_int8_t *packet)
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
		u_int32_t ip;
		memcpy(&ip, (char*)harp + harp->ar_hln
		       + LIBNET_ARP_H,4);
		if (addr_must_be_same
		    && (memcmp((u_char*)harp+sizeof(struct libnet_arp_hdr),
			       dstmac, ETH_ALEN))) {
			return;
		}
		if (dstip == ip) {
			switch(display) {
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
			if (display != QUIET) {
				printf(beep?"\a\n":"\n");
			}
			numrecvd++;
		}
	}
}

/*
 * 
 */
static void pingmac_recv(const char *unused, struct pcap_pkthdr *h,
			u_int8_t *packet)
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
/*		u_int8_t *cp = heth->_802_3_shost; */
		if (addr_must_be_same) {
			u_int32_t tmp;
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


#ifdef WIN32
static void
ping_recv_win32(pcap_t *pcap,u_int32_t packetwait, pcap_handler func)
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

static void
fixup_timeval(struct timeval *tv)
{
	while (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}


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


/*
 * 
 */
static void
ping_recv_unix(pcap_t *pcap,u_int32_t packetwait, pcap_handler func)
{
       struct timeval tv;
       struct timeval endtime;
       char done = 0;
       fd_set fds;

       gettv(&tv);
       endtime.tv_sec = tv.tv_sec + (packetwait / 1000000);
       endtime.tv_usec = tv.tv_usec + (packetwait % 1000000);
       fixup_timeval(&endtime);

       for (;!done;) {
	       int sr;
	       FD_ZERO(&fds);
	       FD_SET(pcap_fileno(pcap), &fds);

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
#ifndef HAVE_WEIRD_BSD
	       switch((sr = select(pcap_fileno(pcap)+1,
				   &fds,
				   NULL,NULL,&tv))) {
	       case -1:
		       if (errno == EINTR) {
			       return;
		       }
		       fprintf(stderr, "arping: select(%lu.%lu): "
			       "%s\n",
			       tv.tv_sec,
			       tv.tv_usec,
			       strerror(errno));
		       sigint(0);
	       case 0:
		       done = 1;
		       break;
	       default: {
#else
	       usleep(10);
	       {{
#endif
		       int ret;
		       if (1 != (ret = pcap_dispatch(pcap, 1,
						     func,
						     NULL))) {
			       // rest, so we don't take 100% CPU... mostly
			       // hmm... does usleep() exist everywhere?
			       usleep(10);
#ifndef HAVE_WEIRD_BSD
			       // weird is normal on bsd :)
			       if (verbose) {
				       fprintf(stderr, "arping: select=%d "
					       "pcap_dispatch=%d!\n",
					       sr, ret);
			       }
		       }
		       break;
#else
	               }
#endif
		       }
	       }
       }
}

/*
 * 
 */
static void
ping_recv(pcap_t *pcap,u_int32_t packetwait, pcap_handler func)
{
       if(verbose>3) {
               printf("arping: receiving packets...\n");
       }

#ifdef WIN32
       ping_recv_win32(pcap,packetwait,func);
#else
       ping_recv_unix(pcap,packetwait,func);
#endif
}

/*
 *
 */
int main(int argc, char **argv)
{
	char ebuf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
	char *cp;
/*	int nullip = 0;*/
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

	memset(ethnull, 0, ETH_ALEN);

	srcip = 0;
	dstip = 0xffffffff;
	memset(dstmac, 0xff, ETH_ALEN);
	memset(ethxmas, 0xff, ETH_ALEN);

	while (EOF!=(c=getopt(argc, argv, "0aAbBc:dFhi:I:pqrRs:S:t:T:uvw:"))) {
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
		case 's': {// spoof source MAC
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
		case 'S': // set source IP, may be null for don't-know
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
		case 't': { // set taget mac
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
		case 'T': // set destination IP
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

	parm = (optind < argc) ? argv[optind] : NULL;

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
		// FIXME: check for other probably-not interfaces
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
#ifdef HAVE_NET_BPF_H
	{
		u_int32_t on = 1;
		if (0 < (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE,
			       &on))) {
			fprintf(stderr, "arping: ioctl(fd,BIOCIMMEDIATE, 1) "
				"failed, continuing anyway, YMMV: %s\n",
				strerror(errno));
		}
	}
#endif

	if (mode == PINGIP) {
		// FIXME: better filter with addresses?
		if (-1 == pcap_compile(pcap, &bp, "arp", 0,-1)) {
			fprintf(stderr, "arping: pcap_compile(): error\n");
			exit(1);
		}
	} else { // ping mac
		// FIXME: better filter with addresses?
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
#ifdef WIN32
	//SetConsoleCtrlHandler(NULL, TRUE);
	SetConsoleCtrlHandler(arping_console_ctrl_handler, TRUE);
#else
	signal(SIGINT, sigint);
#endif

	if (verbose) {
		printf("This box:   Interface: %s  IP: %s   MAC address: ",
		       ifname, libnet_addr2name4(libnet_get_ipaddr4(libnet),
						 0));
		for (c = 0; c < ETH_ALEN - 1; c++) {
			printf("%.2x:", (u_int8_t)srcmac[c]);
		}
		printf("%.2x\n", (u_int8_t)srcmac[ETH_ALEN - 1]);
	}


	if (display == NORMAL) {
		printf("ARPING %s\n", parm);
	}

	/*
	 * let's roll
	 */
	if (mode == PINGIP) {
		unsigned int c;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingip_send(srcmac, dstmac, srcip, dstip);
			ping_recv(pcap,packetwait,
				  (pcap_handler)pingip_recv);
		}
	} else { // PINGMAC
		unsigned int c;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingmac_send(srcmac, dstmac, srcip, dstip, rand(), c);
			ping_recv(pcap,packetwait,
				  (pcap_handler)pingmac_recv);
		}
	}
	if (display == NORMAL) {
		printf("\n--- %s statistics ---\n"
		       "%d packets transmitted, %d packets received, %3.0f%% "
		       "unanswered\n",target,numsent,numrecvd,
		       100.0 - 100.0 * (float)(numrecvd)/(float)numsent); 
	}
	exit(!numrecvd);

	return 0;
}
