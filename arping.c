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
 * $Id: arping.c 860 2003-04-07 18:02:51Z marvin $
 */
/*
 *  Copyright (C) 2000-2002 Thomas Habets <thomas@habets.pp.se>
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
 *  You should have received a copy of the GNU General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
/*
 * Note to self:
 *  Test this on each platform:
 *    command                   expected response
 *    arping host               pongs
 *    arping -a host            audiable pongs
 *    arping mac                pongs
 *    arping -a mac             audiable pongs
 *    arping -A host            nothing
 *    arping -A mac             nothing
 *    arping -A host -t mac     nothing
 *    arping -A mac  -T ip      nothing
 *    arping -r host            mac
 *    arping -R host            ip
 *    arping -r mac             ip
 *    arping -R mac             mac
 *    arping -rR mac            mac ip
 *    ./arping-scan-net.sh mac  ip
 *    
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#if FREEBSD
#include <sys/socket.h>
#include "freebsd.h" 
#endif

#if MACOSX
#include <sys/socket.h>
#include "freebsd.h" 
#endif

#if USE_NETIF
#include <net/if.h>
#include <net/if_arp.h>
#endif

#include <libnet.h>
#include <pcap.h>

#if OPENBSD
#include "openbsd.h"
#endif

#if SOLARIS
#include "solaris.h"
#include "netinet/arp.h"
#endif

#if 0
#define DEBUG(a) a
#else
#define DEBUG(a)
#endif

const float version = 1.07;

struct ether_addr *mymac;
static u_char eth_xmas[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static u_char eth_null[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static u_char eth_target[ETH_ALEN];
static u_char eth_source[ETH_ALEN];  // only used in main() but it belongs here

static struct timeval lastpacketsent;
static const u_int ip_xmas = 0xffffffff;

static pcap_t *pcap;
//static struct bpf_program bpf_prog;
//static struct in_addr net,mask;
#if 0
// Use this if you want to hard-code a default interface
static char *ifname = "eth0";
#else
static char *ifname = NULL;
#endif
static u_int32_t dip = 0;
static u_char *packet;
static struct libnet_link_int *linkint;

static unsigned int beep = 0;
static unsigned int verbose = 0;
static unsigned int numsent = 0;
static unsigned int numrecvd = 0;
static unsigned int searchmac = 0;
static unsigned int finddup = 0;
static unsigned int maxcount = -1;
static unsigned int rawoutput = 0;
static unsigned int quiet = 0;
static unsigned int nullip = 0;
static unsigned int is_promisc = 0;
static unsigned int addr_must_be_same = 0;

static void sigint(int i)
{
	DEBUG(printf("sigint()\n"));
	if (!rawoutput) {
		if (searchmac) {
			u_char *cp=eth_target;
			int c;
			printf("\n--- ");
			for (c = 0; c < ETH_ALEN-1; c++) {
				printf("%.2x:", (u_char)*cp++);
			}
			printf("%.2x statistics ---\n", *cp);
		} else {
			printf("\n--- %s statistics ---\n",
			       libnet_host_lookup(dip,0));
		}
		printf("%d packets transmitted, %d packets received, %3.0f%% "
		       "unanswered\n", numsent, numrecvd,
		       100.0 - 100.0 * (float)(numrecvd)/(float)numsent);
	}
	exit(i);
}


static void usage(int ret)
{
	printf("ARPing %1.2f, by Thomas Habets <thomas@habets.pp.se>\n",
	       version);
	printf("usage: arping [ -qvrRd0bpAa ] [ -S <host/ip> ] [ -T <host/ip ]"
	       " [ -s <MAC> ]\n"
	       "              [ -t <MAC> ] [ -c <count> ] [ -i <interface> ] "
	       "<host/ip/MAC | -B>\n");
	exit(ret);
}

static void alasend(int i)
{
	DEBUG(printf("alasend()\n"));
	if (numsent >= maxcount) {
		sigint(numrecvd ? 0 : 1);
	}
	numsent++;
	if (searchmac) {
		libnet_build_icmp_echo(ICMP_ECHO,      /* type */ 
				       0,              /* code */ 
				       (short)random(),           /* id */ 
				       htons(numsent-1), /* seq */ 
				       NULL,           /* pointer to payload */
				       0,              /* payload length */ 
				       /* header memory */ 
				       packet + LIBNET_ETH_H + LIBNET_IP_H);

		if (libnet_do_checksum(packet + LIBNET_ETH_H, IPPROTO_ICMP,
				       LIBNET_ICMP_ECHO_H) == -1) { 
			libnet_error(LIBNET_ERR_FATAL,
				     "libnet_do_checksum failed\n"); 
		}
		
		if (libnet_do_checksum(packet + LIBNET_ETH_H,
				       IPPROTO_IP, LIBNET_IP_H) == -1) { 
			libnet_error(LIBNET_ERR_FATAL,
				     "libnet_do_checksum failed\n"); 
		} 

	}
	if (finddup && numrecvd) {
		sigint(0);
	}
	if (verbose > 1) {
		printf("Sending packet\n");
	}
	if (-1 == (libnet_write_link_layer(linkint,
					   (u_char*)ifname,
					   (u_char*)packet,
					   LIBNET_ARP_H + LIBNET_ETH_H))) {
		fprintf(stderr, "libnet_write_link_layer(): error\n");
		exit(1);
	}
	if (gettimeofday(&lastpacketsent, NULL)) {
		fprintf(stderr, "arping: %s\n", strerror(errno));
		exit(1);
	}
	alarm(1);
	DEBUG(fprintf(stderr, "Resetting timer\n"));
#if SOLARIS
	signal(SIGALRM, alasend);
#endif
}

/*
 * NOTE: not re-entrant
 */
static char* tvtoda(const struct timeval *tv, const struct timeval *tv2)
{
	static char buf[128];
	double f,f2;

	f = tv->tv_sec + (double)tv->tv_usec / 1000000;
	f2 = tv2->tv_sec + (double)tv2->tv_usec / 1000000;
	f = (f2 - f) * 1000000;
	if (f < 1000) {
		sprintf(buf, "%.3f usec", f);
	} else if (f < 1000000) {
		sprintf(buf, "%.3f msec", f / 1000);
	} else {
		sprintf(buf, "%.3f sec", f / 1000000);
	}
	return buf;
}

static void handlepacket(const char *unused, struct pcap_pkthdr *h,
			 u_char *packet)
{
	struct ethhdr *eth;
	struct arphdr *harp;
	struct iphdr *hip;
	struct icmphdr *hicmp;
	unsigned int c;
	unsigned char *cp;
	struct timeval recvtime;

	DEBUG(printf("handlepacket()\n"));

	if (gettimeofday(&recvtime, NULL)) {
		fprintf(stderr, "arping: %s\n", strerror(errno));
		exit(1);
	}

	eth = (struct ethhdr*)packet;

	if (searchmac) {
		// ping mac
		hip = (struct iphdr*)((char*)eth
				      + sizeof(struct libnet_ethernet_hdr));
		hicmp = (struct icmphdr*)((char*)hip + sizeof(struct iphdr));
		if ((htons(hicmp->type) == ICMP_ECHOREPLY)
		    && ((!memcmp(eth->h_source, eth_target, ETH_ALEN)
			 || !memcmp(eth_target, eth_xmas, ETH_ALEN)))
		    && !memcmp(eth->h_dest, eth_source,
			       ETH_ALEN)) {
			u_char *cp = eth->h_source;
			if (addr_must_be_same && (dip != hip->saddr)) {
				return;
			}
			numrecvd++;
			if (!rawoutput) {
				printf("%d bytes from ", h->len);
			}
			if (!quiet) {
				if (rawoutput & 2) {
					for (c = 0; c < 5; c++) {
						printf("%.2x:", *cp++);
					}
					printf("%.2x ", *cp++);
				}
				if (rawoutput & 1) {
					u_int32_t tmp;
					memcpy(&tmp, &hip->saddr, 4);
					printf("%s",
					       libnet_host_lookup(tmp,
								  0));
				}
				if (!rawoutput) {
					/*
					 * ugly code due to non-aligned saddr
					 * (bus error on sparc)
					 */
					u_int32_t tmp;
					memcpy(&tmp, &hip->saddr,
					       sizeof(u_int32_t));
					printf("%s",libnet_host_lookup(tmp,0));
					printf(" (");
					for (c = 0; c < ETH_ALEN-1; c++) {
						printf("%.2x:", *cp++);
					}
					printf("%.2x): icmp_seq=%d time=%s",
					       *cp,
					       hicmp->un.echo.sequence,
					       tvtoda(&lastpacketsent,
						      &recvtime));
				}
				if (beep) {
					printf("\a");
				}
				printf("\n");
			}
		}
	} else {
		/* ping ip */
		harp = (struct arphdr*)((char*)eth
					+ sizeof(struct libnet_ethernet_hdr));
		if ((htons(harp->ar_op) == ARPOP_REPLY)
		    && (htons(harp->ar_pro) == ETH_P_IP)
		    && (htons(harp->ar_hrd) == ARPHRD_ETHER)) {
			u_int32_t ip;
			memcpy(&ip, (char*)harp + harp->ar_hln
			       + sizeof(struct arphdr), 4);
			if (addr_must_be_same
			    && (memcmp((u_char*)harp+sizeof(struct arphdr),
				       eth_target, ETH_ALEN))) {
				return;
			}

			if (dip == ip) {
				cp = (u_char*)harp + sizeof(struct arphdr);
				if (!rawoutput && !finddup) {
					printf("%d bytes from ", h->len);
				}

				if (!quiet) {
					if (rawoutput & 1) {
						for (c = 0; c < harp->ar_hln-1;
						     c++) {
							printf("%.2x:", *cp++);
						}
						printf("%.2x ", *cp++);
					}
					if (rawoutput & 2) {
						printf("%s",
						       libnet_host_lookup(ip,
									  0));
					}
					if (!rawoutput) {
						for (c = 0; c < harp->ar_hln-1;
						     c++) {
							printf("%.2x:", *cp++);
						}
						printf("%.2x", *cp);
					}
					if (!rawoutput) {
						printf(" (%s): index=%d time=%s",
						       libnet_host_lookup(ip, 0),
						       numrecvd, tvtoda(&lastpacketsent, &recvtime));
					}
					if (beep) {
						printf("\a");
					}
					printf("\n");
				}
				numrecvd++;
			}
		}
	}
}

static void recvpackets(void)
{
	DEBUG(printf("recvpackets()\n"));
	if (-1 == pcap_loop(pcap, -1, (pcap_handler)handlepacket, NULL)) {
		fprintf(stderr, "pcap_loop(): error\n");
		exit(1);
	}
	// does not return
}

int main(int argc, char **argv)
{
	u_long myip = 0;
	char ebuf[LIBNET_ERRBUF_SIZE];
	int c;
	struct bpf_program bp;
	char must_be_pingip = 0;
	char have_eth_source = 0;
	
	DEBUG(printf("main()\n"));

	strncpy(ebuf, "no error", LIBNET_ERRBUF_SIZE);
	ebuf[LIBNET_ERRBUF_SIZE -1 ] = 0;

	memcpy(eth_target, eth_xmas, ETH_ALEN);

	while ((c = getopt(argc, argv, "0bdS:T:Bvhi:rRc:qs:t:paA")) != EOF) {
		switch (c) {
		case 'A':
			addr_must_be_same = 1;
			break;
		case 'a':
			beep = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			usage(0);
		case 'i':
			if (strchr(optarg, ':')) {
				fprintf(stderr, "arping: If you're trying to "
					"feed me an interface alias then you "
					"don't really\nknow what this programs"
					" does, do you?\n");
				exit(1);
			}
			ifname = optarg;
			break;
		case 'r':
			rawoutput |= 1;
			break;
		case 'R':
			rawoutput |= 2;
			break;
		case 'q':
			quiet = rawoutput = 1;
			break;
		case 'c':
			maxcount = atoi(optarg);
			break;
		case 'd':
			finddup = 1;
			break;	
		case 'S':
			if ((myip = libnet_name_resolve(optarg,
							LIBNET_RESOLVE))
			    == -1) {
				fprintf(stderr,"arping: Can't to resolve %s\n",
					optarg);
				exit(1);
			}
			if (!myip) {
				nullip = 1;
			}
			break;
		case 'T': // destination IP in mac ping (default: 0xffffffff)
			dip = libnet_name_resolve(optarg,
						  LIBNET_RESOLVE);
			searchmac = 1;
			break;
		case 'b':
			myip = 0xffffffff;
			break;
		case 'B':
			dip = 0xffffffff;
			break;
		case '0':
			nullip = 1;
			break;
		case 's': // spoofed source MAC
			{
                           unsigned int n[6];
			   
			   if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
				      &n[0],
				      &n[1],
				      &n[2],
				      &n[3],
				      &n[4],
				      &n[5]
				   ) != 6) {
				   fprintf(stderr, "Illegal MAC addr %s\n",
					   optarg);
				   exit(1);
			   }
			   for (c = 0; c < 6; c++) {
				   eth_source[c] = n[c] & 0xff;
			   }
			   have_eth_source = 1;
			}
			break;
		case 't':
			must_be_pingip = 1;
			{
                           unsigned int n[6];
			   
			   if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
				      &n[0],
				      &n[1],
				      &n[2],
				      &n[3],
				      &n[4],
				      &n[5]
				   ) != 6) {
				   fprintf(stderr, "Illegal MAC addr %s\n",
					   optarg);
				   exit(1);
			   }
			   for (c = 0; c < 6; c++) {
				   eth_target[c] = n[c] & 0xff;
			   }
			}
			break;
		case 'p':
			is_promisc = 1;
			break;
		default:
			usage(1);
		}
	}
	if (!searchmac && !dip && (optind + 1 != argc)) {
		usage(1);
	} else if (searchmac && (optind + 1 != argc)) {
		usage(1);
	}
	if (getuid() && geteuid()) {
		fprintf(stderr, "arping: must run as root\n");
		return 1;
	}

	if (myip && nullip) {
		fprintf(stderr, "-S, -b and -0 are mutually exclusive\n");
		exit(1);
	}

	if (searchmac || (!dip && strchr(argv[optind], ':'))) {
		unsigned int n[6];
		if (!dip) {
			dip = ip_xmas;
		}

		if (must_be_pingip) {
			fprintf(stderr, "Specified switch can't be used in "
				"MAC-ping mode\n");
			exit(1);
		}

		if (sscanf(argv[optind], "%x:%x:%x:%x:%x:%x", 
			   &n[0],
			   &n[1],
			   &n[2],
			   &n[3],
			   &n[4],
			   &n[5]
			   ) != 6) {
			fprintf(stderr, "Illegal mac addr %s\n", argv[optind]);
			return 1;
		}
		for (c = 0; c < 6; c++) {
			eth_target[c] = n[c] & 0xff;
		}
		searchmac = 1;
	} else if (!dip) {
		
		if (-1 == (dip = libnet_name_resolve((u_char*)argv[optind],
						     LIBNET_RESOLVE))) {
			fprintf(stderr, "arping: Can't resolve %s\n",
				argv[optind]);
			exit(1);
		}
	}
	if (finddup && maxcount == -1) {
		maxcount = 3;
	}
	/*
	 * libnet init
	 */
	if (!ifname) {
		if (!(ifname = pcap_lookupdev(ebuf))) {
			fprintf(stderr, "pcap_lookupdev(): %s\n", ebuf);
			exit(1);
		}
		// FIXME: check for other probably-not interfaces
		if (!strncmp(ifname, "ipsec", 5)) {
			fprintf(stderr, "arping: Um.. %s looks like the wrong "
				"interface to use. Is it? "
				"(-i switch)\n", ifname);
			fprintf(stderr, "arping: using it anyway this time\n");
		}
	}

	if (!(linkint = libnet_open_link_interface(ifname, ebuf))) {
		fprintf(stderr, "libnet_open_link_interface(): %s\n", ebuf);
		exit(1);
	}
	
	if (!have_eth_source) {
		if (!(mymac = libnet_get_hwaddr(linkint, (u_char*)ifname,
						ebuf))) {
			fprintf(stderr, "libnet_get_hwaddr(): %s\n", ebuf);
			exit(1);
		}
		memcpy(eth_source, mymac->ether_addr_octet, ETH_ALEN);
		have_eth_source = 1;
	}

	if (nullip) {
		myip = 0;
	} else if (myip) {
		// myip set, don't touch it
	} else if  (!(myip = htonl(libnet_get_ipaddr(linkint,(u_char*)ifname,
						     ebuf)))) {
		fprintf(stderr, "libnet_get_ipaddr(): %s\n", ebuf);
		exit(1);
	}

	if (searchmac) {
		if (-1 == libnet_init_packet(LIBNET_ETH_H + LIBNET_IP_H
					     + LIBNET_ICMP_ECHO_H, &packet)) {
			fprintf(stderr, "libnet_init_packet(): error\n");
			exit(1);
		}
	} else {
		/*
		 * this makes it work on solaris.
		 * not sure if LIBNET_ICMP_H is needed though, but it works
		 */
		if (-1 == libnet_init_packet(LIBNET_ETH_H + LIBNET_ARP_H
					     + LIBNET_ICMP_H, &packet)) {
			fprintf(stderr, "libnet_init_packet(): error\n");
			exit(1);
		}
	}
	
	if (verbose) {
		printf("This box:   Interface: %s  IP: %s   MAC address: ",
		       ifname, libnet_host_lookup(myip,0));
		for (c = 0; c < ETH_ALEN - 1; c++) {
			printf("%.2x:", (unsigned )eth_source[c]);
		}
		printf("%.2x\n", eth_source[ETH_ALEN - 1]);
	}

	if (searchmac) {
		// ping MAC
		/*
		 * KEYWORD
		 * What the hell was I thinking when I wrote the comment below?
		 * -------
		 * note: it's eth_xmas below, that's a feature. I don't want
		 *       a -t line to affect a MAC ping (even though it can't
		 *       since the lone arg is written last).
		 * -------
		 * Phew! Anyway, change eth_target to eth_xmas three lines
		 *       below to change it back.
		 */
		if (-1 == libnet_build_ethernet(eth_target, /* <---- here  */
						eth_source,
						ETHERTYPE_IP,
						NULL,
						0,
						packet)) {
			fprintf(stderr, "libnet_build_ethernet(): error\n");
			exit(1);
		}

		libnet_build_ip(ICMP_ECHO_H,  /* Size of the payload */ 
				0,  /* IP tos */ 
				rand(),               /* IP ID */ 
				0,                  /* frag stuff */ 
				48,                 /* TTL */ 
				IPPROTO_ICMP,       /* transport protocol */ 
				myip,               /* source IP */ 
				dip,                /* destination IP */ 
				NULL,               /* pointer to payload */ 
				0,                  /* payload length */ 
				packet + LIBNET_ETH_H); /* header memory */ 

		libnet_build_icmp_echo(ICMP_ECHO,     /* type */ 
				       0,             /* code */ 
				       4321,          /* id */ 
				       6,             /* seq */ 
				       NULL,          /* pointer to payload */
				       0,             /* payload length */ 
				       /* header memory */ 
				       packet + LIBNET_ETH_H + LIBNET_IP_H);
	} else {
		// ping ip
		if (-1 == libnet_build_ethernet(eth_target, // usually xmas
						eth_source, // this box
						ETHERTYPE_ARP,
						NULL,
						0,
						packet)) {
			fprintf(stderr, "libnet_build_ethernet(): error\n");
			exit(1);
		}
		
		if (-1 == libnet_build_arp(ARPHRD_ETHER,
					   ETHERTYPE_IP,
					   6,
					   4,
					   ARPOP_REQUEST,
					   eth_source,
					   (u_char*)&myip,
					   eth_null,
					   (u_char*)&dip,
					   NULL,
					   0,
					   packet + LIBNET_ETH_H)) {
			fprintf(stderr, "libnet_build_arp(): error\n");
			exit(1);
		}
      	}
	/*
	 * pcap init
	 */
	if (!(pcap = pcap_open_live(ifname, 100, is_promisc, 10, ebuf))) {
		fprintf(stderr, "pcap_open_live(): %s\n", ebuf);
		exit(1);
	}

	if (searchmac) {
		if (-1 == pcap_compile(pcap,&bp,"icmp",0,-1)) {
			fprintf(stderr, "pcap_compile(): error\n");
			exit(1);
		}
	} else {
		if (-1 == pcap_compile(pcap,&bp,"arp",0,-1)) {
			fprintf(stderr, "pcap_compile(): error\n");
			exit(1);
		}
	}
	if (-1 == pcap_setfilter(pcap, &bp)) {
		fprintf(stderr, "pcap_setfilter(): error\n");
		exit(1);
	}
	/*
	 * main program
	 */
	signal(SIGALRM, alasend);
	signal(SIGINT, sigint);
	if (!rawoutput) {
		if (searchmac) {
			printf("ARPING %s\n", argv[optind]);
		} else {
			printf("ARPING %s\n", libnet_host_lookup(dip,0));
		}
	}
	alasend(0);
	for(;;) {
		recvpackets();
	}
	libnet_destroy_packet(&packet);
	return 0;
}
