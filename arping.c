/*
 * arping
 *
 * By marvin@nss.nu
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
 * $Id: arping.c 120 2000-09-09 22:20:30Z marvin $
 */
/*
 *  Copyright (C) 2000 Marvin (marvin@nss.nu)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#include <stdlib.h>
#include <unistd.h>

#if USE_NETIF
#include <net/if.h>
#include <net/if_arp.h>
#endif

#include <libnet.h>
#include <pcap.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#if OPENBSD
#include "openbsd.h"
#endif

#if 0
#define DEBUG(a) a
#else
#define DEBUG(a)
#endif

const float version = 0.8;

struct ether_addr *mymac;
u_char eth_xmas[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u_char eth_null[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
u_char eth_target[ETH_ALEN];

u_int ip_xmas = 0xffffffff;

pcap_t *pcap;
struct bpf_program bpf_prog;
struct in_addr net,mask;
#if 0
// Use this if you want to hard-code a default interface
char *ifname = "eth0";
#else
char *ifname = NULL;
#endif
u_long dip = 0;
u_char *packet;
struct libnet_link_int *linkint;

unsigned int verbose = 0;
unsigned int numsent = 0;
unsigned int numrecvd = 0;
unsigned int searchmac = 0;
unsigned int finddup = 0;
unsigned int maxcount = -1;
unsigned int rawoutput = 0;
unsigned int nullip = 0;

void sigint(int i);


void usage(int ret)
{
	printf("arping %1.1f [ -v ] [ -r ] [ -d ] [-0 ] [ -c count ] "
	       "[ -i <interface> ] <host/ip/MAC>\n", version);
	exit(ret);
}

void alasend(int i)
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
	alarm(1);
}

void sigint(int i)
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

void handlepacket(const char *unused, struct pcap_pkthdr *h, u_char *packet)
{
	struct ethhdr *eth;
	struct arphdr *harp;
	struct iphdr *hip;
	struct icmphdr *hicmp;
	unsigned int c;
	unsigned char *cp;

	DEBUG(printf("handlepacket()\n"));

	eth = (struct ethhdr*)packet;

	if (searchmac) {
		hip = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));
		hicmp = (struct icmphdr*)((char*)hip + sizeof(struct iphdr));
		if ((htons(hicmp->type) == ICMP_ECHOREPLY)
		    && ((!memcmp(eth->h_source, eth_target, ETH_ALEN)
			 || !memcmp(eth_target, eth_xmas, ETH_ALEN)))
		    && !memcmp(eth->h_dest, mymac->ether_addr_octet,
			       ETH_ALEN)) {
			u_char *cp = eth->h_source;
			if (!rawoutput) {
				printf("%d bytes from ", h->len);
			}
			printf("%s",libnet_host_lookup(hip->saddr, 0));
			if (!rawoutput) {
				printf(" (");
				for (c = 0; c < ETH_ALEN-1; c++) {
					printf("%.2x:", *cp++);
				}
				printf("%.2x): icmp_seq=%d", *cp,
				       hicmp->un.echo.sequence);
			}
			printf("\n");
		}
	} else {
		harp = (struct arphdr*)((char*)eth + sizeof(struct ethhdr));
		if ((htons(harp->ar_op) == ARPOP_REPLY)
		    && (htons(harp->ar_pro) == ETH_P_IP)
		    && (htons(harp->ar_hrd) == ARPHRD_ETHER)) {
		  int ip;
			memcpy(&ip, (char*)harp + harp->ar_hln + sizeof(struct arphdr), 4);
			if (dip == ip) {

				cp = (u_char*)harp + sizeof(struct arphdr);
				if (!rawoutput && !finddup) {
					printf("%d bytes from ", h->len);
				}
				for (c = 0; c < harp->ar_hln -1; c++) {
					printf("%.2x:", *cp++);
				}
				printf("%.2x", *cp);
				if (!rawoutput) {
					printf(" (%s): index=%d",
					       libnet_host_lookup(ip, 0),
					       numrecvd++);
				}
				printf("\n");
			}
		}
	}

}

void recvpackets(void)
{
  DEBUG(printf("recvpackets()\n"));
	if (-1 == pcap_loop(pcap, -1, (pcap_handler)handlepacket, NULL)) {
		fprintf(stderr, "pcap_loop(): error\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	u_long myip;
	char *ebuf = "no error";
	int c;
	struct bpf_program bp;
	
	DEBUG(printf("main()\n"));

	while ((c = getopt(argc, argv, "0dvhi:rc:")) != EOF) {
		switch (c) {
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
			rawoutput = 1;
			break;
		case 'c':
			maxcount = atoi(optarg);
			break;
		case 'd':
			finddup = 1;
			break;
		case '0':
			nullip = 1;
			break;
		default:
			usage(1);
		}
	}
	if (optind >= argc) {
		usage(1);
		exit(1);
	}
	if (getuid() && geteuid()) {
		fprintf(stderr, "Must be r00t\n");
		return 1;
	}

	if (strchr(argv[optind], ':')) {
		unsigned int n[6];
		dip = ip_xmas;

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
	} else {
		dip = libnet_name_resolve((u_char*)argv[optind],
					  LIBNET_RESOLVE);
		memcpy(eth_target, eth_xmas, ETH_ALEN);
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
	}

	if (!(linkint = libnet_open_link_interface(ifname, ebuf))) {
		fprintf(stderr, "libnet_get_hwaddr(): %s\n", ebuf);
		exit(1);
	}
	
	if (!(mymac = libnet_get_hwaddr(NULL, (u_char*)ifname,  ebuf))) {
		fprintf(stderr, "libnet_get_hwaddr(): %s\n", ebuf);
		exit(1);
	}
	
	if (nullip) {
		myip = 0;
	} else if  (!(myip = htonl(libnet_get_ipaddr(linkint,(u_char*)ifname,
						     ebuf)))) {
		fprintf(stderr, "libnet_get_ipaddr(): %s\n", ebuf);
		exit(1);
	}
	
	if (-1 == libnet_init_packet(LIBNET_ETH_H + LIBNET_IP_H
				     + LIBNET_ICMP_H, &packet)) {
		fprintf(stderr, "libnet_init_packet(): error\n");
		exit(1);
	}
	
	if (verbose) {
		printf("This box:   Interface: %s  IP: %s   MAC address: ",
		       ifname, libnet_host_lookup(myip,0));
		for (c = 0; c < ETH_ALEN - 1; c++) {
			printf("%.2x:", (unsigned )mymac->ether_addr_octet[c]);
		}
		printf("%.2x\n", mymac->ether_addr_octet[ETH_ALEN - 1]);
	}

	if (searchmac) {
		if (-1 == libnet_build_ethernet(eth_xmas,
						mymac->ether_addr_octet,
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
		if (-1 == libnet_build_ethernet(eth_xmas,
						mymac->ether_addr_octet,
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
					   mymac->ether_addr_octet,
					   (u_char*)&myip,
					   eth_null,
					   (u_char*)&dip,
					   NULL,
					   0,
					   packet + LIBNET_ETH_H)) {
			fprintf(stderr, "libnet_init_packet(): error\n");
			exit(1);
		}
		
	}
	/*
	 * pcap init
	 */
	if (!(pcap = pcap_open_live(ifname, 100, 0, 10, ebuf))) {
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
