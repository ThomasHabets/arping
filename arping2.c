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
 * $Id: arping2.c 704 2002-08-27 00:57:19Z marvin $
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <libnet.h>
#include <pcap.h>


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

const float version = 2.0;

libnet_t *libnet;

static int beep = 0;
static int verbose = 0;
static int pingmac = 0;
static int finddup = 0;
static unsigned int numsent = 0;
static unsigned int numrecvd = 0;
static enum { NORMAL,QUIET,RAW,RRAW,SELF } display = NORMAL;
static char *target = "huh? bug in arping?";
static u_int8_t ethnull[ETH_ALEN];

volatile int time_to_die = 0;

/*
 *
 */
static void sigint(int i)
{
	time_to_die = 1;
}

/*
 *
 */
static void usage(int ret)
{
	printf("ARPing %1.2f, by Thomas Habets <thomas@habets.pp.se>\n",
	       version);
	printf("usage: arping [ -qvrRd0bp ] [ -w <us> ] [ -S <host/ip> ] "
	       "[ -T <host/ip ]\n"
	       "              [ -s <MAC> ] [ -t <MAC> ] [ -c <count> ] "
	       "[ -i <interface> ]\n"
	       "              <host/ip/MAC | -B>\n");
	exit(ret);
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
	case 1:
		sprintf(buf, "%.3f msec", f);
		break;
	case 2:
		sprintf(buf, "%.3f sec", f);
		break;
	case 3:
		sprintf(buf, "%.3f sec", f*1000);
		break;
        default:
		// huh, uh, huhuh
		sprintf(buf, "%.3fe%d sec", f,exp);
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
	if (-1 == (c = libnet_write(libnet))) {
		fprintf(stderr, "libnet_write(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	numsent++;
}

/*
 *
 */
static void pingmac_recv()
{
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
		fprintf(stderr, "libnet_build_arp(): %s\n",
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
		fprintf(stderr, "libnet_build_ethernet(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}

	if (-1 == libnet_write(libnet)) {
		fprintf(stderr, "arping: libnet_write(): %s\n", 
			libnet_geterror(libnet));
		sigint(0);
	}
	numsent++;
}

/*
 *
 */
static void pingip_recv(void)
{

}

/*
 *
 */
int main(int argc, char **argv)
{
	char ebuf[LIBNET_ERRBUF_SIZE];
	char srcmac[ETH_ALEN];
	char dstmac[ETH_ALEN];
	u_int32_t srcip,dstip;
	char *cp;
	int nullip = 0;
	int promisc = 0;
	int srcip_given = 0;
	int srcmac_given = 0;
	int dstip_given = 0;
	char *ifname = NULL;
	char *parm;
	int c;
	unsigned int maxcount = -1;
	struct bpf_program bp;
	pcap_t *pcap;
	static enum { NONE, PINGMAC, PINGIP } mode = NONE;
	unsigned int packetwait = 1000;
	
	memset(ethnull, 0, ETH_ALEN);

	srcip = 0;
	dstip = 0xffffffff;
	memset(dstmac, 0xff, ETH_ALEN);

	while ((c = getopt(argc, argv, "0bdS:T:Bvhi:rRc:qs:t:paw:")) != EOF) {
		switch(c) {
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
					"don't really\nknow what this program "
					"does, do you?\n");
				exit(1);
			}
			ifname = optarg;
			break;
		case 'r':
			display = RAW;
			break;
		case 'R':
			display = RRAW;
			break;
		case 'q':
			display = QUIET;
			break;
		case 'c':
			maxcount = atoi(optarg);
			break;
		case 'd':
			finddup = 1;
			break;
		case 'S': // set source IP, may be null for don't-know
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
		case 'T': // set destination IP
			if (mode == PINGIP) {
				fprintf(stderr, "arping: -T can only be used "
					"in MAC ping mode\n");
				exit(1);
			}
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
		case 'b':
			srcip = 0xffffffff;
			srcip_given = 1;
			break;
		case 'B':
			dstip = 0xffffffff;
			dstip_given = 1;
			break;
		case '0':
			srcip = 0;
			srcip_given = 1;
			break;
		case 's': {// spoof source MAC
			unsigned int n[6];
			   
			if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
				   &n[0],
				   &n[1],
				   &n[2],
				   &n[3],
				   &n[4],
				   &n[5]
				    ) != 6) {
				fprintf(stderr, "arping: Weird MAC addr %s\n",
					optarg);
				exit(1);
			}
			for (c = 0; c < 6; c++) {
				srcmac[c] = n[c] & 0xff;
			}
			break;
		}
		case 't': { // set taget mac
			unsigned int n[6];
			if (mode == PINGMAC) {
				fprintf(stderr, "arping: -t can only be used "
					"in IP ping mode\n");
				exit(1);
			}
			
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
				dstmac[c] = n[c] & 0xff;
			}
			break;
			mode = PINGIP;
		}
		case 'p':
			promisc = 1;
			break;
		case 'w':
			packetwait = (unsigned)atoi(optarg);
			break;
		default:
			usage(1);
		}
	}

	/*
	 * libnet init
	 */
	if (!(libnet = libnet_init(LIBNET_LINK,
				   ifname,
				   ebuf))) {
		fprintf(stderr, "arping: libnet_init(): %s\n", ebuf);
		exit(1);
	}
	


	parm = argv[optind];

	/*
	 * Handle dstip_given instead of ip address after parms (-B really)
	 */
	if (mode == NONE) {
		if (optind + 1 == argc) {
			mode = strchr(parm, ':')?PINGMAC:PINGIP;
		} else if (dstip_given) {
			mode = PINGIP;
			parm = strdup(libnet_addr2name4(dstip,
							0));
		}
	}

	if (mode == NONE) {
		usage(1);
	}
	
	/*
	 * Make sure dstip and parm like eachother
	 */
	if (mode == PINGIP && (!dstip_given)) {
		if (strchr(parm, ':')) {
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
	}

	/*
	 * parse parm into dstmac
	 */
	if (mode == PINGMAC) {
		unsigned char n[6];
		if (optind + 1 != argc) {
			usage(1);
		}
		if (!strchr(parm, ':')) {
			fprintf(stderr, "arping: Options given only apply to "
				"MAC ping, but no MAC address given as "
				"argument\n");
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
			dstmac[c] = n[c] & 0xff;
		}
	}	

	target = parm;
	/*
	 * Argument processing done, parameters considered sane below
	 */

	/*
	 * Get some good iface. FIXME: traverse routing or something to find
	 * right one.
	 */
	if (!ifname) {
		if (!(ifname = pcap_lookupdev(ebuf))) {
			fprintf(stderr, "arping: pcap_lookupdev(): %s\n",ebuf);
			exit(1);
		}
	}

	/*
	 * pcap init
	 */
	if (!(pcap = pcap_open_live(ifname, 100, promisc, 10, ebuf))) {
		fprintf(stderr, "arping: pcap_open_live(): %s\n",ebuf);
		exit(1);
	}
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
			fprintf(stderr, "libnet_get_hwaddr(): %s\n",
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
	signal(SIGINT, sigint);

	if (display != QUIET) {
		printf("ARPING %s\n", parm);
	}

	/*
	 * let's roll
	 */
	if (mode == PINGIP) {
		unsigned int c;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingip_send(srcmac, dstmac, srcip, dstip);
		}
	} else { // PINGMAC
		unsigned int c;
		for (c = 0; c < maxcount && !time_to_die; c++) {
			pingmac_send(srcmac, dstmac, srcip, dstip, 0, 0);
		}
	}
	if (display == NORMAL) {
		printf("\n--- %s statistics ---\n"
		       "%d packets transmitted, %d packets received, %3.0f%% "
		       "unanswered\n",target,numsent,numrecvd,
		       100.0 - 100.0 * (float)(numrecvd)/(float)numsent); 
	}
	exit(numrecvd);


	return 0;
}
