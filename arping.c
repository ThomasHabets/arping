/*
 * arping 0.2
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
 * Changelog:
 * 2000-02-25: Told pcap to filter !arp
 *             Cleaned up error messages
 * 2000-02-24: ------ Released 0.1 --------
 */
#include <getopt.h>
#include <libnet.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>

const float version = 0.2;

u_char eth_xmas[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u_char eth_null[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

pcap_t *pcap;
struct bpf_program bpf_prog;
struct in_addr net,mask;
char *ifname = "eth0";
u_long dip = 0;
u_char *packet;
struct libnet_link_int *linkint;

int verbose = 0;
int numsent = 0;
int numrecvd = 0;

void usage(int ret)
{
	printf("arping %1.1f [ -v ] [ -i <interface> ] <host/ip>\n", version);
	exit(ret);
}

void alasend(int i)
{
	if (-1 == (libnet_write_link_layer(linkint,
					   (u_char*)ifname,
					   (u_char*)packet,
					   LIBNET_ARP_H + LIBNET_ETH_H))) {
		fprintf(stderr, "libnet_write_link_layer(): error\n");
		exit(1);
	}
	numsent++;
	alarm(1);
}

void sigint(int i)
{
	printf("\n--- %s statistics ---\n", libnet_host_lookup(dip,0));
	printf("%d packets transmitted, %d packets recieved, %3.0f%% unanswered\n",
	       numsent, numrecvd, 100.0 - 100.0 * (float)(numrecvd)/(float)numsent);
	exit(1);
}

void handlepacket(const char *unused, struct pcap_pkthdr *h, u_char *packet)
{
	struct ethhdr *eth;
	struct arphdr *harp;
	unsigned int c;
	unsigned char *cp;

	eth = (struct ethhdr*)packet;

	harp = (struct arphdr*)((char*)eth + sizeof(struct ethhdr));
	if ((htons(harp->ar_op) == ARPOP_REPLY)
	    && (htons(harp->ar_pro) == ETH_P_IP)
	    && (htons(harp->ar_hrd) == ARPHRD_ETHER)) {
		int ip = (int)*(int*)((char*)harp + sizeof(struct arphdr) + harp->ar_hln);
		if (dip == ip) {
			cp = (u_char*)harp + sizeof(struct arphdr);
			printf("%d bytes from ", h->len);
			for (c = 0; c < harp->ar_hln -1; c++) {
				printf("%.2x:", *cp++);
			}
			printf("%.2x (%s): index=%d\n", *cp, libnet_host_lookup(ip, 0), numrecvd++);
		}
	}
}

void recvpackets(void)
{
	if (-1 == pcap_loop(pcap, -1, (pcap_handler)handlepacket, NULL)) {
		fprintf(stderr, "pcap_loop(): error\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	u_long myip;
	char *ebuf = "no error";
	struct ether_addr *mymac;
	int c;
	struct bpf_program bp;
	
	while ((c = getopt(argc, argv, "vhi:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'h':
			usage(0);
		case 'i':
			ifname = optarg;
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
  
	dip = libnet_name_resolve((u_char*)argv[optind], LIBNET_RESOLVE);
		
	/*
	 * libnet init
	 */
	if (!(linkint = libnet_open_link_interface(ifname, ebuf))) {
		fprintf(stderr, "libnet_get_hwaddr(): %s\n", ebuf);
		exit(1);
	}
	
	if (!(mymac = libnet_get_hwaddr(NULL, (u_char*)ifname,  ebuf))) {
		fprintf(stderr, "libnet_get_hwaddr(): %s\n", ebuf);
		exit(1);
	}
	
	if (!(myip = htonl(libnet_get_ipaddr(linkint, (u_char*)ifname, ebuf)))) {
		fprintf(stderr, "libnet_get_ipaddr(): %s\n", ebuf);
		exit(1);
	}

	if (-1 == libnet_init_packet(LIBNET_ARP_H + LIBNET_ETH_H, &packet)) {
		fprintf(stderr, "libnet_init_packet(): error\n");
		exit(1);
	}
	
	if (verbose) {
		printf("This box:   Interface: %s  IP: %s   MAC address: ", ifname, libnet_host_lookup(myip,0));
		for (c = 0; c < ETH_ALEN - 1; c++) {
			printf("%.2x:", (unsigned )mymac->ether_addr_octet[c]);
		}
		printf("%.2x\n", mymac->ether_addr_octet[ETH_ALEN - 1]);
	}
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

	/*
	 * pcap init
	 */
	if (!(pcap = pcap_open_live(ifname, 100, 0, 10, ebuf))) {
		fprintf(stderr, "pcap_open_live(): %s\n", ebuf);
		exit(1);
	}

	if (-1 == pcap_compile(pcap,&bp,"arp",0,-1)) {
		fprintf(stderr, "pcap_compile(): error\n");
		exit(1);
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
	printf("ARPING %s\n", libnet_host_lookup(dip,0));
	alasend(0);
	for(;;) {
		recvpackets();
	}
	libnet_destroy_packet(&packet);
	return 0;
}
