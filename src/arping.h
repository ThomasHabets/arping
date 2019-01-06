/* arping/src/arping.h
 *
 *  Copyright (C) 2000-2015 Thomas Habets <thomas@habets.se>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Forward declarations */
struct pcap_pkthdr;

extern int verbose;
extern uint32_t srcip;
extern uint32_t dstip;
extern unsigned int numrecvd;
extern unsigned int numsent;

const char *
arping_lookupdev(uint32_t srcip, uint32_t dstip, char *ebuf);
void do_signal_init();
void do_libnet_init(const char *ifname, int recursive);
void sigint(int);
const char *arping_lookupdev_default(uint32_t srcip, uint32_t dstip,
				     char *ebuf);
int arping_main(int argc, char **argv);


void pingip_recv(const char *unused, struct pcap_pkthdr *h, const char* const packet);
void pingmac_recv(const char *unused, struct pcap_pkthdr *h, uint8_t *packet);
