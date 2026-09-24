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

#if HAVE_STDDEF_H
#include <stddef.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if defined(HAVE_SECCOMP_H) && defined(HAVE_LIBSECCOMP)
#define USE_SECCOMP 1
#else
#define USE_SECCOMP 0
#endif

/* Forward declarations */
struct pcap_pkthdr;

extern int verbose;
extern uint32_t srcip;
extern uint32_t dstip;
extern unsigned int numrecvd;
extern unsigned int numsent;

void xsnprintf(char *buf, size_t size, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));
void drop_seccomp(int libnet_fd);
void arping_format_bpf_filter(char* buf, size_t size, const char* protocol,
                              int16_t tag, int buggy_pcap);
const char *
arping_lookupdev(uint32_t srcip, uint32_t dstip, char *ebuf);
void do_signal_init(void);
void do_libnet_init(const char *ifname, int recursive);
void sigint(int);
const char *arping_lookupdev_default(uint32_t srcip, uint32_t dstip,
				     char *ebuf);
int arping_main(int argc, char **argv);
int is_mac_addr(const char *p);
int get_mac_addr(const char *in, uint8_t *out);


void pingip_recv(unsigned char *unused, const struct pcap_pkthdr *h, const unsigned char* const packet);
void pingmac_recv(unsigned char *unused, const struct pcap_pkthdr *h, const uint8_t *packet);
