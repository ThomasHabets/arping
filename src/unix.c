/* arping/src/unix.c
 *
 *  Copyright (C) 2000-2011 Thomas Habets <thomas@habets.se>
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
#define _GNU_SOURCE
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <signal.h>
#include <string.h>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <pcap.h>

#include "arping.h"

#define UNUSED(x) (void)(x)

/**
 * Fall back on getting device name from pcap.
 */
const char *
arping_lookupdev_default(uint32_t srcip, uint32_t dstip, char *ebuf)
{
#ifdef HAVE_PCAP_FINDALLDEVS
        UNUSED(srcip);
        pcap_if_t *ifs = NULL;
        int rc = pcap_findalldevs(&ifs, ebuf);
        if (rc) {
                return NULL;
        }

        pcap_if_t *t;
        char* ifname = NULL;
        for (t = ifs; !ifname && t; t = t->next) {
#ifdef PCAP_IF_LOOPBACK
                if (t->flags & PCAP_IF_LOOPBACK) {
                        continue;
                }
#endif
#ifdef PCAP_IF_UP
                if (!(t->flags & PCAP_IF_UP)) {
                        continue;
                }
#endif

                // This code is only called when using -F, which is "don't try
                // to be smart". If we wanted to be smart we would have used
                // findif_*.c.
                if (1) {
                        ifname = strdup(t->name); // Memory leak.
                        break;
                }

                // UNREACHABLE
                pcap_addr_t *a;
                for (a = t->addresses; !ifname && a; a = a->next) {
                        if (a->addr->sa_family != AF_INET) {
                                continue;
                        }
                        const struct sockaddr_in* sa = (struct sockaddr_in*)a->addr;
                        const struct sockaddr_in* smask = (struct sockaddr_in*)a->netmask;
                        const uint32_t addr = sa->sin_addr.s_addr;
                        const uint32_t mask = smask->sin_addr.s_addr;
                        if ((addr & mask) != (dstip & mask)) {
                                // Not optimal: memory leak.
                                ifname = strdup(t->name);
                        }
                }
        }
        pcap_freealldevs(ifs);
        return ifname;
#else
        UNUSED(srcip);
        UNUSED(dstip);
        return pcap_lookupdev(ebuf);
#endif
}

/**
 *
 */
void
do_signal_init()
{
        if (SIG_ERR == signal(SIGINT, sigint)) {
                fprintf(stderr, "arping: failed to set SIGINT handler: %s\n",
                        strerror(errno));
        }
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
