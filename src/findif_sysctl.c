/* arping/src/findif_sysctl.c
 *
 *  Copyright (C) 2000-2014 Thomas Habets <thomas@habets.se>
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
/**
 * This file should never be used. Systems that are chosen for sysctl()
 * should always have getifaddrs() which is preferred to this.
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#if HAVE_LIBNET_H
#include <libnet.h>
#endif

#include "arping.h"

#ifndef SALIGN
#define SALIGN (sizeof(int32_t) - 1)
#endif

#ifndef SA_SIZE
#define SA_SIZE(sa) ((sa)->sa_len \
                     ? (((sa)->sa_len + SALIGN) & ~SALIGN)\
                     : (SALIGN + 1))
#endif


/**
 *
 */
const char *
arping_lookupdev(uint32_t srcip,
                 uint32_t dstip,
                 char *ebuf)
{
        int mib[6] = {
                CTL_NET,
                PF_ROUTE,
                0,              /* Protocol */
                AF_INET,        /* Address family */
                NET_RT_IFLIST,
                0
        };
        int c;

        /* buffer */
        char *buf_memory = NULL;
        char *lim;
        size_t bufsize;

        /* Matching interfaces */
        int match_count = 0;

        /* best match */
        in_addr_t best_mask = 0;
        struct in_addr best_addr;

        /* Results */
        static char ifName[IFNAMSIZ];
        *ebuf = 0;

        /* Allocate buffer and retrieve data. */
        for (c = 0;;) {
                if (sysctl(mib, 6, NULL, &bufsize, NULL, 0) < 0) {
                        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                                 "sysctl: get buffer size error: %s",
                                 strerror(errno));
                        goto failed;
                }
                if ((buf_memory = malloc(bufsize)) == NULL) {
                        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                                 "malloc: error: %s", strerror(errno));
                        goto failed;
                }
                if (sysctl(mib, 6, buf_memory, &bufsize, NULL, 0) == 0) {
                        break;
                }
                if (errno != ENOMEM || ++c >= 10 ) {
                        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                                 "sysctl: get ifaces error: %s",
                                 strerror(errno));
                        goto failed;
                }
                if (verbose > 2) {
                        printf("sysctl: buffer size changed.");
                }
                free(buf_memory);
                buf_memory = NULL;
        }

        const char* buf = buf_memory;
        lim = buf + bufsize;

        /* Loop through all interfaces */
        while (buf < lim) {
                struct sockaddr_dl *sdl;
                char  tmpIfName[IFNAMSIZ];
                int   i;

                struct if_msghdr *ifh = (struct if_msghdr *)buf;
                if (ifh->ifm_type != RTM_IFINFO) {
                        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                                 "Wrong data in NET_RT_IFLIST.");
                        return NULL;
                }
                sdl = (struct sockaddr_dl *)(buf +
                                             sizeof(struct if_msghdr) -
                                             sizeof(struct if_data) +
                                             sizeof(struct if_data));

                i = sdl->sdl_nlen < sizeof(ifName)
                        ? sdl->sdl_nlen
                        : (sizeof(tmpIfName)-1);
                memcpy(tmpIfName, sdl->sdl_data, i);
                tmpIfName[i] = 0;

                buf += ifh->ifm_msglen;

                /* Loop through all addresses of interface. */
                while (buf < lim) {
                        struct ifa_msghdr *ifht = (struct ifa_msghdr *)buf;
                        char*  addrptr;
                        struct sockaddr_in *if_addr = NULL;
                        struct sockaddr_in *if_nmsk = NULL;
                        struct sockaddr_in *if_bcst = NULL;
                        in_addr_t mask;

                        if (ifht->ifam_type != RTM_NEWADDR) {
                                break;
                        }

                        addrptr = buf + sizeof(struct ifa_msghdr);
                        buf += ifht->ifam_msglen;

                        if (ifh->ifm_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) {
                                continue;
                        }

                        /* Loop through all the address attributes. */
                        for (c=1; c < (1<<RTAX_MAX); c<<=1) {
                                size_t len;
                                struct sockaddr_in *sa;
                                sa = addrptr;
                                switch (c & ifht->ifam_addrs) {
                                case 0:
                                        continue;
                                case RTA_NETMASK:
                                        if_nmsk = sa;
                                        break;
                                case RTA_IFA:
                                        if_addr = sa;
                                        break;
                                case RTA_BRD:
                                        if_bcst = sa;
                                        break;
                                }
                                addrptr += SA_SIZE((struct sockaddr*)sa);
                        }

                        if (!if_addr || !if_nmsk || !if_bcst) {
                                continue;
                        }

                        if (if_addr->sin_family != AF_INET) {
                                continue;
                        }

                        if ((dstip & if_nmsk->sin_addr.s_addr)
                            != (if_addr->sin_addr.s_addr
                                & if_nmsk->sin_addr.s_addr)) {
                                continue;
                        }

                        match_count++;

                        if (verbose > 1) {
                                printf("Specified addr matches "
                                       "interface '%s':\n", tmpIfName);
                                printf("  IP addr %s, ",
                                       inet_ntoa(if_addr->sin_addr));
                                printf("mask %s, ",
                                       inet_ntoa(if_nmsk->sin_addr));
                                printf("bcast %s\n",
                                       inet_ntoa(if_bcst->sin_addr));
                        }

                        mask = ntohl(if_nmsk->sin_addr.s_addr);
                        if (mask > best_mask) {
                                memcpy(ifName,
                                       tmpIfName,
                                       sizeof(ifName));
                                best_mask = mask;
                                best_addr = if_addr->sin_addr;
                        }
                }
        }

        if (match_count == 0 ) {
                if (verbose) {
                        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                                 "No interface found that matches"
                                 " specified IP.");
                }
                goto failed;
        }

        if (verbose && match_count > 1) {
                printf("arping: Using interface '%s' with src IP %s due "
                       "to longer mask.\n", ifName, inet_ntoa(best_addr));
        }
#if 0
        if (ifce_ip != 0) {
                *ifce_ip = best_addr.s_addr;
        }
#endif
        free(buf_memory);
        return ifName;

 failed:
        free(buf_memory);
	return NULL;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
