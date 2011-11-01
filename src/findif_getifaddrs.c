/* arping/src/findif_getifaddrs.c
 *
 *  Copyright (C) 2000-2011 Thomas Habets <thomas@habets.se>
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
/**
 * Most modern systems should have getifaddrs().
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#include "arping.h"

const char *
arping_lookupdev(const char *ifname_unused,
                 uint32_t srcip,
                 uint32_t dstip,
                 char *ebuf)
{
        struct ifaddrs *ifa = NULL;
        struct ifaddrs *cur;
        const char *ret;
        int match_count = 0;     /* Matching interfaces */

        /* best match */
        in_addr_t best_mask = 0;
        in_addr_t best_addr;

        /* Results */
        static char ifname[IFNAMSIZ];

        ifname[0] = 0;

        if (getifaddrs(&ifa)) {
                if (verbose) {
                        printf("getifaddrs(): %s\n", strerror(errno));
                }
                goto failed;
        }
        for (cur = ifa; cur; cur = cur->ifa_next) {
                in_addr_t addr, mask;

                if (cur->ifa_addr->sa_family != AF_INET) {
                        continue;
                }
                if (cur->ifa_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) {
                        continue;
                }
                addr =((struct sockaddr_in*)cur->ifa_addr)->sin_addr.s_addr;
                mask =((struct sockaddr_in*)cur->ifa_netmask)->sin_addr.s_addr;
                if ((addr & mask) != (dstip & mask)) {
                        continue;
                }
                if (ntohl(mask) > ntohl(best_mask)) {
                        memset(ifname, 0, sizeof(ifname));
                        strncpy(ifname, cur->ifa_name, sizeof(ifname)-1);
                        best_addr = addr;
                        best_mask = mask;
                }
        }
        if (!ifname[0]) {
                if (verbose) {
                        printf("Failed to find iface using getifaddrs().\n");
                }
                goto failed;
        }
        ret = ifname;
 out:
        if (ifa) {
                freeifaddrs(ifa);
        }
        return ret;

 failed:
        ret = arping_lookupdev_default(ifname_unused, srcip, dstip, ebuf);
        goto out;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
