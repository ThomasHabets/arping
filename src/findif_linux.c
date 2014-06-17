/* arping/src/findif_linux.c
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
 * Fallback to ugly solution. This should not actually be used, as
 * modern systems have getifaddrs().
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#if HAVE_LIBNET_H
#include <libnet.h>
#endif

#include "arping.h"

/**
 * WARNING: non-reentrant
 */
const char *
arping_lookupdev(uint32_t srcip,
                 uint32_t dstip,
                 char *ebuf)
{
        FILE *f = NULL;
	static char buf[1024];
	char buf1[1024];
	char buf2[1024];
	char *p,*p2;
	int n;

        *ebuf = 0;

        do_libnet_init(NULL, 0);
	libnet_addr2name4_r(dstip,0,buf2,1024);
	libnet_addr2name4_r(srcip,0,buf1,1024);

	/*
	 * Construct and run command
	 */
	snprintf(buf, 1023, "/sbin/ip route get %s from %s 2>&1",
		 buf2, buf1);
	if (!(f = popen(buf, "r"))) {
                snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                         "popen(/sbin/ip): %s", strerror(errno));
		goto failed;
	}
	if (0>(n = fread(buf, 1, sizeof(buf)-1, f))) {
                snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                         "fread(/sbin/ip): %s", strerror(errno));
		goto failed;
	}
	buf[n] = 0;
	if (-1 == pclose(f)) {
                snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                         "pclose(/sbin/ip): %s", strerror(errno));
		goto failed;
	}
        f = NULL;

	/*
	 * Parse interface name
	 */
        const char* head = "dev ";
        p = strstr(buf, head);
	if (!p) {
                if (verbose) {
                        printf("arping: /sbin/ip output: %s\n", buf);
                }
                snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                         "\"dev \" not found in /sbin/ip output.");
		goto failed;
	}

        p += strlen(head);

	p2 = strchr(p, ' ');
	if (!p2) {
                if (verbose) {
                        printf("arping: /sbin/ip output: %s\n", buf);
                }
                snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                         "interface not found in /sbin/ip output.");
		goto failed;
	}
	*p2 = 0;
	return p;
 failed:
        if (f) {
                pclose(f);
        }
	return NULL;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
