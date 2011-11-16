/* arping/src/findif_bsdroute.c
 *
 *  Copyright (C) 2000-2009 Thomas Habets <thomas@habets.se>
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
 * Fallback to ugly solution. This should not actually be used, as
 * modern systems have getifaddrs().
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "arping.h"

/**
 *
 */
const char *
arping_lookupdev(uint32_t srcip,
                 uint32_t dstip,
                 char *ebuf)
{
	FILE *f;
	static char buf[10240];
	char buf1[1024];
	char *p,*p2;
	int n;

	do_libnet_init(NULL);
	libnet_addr2name4_r(dstip,0,buf1, 1024);

	/*
	 * Construct and run command
	 */
	snprintf(buf, 1023, "/sbin/route -n get %s 2>&1",
		 buf1);
	if (!(f = popen(buf, "r"))) {
		goto failed;
	}
	if (0 > (n = fread(buf, 1, sizeof(buf)-1, f))) {
		pclose(f);
		goto failed;
	}
	buf[n] = 0;
	if (-1 == pclose(f)) {
		perror("arping: pclose()");
		goto failed;
	}

	/*
	 * Parse interface name
	 */
	p = strstr(buf, "interface: ");
	if (!p) {
		goto failed;
	}

	p+=11;

	p2 = strchr(p, '\n');
	if (!p2) {
		goto failed;
	}
	*p2 = 0;
	return p;
 failed:
	return NULL;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
