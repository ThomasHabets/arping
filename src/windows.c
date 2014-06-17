/* arping/src/windows.c
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

/***************
 * This code has worked at one point, but I'm not a Windows programmer
 * so it's not being maintained. Should not be hard to get working
 * again though for someone who is.
 ***************/
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>

#include "arping.h"

/**
 *
 */
void
do_signal_init()
{
	SetConsoleCtrlHandler(arping_console_ctrl_handler, TRUE);
	/* SetConsoleCtrlHandler(NULL, TRUE); */
}

/**
 * untested for a long time. Maybe since arping 2.05 or so.
 */
static void
ping_recv_win32(pcap_t *pcap, uint32_t packetwait, pcap_handler func)
{
        struct timespec tv,tv2;
       char done = 0;
       /* windows won't let us do select() */
       getclock(&tv2);

       while (!done && !time_to_die) {
	       struct pcap_pkthdr *pkt_header;
	       u_char *pkt_data;
	       if (pcap_next_ex(pcap, &pkt_header, &pkt_data) == 1) {
		       func(pcap, pkt_header, pkt_data);
	       }
               getclock(&tv);

               /*
                * setup next timespec, not very exact
                */
               tv.tv_sec  = (packetwait / 1000000)
		       - (tv.tv_sec - tv2.tv_sec);
	       tv.tv_nsec = (packetwait % 1000000)
                       - (tv.tv_nsec - tv2.tv_nsec);
               fixup_timespec(&tv);

	       usleep(10);
	       if (tv.tv_sec < 0) {
		       done=1;
	       }
       }
}

/**
 * Fall back on getting device name from pcap.
 */
const char *
arping_lookupdev_default(int32_t srcip, uint32_t dstip,
			 char *ebuf)
{
	WCHAR buf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
	WCHAR* ret = (WCHAR*)pcap_lookupdev((char*)buf);
	if (ret != NULL) {
		wcstombs(ebuf, ret, LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE);
		return ebuf;
	}
	return NULL;
}

static BOOL WINAPI arping_console_ctrl_handler(DWORD dwCtrlType)
{
        if (verbose) {
                printf("arping_console_ctrl_handler(%d)\n", (int)dwCtrlType);
	}
	time_to_die = 1;

        if (0) {
                /* if SetConsoleCtrlHandler() does what I think, this
                   isn't needed */
                if (display == NORMAL) {
                        printf("\n--- %s statistics ---\n"
                               "%d packets transmitted, %d packets received, "
                               "%3.0f%% "
                               "unanswered\n", target, numsent, numrecvd,
                               100.0
                               - 100.0 * (float)(numrecvd)/(float)numsent);
                }
        }
	return TRUE;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
