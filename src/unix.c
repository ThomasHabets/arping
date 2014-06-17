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
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <signal.h>

#include <pcap.h>

#include "arping.h"

/**
 * Fall back on getting device name from pcap.
 */
const char *
arping_lookupdev_default(uint32_t srcip, uint32_t dstip, char *ebuf)
{
        return pcap_lookupdev(ebuf);
}

/**
 *
 */
void
do_signal_init()
{
        signal(SIGINT, sigint);
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
