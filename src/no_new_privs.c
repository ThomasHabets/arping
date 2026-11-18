/*
 *  Copyright (C) 2025 Thomas Habets <thomas@habets.se>
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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#if HAVE_LINUX_PRCTL_H
#include <linux/prctl.h>  /* Definition of PR_* constants */
#endif
#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "arping.h"

void
drop_no_new_privs()
{
#ifdef HAS_NO_NEW_PRIVS
        if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L)) {
                fprintf(stderr, "arping: setting NO_NEW_PRIVS failed: %s\n",
                        strerror(errno));
                return;
        }
        if (verbose > 2) {
                printf("arping: Prevented new privs being set\n");
        }
#endif
}
