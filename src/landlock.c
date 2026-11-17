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

#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#if HAVE_LINUX_LANDLOCK_H
#if HAS_LANDLOCK
#include<linux/landlock.h>
#include<sys/syscall.h>
#define ACTUALLY_USE_LANDLOCK 1
#endif
#endif

#include "arping.h"
#include "cast.h"

#ifdef ACTUALLY_USE_LANDLOCK
static int ll_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
        return cast_long_int(syscall(SYS_landlock_create_ruleset, attr, size, flags), NULL);
}
/*
static int ll_add_rule(int ruleset_fd, enum landlock_rule_type type, const void *rule_attr, __u32 flags) {
    return syscall(SYS_landlock_add_rule, ruleset_fd, type, rule_attr, flags);
}
*/
static long ll_restrict_self(int ruleset_fd, __u32 flags) {
    return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}
#endif

void
drop_landlock()
{
#ifdef ACTUALLY_USE_LANDLOCK
        const int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 0) {
                fprintf(stderr, "arping: Failed to query Landlock ABI: %s\n",
                        strerror(errno));
                return;
        }
        struct landlock_ruleset_attr ruleset_attr = {
                .handled_access_fs = 0
                        | LANDLOCK_ACCESS_FS_WRITE_FILE
                        | LANDLOCK_ACCESS_FS_READ_FILE
                        | LANDLOCK_ACCESS_FS_READ_DIR
                        | LANDLOCK_ACCESS_FS_REMOVE_DIR
                        | LANDLOCK_ACCESS_FS_REMOVE_FILE
                        | LANDLOCK_ACCESS_FS_MAKE_CHAR
                        | LANDLOCK_ACCESS_FS_MAKE_DIR
                        | LANDLOCK_ACCESS_FS_MAKE_REG
                        | LANDLOCK_ACCESS_FS_MAKE_SOCK
                        | LANDLOCK_ACCESS_FS_MAKE_FIFO
                        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
                        | LANDLOCK_ACCESS_FS_MAKE_SYM
                        | LANDLOCK_ACCESS_FS_EXECUTE,
        };
#ifdef LANDLOCK_ACCESS_FS_REFER
        if (abi >= 2) {
                ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
        }
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= 3) {
                ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
#endif
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
        if (abi >= 4) {
                ruleset_attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP
                        | LANDLOCK_ACCESS_NET_CONNECT_TCP;
        }
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
        if (abi >= 5) {
                ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
#endif
#ifdef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
        if (abi >= 6) {
                ruleset_attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
                        | LANDLOCK_SCOPE_SIGNAL;
        }
#endif
        int ruleset = ll_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
        if (ruleset < 0) {
                fprintf(stderr, "arping: Failed to create landlock ruleset: %s\n",
                        strerror(errno));
                return;
        }
        if (ll_restrict_self(ruleset, 0)) {
                fprintf(stderr, "arping: Failed to restrict with landlock: %s\n",
                        strerror(errno));
                close(ruleset);
                return;
        }
        close(ruleset);
        DIR *de = opendir("/");
        if (de) {
                fprintf(stderr, "arping: landlock failed to take effect\n");
                closedir(de);
        } else if (errno != EACCES) {
                fprintf(stderr, "arping: landlock caused error not EACCES: %s\n",
                        strerror(errno));
        }
        if (verbose > 0) {
                printf("arping: Landlock enabled\n");
        }
#endif
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vim: ts=8 sw=8
 */
