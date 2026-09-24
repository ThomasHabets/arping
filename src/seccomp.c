#define _GNU_SOURCE
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "arping.h"
#include "cast.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

#if !USE_SECCOMP
void
drop_seccomp(int libnet_fd)
{
        UNUSED(libnet_fd);
        if (verbose > 2) {
                printf("arping: seccomp support not built in, skipping\n");
        }
}
#else
#include <seccomp.h>

/**
 * Allow syscall by name.
 *
 * If there's no such syscall, that's fine.
 *
 * If allowing this syscall fails, then log verbose error.
 */
static void
seccomp_allow(scmp_filter_ctx ctx, const char* name)
{
        const int resolved = seccomp_syscall_resolve_name(name);
        if (resolved == __NR_SCMP_ERROR) {
                if (verbose) {
                        fprintf(stderr,
                                "arping: seccomp can't resolve syscall %s:"
                                " skipping allowing that\n"
                                "arping: If arping fails, retry with -Z\n",
                                name);
                }
                return;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, resolved, 0)) {
                if (verbose) {
                        fprintf(stderr,
                                "arping: seccomp_rule_add_exact(%s): %s\n",
                                name, strerror(errno));
                }
        }
}

/**
 * Allow syscall by name if first arg is the given file descriptor.
 *
 * If there's no such syscall, that's fine.
 *
 * If allowing this syscall fails, then print warning to stderr. It's write(),
 * so this has to work.
 */
static void
seccomp_allow_fd(scmp_filter_ctx ctx, const char* name, int fd)
{
        const int resolved = seccomp_syscall_resolve_name(name);
        if (resolved == __NR_SCMP_ERROR) {
                if (verbose) {
                        fprintf(stderr,
                                "arping: seccomp can't resolve syscall %s:"
                                " skipping allowing that\n"
                                "arping: If arping fails, retry with -Z\n",
                                name);
                }
                return;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, resolved, 1,
                             SCMP_A0(SCMP_CMP_EQ, cast_int_ulong(fd, NULL)))) {
                fprintf(stderr, "arping: seccomp_rule_add(%s for fd %d)",
                        name, fd);
        }
}

void
drop_seccomp(int libnet_fd)
{
        //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(13));
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
                perror("seccomp_init()");
                exit(1);
        }

        //
        // Whitelist.
        //
        // Stat and write to stdout and stderr.
        seccomp_allow_fd(ctx, "statx", STDOUT_FILENO);
        seccomp_allow_fd(ctx, "fstat", STDOUT_FILENO);
        seccomp_allow_fd(ctx, "write", STDOUT_FILENO);
        seccomp_allow_fd(ctx, "write", STDERR_FILENO);

        // Libnet.
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, cast_int_uint(libnet_fd, NULL)))) {
                perror("seccomp_rule_add(ioctl libnet)");
                exit(1);
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 1, SCMP_A0(SCMP_CMP_EQ, cast_int_uint(libnet_fd, NULL)))) {
                perror("seccomp_rule_add(sendto libnet)");
                exit(1);
        }

        // Other.
        seccomp_allow(ctx, "read");
        seccomp_allow(ctx, "recvfrom");
        seccomp_allow(ctx, "select");
        seccomp_allow(ctx, "pselect6");
        seccomp_allow(ctx, "newfstatat");
        seccomp_allow(ctx, "exit_group");
        seccomp_allow(ctx, "rt_sigreturn");
        seccomp_allow(ctx, "clock_gettime64");
        seccomp_allow(ctx, "clock_nanosleep");
        seccomp_allow(ctx, "nanosleep");
        seccomp_allow(ctx, "clock_nanosleep_time64");
        seccomp_allow(ctx, "clock_gettime");
        // MAC pings generate a fresh ICMP identifier for every request.
        seccomp_allow(ctx, "getrandom");

        // Load.
        if (seccomp_load(ctx)) {
                perror("seccomp_load()");
                exit(1);
        }
        seccomp_release(ctx);
        if (verbose > 1) {
                printf("arping: Successfully applied seccomp policy\n");
        }
}
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vim: ts=8 sw=8
 */
