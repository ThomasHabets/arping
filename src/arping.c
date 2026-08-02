/** arping/src/arping.c
 *
 * arping
 *
 * By Thomas Habets <thomas@habets.se>
 *
 * ARP 'ping' utility
 *
 * Broadcasts a who-has ARP packet on the network and prints answers.
 * *VERY* useful when you are trying to pick an unused IP for a net that
 * you don't yet have routing to. Then again, if you have no idea what I'm
 * talking about then you prolly don't need it.
 *
 * Also finds out IP of specified MAC.
 *
 */
/*
 *  Copyright (C) 2000-2024 Thomas Habets <thomas@habets.se>
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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <poll.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if HAVE_TIME_H
#include <time.h>
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#if HAVE_GRP_H
#include <grp.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_LIBNET_H
#include <libnet.h>
#endif

#if HAVE_WIN32_LIBNET_H
#include <win32/libnet.h>
#endif

#if HAVE_PWD_H
#include <pwd.h>
#endif

#if HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#else
// It seems that some environments have a libc with cap_init, but do not have
// the header files. Without the header files we won't have the cap_t struct, so
// it won't actually work.
//
// TODO: Probably this logic should be in configure.ac instead.
#undef HAVE_CAP_INIT
#endif

#if HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
#include <pcap.h>

#include "arping.h"
#include "cast.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#ifndef WIN32
#define WIN32 0
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

#define UNUSED(x) (void)(x)

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

/**
 * OS-specific interface finding using routing table. See findif_*.c
 * ebuf must be called with a size of at least
 * max(LIBNET_ERRBUF_SIZE, PCAP_ERRBUF_SIZE).
 */
const char *
arping_lookupdev(uint32_t srcip, uint32_t dstip, char *ebuf);

const char *
arping_lookupdev_default(uint32_t srcip, uint32_t dstip, char *ebuf);

static const char *version = VERSION; /* from autoconf */

libnet_t *libnet = 0;

/*
 * Exit if dropping privs fails. Intentionally disabled for now.
 */
static const int exit_on_drop_fail = 0;

/* Timestamp of last packet sent.
 * Used for timing, and assumes that reply is due to most recent sent query.
 */
static struct timespec lastpacketsent;

/* target string */
static const char *target = "huh? bug in arping?";

/*
 * Ping IP mode:   cmdline target
 * Ping MAC mode:  255.255.255.255, override with -T
 */
uint32_t dstip;

/*
 * Ping IP mode:   ethxmas, override with -t
 * Ping MAC mode:  cmdline target
 */
static uint8_t dstmac[ETH_ALEN];

/* For ping MAC mode, use some extra ICMP echo payload data to confirm it's our
 * ping.
 */
char* payload_suffix = NULL;
const size_t payload_suffix_size = 4;

// Must be at least big enough to capture an entire packet.
// Longest possible:
//   MAC: 802.1q(16) + IPv4(20) + ICMPv4(4) + timespec(18?) + 4 = 62.
//   IP: 802.1q(16) + ARP(8) + 2xaddr_pair = 44.
// 100 is enough.
static const int pcap_snaplen = 100;
static const int pcap_timeout_ms = 10;

/* If there were any libnet write failures, we return error. */
static size_t libnet_write_failures = 0;

uint32_t srcip;                   /* autodetected, override with -S/-b/-0 */
uint8_t srcmac[ETH_ALEN];         /* autodetected, override with -s */

static int16_t vlan_tag = -1; /* 802.1Q tag to add to packets. -V */
static int16_t vlan_prio = -1; /* 802.1p prio to use with 802.1Q. -Q */

static int beep = 0;                 /* beep when reply is received. -a */
static int reverse_beep = 0;         /* beep when expected reply absent. -e */
static int alsototal = 0;            /* print sent as well as received. -u */
static int addr_must_be_same = 0;    /* -A */
static int unsolicited = 0;          /* -U */
static int send_reply = 0;           /* Send reply instead of request. -P */
static int promisc = 0;              /* Use promisc mode. -p */

static int finddup = 0;              /* finddup mode. -d */
static int dupfound = 0;             /* set to 1 if dup found */
static char lastreplymac[ETH_ALEN];  /* if last different from this then dup */

/* -z to turn on, -Z to turn off. Default is compile time option */
static int use_seccomp = DEFAULT_SECCOMP;

unsigned int numsent = 0;                   /* packets sent */
unsigned int numrecvd = 0;                  /* packets received */
static unsigned int max_replies = UINT_MAX; /* exit after -C replies */
static const char* timestamp_type = NULL;   /* Incoming packet measurement ts type (-m) */

static double stats_min_time = -1;
static double stats_max_time = -1;
static double stats_total_time = 0;
static double stats_total_sq_time = 0;

/* RAWRAW is RAW|RRAW */
static enum { NORMAL,      /* normal output */
              QUIET,       /* No output. -q */
              RAW,         /* Print MAC when pinging IP. -r */
              RRAW,        /* Print IP when pinging IP. -R */
              RAWRAW,      /* Print both. -r and -R */
              DOT          /* Print '.' and '!', Cisco-style. -D */
} display = NORMAL;

static const uint8_t ethnull[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
static const uint8_t ethxmas[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const char* ip_broadcast = "255.255.255.255";
static const uint32_t ip_broadcast_num = (uint32_t)-1;

int verbose = 0;  /* Increase with -v */

/* Doesn't really need to be volatile, but doesn't hurt. */
static volatile sig_atomic_t time_to_die = 0;

void drop_landlock();
void drop_no_new_privs();

void
xsnprintf(char *buf, size_t size, const char* fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);

        const int ret = vsnprintf(buf, size, fmt, ap);
        if (ret < 0) {
                fprintf(stderr, "arping: snprintf() returned negative: %d\n", ret);
                exit(1);
        }
        if (cast_int_size(ret, "snprintf return %d not castable to size_t", ret) >= size) {
                fprintf(stderr, "arping: snprintf() overflow: %d >= %zu\n", ret, size);
                exit(1);
        }

        va_end(ap);
}

static float
must_parse_float(const char* in, const char* what)
{
        if (!*in) {
                fprintf(stderr, "arping: %s: value was empty\n", what);
                exit(1);
        }
        char *endp = NULL;
        errno = 0;
        // Maybe need to use strtod() instead? It's in C89, whereas
        // looks like strtof() is in POSIX.1-2001, POSIX.1-2008, C99.
        const float ret = strtof(in, &endp);
        if (errno) {
                fprintf(stderr, "arping: %s: parsing <%s> as float: %s\n",
                        what, in, strerror(errno));
                exit(1);
        }
        if (*endp) {
                fprintf(stderr,
                        "arping: %s: failed parsing <%s> as float\n",
                        what, in);
                exit(1);
        }
        return ret;
}

static int
must_parse_int(const char* in, const char* what)
{
        if (!*in) {
                fprintf(stderr, "arping: %s: value was empty\n", what);
                exit(1);
        }
        char *endp = NULL;
        errno = 0;
        const long ret = strtol(in, &endp, 0);
        if (errno) {
                fprintf(stderr, "arping: %s: parsing <%s> as integer: %s\n",
                        what, in, strerror(errno));
                exit(1);
        }
        if (*endp) {
                fprintf(stderr,
                        "arping: %s: failed parsing <%s> as integer\n",
                        what, in);
                exit(1);
        }
        return cast_long_int(ret, "%s %s", what, in);
}

static int16_t
must_parse_int16(const char* in, const char* what)
{
        const int out = must_parse_int(in, what);
        return cast_int_int16(out, "%s %s", what, in);
}

/*
 * It's not actually possible to parse unsigned numbers in C.
 * The best this function can do is parse as a long, then reject
 * negative numbers. If sizeof(int) == sizeof(long) then that cuts
 * off half of all possible values.
 *
 * More ranting here:
 * https://blog.habets.se/2022/10/No-way-to-parse-integers-in-C.html
 */
static unsigned int
must_parse_uint(const char* in, const char* what)
{
        if (!*in) {
                fprintf(stderr, "arping: %s: value was empty\n", what);
                exit(1);
        }
        char *endp = NULL;
        errno = 0;
#if HAVE_STRTOLL
#define CASTER cast_longlong_uint
        const long long ret = strtoll(in, &endp, 0);
#else
#define CASTER cast_long_uint
        const long ret = strtol(in, &endp, 0);
#endif
        if (errno) {
                fprintf(stderr, "arping: %s: parsing <%s> as integer: %s\n",
                        what, in, strerror(errno));
                exit(1);
        }
        if (*endp) {
                fprintf(stderr,
                        "arping: %s: failed parsing <%s> as integer\n",
                        what, in);
                exit(1);
        }
        if (ret < 0) {
                fprintf(stderr,
                        "arping: %s: <%s> is negative\n", what, in);
                exit(1);
        }
        return CASTER(ret, "%s %s", what, in);
#undef CASTER
}

static unsigned long
parse_ulong(const char* in, const char* what, char* ebuf, size_t ebuflen)
{
        if (!*in) {
                xsnprintf(ebuf, ebuflen, "arping: %s: value was empty\n", what);
                return 0;
        }
        char *endp = NULL;
        errno = 0;
#if HAVE_STRTOLL
#define CASTER cast_longlong_ulonglong
        const long long ret = strtoll(in, &endp, 0);
#else
#define CASTER cast_long_ulong
        const long ret = strtol(in, &endp, 0);
#endif
        if (errno) {
                xsnprintf(ebuf, ebuflen, "arping: %s: parsing <%s> as integer: %s\n",
                        what, in, strerror(errno));
                return 0;
        }
        if (*endp) {
                xsnprintf(ebuf, ebuflen,
                        "arping: %s: failed parsing <%s> as integer\n",
                        what, in);
                return 0;
        }
        if (ret < 0) {
                xsnprintf(ebuf, ebuflen,
                        "arping: %s: <%s> is negative\n", what, in);
                return 0;
        }
        return CASTER(ret, "%s %s", what, in);
#undef CASTER
}

static ssize_t
xgetrandom(void *buf, const size_t buflen, const unsigned int flags)
{
#ifdef ACTUALLY_HAS_GETRANDOM
        return getrandom(buf, buflen, flags);
#else
        UNUSED(flags);
        uint8_t* p = buf;
        for (size_t n = 0; n < buflen; n++) {
                p[n] = cast_long_uint8(random() & 0xff, NULL);
        }
        return cast_size_ssize(buflen, NULL);
#endif
}

static uint16_t
xrandom16() {
        const int maxtry = 10;
        for (int c = 0; c < maxtry; c++) {
                uint16_t ret;
                const ssize_t rc = xgetrandom(&ret, sizeof(ret), 0);
                if (rc == -1) {
                        fprintf(stderr, "arping: failed to get random bytes: %s\n", strerror(errno));
                        continue;
                }
                if (sizeof(ret) != rc) {
                        fprintf(stderr, "arping: got too few random bytes %zd, want %zu\n", rc, sizeof(ret));
                        continue;
                }
                return ret;
        }
        fprintf(stderr, "arping: failed to get random bytes after %d tries\n", maxtry);
        exit(1);
}

/**
 * If possible, chroot.
 *
 * The sshd user is used for privilege separation in OpenSSH.
 * Let's assume it's installed and chroot() to there.
 */
static void
drop_fs_root()
{
        const char* chroot_user = "sshd";
        struct passwd *pw;
        errno = 0;
        if (!(pw = getpwnam(chroot_user))) {
                if (verbose > 1) {
                        printf("arping: getpwnam(%s): %s\n",
                               chroot_user, strerror(errno));
                }
                return;
        }
        if (chdir(pw->pw_dir)) {
                if (verbose) {
                        printf("arping: chdir(%s): %s\n",
                               pw->pw_dir, strerror(errno));
                }
                return;
        }
        if (chroot(pw->pw_dir)) {
                if (verbose) {
                        printf("arping: chroot(%s): %s\n",
                               pw->pw_dir, strerror(errno));
                }
                return;
        }
        if (chdir("/")) {
                if (verbose) {
                        printf("arping: chdir(/): %s\n", strerror(errno));
                }
                return;
        }
        if (verbose > 1) {
                printf("arping: Successfully chrooted to %s\n", pw->pw_dir);
        }
}

/**
 * If possible, drop uid to nobody.
 *
 * This code only successfully sets all [ug]ids if running as
 * root. ARPing is most likely running as root unless using
 * capabilities, and those are dropped elsewhere.
 */
static void
drop_uid(uid_t uid, gid_t gid)
{
        int fail = 0;
        if (setgroups(0, NULL)) {
                if (exit_on_drop_fail) {
                        fprintf(stderr, "arping: setgroups(0, NULL): %s\n", strerror(errno));
                        exit(1);
                } else if (verbose) {
                        printf("arping: setgroups(0, NULL): %s\n", strerror(errno));
                }
                fail++;
        }
        if (gid && setgid(gid)) {
                if (exit_on_drop_fail) {
                        fprintf(stderr, "arping: setgid(): %s\n", strerror(errno));
                        exit(1);
                } else if (verbose) {
                        printf("arping: setgid(): %s\n", strerror(errno));
                }
                fail++;
        }
        if (uid && setuid(uid)) {
                if (exit_on_drop_fail) {
                        fprintf(stderr, "arping: setuid(): %s\n", strerror(errno));
                        exit(1);
                } else if (verbose) {
                        printf("arping: setuid(): %s\n", strerror(errno));
                }
                fail++;
        }
        if (!fail && verbose > 1) {
                printf("arping: Successfully dropped uid/gid to %lld/%lld.\n",
                       cast_uid_longlong(uid, NULL), cast_gid_longlong(gid, NULL));
        }
}

/**
 * Drop any and all capabilities.
 */
static void
drop_capabilities()
{
#ifdef ACTUALLY_HAS_CAP_INIT
        cap_t no_cap;
        if (!(no_cap = cap_init())) {
                if (verbose) {
                        printf("arping: cap_init(): %s\n", strerror(errno));
                }
                return;
        }
        if (cap_set_proc(no_cap)) {
                if (verbose) {
                        printf("arping: cap_set_proc(): %s\n", strerror(errno));
                }
        }
        if (verbose > 1) {
                printf("arping: Successfully dropped all capabilities.\n");
        }
        cap_free(no_cap);
#endif
}

/**
 * Get GID of input (handle both name and number) or die.
 */
static gid_t
must_get_group(const char* ident)
{
        // Special case empty string, because strtol.
        int saved_errno = 0;
        if (*ident) {
                // First try it as a name.
                {
                        struct group* gr;
                        errno = 0;
                        if ((gr = getgrnam(ident))) {
                                return gr->gr_gid;
                        }
                        saved_errno = errno;
                }

                // Not a name. Try it as an integer.
                {
                        char ebuf[1024] = {0};
                        const unsigned long v = parse_ulong(ident, "gid", ebuf, sizeof(ebuf));
                        if (!ebuf[0]) {
                                return cast_ulong_gid(v, NULL);
                        }
                }
        }

        if (saved_errno != 0) {
                fprintf(stderr,
                        "arping: %s not a number and getgrnam(%s): %s\n",
                        ident, ident, strerror(saved_errno));
        } else {
                // If group was supplied, then not
                // existing is fatal error too.
                fprintf(stderr,
                        "arping: %s is not a number or group\n",
                        ident);
        }
        exit(1);
}

/**
 * drop all privileges.
 *
 * To be called as early as possible. IOW: immediately after opening
 * raw socket.
 */
static void
drop_privileges(const char* drop_group)
{
        // Need to get uid/gid of 'nobody' before chroot().
        const char* drop_user = "nobody";
        struct passwd *pw;
        errno = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        if (!(pw = getpwnam(drop_user))) {
                if (exit_on_drop_fail) {
                        if (errno != 0) {
                                fprintf(stderr, "arping: getpwnam(%s): %s\n",
                                        drop_user, strerror(errno));
                        } else {
                                fprintf(stderr, "arping: getpwnam(%s): unknown user\n",
                                        drop_user);
                        }
                        exit(1);
                } else if (verbose) {
                        if (errno != 0) {
                                printf("arping: getpwnam(%s): %s\n",
                                       drop_user, strerror(errno));
                        } else {
                                printf("arping: getpwnam(%s): unknown user\n",
                                       drop_user);
                        }
                }
        } else {
                uid = pw->pw_uid;
                gid = pw->pw_gid;
        }

        // If group is supplied, use that gid instead.
        if (drop_group != NULL) {
                gid = must_get_group(drop_group);
        }
        drop_fs_root();
        drop_no_new_privs();
        drop_landlock();
        drop_uid(uid, gid);
        drop_capabilities();
#ifdef HAVE_UNVEIL
        if (unveil("/", "")) {
                fprintf(stderr,
                        "arping: failed to unveil(/, <>): %s\n",
                        strerror(errno));
                exit(1);
        }
        if (unveil(NULL, NULL)) {
                fprintf(stderr, "arping: failed to unveil(NULL, NULL): %s\n",
                       strerror(errno));
                exit(1);
        }
        if (verbose > 1) {
                printf("arping: Successfully unveiled\n");
        }
#endif
}

/**
 * drop even more privileges, where possible.
 *
 * After all setup is done and main loop is about to start.
 */
static void
drop_more_privileges(int libnet_fd)
{
        UNUSED(libnet_fd);
#ifdef HAVE_PLEDGE
        if (pledge("stdio tty", "")) {
                fprintf(stderr, "arping: failed to pledge(stdio, <empty>): %s\n",
                       strerror(errno));
                exit(1);
        } else if (verbose > 1) {
                printf("arping: Successfully pledged\n");
        }
#endif
        if (use_seccomp) {
                drop_seccomp(libnet_fd);
        }
}

/**
 * Check for buggy libpcap version
 * https://github.com/the-tcpdump-group/libpcap/issues/461
 *
 * This list is not authoritative.
 *
 * If it's over matching wrong the only impact *should* be that too many packets
 * come through the BPF filter.
 *
 * If it's under-matching then replies with dot1p nonzero will not be seen.
 */
static int
bug_pcap_vlan()
{
        const char* bad[] = {
                // Broken in 1.7.0.
                "libpcap version 1.7",
                "libpcap version 1.8",
                "libpcap version 1.9.0",
                // Fixed in 1.9.1.
                // Fixed in 1.10 and up.
                NULL,
        };
        const char* v = pcap_lib_version();
        for (const char** t = bad; *t; t++) {
                if (!strncmp(v, *t, strlen(*t))) {
                        return 1;
                }
        }
        return 0;
}

/**
 * Do pcap_open_live(), except by using the pcap_create() interface
 * introduced in 2008 (libpcap 0.4) where available.
 * This is so that we can set some options, which can't be set with
 * pcap_open_live:
 * 1) Immediate mode -- this prevents pcap from buffering.
 * 2) Set timestamp type -- specify what type of timer to use.
 *
 * FIXME: Use pcap_set_buffer_size()?
 */
static pcap_t*
try_pcap_open_live(const char *device, int snaplen, int to_ms, char *errbuf)
{
#ifdef HAVE_PCAP_CREATE
        pcap_t* pcap;
        int rc;

        if (!(pcap = pcap_create(device, errbuf))) {
                goto err;
        }
        if ((rc = pcap_set_snaplen(pcap, snaplen))) {
                xsnprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_snaplen(): %s", pcap_statustostr(rc));
                goto err;
        }
        if ((rc = pcap_set_promisc(pcap, promisc))) {
                xsnprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_promisc(): %s", pcap_statustostr(rc));
                goto err;
        }
        if ((rc = pcap_set_timeout(pcap, to_ms))) {
                xsnprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_timeout(): %s", pcap_statustostr(rc));
                goto err;
        }

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
        // Without immediate mode some architectures (e.g. Linux with
        // TPACKET_V3) will buffer replies and incorrectly report upwards of
        // hundreds of milliseconds of delay.
        if ((rc = pcap_set_immediate_mode(pcap, 1))) {
                if (verbose) {
                        fprintf(stderr, "arping: pcap_set_immediate_mode() failed: %s\n", pcap_statustostr(rc));
                }
        }
#endif
#ifdef HAVE_PCAP_LIST_TSTAMP_TYPES
        if (timestamp_type) {
                int err;
                int v = pcap_tstamp_type_name_to_val(timestamp_type);
                if (v == PCAP_ERROR) {
                        fprintf(stderr, "arping: Unknown timestamp type \"%s\"\n", timestamp_type);
                        exit(1);
                }
                if ((err = pcap_set_tstamp_type(pcap, v))) {
                        fprintf(stderr,
                                "arping: Failed to set timestamp type \"%s\" (%d): %s\n",
                                timestamp_type, v, pcap_statustostr(err));
                }
        }
#endif
        if ((rc = pcap_activate(pcap))) {
                if (timestamp_type) {
                        xsnprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate(tstype=\"%s\"): %s. Try without setting timestamp type.", timestamp_type, pcap_statustostr(rc));
                } else {
                        xsnprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate(): %s", pcap_statustostr(rc));
                }
                goto err;
        }
#ifdef HAVE_PCAP_LIST_TSTAMP_TYPES
        // List timestamp types after activating, since we don't want to list
        // them if activating failed.
        if (verbose > 1) {
                int *ts;
                int count;
                count = pcap_list_tstamp_types(pcap, &ts);
                if (count == PCAP_ERROR) {
                        fprintf(stderr, "arping: pcap_list_tstamp_types() failed\n");
                } else {
                        int c;
                        const char* fmt = "  %-18s %s\n";
                        fprintf(stderr, "Timestamp types:\n");
                        fprintf(stderr, fmt, "Name", "Description");
                        for (c = 0; c < count; c++) {
                                fprintf(stderr, fmt, pcap_tstamp_type_val_to_name(ts[c]),
                                        pcap_tstamp_type_val_to_description(ts[c]));
                        }
                        pcap_free_tstamp_types(ts);
                }
        }
#endif
        return pcap;
err:
        if (pcap) {
                pcap_close(pcap);
        }
        return NULL;
#else
        return pcap_open_live(device, snaplen, to_ms, errbuf);
#endif
}

/**
 * Some stupid OSs (Solaris) think it's a good idea to put network
 * devices in /dev and then play musical chairs with them.
 *
 * Since libpcap doesn't seem to have a workaround for that, here's arpings
 * workaround.
 *
 * E.g. if the network interface is called net0, pcap will fail because it
 * fails to open /dev/net, because it's a directory.
 */
static pcap_t*
do_pcap_open_live(const char *device, int snaplen, int to_ms, char *errbuf)
{
        pcap_t* ret;
        char buf[PATH_MAX];

        if ((ret = try_pcap_open_live(device, snaplen, to_ms, errbuf))) {
                return ret;
        }

        xsnprintf(buf, sizeof(buf), "/dev/%s", device);
        if ((ret = try_pcap_open_live(buf, snaplen, to_ms, errbuf))) {
                return ret;
        }

        xsnprintf(buf, sizeof(buf), "/dev/net/%s", device);
        if ((ret = try_pcap_open_live(buf, snaplen, to_ms, errbuf))) {
                return ret;
        }

        /* Call original again to reset the error message. */
        return try_pcap_open_live(device, snaplen, to_ms, errbuf);
}

/**
 * Some Libnet error messages end with a newline. Strip that in place.
 */
void
strip_newline(char* s) {
        size_t n;
        for (n = strlen(s); n && (s[n - 1] == '\n'); --n) {
                s[n - 1] = 0;
        }
}

/**
 * Init libnet with specified ifname. Destroy if already inited.
 *
 * Libnet usually needs init before we have searched for the real
 * interface. In that case, first we just give a NULL pointer as the
 * interface. But libnet sometimes fails to find an interface (no idea
 * why), so then we try to use "lo" and "lo0" explicitly.
 *
 * If even loopback fails, then it'll preserve the original error
 * message.
 *
 * Call with recursive=0.
 */
void
do_libnet_init(const char *inifname, int recursive)
{
        const char* ifname = inifname;
        int last = 0;
        switch (recursive) {
        case 0:
                break;
        case 1:
                ifname = "lo"; // E.g. Linux.
                break;
        case 2:
                ifname = "lo0"; // E.g. OpenBSD.
                break;
        default:
                last = 1;
                break;
        }

        // If we're given an interface name then always use that.
        // No need to be recursive about it.
        if (inifname != NULL && recursive == 0) {
                ifname = inifname;
                last = 1;
        }

	char ebuf[LIBNET_ERRBUF_SIZE];
        ebuf[0] = 0;
	if (verbose > 1) {
                printf("arping: trying libnet_init(LIBNET_LINK, %s)\n",
                       ifname ? ifname : "<null>");
	}
	if (libnet) {
		/* Probably going to switch interface from temp to real. */
		libnet_destroy(libnet);
		libnet = 0;
	}

        /* Try libnet_init() even though we maybe aren't root. We may have
         * a capability or something. */
	if (!(libnet = libnet_init(LIBNET_LINK,
				   (char*)ifname,
				   ebuf))) {
                strip_newline(ebuf);
                if (verbose) {
                        fprintf(stderr,
                                "arping: libnet_init(LIBNET_LINK, %s): %s\n",
                                ifname ? ifname : "<null>",
                                *ebuf ? ebuf : "<no error message>");
                }
                if (!last) {
                        do_libnet_init(ifname, recursive+1);
                        if (libnet != NULL) {
                                return;
                        }
                }
                if (!verbose) {
                        // Prevent double-print when verbose.
                        fprintf(stderr,
                                "arping: libnet_init(LIBNET_LINK, %s): %s\n",
                                ifname ? ifname : "<null>",
                                *ebuf ? ebuf : "<no error message>");
                }
                if (getuid() && geteuid()) {
                        fprintf(stderr,
                                "arping: you may need to run as root\n");
                }
		exit(1);
	}
}

/**
 *
 */
void
sigint(int i)
{
        UNUSED(i);
	time_to_die = 1;
}

/**
 * idiot-proof clock_gettime() wrapper
 */
static void
getclock(struct timespec *ts)
{
        memset(ts, 0, sizeof(struct timespec));
#if HAVE_CLOCK_MONOTONIC
        static int clock_gettime_failed = 0;
        if (!clock_gettime_failed) {
                if (0 == clock_gettime(CLOCK_MONOTONIC, ts)) {
                        return;
                }
                fprintf(stderr, "arping: clock_gettime(): %s\n",
                        strerror(errno));
                clock_gettime_failed = 1; // Prevent duplicate error messages.
        }
#endif
        struct timeval tv;
        if (-1 == gettimeofday(&tv, NULL)) {
                fprintf(stderr, "arping: gettimeofday(): %s\n",
                        strerror(errno));
                sigint(0);
        }
        ts->tv_sec = tv.tv_sec;
        ts->tv_nsec = tv.tv_usec * 1000;
}

/**
 *
 */
static char*
format_mac(const unsigned char* mac, char* buf, size_t bufsize) {
        xsnprintf(buf, bufsize, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (unsigned)mac[0], (unsigned)mac[1],
                (unsigned)mac[2], (unsigned)mac[3],
                (unsigned)mac[4], (unsigned)mac[5]);
        return buf;
}

/**
 *
 */
static void
extended_usage()
{
	printf("\nOptions:\n");
	printf("\n"
	       "    -0     Use this option to ping with source IP address 0.0.0.0. Use this\n"
	       "           when you haven't configured your interface yet.  Note that  this\n"
	       "           may  get  the  MAC-ping  unanswered.   This  is  an alias for -S\n"
	       "           0.0.0.0.\n"
	       "    -a     Audiable ping.\n"
	       "    -A     Only count addresses matching  requested  address  (This  *WILL*\n"
	       "           break  most things you do. Only useful if you are arpinging many\n"
	       "           hosts at once. See arping-scan-net.sh for an example).\n"
	       "    -b     Like -0 but source broadcast source  address  (255.255.255.255).\n"
	       "           Note that this may get the arping unanswered since it's not nor-\n"
	       "           mal behavior for a host.\n"
	       "    -B     Use instead of host if you want to address 255.255.255.255.\n"
	       "    -c count\n"
	       "           Only send count requests.\n"
               "    -C count\n"
               "           Only wait for this many replies, regardless of -c and -w.\n"
	       "    -d     Find duplicate replies. Exit with 1 if there are "
               "answers from\n"
               "           two different MAC addresses.\n"
	       "    -D     Display answers as exclamation points and missing packets as dots.\n"
               "    -e     Like -a but beep when there is no reply.\n"
	       "    -F     Don't try to be smart about the interface name.  (even  if  this\n"
	       "           switch is not given, -i overrides smartness)\n"
               "    -g group\n"
               "           setgid() to this group instead of the nobody group.\n"
	       "    -h     Displays a help message and exits.\n"
	       "    -i interface\n"
	       "           Use the specified interface.\n"
               "    -m type"
#ifndef HAVE_PCAP_LIST_TSTAMP_TYPES
               " (Disabled on this system. Option ignored)"
#endif
               "\n           Type of timestamp to use for incoming packets. Use -vv when\n"
               "           pinging to list available ones.\n"
	       "    -q     Does not display messages, except error messages.\n"
               "    -Q pri 802.1p priority to set. Should be used with 802.1Q (-V).\n"
               "           Defaults to 0.\n"
	       "    -r     Raw output: only the MAC/IP address is displayed for each reply.\n"
	       "    -R     Raw output: Like -r but shows \"the other one\", can  be  combined\n"
	       "           with -r.\n"
	       "    -s MAC Set source MAC address. You may need to use -p with this.\n"
	       "    -S IP  Like  -b and -0 but with set source address.  Note that this may\n"
	       "           get the arping unanswered if the target does not have routing to\n"
	       "           the  IP.  If you don't own the IP you are using, you may need to\n"
	       "           turn on promiscious mode on the interface (with -p).  With  this\n"
	       "           switch  you can find out what IP-address a host has without tak-\n"
	       "           ing an IP-address yourself.\n"
	       "    -t MAC Set target MAC address to use when pinging IP address.\n"
	       "    -T IP  Use -T as target address when pinging MACs that won't respond to\n"
	       "           a broadcast ping but perhaps to a directed broadcast.\n"
	       "           Example:\n"
	       "           To check the address of MAC-A, use knowledge of MAC-B and  IP-B.\n"
	       "           $ arping -S <IP-B> -s <MAC-B> -p <MAC-A>\n"
	       "    -p     Turn  on  promiscious  mode  on interface, use this if you don't\n"
	       "           \"own\" the MAC address you are using.\n"
               "    -P     Send ARP replies instead of requests. Useful with -U.\n"
	       "    -u     Show index=received/sent instead  of  just  index=received  when\n"
	       "           pinging MACs.\n"
	       "    -U     Send unsolicited ARP.\n"
	       "    -v     Verbose output. Use twice for more messages.\n"
               "    -V num 802.1Q tag to add. Defaults to no VLAN tag.\n"
               "    -w sec Specify a timeout before ping exits regardless of how many\n"
               "           packets have been sent or received.\n"
               "    -W sec Time to wait between pings.\n"
#if USE_SECCOMP
               "    -z     Enable seccomp%s\n"
               "    -Z     Disable seccomp%s\n",
               DEFAULT_SECCOMP ? " (default)" : "",
               DEFAULT_SECCOMP ? "" : " (default)"
#endif
               );
        printf("Report bugs to: thomas@habets.se\n"
               "Arping home page: <http://www.habets.pp.se/synscan/>\n"
               "Development repo: http://github.com/ThomasHabets/arping\n");
}

/**
 *
 */
static void
standard_usage()
{
	printf("ARPing %s, by Thomas Habets <thomas@habets.se>\n",
	       version);
        printf("usage: arping [ -0aAbdDeFpPqrRuUv%s ] [ -w <sec> ] "
               "[ -W <sec> ] "
               "[ -S <host/ip> ]\n"
               "              "
               "[ -T <host/ip ] "
               "[ -s <MAC> ] [ -t <MAC> ] [ -c <count> ]\n"
               "              "
               "[ -C <count> ] [ -i <interface> ] [ -m <type> ]"
               " [ -g <group> ]\n"
               "              "
               "[ -V <vlan> ] [ -Q <priority> ] "
               "<host/ip/MAC | -B>\n", USE_SECCOMP ? "zZ" : "");
}

/**
 *
 */
static void
usage(int ret)
{
        standard_usage();
        if (WIN32) {
                extended_usage();
        } else {
                printf("For complete usage info, use --help"
                       " or check the manpage.\n");
        }
	exit(ret);
}

/**
 *
 */
static void
print_library_versions()
{
        fprintf(stderr, "arping: %s\n", pcap_lib_version());
        if (bug_pcap_vlan()) {
                fprintf(stderr, "arping: bug: https://github.com/the-tcpdump-group/libpcap/issues/461\n");
        }
        fprintf(stderr, "arping: %s\n", libnet_version());
}

/**
 * Check to see if it looks somewhat like a MAC address.
 *
 * It was unclear from msdn.microsoft.com if their scanf() supported
 * [0-9a-fA-F], so I'll stay away from it.
 *
 */
int is_mac_addr(const char *p)
{
        const size_t len = strlen(p);
	/* cisco-style hhhh.hhhh.hhhh */
        if (len == 14) {
		unsigned int c;
                for (c = 0; c < 14; c++) {
			if ((c % 5) == 4) {
				if ('.' != p[c]) {
                                        return 0;
				}
			} else {
				if (!isxdigit((unsigned char)p[c])) {
                                        return 0;
				}
			}
		}
		return 1;
	}
        if (len != 17) {
                // Windows and unix ones are 17 characters.
                return 0;
        }

	/* windows-style xx-xx-xx-xx-xx-xx */
        unsigned int c;
        for (c = 0; c < 17; c++) {
                if ((c % 3) == 2) {
                        if ('-' != p[c]) {
                                goto checkunix;
                        }
                } else {
                        if (!isxdigit((unsigned char)p[c])) {
                                goto checkunix;
                        }
                }
        }
        return 1;

checkunix:
        /* unix xx:xx:xx:xx:xx:xx */
        for (c = 0; c < 17; c++) {
                if ((c % 3) == 2) {
                        if (':' != p[c]) {
                                return 0;
                        }
                } else {
                        if (!isxdigit((unsigned char)p[c])) {
                                return 0;
                        }
                }
        }
        return 1;
}

/**
 * parse mac address.
 *
 * return 1 on success.
 */
int
get_mac_addr(const char *in, uint8_t *out)
{
        const char *formats[] = {
                "%x:%x:%x:%x:%x:%x%n",
                "%2x%x.%2x%x.%2x%x%n",
                "%x-%x-%x-%x-%x-%x%n",
                NULL,
        };
        if (!is_mac_addr(in)) {
                return 0;
        }
        int c;
        for (c = 0; formats[c]; c++) {
                unsigned int n[6];
                int endp = 0;
                if (6 == sscanf(in, formats[c],
                                &n[0], &n[1], &n[2], &n[3], &n[4], &n[5],
                                &endp)) {
                        int i;
                        if (in[endp] != '\0') {
                                return 0;
                        }
                        for (i = 0; i < 6; i++) {
                                if (n[i] > 0xff) {
                                        return 0;
                                }
                                out[i] = (uint8_t)n[i];
                        }
                        return 1;
                }
        }
        return 0;
}

/**
 *
 */
static void
update_stats(double sample)
{
        if (stats_min_time < 0 || sample < stats_min_time) {
                stats_min_time = sample;
        }
        if (sample > stats_max_time) {
                stats_max_time = sample;
        }
        stats_total_time += sample;
        stats_total_sq_time += sample * sample;
}

/**
 * return 1 if reply limit reached.
 */
static int
stop_at_reply_limit(unsigned char* pcap_user)
{
        if (numrecvd < max_replies) {
                return 0;
        }
        if (pcap_user) {
                pcap_breakloop((pcap_t*)pcap_user);
        }
        return 1;
}

/**
 *
 */
static double
timespec2dbl(const struct timespec *tv)
{
        return (double)tv->tv_sec + (double)tv->tv_nsec / 1000000000;
}

/**
 * return number of microseconds to wait for packets.
 */
static uint32_t
wait_time(double deadline, uint32_t packetwait)
{
        struct timespec ts;

        // If deadline not specified, then don't use it.
        if (deadline < 0) {
                return packetwait;
        }

        getclock(&ts);
        const double max_wait = deadline - timespec2dbl(&ts);
        if (max_wait < 0) {
                return 0;
        }
        if (max_wait > packetwait / 1000000.0) {
                return packetwait;
        }
        return cast_double_uint32(max_wait * 1000000);
}

/**
 * max size of buffer is intsize + 1 + intsize + 4 = 70 bytes or so
 *
 * Still, I'm using at least 128bytes below
 */
static char *ts2str(const struct timespec *tv, const struct timespec *tv2,
                    char *buf, size_t bufsize)
{
	double f,f2;
	int exp = 0;

        f = timespec2dbl(tv);
        f2 = timespec2dbl(tv2);
	f = (f2 - f) * 1000000000;
	while (f > 1000) {
		exp += 3;
		f /= 1000;
	}
	switch (exp) {
	case 0:
                xsnprintf(buf, bufsize, "%.3f nsec", f);
		break;
	case 3:
                xsnprintf(buf, bufsize, "%.3f usec", f);
		break;
	case 6:
                xsnprintf(buf, bufsize, "%.3f msec", f);
		break;
	case 9:
                xsnprintf(buf, bufsize, "%.3f sec", f);
		break;
	case 12:
                xsnprintf(buf, bufsize, "%.3f sec", f*1000);
		break;
        default:
		/* huh, uh, huhuh */
                xsnprintf(buf, bufsize, "%.3fe%d sec", f, exp-9);
	}
	return buf;
}

/** Send directed IPv4 ICMP echo request.
 *
 * \param id      IP id
 * \param seq     Ping seq
 */
static void
pingmac_send(uint16_t id, uint16_t seq)
{
	static libnet_ptag_t icmp = 0, ipv4 = 0,eth=0;

        // Padding size chosen fairly arbitrarily.
        // Without this padding some systems (e.g. Raspberry Pi 3
        // wireless interface) failed. dmesg said:
        //   arping: packet size is too short (42 <= 50)
        const size_t padding_size = sizeof(struct timespec) + payload_suffix_size;
        uint8_t padding[padding_size];
        memset(padding, 0, padding_size);
        {
                struct timespec ts;
                getclock(&ts);
                memcpy(padding, &ts, sizeof(struct timespec));
                memcpy(&padding[sizeof(struct timespec)],
                       payload_suffix, payload_suffix_size);
        }

	if (-1 == (icmp = libnet_build_icmpv4_echo(ICMP_ECHO, /* type */
						   0, /* code */
						   0, /* checksum */
						   id, /* id */
						   seq, /* seq */
						   (uint8_t*)padding, /* payload */
						   cast_size_uint32(padding_size, NULL), /* payload len */
						   libnet,
						   icmp))) {
		fprintf(stderr, "libnet_build_icmpv4_echo(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}

        if (-1 == (ipv4 = libnet_build_ipv4(
                cast_size_uint16(
                    LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + padding_size,
                    NULL),
					  0, /* ToS */
					  id, /* id */
					  0, /* frag */
					  64, /* ttl */
					  IPPROTO_ICMP,
					  0, /* checksum */
					  srcip,
					  dstip,
					  NULL, /* payload */
					  0,
					  libnet,
					  ipv4))) {
		fprintf(stderr, "libnet_build_ipv4(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}
	if (vlan_tag >= 0) {
                eth = libnet_build_802_1q(dstmac,
                                          srcmac,
                                          ETHERTYPE_VLAN,
                                          cast_int16_uint8(vlan_prio, NULL),
                                          0, // cfi
                                          cast_int16_uint16(vlan_tag, NULL),
                                          ETHERTYPE_IP,
                                          NULL, // payload
                                          0, // payload length
                                          libnet,
                                          eth);
        } else {
                eth = libnet_build_ethernet(dstmac,
                                            srcmac,
                                            ETHERTYPE_IP,
                                            NULL, // payload
                                            0, // payload length
                                            libnet,
                                            eth);
        }
        if (-1 == eth) {
                fprintf(stderr, "arping: %s: %s\n",
                        (vlan_tag >= 0) ? "libnet_build_802_1q()" :
                        "libnet_build_ethernet()",
                        libnet_geterror(libnet));
                sigint(0);
        }
	if (verbose > 1) {
                getclock(&lastpacketsent);
                printf("arping: sending packet at time %"PRIdMAX".%09"PRIdMAX"\n",
                       (intmax_t)lastpacketsent.tv_sec,
                       (intmax_t)lastpacketsent.tv_nsec);
	}
        if (-1 == libnet_write(libnet)) {
		fprintf(stderr, "arping: libnet_write(): %s\n",
			libnet_geterror(libnet));
                libnet_write_failures++;
		sigint(0);
	}
        getclock(&lastpacketsent);
	numsent++;
}

/** Send ARP who-has.
 *
 */
static void
pingip_send()
{
	static libnet_ptag_t arp=0,eth=0;

        // Padding size chosen fairly arbitrarily.
        // Without this padding some systems (e.g. Raspberry Pi 3
        // wireless interface) failed. dmesg said:
        //   arping: packet size is too short (42 <= 50)
        const uint8_t padding[16] = {0};

	if (-1 == (arp = libnet_build_arp(ARPHRD_ETHER,
					  ETHERTYPE_IP,
					  ETH_ALEN,
					  IP_ALEN,
                                          send_reply ? ARPOP_REPLY : ARPOP_REQUEST,
					  srcmac,
					  (uint8_t*)&srcip,
					  unsolicited ? (uint8_t*)ethxmas : (send_reply ? dstmac : (uint8_t*)ethnull),
					  (uint8_t*)&dstip,
					  (uint8_t*)padding,
					  sizeof padding,
					  libnet,
					  arp))) {
		fprintf(stderr, "arping: libnet_build_arp(): %s\n",
			libnet_geterror(libnet));
		sigint(0);
	}

        if (vlan_tag >= 0) {
                eth = libnet_build_802_1q(dstmac,
                                          srcmac,
                                          ETHERTYPE_VLAN,
                                          cast_int16_uint8(vlan_prio, NULL),
                                          0, // cfi
                                          cast_int16_uint16(vlan_tag, NULL),
                                          ETHERTYPE_ARP,
                                          NULL, // payload
                                          0, // payload size
                                          libnet,
                                          eth);
        } else {
                eth = libnet_build_ethernet(dstmac,
                                            srcmac,
                                            ETHERTYPE_ARP,
                                            NULL, // payload
                                            0, // payload size
                                            libnet,
                                            eth);
        }
	if (-1 == eth) {
		fprintf(stderr, "arping: %s: %s\n",
			(vlan_tag >= 0) ? "libnet_build_802_1q()" :
                        "libnet_build_ethernet()",
			libnet_geterror(libnet));
		sigint(0);
	}
	if (verbose > 1) {
                getclock(&lastpacketsent);
                printf("arping: sending packet at time %"PRIdMAX".%09"PRIdMAX"\n",
                       (intmax_t)lastpacketsent.tv_sec,
                       (intmax_t)lastpacketsent.tv_nsec);
	}
        if (send_reply && display != QUIET) {
                printf("Sending ARP reply\n");
        }
	if (-1 == libnet_write(libnet)) {
		fprintf(stderr, "arping: libnet_write(): %s\n",
			libnet_geterror(libnet));
                libnet_write_failures++;
		sigint(0);
	}
        getclock(&lastpacketsent);
	numsent++;
}

/** handle incoming packet when pinging an IP address.
 *
 * \param h       packet metadata
 * \param packet  packet data
 */
void
pingip_recv(unsigned char *pcap_user, const struct pcap_pkthdr *h, const unsigned char * const packet)
{
        unsigned char pkt_srcmac[ETH_ALEN];
        const unsigned char* arpdata = NULL;
        int ethernet_header_size = LIBNET_ETH_H;
        struct libnet_arp_hdr harp;
        struct timespec arrival;
        assert(packet);

        if (stop_at_reply_limit(pcap_user)) {
                return;
        }

        if (verbose > 2) {
		printf("arping: received response for IP ping\n");
	}

        getclock(&arrival);

        // Handle both sizes of ethernet frames.
	if (vlan_tag >= 0) {
                struct libnet_802_1q_hdr veth;
                if (h->caplen < LIBNET_802_1Q_H + LIBNET_ARP_H + 2*(ETH_ALEN + 4)) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... good length\n");
                }
                ethernet_header_size = LIBNET_802_1Q_H;
                memcpy(&veth, (void*)packet, LIBNET_802_1Q_H);
                memcpy(pkt_srcmac, veth.vlan_shost, ETH_ALEN);

                if (ntohs(veth.vlan_tpi) != 0x8100) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... TPI 0x8100\n");
                }
                const int packet_vlan = 0xfff & ntohs(veth.vlan_priority_c_vid);
                if (verbose > 4) {
                        printf("arping: ... is dot1q VLAN %d\n", packet_vlan);
                }
                if (packet_vlan != vlan_tag) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... right VLAN\n");
                }
	} else {
                if (h->caplen < LIBNET_ETH_H + LIBNET_ARP_H + 2*(ETH_ALEN + 4)) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... good length\n");
                }
                struct libnet_802_3_hdr heth;
                memcpy(&heth, (void*)packet, sizeof(heth));
                memcpy(pkt_srcmac, heth._802_3_shost, ETH_ALEN);
        }

        // Set up aligned structs for further checking.
        memcpy(&harp, (char*)packet + ethernet_header_size, LIBNET_ARP_H);
        arpdata = packet + ethernet_header_size + LIBNET_ARP_H;

        // Not checking ethertype because in theory this could be used for
        // Ethernet II.

        // Wrong length of hardware address.
        if (harp.ar_hln != ETH_ALEN) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... L2 addr len is correct\n");
        }

        // Wrong length of protocol address.
        if (harp.ar_pln != 4) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... L3 addr len is correct\n");
        }

        // ARP reply.
        if (ntohs(harp.ar_op) != ARPOP_REPLY) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... packet is ARP reply\n");
        }

        // From IPv4 address reply.
        if (ntohs(harp.ar_pro) != ETHERTYPE_IP) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... from IPv4 address\n");
        }

        // To Ethernet address.
        if (ntohs(harp.ar_hrd) != ARPHRD_ETHER) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... to Ethernet address\n");
        }

        // Must be sent from target address.
        // Should very likely only be used if using -t.
        if (addr_must_be_same) {
                if (memcmp(arpdata, dstmac, ETH_ALEN)) {
                        return;
                }
        }
        if (verbose > 3) {
                printf("arping: ... sent by acceptable host\n");
        }

        // Special case: If we're not in promisc mode we could still
        // get packets where DST mac is not us, if they're *sent* from
        // the local host. This is an edge case but in general falls under "is promisc?".
        //
        // It may cause confusion because `-p` now means not just
        // enable promisc mode (disable filter on card / in kernel),
        // but also allow packets to any destination (disable filter
        // in `arping`).
        {
                const uint8_t* p = (u_char*)arpdata
                        + ETH_ALEN
                        + IP_ALEN;
                char buf[128];
                if (!promisc && memcmp(p, srcmac, ETH_ALEN)) {
                        format_mac(p, buf, sizeof buf);
                        if (verbose > 3) {
                                printf("arping: ... but sent from %s\n", buf);
                        }
                        return;
                }
        }
        if (verbose > 3) {
                printf("arping: ... destination is the source we used\n");
        }

        // Actually the IPv4 address we asked for.
        uint32_t ip;
        memcpy(&ip, (char*)arpdata + harp.ar_hln, 4);
        if (dstip != ip) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... for the right IPv4 address!\n");
        }

        // Packet is correct.

        update_stats(timespec2dbl(&arrival) - timespec2dbl(&lastpacketsent));
        char buf[128];
        if (beep) {
                printf("\a");
        }
        switch(display) {
        case DOT:
                putchar('!');
                break;
        case NORMAL:
                printf("%u bytes from %s (%s): index=%u",
                       h->len, format_mac(pkt_srcmac, buf, sizeof(buf)),
                       libnet_addr2name4(ip, 0), numrecvd);

                if (alsototal) {
                        unsigned int t = numsent;
                        if (t > 0) {
                                --t;
                        }
                        printf("/%u", t);
                }
                printf(" time=%s", ts2str(&lastpacketsent, &arrival, buf,
                                          sizeof(buf)));
                break;
        case QUIET:
                break;
        case RAWRAW:
                printf("%s %s", format_mac(pkt_srcmac, buf, sizeof(buf)),
                       libnet_addr2name4(ip, 0));
                break;
        case RRAW:
                printf("%s", libnet_addr2name4(ip, 0));
                break;
        case RAW:
                printf("%s", format_mac(pkt_srcmac, buf, sizeof(buf)));
                break;
        default:
                fprintf(stderr, "arping: can't happen!\n");
        }
        fflush(stdout);

        switch (display) {
        case QUIET:
        case DOT:
                break;
        default:
                printf("\n");
        }
        if (numrecvd) {
                if (memcmp(lastreplymac,
                           pkt_srcmac, ETH_ALEN)) {
                        dupfound = 1;
                }
        }
        memcpy(lastreplymac, pkt_srcmac, ETH_ALEN);

        numrecvd++;
        stop_at_reply_limit(pcap_user);
}

/** handle incoming packet when pinging an MAC address.
 *
 * \param h       packet metadata
 * \param packet  packet data
 */
void
pingmac_recv(unsigned char* pcap_user, const struct pcap_pkthdr *h, const uint8_t *packet)
{
        unsigned char pkt_dstmac[ETH_ALEN];
        unsigned char pkt_srcmac[ETH_ALEN];
        struct libnet_ipv4_hdr hip;
        // TODO: also inspect the echo fields.
        struct libnet_icmpv4_hdr hicmp;
        struct timespec arrival;
        const uint8_t* payload = NULL;
        assert(packet);

        if (stop_at_reply_limit(pcap_user)) {
                return;
        }

	if(verbose>2) {
                printf("arping: received response for mac ping len=%u caplen=%u\n",
                       h->len, h->caplen);
	}

        getclock(&arrival);

        if (vlan_tag >= 0) {
                struct libnet_802_1q_hdr veth;
                if (h->caplen < LIBNET_802_1Q_H + LIBNET_IPV4_H
                                + LIBNET_ICMPV4_ECHO_H
                                + sizeof(struct timespec)
                                + payload_suffix_size) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... good length\n");
                }
                memcpy(&veth, packet, LIBNET_802_1Q_H);
                memcpy(&hip, (char*)packet
                                + LIBNET_802_1Q_H, LIBNET_IPV4_H);
                memcpy(&hicmp, (char*)packet
                                + LIBNET_802_1Q_H
                                + LIBNET_IPV4_H, LIBNET_ICMPV4_ECHO_H);
                memcpy(pkt_srcmac, veth.vlan_shost, ETH_ALEN);
                memcpy(pkt_dstmac, veth.vlan_dhost, ETH_ALEN);
                payload = packet
                        + LIBNET_802_1Q_H
                        + LIBNET_IPV4_H
                        + LIBNET_ICMPV4_ECHO_H;

                if (ntohs(veth.vlan_tpi) != 0x8100) {
                        return;
                }
                const int packet_vlan = 0xfff & ntohs(veth.vlan_priority_c_vid);
                if (verbose > 3) {
                        printf("arping: ... is dot1q %d\n", packet_vlan);
                }
                if (packet_vlan != vlan_tag) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... right VLAN\n");
                }
        } else {
                struct libnet_802_3_hdr heth;
                if (h->caplen < LIBNET_ETH_H + LIBNET_IPV4_H
                                + LIBNET_ICMPV4_ECHO_H
                                + sizeof(struct timespec)
                                + payload_suffix_size) {
                        return;
                }
                if (verbose > 3) {
                        printf("arping: ... good length\n");
                }
                memcpy(&heth, packet, LIBNET_ETH_H);
                memcpy(&hip, (char*)packet
                                + LIBNET_ETH_H, LIBNET_IPV4_H);
                memcpy(&hicmp, (char*)packet
                                + LIBNET_ETH_H
                                + LIBNET_IPV4_H, LIBNET_ICMPV4_ECHO_H);
                memcpy(pkt_srcmac, heth._802_3_shost, ETH_ALEN);
                memcpy(pkt_dstmac, heth._802_3_dhost, ETH_ALEN);
                payload = packet
                        + LIBNET_ETH_H
                        + LIBNET_IPV4_H
                        + LIBNET_ICMPV4_ECHO_H;
        }

        // Not checking ethertype because in theory this could be used for
        // Ethernet II.

        // Dest MAC must be me.
        if (memcmp(pkt_dstmac, srcmac, ETH_ALEN)) {
                return;
        }

        if (verbose > 3) {
                printf("arping: ... right dst mac\n");
        }

        // Source MAC must match, if set.
        if (memcmp(dstmac, ethxmas, ETH_ALEN)) {
                if (memcmp(pkt_srcmac, dstmac, ETH_ALEN)) {
                        return;
                }
        }

        if (verbose > 3) {
                printf("arping: ... right src mac\n");
        }

        // TODO: Even though we have a BPF filter, add checks for IP version and
        // protocol fields.

        // IPv4 Address must be me (maybe).
        if (addr_must_be_same) {
                uint32_t tmp;
                memcpy(&tmp, &hip.ip_src, 4);
                if (dstip != tmp) {
                        return;
                }
        }
        if (verbose > 3) {
                printf("arping: ... src IP acceptable\n");
        }

        // Must be ICMP echo reply type.
        if (hicmp.icmp_type != ICMP_ECHOREPLY) {
                return;
        }

        if (verbose > 3) {
                printf("arping: ... is echo reply type\n");
        }

        // Must be ICMP echo reply code 0.
        if (hicmp.icmp_code != 0) {
                return;
        }

        if (verbose > 3) {
                printf("arping: ... is echo reply code\n");
        }

        const size_t tmp = cast_ssize_size(payload - (uint8_t*)packet, NULL);
        if (h->caplen < tmp) {
                return;
        }
        const size_t payload_size = h->caplen - tmp;
        if (payload_size < sizeof(struct timespec) + payload_suffix_size) {
                return;
        }
        if (verbose > 3) {
                printf("arping: ... correct payload size (%zu, suffix %zu)\n",
                       payload_size, payload_suffix_size);
        }
        if (memcmp(&payload[sizeof(struct timespec)],
                   payload_suffix, payload_suffix_size)) {
                    return;
        }
        if (verbose > 3) {
                printf("arping: ... correct payload suffix\n");
        }

        // TODO: use timestamp from packet payload instead of last packet sent.
        update_stats(timespec2dbl(&arrival) - timespec2dbl(&lastpacketsent));
        if (beep) {
                printf("\a");
        }
        char buf[128];
        char buf2[128];
        switch(display) {
        case QUIET:
                break;
        case DOT:
                putchar('!');
                break;
        case NORMAL:
                printf("%u bytes from %s (%s): icmp_seq=%hu time=%s", h->len,
                       libnet_addr2name4(hip.ip_src.s_addr, 0),
                       format_mac(pkt_srcmac, buf, sizeof(buf)),
                       ntohs(hicmp.icmp_seq),
                       ts2str(&lastpacketsent, &arrival, buf2, sizeof(buf2)));
                break;
        case RAW:
                printf("%s", libnet_addr2name4(hip.ip_src.s_addr, 0));
                break;
        case RRAW:
                printf("%s", format_mac(pkt_srcmac, buf, sizeof(buf)));
                break;
        case RAWRAW:
                printf("%s %s",
                       format_mac(pkt_srcmac, buf, sizeof(buf)),
                       libnet_addr2name4(hip.ip_src.s_addr, 0));
                break;
        default:
                fprintf(stderr, "arping: can't-happen-bug\n");
                sigint(0);
        }
        fflush(stdout);
        switch (display) {
        case QUIET:
        case DOT:
                break;
        default:
                printf("\n");
        }
        numrecvd++;
        stop_at_reply_limit(pcap_user);
}

/**
 * while negative nanoseconds, take from whole seconds.
 * help function for measuring deltas.
 */
static void
fixup_timespec(struct timespec *tv)
{
	while (tv->tv_nsec < 0) {
		tv->tv_sec--;
		tv->tv_nsec += 1000000000;
	}
        while (tv->tv_nsec >= 1000000000) {
                tv->tv_sec++;
                tv->tv_nsec -= 1000000000;
        }
}

/**
 * try to receive a packet for 'packetwait' microseconds
 */
static void
ping_recv(pcap_t *pcap, uint32_t packetwait, pcap_handler func)
{
       struct timespec ts;
       struct timespec endtime;
       char done = 0;
       int fd;
       unsigned int old_received;

       if (send_reply) {
               if (verbose > 3) {
                       printf("arping: sending replies. Waiting %"PRIdMAX" us…\n",
                              (intmax_t)packetwait);
               }
               usleep(packetwait);
               return;
       }

       if (verbose > 3) {
               printf("arping: receiving packets...\n");
       }

       getclock(&ts);
       endtime.tv_sec = ts.tv_sec + (packetwait / 1000000);
       endtime.tv_nsec = ts.tv_nsec + 1000 * (packetwait % 1000000);
       fixup_timespec(&endtime);

       fd = pcap_get_selectable_fd(pcap);
       if (fd == -1) {
               fprintf(stderr, "arping: pcap_get_selectable_fd()=-1: %s\n",
                       pcap_geterr(pcap));
               exit(1);
       }
       if (fd >= FD_SETSIZE) {
               fprintf(stderr, "arping: pcap fd %d >= FD_SETSIZE (%d). Use a modern OS or report a bug.\n",
                       fd, FD_SETSIZE);
               exit(1);
       }
       old_received = numrecvd;

       for (;!done;) {
	       int trydispatch = 0;

	       getclock(&ts);
	       ts.tv_sec = endtime.tv_sec - ts.tv_sec;
	       ts.tv_nsec = endtime.tv_nsec - ts.tv_nsec;
	       fixup_timespec(&ts);
               if (verbose > 2) {
                       printf("arping: listen for replies for %"PRIdMAX".%09"PRIdMAX" sec\n",
                              (intmax_t)ts.tv_sec, (intmax_t)ts.tv_nsec);
               }

               /* if time has passed, do one last check and then we're done.
                * this also triggers if not using monotonic clock and time
                * is set forwards */
	       if (ts.tv_sec < 0) {
		       ts.tv_sec = 0;
		       ts.tv_nsec = 1;
		       done = 1;
	       }

               /* if wait-for-packet time is longer than full period,
                * we're obviously not using a monotonic clock and the system
                * time has been changed.
                * we don't know how far we're into the waiting, so just end
                * it here */
               if ((ts.tv_sec > packetwait / 1000000)
                   || ((ts.tv_sec == packetwait / 1000000)
                       && (ts.tv_nsec/1000 > packetwait % 1000000))) {
		       ts.tv_sec = 0;
		       ts.tv_nsec = 1;
                       done = 1;
               }

               /* check for sigint */
	       if (time_to_die) {
		       return;
	       }

	       /* try to wait for data */
	       {
                       fd_set fds;
		       int r;
                       struct timeval tv;
                       tv.tv_sec = ts.tv_sec;
                       tv.tv_usec = ts.tv_nsec / 1000;

                       FD_ZERO(&fds);
                       FD_SET(fd, &fds);

                       r = select(fd + 1, &fds, NULL, NULL, &tv);
		       switch (r) {
		       case 0: /* timeout */
                               if (numrecvd == old_received) {
                                       if (reverse_beep) {
                                               printf("\a");
                                       }
                                       switch (display) {
                                       case NORMAL:
                                               printf("Timeout\n");
                                               break;
                                       case DOT:
                                               printf(".");
                                               break;
                                       case RAW:
                                       case RAWRAW:
                                       case RRAW:
                                       case QUIET:
                                               break;
                                       }
                                       fflush(stdout);
                               }
			       done = 1;
			       break;
		       case -1: /* error */
			       if (errno != EINTR) {
				       done = 1;
				       sigint(0);
				       fprintf(stderr,
					       "arping: select() failed: %s\n",
					       strerror(errno));
			       }
			       break;
		       default: /* data returned */
			       trydispatch = 1;
			       break;
		       }
	       }
	       if (trydispatch) {
		       int ret;
                       if (0 > (ret = pcap_dispatch(pcap, -1,
                                                    func,
                                                    (unsigned char*)pcap))) {
                               if (time_to_die) {
                                       return;
                               }
			       /* rest, so we don't take 100% CPU... mostly
                                  hmm... does usleep() exist everywhere? */
			       usleep(1);

			       /* weird is normal on bsd :) */
			       if (verbose > 3) {
				       fprintf(stderr,
					       "arping: select says ok, but "
					       "pcap_dispatch=%d!\n",
					       ret);
			       }
		       }
	       }
       }
}

// return 1 on success.
static int
xresolve(libnet_t* l, const char *name, uint8_t r, uint32_t *addr)
{
        if (!strcmp(ip_broadcast, name)) {
                *addr = 0xffffffff;
                return 1;
        }
        *addr = libnet_name2addr4(l, (char*)name, r);
        return *addr != 0xffffffff;
}

/**
 *
 */
int
arping_main(int argc, char **argv)
{
	char ebuf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
	char *cp;
        const char *srcip_opt = NULL;
        const char *dstip_opt = NULL;
        // `dstip_given` can be set even when there's no arg past flags on the
        // cmdline and -B not set. E.g. -d defaults to self, so requires no
        // extra arg.
	int dstip_given = 0;
        const char *srcmac_opt = NULL;
        const char *dstmac_opt = NULL;
	const char *ifname = NULL;      // -i/-I
        int opt_B = 0;
        int opt_T = 0;
        int opt_U = 0;
        int c;
        const char* drop_group = NULL;  // -g
        const char *parm; // First argument, meaning the target IP.
	int maxcount = -1;
	int dont_use_arping_lookupdev=0;
	struct bpf_program bp;
	pcap_t *pcap;
	enum { NONE, PINGMAC, PINGIP } mode = NONE;
	unsigned int packetwait = 1000000; // Default one second.
        double deadline = -1;
        char bpf_filter[64];
        ebuf[0] = 0;
        srandom((unsigned)time(NULL));

        {
                int c;
                for (c = 1; c < argc; c++) {
                        if (!strcmp(argv[c], "--help")) {
                                standard_usage();
                                extended_usage();
                                exit(0);
                        }
                }
        }

	srcip = 0;
	dstip = 0xffffffff;
	memcpy(dstmac, ethxmas, ETH_ALEN);

        while (EOF != (c = getopt(argc, argv,
                                  "0aAbBC:c:dDeFg:hi:I:m:pPqQ:rRs:S:t:T:uUvV:w:W:zZ"))) {
		switch(c) {
		case '0':
			srcip_opt = "0.0.0.0";
			break;
		case 'a':
			beep = 1;
			break;
		case 'A':
			addr_must_be_same = 1;
			break;
		case 'b':
			srcip_opt = ip_broadcast;
			break;
		case 'B':
                        dstip_opt = ip_broadcast;
                        dstip_given = 1;
                        opt_B = 1;
			break;
		case 'c':
                        maxcount = must_parse_int(optarg, "count (-c)");
                        if (maxcount < 0) {
                                fprintf(stderr,
                                        "arping: count (-c) must be >0. Got %d\n",
                                        maxcount);
                                exit(1);
                        }
			break;
                case 'C':
                        max_replies = must_parse_uint(optarg,
                                                      "max replies (-C)");
                        break;
		case 'd':
			finddup = 1;
			break;
		case 'D':
			display = DOT;
			break;
                case 'e':
                        reverse_beep = 1;
                        break;
		case 'F':
			dont_use_arping_lookupdev=1;
			break;
		case 'h':
			usage(0);
                        exit(0); // Needless but shuts up compiler warnings.
                case 'g':
                        drop_group = optarg;
                        break;
		case 'i':
			if (strchr(optarg, ':')) {
				fprintf(stderr, "arping: If you're trying to "
					"feed me an interface alias then you "
					"don't really\nknow what this programs"
					" does, do you?\nUse -I if you really"
					" mean it (undocumented on "
					"purpose)\n");
				exit(1);
			}
			ifname = optarg;
                        break;
		case 'I':
			ifname = optarg;
			break;
                case 'm':
                        timestamp_type = optarg;
                        break;
		case 'p':
			promisc = 1;
			break;
                case 'P':
                        send_reply = 1;
                        break;
		case 'q':
			display = QUIET;
			break;
                case 'Q':
                        vlan_prio = must_parse_int16(optarg, "802.1p prio (-Q)");
                        if (vlan_prio < 0 || vlan_prio > 7) {
                                fprintf(stderr,
                                        "arping: 802.1p priority must be 0-7. It's %d\n",
                                        vlan_prio);
                                exit(1);
                        }
                        break;
		case 'r':
			display = (display==RRAW)?RAWRAW:RAW;
			break;
		case 'R':
			display = (display==RAW)?RAWRAW:RRAW;
			break;
		case 's': { /* spoof source MAC */
                        srcmac_opt = optarg;
			break;
		}
		case 'S': /* set source IP, may be null for don't-know */
                        srcip_opt = optarg;
			break;
		case 't': { /* set taget mac */
                        dstmac_opt = optarg;
			mode = PINGIP;
			break;
		}
		case 'T': /* set destination IP */
                        opt_T = 1;
                        dstip_opt = optarg;
			mode = PINGMAC;
			break;
		case 'u':
			alsototal = 1;
			break;
		case 'U':
                        opt_U = 1;
			unsolicited = 1;
                        mode = PINGIP;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			vlan_tag = must_parse_int16(optarg, "VLAN (-V)");
                        if (vlan_tag < 0 || vlan_tag > 4095) {
                                fprintf(stderr,
                                        "arping: vlan tag must be 0-4095. Is %d\n",
                                        vlan_tag);
                                exit(1);
                        }
                        break;
		case 'w':
                        deadline = must_parse_float(optarg, "deadline (-w)");
                        if (deadline < 0 || !isfinite(deadline)) {
                                fprintf(stderr,
                                        "arping: deadline (-w) must be finite value >=0. Is %f.\n",
                                        deadline);
                                exit(1);
                        }
			break;
                case 'W': {
                        const float val = must_parse_float(optarg,
                                                           "packetwait (-W)");
                        if (val < 0.0) {
                                fprintf(stderr,
                                        "arping: packetwait (-W) must be >=0. Is %f\n",
                                        val);
                                exit(1);
                        }
                        // This overflows (asserts) if the user tries to wait
                        // more than unsigned max number of us. And that's fine.
                        packetwait = cast_float_unsigned(1000000.0f * val);
                        break;
                }
                case 'z':
                        use_seccomp = 1;
                        break;
                case 'Z':
                        use_seccomp = 0;
                        break;
		default:
			usage(1);
		}
	}

        if (argc - optind > 1) {
                // Can be zero if using -d or -B.
                fprintf(stderr, "arping: Too many args on command line."
                        " Expected at most one.\n");
                exit(1);
        }

        if (verbose > 2) {
                print_library_versions();
        }

        // Generate random payload suffix for MAC pings, to be able to
        // differentiate from unrelated ping replies.
        payload_suffix = malloc(payload_suffix_size);
        if (!payload_suffix) {
                fprintf(stderr, "arping: failed to allocate %zu bytes for payload suffix.\n",
                        payload_suffix_size);
                exit(1);
        }

        // Create some default content.
        {
                const char* def = "arping/";
                for (size_t c = 0; c < payload_suffix_size; c++) {
                        payload_suffix[c] = def[c % strlen(def)];
                }
        }

        // Randomize should be even better.
        const ssize_t rc = xgetrandom(payload_suffix, payload_suffix_size, 0);
        if (rc < 0) {
                fprintf(stderr,
                        "arping: failed to get %zu random bytes: %s\n",
                        payload_suffix_size,
                        strerror(errno));
        } else if (payload_suffix_size != cast_ssize_size(rc, NULL)) {
                fprintf(stderr,
                        "arping: only got %zd out of %zu bytes for random suffix\n",
                        rc, payload_suffix_size);
        }

        if (((mode == PINGIP) && opt_T)
            || ((mode == PINGMAC) && (opt_B || dstmac_opt || opt_U))) {
                fprintf(stderr, "arping: -T can only be used to ping MAC"
                        " and -BtU only to ping IPs\n");
                exit(1);
        }
        if (opt_T && opt_B) {
                fprintf(stderr,
                        "arping: -B can't be used with -T,"
                        " since they set the same thing\n");
                exit(1);
        }

        if (srcmac_opt != NULL) {
                if (!get_mac_addr(srcmac_opt, srcmac)) {
                        fprintf(stderr, "arping: Weird MAC addr %s\n",
                                srcmac_opt);
                        exit(1);
                }
        }

        if (dstmac_opt != NULL) {
                if (!get_mac_addr(dstmac_opt, dstmac)) {
                        fprintf(stderr, "Illegal MAC addr %s\n", dstmac_opt);
                        exit(1);
                }
        }

        if (srcip_opt != NULL) {
                do_libnet_init(ifname, 0);
                if (!xresolve(libnet, srcip_opt, LIBNET_RESOLVE, &srcip)) {
                        fprintf(stderr, "arping: Can't resolve %s, or "
                                "%s is broadcast. If it is, use -b"
                                " instead of -S\n", srcip_opt,srcip_opt);
                        exit(1);
                }
        }

        if (dstip_opt) {
                do_libnet_init(ifname, 0);
                if (!xresolve(libnet, dstip_opt, LIBNET_RESOLVE, &dstip)) {
                        fprintf(stderr,"arping: Can't resolve %s, or "
                                "%s is broadcast. If it is, use -B "
                                "instead of -T\n",dstip_opt,dstip_opt);
                        exit(1);
                }
        }

        if (vlan_prio >= 0 && vlan_tag == -1) {
                fprintf(stderr, "arping: -Q requires the use of 802.1Q (-V)\n");
                exit(1);
        }
        if (vlan_prio == -1) {
                vlan_prio = 0;
        }

        if (verbose > 1) {
#if HAVE_CLOCK_MONOTONIC
                struct timespec ts;
                if (clock_getres(CLOCK_MONOTONIC, &ts)) {
                        fprintf(stderr,
                                "arping: clock_getres(CLOCK_MONOTONIC, ...): %s\n",
                                strerror(errno));
                } else {
                        printf("arping: clock_getres() = %"PRIdMAX"s %"PRIdMAX"ns\n",
                               (intmax_t)ts.tv_sec, (intmax_t)ts.tv_nsec);
                }
#else
                printf("arping: Using gettimeofday() for time measurements\n");
#endif
        }

        if (display == DOT) {
                if (0 != setvbuf(stdout, NULL, _IONBF, 0)) {
                        fprintf(stderr,
                                "arping: setvbuf(stdout, NULL, IONBF, 0): %s\n",
                                strerror(errno));
                }
        }

        if (finddup && maxcount == -1) {
                maxcount = 3;
        }

	parm = (optind < argc) ? argv[optind] : NULL;
        if (parm && dstip_given) {
                fprintf(stderr, "arping: options (e.g. -B) not compatible with specifying a destination.\n");
                exit(1);
        }

        /* default to own IP address when doing -d */
        if (finddup && !parm) {
                dstip_given = 1;
                do_libnet_init(ifname, 0);
                dstip = libnet_get_ipaddr4(libnet);
                if (verbose) {
                        printf("defaulting to checking dup for %s\n",
                               libnet_addr2name4(dstip, 0));
                }
        }

	/*
	 * Handle dstip_given instead of ip address after parms (-B really)
	 */
	if (mode == NONE) {
		if (parm) {
			mode = is_mac_addr(parm)?PINGMAC:PINGIP;
		} else if (dstip_given) {
			mode = PINGIP;
                        do_libnet_init(ifname, 0);
			parm = strdup(libnet_addr2name4(dstip,0));
			if (!parm) {
				fprintf(stderr, "arping: out of memory\n");
				exit(1);
			}
		}
	}

	if (!parm) {
		usage(1);
	}

        if (send_reply && mode != PINGIP) {
                fprintf(stderr, "arping: -P can't be used with MAC destination.\n");
                exit(1);
        }

	/*
	 *
	 */
	if (mode == NONE) {
		usage(1);
	}

	/*
	 * libnet init (may be done already for resolving)
	 */
        do_libnet_init(ifname, 0);
        if (verbose > 1) {
                printf("arping: libnet_getfd(): %d\n", libnet_getfd(libnet));
        }

	/*
	 * Make sure dstip and parm like eachother
	 */
	if (mode == PINGIP && (!dstip_given)) {
		if (is_mac_addr(parm)) {
			fprintf(stderr, "arping: Options given only apply to "
				"IP ping, but MAC address given as argument"
				"\n");
			exit(1);
		}
                if (!xresolve(libnet, parm, LIBNET_RESOLVE, &dstip)) {
			fprintf(stderr, "arping: Can't resolve %s\n", parm);
			exit(1);
		}
		parm = strdup(libnet_addr2name4(dstip,0));
                if (!parm) {
			fprintf(stderr, "arping: strdup of hostname failed\n");
			exit(1);
                }
	}

	/*
	 * parse parm into dstmac
	 */
	if (mode == PINGMAC) {
		if (optind + 1 != argc) {
			usage(1);
		}
		if (!is_mac_addr(parm)) {
			fprintf(stderr, "arping: Options given only apply to "
				"MAC ping, but no MAC address given as "
				"argument\n");
			exit(1);
		}
                if (!get_mac_addr(argv[optind], dstmac)) {
			fprintf(stderr, "arping: Illegal mac addr %s\n",
				argv[optind]);
			return 1;
		}
	}

	target = parm;
	/*
	 * Argument processing done, parameters considered sane below
	 */

	/*
	 * Get some good iface.
	 */
	if (!ifname) {
                if (!dont_use_arping_lookupdev) {
                        ifname = arping_lookupdev(srcip, dstip, ebuf);
                        strip_newline(ebuf);
                        if (!ifname) {
                                fprintf(stderr, "arping: lookup dev: %s\n",
                                        ebuf);
                        }
                }
                if (!ifname) {
                        ifname = arping_lookupdev_default(srcip, dstip, ebuf);
                        strip_newline(ebuf);
                        if (ifname && !dont_use_arping_lookupdev) {
                                fprintf(stderr,
                                        "arping: Unable to automatically find "
                                        "interface to use. Is it on the local "
                                        "LAN?\n"
                                        "arping: Use -i to manually "
                                        "specify interface. "
                                        "Guessing interface %s.\n", ifname);
                        }
		}
		if (!ifname) {
                        fprintf(stderr, "arping: Gave up looking for interface"
                                " to use: %s\n", ebuf);
			exit(1);
		}
		/* FIXME: check for other probably-not interfaces */
		if (!strcmp(ifname, "ipsec")
		    || !strcmp(ifname,"lo")) {
			fprintf(stderr, "arping: Um.. %s looks like the wrong "
				"interface to use. Is it? "
				"(-i switch)\n", ifname);
			fprintf(stderr, "arping: using it anyway this time\n");
		}
	}

	/*
	 * Init libnet again, because we now know the interface name.
	 * We should know it by know at least
	 */
        do_libnet_init(ifname, 0);

	/*
	 * pcap init
	 */
        if (!(pcap = do_pcap_open_live(ifname, pcap_snaplen,
                                       pcap_timeout_ms, ebuf))) {
                strip_newline(ebuf);
                fprintf(stderr, "arping: pcap_open_live(): %s\n", ebuf);
		exit(1);
	}
        drop_privileges(drop_group);
	if (pcap_setnonblock(pcap, 1, ebuf)) {
                strip_newline(ebuf);
		fprintf(stderr, "arping: pcap_set_nonblock(): %s\n", ebuf);
		exit(1);
	}
	if (verbose > 1) {
		printf("arping: pcap_get_selectable_fd(): %d\n",
		       pcap_get_selectable_fd(pcap));
	}

#ifdef BIOCIMMEDIATE
	{
                // This may be redundant if pcap_set_immediate_mode() is present.
		uint32_t on = 1;
		if (0 != (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE,
			       &on))) {
			fprintf(stderr, "arping: ioctl(fd,BIOCIMMEDIATE, 1) "
				"failed, continuing anyway, YMMV: %s\n",
				strerror(errno));
		}
	}
#endif

        if (vlan_tag >= 0 && bug_pcap_vlan() && verbose) {
                fprintf(stderr,
                        "arping: Working around bug in libpcap 1.7-1.9.0.\n");
        }

	if (mode == PINGIP) {
		/* FIXME: better filter with addresses? */
                if (vlan_tag >= 0 && !bug_pcap_vlan()) {
                        xsnprintf(bpf_filter, sizeof(bpf_filter),
                                 "vlan %"PRId16" and arp", vlan_tag);
                } else {
                        xsnprintf(bpf_filter, sizeof(bpf_filter), "arp");
                }
                if (-1 == pcap_compile(pcap, &bp, bpf_filter, 0,
                                       PCAP_NETMASK_UNKNOWN)) {
                        fprintf(stderr, "arping: pcap_compile(%s): %s\n",
                                bpf_filter, pcap_geterr(pcap));
			exit(1);
		}
	} else { /* ping mac */
		/* FIXME: better filter with addresses? */
                if (vlan_tag >= 0 && !bug_pcap_vlan()) {
                        xsnprintf(bpf_filter, sizeof(bpf_filter),
                                 "vlan %"PRId16" and icmp", vlan_tag);
                } else {
                        xsnprintf(bpf_filter, sizeof(bpf_filter), "icmp");
                }
                if (-1 == pcap_compile(pcap, &bp, bpf_filter, 0,
                                       PCAP_NETMASK_UNKNOWN)) {
                        fprintf(stderr, "arping: pcap_compile(%s): %s\n",
                                bpf_filter, pcap_geterr(pcap));
			exit(1);
		}
	}
	if (-1 == pcap_setfilter(pcap, &bp)) {
                fprintf(stderr, "arping: pcap_setfilter(): %s\n",
                        pcap_geterr(pcap));
		exit(1);
	}

	/*
	 * final init
	 */
        if (srcmac_opt == NULL) {
		if (!(cp = (char*)libnet_get_hwaddr(libnet))) {
			fprintf(stderr, "arping: libnet_get_hwaddr(): %s\n",
				libnet_geterror(libnet));
			exit(1);
		}
		memcpy(srcmac, cp, ETH_ALEN);
	}
        if (srcip_opt == NULL) {
		if (ip_broadcast_num == (srcip = libnet_get_ipaddr4(libnet))) {
			fprintf(stderr,
                                "arping: Unable to get the IPv4 address of "
                                "interface %s:\narping: %s"
                                "arping: "
                                "Use -S to specify address manually.\n",
                                ifname, libnet_geterror(libnet));
			exit(1);
		}
	}
        do_signal_init();

	if (verbose) {
                char buf[128];
		printf("This box:   Interface: %s  IP: %s   MAC address: %s\n",
		       ifname,
                       libnet_addr2name4(libnet_get_ipaddr4(libnet), 0),
                       format_mac(srcmac, buf, sizeof(buf)));
	}

        drop_more_privileges(libnet_getfd(libnet));

	if (display == NORMAL) {
		printf("ARPING %s\n", parm);
	}

	/*
	 * let's roll
	 */
        if (deadline > 0) {
                struct timespec ts;
                getclock(&ts);
                deadline += timespec2dbl(&ts);
        }
	if (mode == PINGIP) {
		int c;
		for (c = 0; (maxcount < 0 || c < maxcount); c++) {
                        if (time_to_die) {
                                break;
                        }
                        if (c == INT_MAX) {
                                --c;
                        }
			pingip_send();
                        if (max_replies != UINT_MAX && numrecvd >= max_replies) {
                                break;
                        }
                        const uint32_t w = wait_time(deadline, packetwait);
                        ping_recv(pcap, w, (pcap_handler)pingip_recv);
		}
	} else { /* PINGMAC */
		int c;
		for (c = 0; (maxcount < 0 || c < maxcount); c++) {
                        if (time_to_die) {
                                break;
                        }
                        if (c == INT_MAX) {
                                --c;
                        }
                        pingmac_send(xrandom16(),
                                     cast_int_uint16(c & 0xffff, NULL));
                        if (max_replies != UINT_MAX && numrecvd >= max_replies) {
                                break;
                        }
                        const uint32_t w = wait_time(deadline, packetwait);
                        ping_recv(pcap, w,  (pcap_handler)pingmac_recv);
		}
	}
        if (display == DOT) {
                double succ = 0.0;
                if (numsent > 0) {
                        succ = 100.0 - 100.0 * (double)(numrecvd)/(double)numsent;
                }
                printf("\t%3.0f%% packet loss (%u extra)\n",
                       (succ < 0.0) ? 0.0 : succ,
                       (succ < 0.0) ? (numrecvd - numsent) : 0);
        } else if (display == NORMAL) {
                double succ = 0.0;
                if (numsent > 0) {
                        succ = 100.0 - 100.0 * (double)(numrecvd)/(double)numsent;
                }
                printf("\n--- %s statistics ---\n"
                       "%u packets transmitted, "
                       "%u packets received, "
                       "%3.0f%% "
                       "unanswered (%u extra)\n",
                       target,numsent,numrecvd,
                       (succ < 0.0) ? 0.0 : succ,
                       (succ < 0.0) ? (numrecvd - numsent): 0);
                if (numrecvd) {
                        double avg = stats_total_time / numrecvd;
                        double stddev2 = stats_total_sq_time/numrecvd-avg*avg;
                        if (stddev2 < 0.0) {
                                // Due to floating point precision, this could be negative.
                                stddev2 = 0.0;
                        }

                        printf("rtt min/avg/max/std-dev = "
                               "%.3f/%.3f/%.3f/%.3f ms",
                               1000*stats_min_time,
                               1000*avg,
                               1000*stats_max_time,
                               1000*sqrt(stddev2));
                }
                printf("\n");
	}

        if (fflush(stdout)) {
                fprintf(stderr, "arping: Failed to write to stdout: %s\n",
                        strerror(errno));
                return EXIT_FAILURE;
        }

        if (ferror(stdout)) {
                fprintf(stderr, "arping: Write failure to stdout: %s\n",
                        strerror(errno));
                return EXIT_FAILURE;
        }

        if (fflush(stderr)) {
                // Likely this will go nowhere. But we can't write to
                // stdout in case it's being machine parsed.
                //
                // At least it should show up in strace.
                fprintf(stderr, "arping: Failed to write to stderr: %s\n",
                        strerror(errno));
                return EXIT_FAILURE;
        }

        if (ferror(stderr)) {
                // Same here. Likely will go nowhere.
                fprintf(stderr, "arping: Write failure to stderr: %s\n",
                        strerror(errno));
                return EXIT_FAILURE;
        }

        // We could close stdout/stdin too, but that'll interfere with
        // unit testing.

        if (finddup) {
                return dupfound;
        }
        if (libnet_write_failures > 0) {
                return EXIT_FAILURE;
        }
        if ((numrecvd > 0) || send_reply) {
                return EXIT_SUCCESS;
        }
        return EXIT_FAILURE;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vim: ts=8 sw=8
 */
