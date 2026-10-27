/* Fault injection for the Linux network integration tests. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <libnet.h>
#include <pcap.h>

static int build_failed;
static int clock_failed;

static int
fail_build(const char *name, libnet_t *l)
{
        const char *fault = getenv("ARPING_TEST_FAIL");
        if (!fault || strcmp(fault, name)) {
                return 0;
        }
        static unsigned int calls;
        const char *after = getenv("ARPING_TEST_FAIL_AFTER");
        if (calls++ < (after ? strtoul(after, NULL, 10) : 0)) {
                return 0;
        }
        snprintf(l->err_buf, sizeof(l->err_buf), "injected %s failure", name);
        build_failed = 1;
        return 1;
}

#define BUILD(name, args) \
        if (fail_build(#name, l)) return -1; \
        __typeof__(&name) original = dlsym(RTLD_NEXT, #name); \
        if (!original) abort(); \
        return original args

libnet_ptag_t
libnet_build_arp(uint16_t hrd, uint16_t pro, uint8_t hln, uint8_t pln,
                 uint16_t op, const uint8_t *sha, const uint8_t *spa,
                 const uint8_t *tha, const uint8_t *tpa, const uint8_t *payload,
                 uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
        BUILD(libnet_build_arp, (hrd, pro, hln, pln, op, sha, spa, tha, tpa,
                                 payload, payload_s, l, ptag));
}

libnet_ptag_t
libnet_build_icmpv4_echo(uint8_t type, uint8_t code, uint16_t sum,
                        uint16_t id, uint16_t seq, const uint8_t *payload,
                        uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
        BUILD(libnet_build_icmpv4_echo, (type, code, sum, id, seq, payload,
                                         payload_s, l, ptag));
}

libnet_ptag_t
libnet_build_ipv4(uint16_t len, uint8_t tos, uint16_t id, uint16_t frag,
                  uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src,
                  uint32_t dst, const uint8_t *payload, uint32_t payload_s,
                  libnet_t *l, libnet_ptag_t ptag)
{
        BUILD(libnet_build_ipv4, (len, tos, id, frag, ttl, prot, sum, src, dst,
                                  payload, payload_s, l, ptag));
}

libnet_ptag_t
libnet_build_ethernet(const uint8_t *dst, const uint8_t *src, uint16_t type,
                      const uint8_t *payload, uint32_t payload_s, libnet_t *l,
                      libnet_ptag_t ptag)
{
        BUILD(libnet_build_ethernet, (dst, src, type, payload, payload_s, l, ptag));
}

libnet_ptag_t
libnet_build_802_1q(const uint8_t *dst, const uint8_t *src, uint16_t tpi,
                   uint8_t priority, uint8_t cfi, uint16_t vlan_id,
                   uint16_t len_proto, const uint8_t *payload,
                   uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
        BUILD(libnet_build_802_1q, (dst, src, tpi, priority, cfi, vlan_id,
                                    len_proto, payload, payload_s, l, ptag));
}

int
libnet_write(libnet_t *l)
{
        if (build_failed || clock_failed) {
                fprintf(stderr, "transmission attempted after build or clock failure\n");
                _exit(99);
        }
        __typeof__(&libnet_write) original = dlsym(RTLD_NEXT, "libnet_write");
        if (!original) abort();
        return original(l);
}

static int received_reply;
static pcap_handler packet_handler;
static int clocks_armed;
static int reply_started;

static void
track_reply(unsigned char *user, const struct pcap_pkthdr *h,
             const unsigned char *packet)
{
        reply_started = h->caplen >= 42 && packet[12] == 8 && packet[13] == 6
                && packet[20] == 0 && packet[21] == 2;
        if (h->caplen >= 42 && packet[12] == 8 && packet[13] == 0
            && packet[23] == IPPROTO_ICMP) {
                const size_t icmp_offset = 14 + (size_t)(packet[14] & 15) * 4;
                reply_started = h->caplen >= icmp_offset + 8
                        && packet[icmp_offset] == ICMP_ECHOREPLY;
        }
        packet_handler(user, h, packet);
        if (reply_started) {
                received_reply = 1;
        }
}

int
pcap_setfilter(pcap_t *pcap, struct bpf_program *bp)
{
        __typeof__(&pcap_setfilter) original = dlsym(RTLD_NEXT, "pcap_setfilter");
        if (!original) abort();
        const int ret = original(pcap, bp);
        // Do not interfere with clocks used by NSS during privilege setup.
        if (ret == 0) clocks_armed = 1;
        return ret;
}

static int monotonic_failed;

int
clock_gettime(clockid_t clock, struct timespec *ts)
{
        const char *fault = getenv("ARPING_TEST_FAIL");
        if (clocks_armed && clock == CLOCK_MONOTONIC && fault) {
                static unsigned int calls;
                const char *after = getenv("ARPING_TEST_FAIL_AFTER");
                const int fail = (!strcmp(fault, "clock")
                                  && calls++ >= (after ? strtoul(after, NULL, 10) : 0))
                        || !strcmp(fault, "clock-fallback")
                        || (!strcmp(fault, "clock-on-reply") && reply_started)
                        || (!strcmp(fault, "clock-after-reply") && received_reply);
                if (fail) {
                        fprintf(stderr, "injected %s failure\n", fault);
                        monotonic_failed = 1;
                        errno = EIO;
                        return -1;
                }
        }
        __typeof__(&clock_gettime) original = dlsym(RTLD_NEXT, "clock_gettime");
        if (!original) abort();
        return original(clock, ts);
}

int
gettimeofday(struct timeval *tv, void *tz)
{
        const char *fault = getenv("ARPING_TEST_FAIL");
        if (monotonic_failed && fault && strcmp(fault, "clock-fallback")) {
                clock_failed = 1;
                errno = EIO;
                return -1;
        }
        __typeof__(&gettimeofday) original = dlsym(RTLD_NEXT, "gettimeofday");
        if (!original) abort();
        return original(tv, tz);
}

int
pcap_dispatch(pcap_t *pcap, int count, pcap_handler handler, unsigned char *user)
{
        __typeof__(&pcap_dispatch) original = dlsym(RTLD_NEXT, "pcap_dispatch");
        if (!original) abort();
        packet_handler = handler;
        const int ret = original(pcap, count, track_reply, user);
        const char *fault = getenv("ARPING_TEST_FAIL");
        if (fault && !strcmp(fault, "pcap-dispatch") && received_reply) {
                fprintf(stderr, "injected %s failure\n", fault);
                return PCAP_ERROR;
        }
        return ret;
}

int
pcap_get_selectable_fd(pcap_t *pcap)
{
        const char *fault = getenv("ARPING_TEST_FAIL");
        if (fault && (!strcmp(fault, "pcap-fd")
                      || !strcmp(fault, "pcap-fd-limit"))) {
                fprintf(stderr, "injected %s failure\n", fault);
                return !strcmp(fault, "pcap-fd") ? -1 : FD_SETSIZE;
        }
        __typeof__(&pcap_get_selectable_fd) original =
                dlsym(RTLD_NEXT, "pcap_get_selectable_fd");
        if (!original) abort();
        return original(pcap);
}

int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        struct timeval *timeout)
{
        const char *fault = getenv("ARPING_TEST_FAIL");
        static int interrupted;
        const int interrupt = fault && !strcmp(fault, "select-eintr")
                && !interrupted;
        if (fault && (!strcmp(fault, "select") || interrupt
                      || (!strcmp(fault, "select-after-reply")
                          && received_reply))) {
                fprintf(stderr, "injected %s failure\n", fault);
                interrupted = 1;
                errno = interrupt ? EINTR : EBADF;
                return -1;
        }
        __typeof__(&select) original = dlsym(RTLD_NEXT, "select");
        if (!original) abort();
        return original(nfds, readfds, writefds, exceptfds, timeout);
}
