/* arping/src/arping_test.c
 *
 *  Copyright (C) 2015-2019 Thomas Habets <thomas@habets.se>
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
#include"config.h"
#define _GNU_SOURCE
#include<assert.h>
#include<errno.h>
#include<fcntl.h>
#include<inttypes.h>
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>

#include<check.h>
#include<libnet.h>
#include<pcap.h>

#include"arping.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

extern libnet_t* libnet;
extern int mock_libnet_lo_ok;
extern int mock_libnet_null_ok;

struct registered_test {
        void* fn;
        const char* name;
};

static int numtests = 0;
static struct registered_test test_registry[1024];

static int num_exit_tests = 0;
static struct registered_test test_exit_registry[1024];

int get_mac_addr(const char *in, char *out);
void strip_newline(char* s);


#define MYTEST(a) static void a(int);__attribute__((constructor)) \
static void cons_##a() {                           \
                test_registry[numtests].fn = a;    \
                test_registry[numtests].name = #a; \
                numtests++;                        \
} START_TEST(a)

#define MY_EXIT_TEST(a) static void a(int);__attribute__((constructor)) \
static void cons_##a() {                                      \
                test_exit_registry[num_exit_tests].fn = a;    \
                test_exit_registry[num_exit_tests].name = #a; \
                num_exit_tests++;                             \
} START_TEST(a)

/**
 *
 */
static void
xclose(int* fd)
{
        if (0 > close(*fd)) {
                fprintf(stderr, "close(%d): %s", *fd, strerror(errno));
                *fd = -1;
        }
}

struct captured_output {
        int saved_fd;  // Old fd, will be dup2()ed back in place when done.
        int fno;       // Overridden fd (e.g. stdout or stderr).
        int reader_fd; // Reader end of the pipe.
        char* buffer;  // Output buffer.
        size_t bufsize; // Buffer size.
        pthread_t thread;  // Reader thread.
};

/**
 * Helper function for stdout/stderr catching.
 *
 * This is the main() for the thread that reads from the fake stdout pipe
 * and writes into the buffer.
 *
 */
static void*
read_main(void* p)
{
        struct captured_output* out = p;
        char *cur = out->buffer;

        for (;;) {
                ssize_t n;
                n = out->bufsize - (cur - out->buffer);
                assert(n > 0);
                n = read(out->reader_fd, cur, n);
                if (n > 0) {
                        cur += n;
                }
                if (n == 0) {
                        return NULL;
                }
        }
}

/**
 * Helper function to capture stdout/stderr output.
 *
 * Args:
 *   fd:  The fd to capture.
 * Returns:
 *   A structure to be used as a handle. Only thing caller should do with
 *   this structure is call stop_capture(), read its .buffer member, and
 *   uncapture().
 */
static struct captured_output*
capture(int fd)
{
        struct captured_output* out;

        out = calloc(1, sizeof(struct captured_output));
        fail_if(out == NULL);

        out->fno = fd;
        out->saved_fd = dup(fd);
        out->bufsize = 1024*100;
        out->buffer = calloc(1, out->bufsize);

        fail_if(0 > out->saved_fd);
        fail_if(out->buffer == NULL);

        // set up pipe
        int fds[2];
        fail_if(0 > pipe(fds));
        fail_if(0 > dup2(fds[1], fd));
        out->reader_fd = fds[0];
        xclose(&fds[1]);

        fail_if(pthread_create(&out->thread, NULL, read_main, (void*)out));
        return out;
}

/**
 * Helper function to capture stdout/stderr output.
 *
 * Stop capture, so that .buffer becomes readable.
 */
static void
stop_capture(struct captured_output* out)
{
        fail_if(0 > dup2(out->saved_fd, out->fno));
        xclose(&out->saved_fd);
        fail_if(pthread_join(out->thread, NULL));
        xclose(&out->reader_fd);
}

/**
 * Helper function to capture stdout/stderr output.
 *
 * Deallocate buffer. stop_capture() must be called before uncapture().
 */
static void
uncapture(struct captured_output* out)
{
        free(out->buffer);
        out->buffer = NULL;
        free(out);
}

static uint8_t*
mkpacket(struct pcap_pkthdr* pkthdr)
{
        uint8_t* packet = calloc(1, 1500);
        fail_if(packet == NULL);

        struct libnet_802_3_hdr* heth;
        struct libnet_arp_hdr* harp;

        // Set up ethernet header
        heth = (void*)packet;
        memcpy(heth->_802_3_dhost, "\x11\x22\x33\x44\x55\x66", 6);
        memcpy(heth->_802_3_shost, "\x77\x88\x99\xaa\xbb\xcc", 6);
        heth->_802_3_len = 0;  // FIXME: is this correct?

        // Set up ARP header.
        harp = (void*)((char*)heth + LIBNET_ETH_H);
        harp->ar_hln = 6;
        harp->ar_pln = 4;
        harp->ar_hrd = htons(ARPHRD_ETHER);
        harp->ar_op = htons(ARPOP_REPLY);
        harp->ar_pro = htons(ETHERTYPE_IP);

        memcpy((char*)harp + LIBNET_ARP_H, heth->_802_3_shost, 6);
        memcpy((char*)harp + LIBNET_ARP_H + harp->ar_hln, &dstip, 4);

        memcpy((char*)harp + LIBNET_ARP_H
               + harp->ar_hln
               + harp->ar_pln, heth->_802_3_dhost, 6);
        memcpy((char*)harp + LIBNET_ARP_H
               + harp->ar_hln
               + harp->ar_pln
               + harp->ar_hln, &srcip, 4);

        pkthdr->ts.tv_sec = time(NULL);
        pkthdr->ts.tv_usec = 0;
        pkthdr->len = 60;
        pkthdr->caplen = 60;

        return packet;
}

static void
dump_packet(uint8_t* packet, int len)
{
        int c;
        for (c = 0; c < len; c++) {
                fprintf(stderr, "0x%.2x, ", (int)packet[c]);
                if (!((c+1) % 10)) {
                        fprintf(stderr, "\n");
                }
        }
        fprintf(stderr, "\n");
}

MYTEST(test_mkpacket)
{
        uint8_t correct_packet[] = {
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                0xbb, 0xcc, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
                0x00, 0x02, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x12, 0x34,
                0x56, 0x78, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x87, 0x65,
                0x43, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        struct pcap_pkthdr pkthdr;
        dstip = htonl(0x12345678);
        srcip = htonl(0x87654321);

        uint8_t* packet = mkpacket(&pkthdr);
        fail_if(packet == NULL);
        fail_unless(pkthdr.caplen == 60);
        if (memcmp(packet, correct_packet, pkthdr.caplen)) {
                dump_packet(packet, pkthdr.caplen);
        }
        fail_unless(!memcmp(packet, correct_packet, pkthdr.caplen));
} END_TEST


// Received uninteresting packet, should not record anything.
MYTEST(pingip_uninteresting_packet)
{
        struct pcap_pkthdr pkthdr;
        uint8_t* packet;
        struct libnet_802_3_hdr* heth;
        struct libnet_arp_hdr* harp;

        int prev_numrecvd = numrecvd;
        struct captured_output* sout;

        // Completely broken packet.
        packet = calloc(1, 1500);
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(strlen(sout->buffer) == 0);
        fail_unless(prev_numrecvd == numrecvd);
        uncapture(sout);
        free(packet);

        // Not ETHERTYPE_IP.
        packet = mkpacket(&pkthdr);
        harp = (void*)((char*)packet + LIBNET_ETH_H);
        harp->ar_pro = 0;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);

        // Not ARPHRD_ETHER
        packet = mkpacket(&pkthdr);
        harp = (void*)((char*)packet + LIBNET_ETH_H);
        harp->ar_hrd = 0;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);

        // Wrong dstip
        if (0) {
                uint32_t wrongip = 123;
                packet = mkpacket(&pkthdr);
                harp = (void*)((char*)packet + LIBNET_ETH_H);
                memcpy((char*)harp + harp->ar_hln + LIBNET_ARP_H, &wrongip, 4);
                sout = capture(1);
                pingip_recv(NULL, &pkthdr, packet);
                stop_capture(sout);
                fail_unless(prev_numrecvd == numrecvd);
                fail_unless(strlen(sout->buffer) == 0);
                uncapture(sout);
                free(packet);
        }

        // Short packet.
        packet = mkpacket(&pkthdr);
        pkthdr.caplen = pkthdr.len = 41;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);

        // Short captured packet.
        packet = mkpacket(&pkthdr);
        pkthdr.caplen = 41;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);

        // Wrong length of hardware address.
        {
                uint8_t packet[] = {
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // dst
                        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, // src
                        0x00, 0x00, // type
                        0x00, 0x01, // hardware
                        0x08, 0x00, // protocol
                        0x04, 0x04, // lengths (for this test length is wrong)
                        0x00, 0x02, // operator

                        0x77, 0x88, 0x99, 0xaa, // sender (wrong length for test)
                        0x12, 0x34, 0x56, 0x78, // sender protocol address

                        0x11, 0x22, 0x33, 0x44, // receiver (wrong length for test)
                        0x87, 0x65, 0x43, 0x21, // receiver protocol address

                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x6f, 0xa8, 0x58, 0x63,
        };
                pkthdr.len = 60;
                pkthdr.caplen = 60;
                sout = capture(1);
                pingip_recv(NULL, &pkthdr, packet);
                stop_capture(sout);
                fail_unless(strlen(sout->buffer) == 0, sout->buffer);
                fail_unless(prev_numrecvd == numrecvd);
                uncapture(sout);
        }

        // Wrong length of protocol address.
        packet = mkpacket(&pkthdr);
        ((struct libnet_arp_hdr*)((char*)packet + LIBNET_ETH_H))->ar_pln = 6;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);
} END_TEST

// Received reply that actually matches. Things should happen.
MYTEST(pingip_interesting_packet)
{
        struct pcap_pkthdr pkthdr;
        extern uint8_t srcmac[ETH_ALEN];
        memcpy(srcmac, "\x11\x22\x33\x44\x55\x66", ETH_ALEN);
        uint8_t packet[] = {
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // dst
                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, // src
                0x00, 0x00, // type
                0x00, 0x01, // hardware
                0x08, 0x00, // protocol
                0x06, 0x04, // lengths
                0x00, 0x02, // operator

                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, // sender
                0x12, 0x34, 0x56, 0x78, // sender protocol address

                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // receiver
                0x87, 0x65, 0x43, 0x21, // receiver protocol address

                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x6f, 0xa8, 0x58, 0x63,
        };
        numrecvd = 0;
        int prev_numrecvd = numrecvd;

        dstip = htonl(0x12345678);

        pkthdr.ts.tv_sec = time(NULL);
        pkthdr.ts.tv_usec = 0;
        pkthdr.len = 60;
        pkthdr.caplen = 60;

        struct captured_output *sout;

        // First ping.
        const char* correct0 =
                        "60 bytes from 77:88:99:aa:bb:cc (18.52.86.120): "
                        "index=0 time=";
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);

        char* emsg = NULL;
        fail_unless(0 < asprintf(&emsg, "Captured: <%s> (%zd), want   <%s> %zd\n",
                         sout->buffer, strlen(sout->buffer),
                                 correct0, strlen(correct0)));
        fail_unless(!strncmp(sout->buffer, correct0, strlen(correct0)), emsg);
        uncapture(sout);
        free(emsg);

        fail_unless(numrecvd == prev_numrecvd + 1,
                    "numrecvd not incremented");

        pingip_recv(NULL, &pkthdr, packet);
        fail_unless(numrecvd == prev_numrecvd + 2,
                    "numrecvd not incremented second time");
} END_TEST

MYTEST(strip_newline_test)
{
        const char *tests[][2] = {
                {"", ""},
                {"\n", ""},
                {"\n\n\n", ""},
                {"foo", "foo"},
                {"foo\n", "foo"},
                {"foo\n\n\n", "foo"},
                {NULL, NULL},
        };
        int c;
        for (c = 0; tests[c][0]; c++){
                char buf[128];
                strcpy(buf, tests[c][0]);
                strip_newline(buf);
                fail_unless(!strcmp(buf, tests[c][1]));
        }
} END_TEST

MYTEST(get_mac_addr_success)
{
        const char *tests[][2] = {
                // Null.
                {"0000.0000.0000", "\x00\x00\x00\x00\x00\x00"},
                {"00:00:00:00:00:00", "\x00\x00\x00\x00\x00\x00"},
                {"00-00-00-00-00-00", "\x00\x00\x00\x00\x00\x00"},

                // Broadcast.
                {"FFFF.FFFF.FFFF", "\xFF\xFF\xFF\xFF\xFF\xFF"},
                {"FF:FF:FF:FF:FF:FF", "\xFF\xFF\xFF\xFF\xFF\xFF"},
                {"FF-FF-FF-FF-FF-FF", "\xFF\xFF\xFF\xFF\xFF\xFF"},

                // Normal looking.
                {"1122.3344.5566", "\x11\x22\x33\x44\x55\x66"},
                {"11:22:33:44:55:66", "\x11\x22\x33\x44\x55\x66"},
                {"11-22-33-44-55-66", "\x11\x22\x33\x44\x55\x66"},

                // Has some zeroes.
                {"1100.0000.5566", "\x11\x00\x00\x00\x55\x66"},
                {"11:00:00:00:55:66", "\x11\x00\x00\x00\x55\x66"},
                {"11-00-00-00-55-66", "\x11\x00\x00\x00\x55\x66"},
                {NULL, NULL},
        };
        int c;
        for (c = 0; tests[c][0]; c++){
                char buf[6];
                fail_unless(get_mac_addr(tests[c][0], buf));
                fail_unless(!memcmp(buf, tests[c][1], 6));
        }
} END_TEST

MYTEST(get_mac_addr_fail)
{
        const char *tests[] = {
                "",
                "blaha",
                "11:22:33:44:55",
                "11:22:33:44:55:zz",
                NULL,
        };
        int c;
        for (c = 0; tests[c]; c++){
                char buf[6];
                fail_if(get_mac_addr(tests[c], buf));
        }
} END_TEST

MY_EXIT_TEST(libnet_init_bad_nolo)
{
        // It'll only try lo if named interface fails.
        // So by accepting lo, we make sure it doesn't try lo.
        mock_libnet_lo_ok = 1;
        do_libnet_init("bad", 0);
} END_TEST

MY_EXIT_TEST(libnet_init_null_nolo_nonull)
{
        mock_libnet_lo_ok = 0;
        mock_libnet_null_ok = 0;
        do_libnet_init(NULL, 0);
} END_TEST

MYTEST(libnet_init_good)
{
        mock_libnet_lo_ok = 0; // Don't even try falling back to lo.
        do_libnet_init("good", 0);
        fail_if(libnet == NULL);
} END_TEST

MYTEST(libnet_init_null_nolo)
{
        mock_libnet_lo_ok = 0;
        mock_libnet_null_ok = 1;
        do_libnet_init(NULL, 0);
        fail_if(libnet == NULL);
} END_TEST

static Suite*
arping_suite(void)
{
        int c;
        Suite* s = suite_create("Arping");

        //tcase_add_checked_fixture (tc_core, setup, teardown);
        for (c = 0; c < numtests; c++) {
                TCase *tc_core = tcase_create(test_registry[c].name);
                tcase_add_test(tc_core, test_registry[c].fn);
                suite_add_tcase(s, tc_core);
        }
        for (c = 0; c < num_exit_tests; c++) {
                TCase *tc_core = tcase_create(test_exit_registry[c].name);
                tcase_add_exit_test(tc_core, test_exit_registry[c].fn, 1);
                suite_add_tcase(s, tc_core);
        }
        return s;
}

int
main()
{
        int number_failed;
        Suite *s = arping_suite();
        SRunner *sr = srunner_create (s);
        srunner_run_all (sr, CK_NORMAL);
        number_failed = srunner_ntests_failed (sr);
        srunner_free (sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
