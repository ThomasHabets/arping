/* arping/src/arping_test.c
 *
 *  Copyright (C) 2015 Thomas Habets <thomas@habets.se>
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
#include<inttypes.h>
#include<stdlib.h>

#include<check.h>
#include<pcap.h>

#include"arping.h"

static int numtests = 0;
static void* test_registry[1024];

#define MYTEST(a) static void a(int);__attribute__((constructor)) static void cons_##a() { test_registry[numtests++] = a;} START_TEST(a)

// Received uninteresting packet, should not record anything.
MYTEST(pingip_uninteresting_packet)
{
        struct pcap_pkthdr pkthdr;
        uint8_t packet[128];

        int prev_numrecvd = numrecvd;

        pingip_recv(NULL, &pkthdr, packet);

        fail_unless(prev_numrecvd == numrecvd);
} END_TEST

// Received reply that actually matches. Things should happen.
MYTEST(pingip_interesting_packet)
{
        struct pcap_pkthdr pkthdr;
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
        int prev_numrecvd = numrecvd;

        dstip = htonl(0x12345678);

        pingip_recv(NULL, &pkthdr, packet);
        fail_unless(numrecvd == prev_numrecvd + 1,
                    "numrecvd not incremented");

        pingip_recv(NULL, &pkthdr, packet);
        fail_unless(numrecvd == prev_numrecvd + 2,
                    "numrecvd not incremented second time");
} END_TEST

static Suite*
arping_suite(void)
{
        int c;
        Suite* s = suite_create("Arping");

        /* Core test case */
        //tcase_add_checked_fixture (tc_core, setup, teardown);
        TCase *tc_core = tcase_create("Receiving");
        for (c = 0; c < numtests; c++) {
                tcase_add_test(tc_core, test_registry[c]);
        }
        suite_add_tcase(s, tc_core);
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
