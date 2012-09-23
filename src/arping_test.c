#include<pcap.h>
#include<inttypes.h>
#include<stdlib.h>
#include<check.h>
#include"arping.h"

START_TEST(uninteresting_packet)
{
        struct pcap_pkthdr pkthdr;
        uint8_t packet[128];

        int prev_numrecvd = numrecvd;

        pingip_recv(NULL, &pkthdr, packet);

        fail_unless(prev_numrecvd == numrecvd);
} END_TEST

START_TEST(interesting_packet)
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

static Suite *
arping_suite (void)
{
        Suite *s = suite_create ("Arping");

        /* Core test case */
        TCase *tc_core = tcase_create ("Receiving");
        //tcase_add_checked_fixture (tc_core, setup, teardown);
        tcase_add_test (tc_core, interesting_packet);
        tcase_add_test (tc_core, uninteresting_packet);
        suite_add_tcase (s, tc_core);
        return s;
}

int
main()
{
        int number_failed;
        Suite *s = arping_suite ();
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
