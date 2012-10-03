#include<pcap.h>
#include<inttypes.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<inttypes.h>
#include<libnet.h>

#include<check.h>

#include"arping.h"

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
        pthread_t thread;  // Reader thread.
};

/**
 * Helper function for stdout/stderr catching.
 *
 * This is the main() for the thread that reads from the fake stdout pipe
 * and writes into the buffer.
 *
 * FIXME: Has no buffer size checking.
 */
static void*
read_main(void* p)
{
        struct captured_output* out = p;
        char *cur = out->buffer;

        while (1) {
                ssize_t n;
                n = read(out->reader_fd, cur, 1024);
                if (n > 0) {
                        cur += n;
                }
                if (n == 0) {
                        break;
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
        out->buffer = calloc(100, 1024);

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
/**
 * Test that test packet is build properly.
 */
START_TEST(test_mkpacket)
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

/**
 * Test that a bogus packet is ignored.
 */
START_TEST(pingip_uninteresting_packet)
{
        struct pcap_pkthdr pkthdr;
        uint8_t *packet;
        int prev_numrecvd = numrecvd;
        struct libnet_arp_hdr* harp;
        struct captured_output *sout;

        // Completely broken packet.
        packet = calloc(1, 1500);
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
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

        // Wrong length of hardware address.
        packet = mkpacket(&pkthdr);
        ((struct libnet_arp_hdr*)((char*)packet + LIBNET_ETH_H))->ar_hln = 4;
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
        free(packet);

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

/**
 * Test that a matching packet is successfully handled.
 */
START_TEST(pingip_interesting_packet)
{
        struct pcap_pkthdr pkthdr;
        int prev_numrecvd = numrecvd;

        dstip = htonl(0x12345678);

        uint8_t* packet = mkpacket(&pkthdr);

        struct captured_output *sout;

        // First ping.
        const char* correct0 =
                "60 bytes from 77:88:99:aa:bb:cc (18.52.86.120): "
                "index=0 time=";
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(numrecvd == prev_numrecvd + 1,
                    "numrecvd not incremented");
        fail_unless(!strncmp(sout->buffer, correct0, strlen(correct0)),
                    sout->buffer);
        uncapture(sout);

        // Second ping.
        const char* correct1 =
                "60 bytes from 77:88:99:aa:bb:cc (18.52.86.120): "
                "index=1 time=";
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(numrecvd == prev_numrecvd + 2,
                    "numrecvd not incremented second time");
        fail_unless(!strncmp(sout->buffer, correct1, strlen(correct1)));
        uncapture(sout);

        free(packet);
} END_TEST

/**
 * Test that -A functionality works.
 */
START_TEST(pingip_flag_A)
{
        struct pcap_pkthdr pkthdr;
        int prev_numrecvd = numrecvd;
        addr_must_be_same = 1;

        dstip = htonl(0x12345678);

        uint8_t* packet = mkpacket(&pkthdr);

        struct captured_output *sout;

        // Wrong MAC.
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(numrecvd == prev_numrecvd,
                    "numrecvd changed");
        fail_unless(!strcmp(sout->buffer, ""),
                    sout->buffer);
        uncapture(sout);

        // Right MAC.
        const char* correct =
                "60 bytes from 77:88:99:aa:bb:cc (18.52.86.120): "
                "index=0 time=";
        memcpy(dstmac, packet + LIBNET_ETH_H + LIBNET_ARP_H, 6);
        sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(numrecvd == prev_numrecvd + 1,
                    "numrecvd not incremented");
        fail_unless(!strncmp(sout->buffer, correct, strlen(correct)),
                    sout->buffer);
        uncapture(sout);

        free(packet);
} END_TEST

/**
 * Set up test suite.
 */
static Suite *
arping_suite (void)
{
        Suite *s = suite_create ("Arping");

        /* Core test case */
        TCase *tc_core = tcase_create ("Receiving");
        //tcase_add_checked_fixture (tc_core, setup, teardown);
        tcase_add_test(tc_core, test_mkpacket);
        tcase_add_test(tc_core, pingip_uninteresting_packet);
        tcase_add_test(tc_core, pingip_interesting_packet);
        tcase_add_test(tc_core, pingip_flag_A);
        suite_add_tcase(s, tc_core);
        return s;
}

/**
 *
 */
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
