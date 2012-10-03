#include<pcap.h>
#include<inttypes.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>

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

/**
 * Test that a bogus packet is ignored.
 */
START_TEST(uninteresting_packet)
{
        struct pcap_pkthdr pkthdr;
        uint8_t packet[128];

        int prev_numrecvd = numrecvd;

        struct captured_output *sout = capture(1);
        pingip_recv(NULL, &pkthdr, packet);
        stop_capture(sout);
        fail_unless(prev_numrecvd == numrecvd);
        fail_unless(strlen(sout->buffer) == 0);
        uncapture(sout);
} END_TEST

/**
 * Test that a matching packet is successfully handled.
 */
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
        fail_unless(numrecvd == prev_numrecvd + 1,
                    "numrecvd not incremented");
        fail_unless(!strncmp(sout->buffer, correct0, strlen(correct0)));
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
        tcase_add_test (tc_core, interesting_packet);
        tcase_add_test (tc_core, uninteresting_packet);
        suite_add_tcase (s, tc_core);
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
