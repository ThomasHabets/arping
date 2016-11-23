#include<errno.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<inttypes.h>

#include<pcap.h>

#include"arping.h"

int
main()
{
        const size_t maxpacket = 1500;
        char* const packet = calloc(1, maxpacket);
        size_t packet_size = 0;

        // Read packet.
        {
                char* p = packet;
                size_t size = maxpacket;
                while (size > 0) {
                        const ssize_t n = read(STDIN_FILENO, p, size);
                        if (n == 0) {
                                break;
                        }
                        if (n < 0) {
                                fprintf(stderr, "read(): %s\n", strerror(errno));
                                return 1;
                        }
                        size -= n;
                        p += n;
                }
                packet_size = p - packet;
        }

        struct pcap_pkthdr pkthdr;
        pkthdr.ts.tv_sec = time(NULL);
        pkthdr.ts.tv_usec = 0;
        pkthdr.len = packet_size;
        pkthdr.caplen = packet_size;

        verbose = 9;
        dstip = htonl(0x12345678);
        pingip_recv(NULL, &pkthdr, packet);

        free(packet);
        return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
