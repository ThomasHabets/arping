/* arping/src/fuzz_pingip.c
 *
 *  Copyright (C) 2016 Thomas Habets <thomas@habets.se>
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
#include<arpa/inet.h>
#include<errno.h>
#include<inttypes.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<unistd.h>

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
