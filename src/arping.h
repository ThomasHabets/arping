#if HAVE_STDINT_H
#include <stdint.h>
#endif

extern uint32_t srcip,dstip;
void do_libnet_init(const char *ifname);
const char *arping_lookupdev_default(const char *ifname,
                                     uint32_t srcip, uint32_t dstip,
                                     char *ebuf);
