/* arping/src/arping.h */

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

extern uint32_t srcip,dstip;
extern int verbose;
void do_libnet_init(const char *ifname);
const char *arping_lookupdev_default(const char *ifname,
                                     uint32_t srcip, uint32_t dstip,
                                     char *ebuf);
