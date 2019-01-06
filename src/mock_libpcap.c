#include<pcap.h>

#define UNUSED(x) (void)(x)

int
pcap_setfilter(pcap_t *pcap, struct bpf_program *prog)
{
        UNUSED(pcap);
        UNUSED(prog);
        return 0;
}

int
pcap_dispatch(pcap_t *pcap, int num, pcap_handler handler, u_char *packet)
{
        UNUSED(pcap);
        UNUSED(num);
        UNUSED(handler);
        UNUSED(packet);
        return 0;
}

int
pcap_compile(pcap_t *pcap, struct bpf_program *prog, const char *x, int y,
             bpf_u_int32 z)
{
        UNUSED(pcap);
        UNUSED(prog);
        UNUSED(x);
        UNUSED(y);
        UNUSED(z);
        return 0;
}

pcap_t*
pcap_open_live(const char *ifname, int a, int b, int c, char *d)
{
        UNUSED(ifname);
        UNUSED(a);
        UNUSED(b);
        UNUSED(c);
        UNUSED(d);
        return NULL;
}

int
pcap_setnonblock(pcap_t *pcap, int a, char *b)
{
        UNUSED(pcap);
        UNUSED(a);
        UNUSED(b);
        return 0;
}

int
pcap_get_selectable_fd(pcap_t *pcap)
{
        UNUSED(pcap);
        return 0;
}

char*
pcap_lookupdev(char *ifname)
{
        UNUSED(ifname);
        return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
