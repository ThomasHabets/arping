#include<pcap.h>

int
pcap_setfilter(pcap_t *pcap, struct bpf_program *prog)
{
}

int
pcap_dispatch(pcap_t *pcap, int num, pcap_handler handler, u_char *packet)
{
}

int
pcap_compile(pcap_t *pcap, struct bpf_program *prog, const char *x, int y,
             bpf_u_int32 z)
{
}

pcap_t*
pcap_open_live(const char *ifname, int a, int b, int c, char *d)
{
}

int
pcap_setnonblock(pcap_t *pcap, int a, char *b)
{
}

int
pcap_get_selectable_fd(pcap_t *pcap)
{
}

char*
pcap_lookupdev(char *ifname)
{
}
