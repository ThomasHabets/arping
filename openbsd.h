#define __u8 u_int8_t
#define __u16 u_int16_t
#define __u32 u_int32_t

struct ethhdr 
{
  __u8 h_dest[ETH_ALEN];/* destination eth addr*/
  __u8 h_source[ETH_ALEN];/* source ether addr*/
  __u16 h_proto;/* packet type ID field*/
};

struct icmphdr {
  __u8 type;
  __u8 code;
  __u16 checksum;
  union {
    struct {
      __u16 id;
      __u16 sequence;
    } echo;
    __u32 gateway;
    struct {
      __u16 __unused;
      __u16 mtu;
    } frag;
  } un;
};

struct iphdr
{
#ifdef LIBNET_LIL_ENDIAN 
  unsigned int ihl:4;
  unsigned int version:4;
#else
  unsigned int version:4;
  unsigned int ihl:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
  /*The options start here. */
};


