/* $Id: solaris.h 138 2000-09-15 17:22:30Z marvin $ */

#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t

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
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
};
