/* arping/openbsd.h
 *
 *  Copyright (C) 2000-2008 Thomas Habets <thomas@habets.pp.se>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
