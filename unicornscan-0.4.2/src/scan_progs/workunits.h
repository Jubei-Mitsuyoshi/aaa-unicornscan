/**********************************************************************
 * Copyright (C) (2004) (Jack Louis) <jack@dyadsecurity.com>          *
 *                                                                    *
 * This program is free software; you can redistribute it and/or      *
 * modify it under the terms of the GNU General Public License        *
 * as published by the Free Software Foundation; either               *
 * version 2 of the License, or (at your option) any later            *
 * version.                                                           *
 *                                                                    *
 * This program is distributed in the hope that it will be useful,    *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
 * GNU General Public License for more details.                       *
 *                                                                    *
 * You should have received a copy of the GNU General Public License  *
 * along with this program; if not, write to the Free Software        *
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.          *
 **********************************************************************/
#ifndef _WORKUNITS_H
# define _WORKUNITS_H

void *get_sp_workunit(size_t *);
void *get_lp_workunit(size_t *);

#define UDP_SEND_MAGIC 0x1a1b1c1d
#define TCP_SEND_MAGIC 0x2a2b2c2d

#define UDP_RECV_MAGIC 0x3a3b3c3d
#define TCP_RECV_MAGIC 0x4a4b4c4d

#define ARP_SEND_MAGIC 0x5a5b5c5d
#define ARP_RECV_MAGIC 0x6a6b6c6d

#define PRI_SEND_MAGIC 0x7a7b7c7d

typedef struct _PACKED_ send_tcp_workunit_t {
	uint32_t magic;
	uint32_t repeats;
	uint16_t send_opts;
	uint32_t pps;
	uint8_t delay_type;
	struct sockaddr_in myaddr;
	uint16_t mtu;

	uint32_t low_ip;
	uint32_t high_ip;
	uint8_t tos;
	uint8_t ttl;
	uint16_t ip_off;
	uint16_t fingerprint;
	int32_t src_port;

	uint8_t tcphdrflgs;
	char tcpoptions[32];
	uint8_t tcpoptions_len;
	uint16_t window_size;
	uint32_t syn_key;

	uint8_t port_str_len;
} send_tcp_workunit_t;

typedef struct _PACKED_ send_udp_workunit_t {
	uint32_t magic;
	uint32_t repeats;
	uint16_t send_opts;
	uint32_t pps;
	uint8_t delay_type;
	struct sockaddr_in myaddr;
	uint16_t mtu;

	uint32_t low_ip;
	uint32_t high_ip;
	uint8_t tos;
	uint8_t ttl;
	uint16_t ip_off;
	uint16_t fingerprint;
	int32_t src_port;

	uint8_t port_str_len;
} send_udp_workunit_t;

typedef struct _PACKED_ send_arp_workunit_t {
	uint32_t magic;
	uint32_t repeats;
	uint16_t send_opts;
	uint32_t pps;
	uint8_t delay_type;
	struct sockaddr_in myaddr;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint16_t mtu;

	uint32_t low_ip;
	uint32_t high_ip;
	uint16_t fingerprint;
} send_arp_workunit_t;

typedef struct _PACKED_ recv_tcp_workunit_t {
	uint32_t magic;
	uint8_t recv_timeout;
	uint16_t mtu;
	uint16_t recv_opts;

	uint32_t syn_key;
} recv_tcp_workunit_t;

typedef struct _PACKED_ recv_udp_workunit_t {
	uint32_t magic;
	uint8_t recv_timeout;
	uint16_t mtu;
	uint16_t recv_opts;
} recv_udp_workunit_t;

typedef struct _PACKED_ recv_arp_workunit_t {
	uint32_t magic;
	uint8_t recv_timeout;
	uint16_t mtu;
	uint16_t recv_opts;
} recv_arp_workunit_t;

/* this is always relative to the currently running scan for protocol types (currently) */
typedef struct _PACKED_ send_pri_workunit_t {
	uint32_t magic;
	uint32_t dhost;
	uint16_t dport;
	uint16_t sport;
	uint32_t flags;
	uint32_t mseq;
	uint32_t tseq;
	uint16_t window_size;
} send_pri_workunit_t;

#endif
