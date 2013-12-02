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
#include <config.h>

#include <scanopts.h>
#include <settings.h>
#include <scan_export.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/arch.h>

#include <workunits.h>

static int workunits_sent=0;
/* static int est_sent=0; */

/*
 * XXX alot to merge here for correct cluster balancing, this is incomplete currently,
 * but for this release, it works enough to do simple things
 */

void *get_sp_workunit(size_t *wk_len) {
	union {
		send_tcp_workunit_t *t;
		send_udp_workunit_t *u;
		send_arp_workunit_t *a;
		void *ptr;
		uint8_t *step;
	} w_u;
	uint32_t hosts=0;

	if (GET_LISTENDRONE()) {
		return NULL;
	}

	hosts=(s->_high_ip - s->_low_ip) + 1;

	if (workunits_sent == 0) {
		/* XXX removed */
		switch (s->ss->mode) {

			case MODE_TCPSCAN:
				w_u.ptr=xmalloc(sizeof(send_tcp_workunit_t) + strlen(s->port_str));
				w_u.t->magic=TCP_SEND_MAGIC;

				w_u.t->repeats=s->repeats;
				w_u.t->send_opts=s->send_opts;
				w_u.t->pps=s->pps;
				w_u.t->delay_type=s->delay_type;
				w_u.t->myaddr.sin_addr.s_addr=s->vi->myaddr.sin_addr.s_addr;
				w_u.t->mtu=s->vi->mtu;

				w_u.t->low_ip=s->_low_ip;
				w_u.t->high_ip=s->_high_ip;
				w_u.t->tos=s->ss->tos;
				w_u.t->ttl=s->ss->ttl;
				w_u.t->ip_off=s->ss->ip_off;
				w_u.t->fingerprint=s->ss->fingerprint;
				w_u.t->src_port=s->ss->src_port;

				w_u.t->tcphdrflgs=s->ss->tcphdrflgs;
				memcpy(w_u.t->tcpoptions, s->ss->tcpoptions, sizeof(w_u.t->tcpoptions));
				w_u.t->tcpoptions_len=s->ss->tcpoptions_len;
				w_u.t->window_size=s->ss->window_size;
				w_u.t->syn_key=s->ss->syn_key;

				w_u.t->port_str_len=strlen(s->port_str);
				memcpy(w_u.step + sizeof(send_tcp_workunit_t), s->port_str, strlen(s->port_str));

				*wk_len=sizeof(send_tcp_workunit_t) + strlen(s->port_str);
				break;

			case MODE_UDPSCAN:
				w_u.ptr=xmalloc(sizeof(send_udp_workunit_t) + strlen(s->port_str));
				w_u.u->magic=UDP_SEND_MAGIC;

				w_u.u->repeats=s->repeats;
				w_u.u->send_opts=s->send_opts;
				w_u.u->pps=s->pps;
				w_u.u->delay_type=s->delay_type;
				w_u.u->myaddr.sin_addr.s_addr=s->vi->myaddr.sin_addr.s_addr;
				w_u.u->mtu=s->vi->mtu;

				w_u.u->low_ip=s->_low_ip;
				w_u.u->high_ip=s->_high_ip;
				w_u.u->tos=s->ss->tos;
				w_u.u->ttl=s->ss->ttl;
				w_u.u->ip_off=s->ss->ip_off;
				w_u.u->fingerprint=s->ss->fingerprint;
				w_u.u->src_port=s->ss->src_port;

				w_u.u->port_str_len=strlen(s->port_str);
				memcpy(w_u.step + sizeof(send_udp_workunit_t), s->port_str, strlen(s->port_str));

				*wk_len=sizeof(send_udp_workunit_t) + strlen(s->port_str);
				break;

			case MODE_ARPSCAN:
				w_u.ptr=xmalloc(sizeof(send_arp_workunit_t));
				w_u.a->magic=ARP_SEND_MAGIC;

				w_u.a->repeats=s->repeats;
				w_u.a->send_opts=s->send_opts;
				w_u.a->pps=s->pps;
				w_u.a->delay_type=s->delay_type;
				w_u.a->myaddr.sin_addr.s_addr=s->vi->myaddr.sin_addr.s_addr;
				memcpy(w_u.a->hwaddr, s->vi->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
				w_u.a->mtu=s->vi->mtu;

				w_u.a->low_ip=s->_low_ip;
				w_u.a->high_ip=s->_high_ip;
				w_u.a->fingerprint=s->ss->fingerprint;

				*wk_len=sizeof(send_arp_workunit_t);
				break;

			default:
				MSG(M_ERR, "Unknown scanning mode `%d'", s->ss->mode);
				break;
		}

		workunits_sent=1;

		return w_u.ptr;
	}
	else {
		return NULL;
	}
}

void *get_lp_workunit(size_t *wk_len) {
	union {
		recv_tcp_workunit_t *t;
		recv_udp_workunit_t *u;
		recv_arp_workunit_t *a;
		void *ptr;
		uint8_t *step;
	} w_u;

	if (GET_SENDDRONE()) {
		return NULL;
	}

	if (s->verbose > 5) {
		MSG(M_DBG2, "Sending workunit with recv_timeout %u mtu %u recv_opts %u and syn_key %.08x\n", s->ss->recv_timeout, s->vi->mtu, s->recv_opts, s->ss->syn_key);
	}

	switch (s->ss->mode) {
		case MODE_TCPSCAN:
			w_u.ptr=xmalloc(sizeof(recv_tcp_workunit_t));
			w_u.t->magic=TCP_RECV_MAGIC;
			w_u.t->recv_timeout=s->ss->recv_timeout;
			w_u.t->mtu=s->vi->mtu;
			w_u.t->recv_opts=s->recv_opts;

			w_u.t->syn_key=s->ss->syn_key;
			*wk_len=sizeof(recv_tcp_workunit_t);
			break;

		case MODE_UDPSCAN:
			w_u.ptr=xmalloc(sizeof(recv_udp_workunit_t));
			w_u.u->magic=UDP_RECV_MAGIC;
			w_u.u->recv_timeout=s->ss->recv_timeout;
			w_u.u->mtu=s->vi->mtu;
			w_u.u->recv_opts=s->recv_opts;
			*wk_len=sizeof(recv_udp_workunit_t);
			break;

		case MODE_ARPSCAN:
			w_u.ptr=xmalloc(sizeof(recv_arp_workunit_t));
			w_u.a->magic=ARP_RECV_MAGIC;
			w_u.a->recv_timeout=s->ss->recv_timeout;
			w_u.a->mtu=s->vi->mtu;
			w_u.a->recv_opts=s->recv_opts;
			*wk_len=sizeof(recv_arp_workunit_t);
			break;

		default:
			MSG(M_ERR, "Unknown scanning mode `%d'", s->ss->mode);
			break;
	}

	return w_u.ptr;
}
