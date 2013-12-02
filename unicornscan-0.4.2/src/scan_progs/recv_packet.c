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

#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

#include <pcap.h>

#include <scanopts.h>
#include <scan_export.h>
#include <settings.h>

#include <unilib/terminate.h>
#include <unilib/xipc.h>
#include <unilib/arch.h>
#include <unilib/xmalloc.h>
#include <unilib/xpoll.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/pcaputil.h>
#include <unilib/panic.h>

#include <workunits.h>
#include <portfunc.h>
#include <modules.h>
#include <packet_parse.h>
#include <drone.h>

#define UDP_PFILTER "udp"
#define UDP_EFILTER "or icmp"

/*
#define TCP_PFILTER "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
#define TCP_EFILTER "or icmp or (tcp[tcpflags] & (tcp-ack|tcp-rst) == (tcp-ack|tcp-rst))"
*/
#define TCP_PFILTER "tcp"
#define TCP_EFILTER "or icmp"

#define ARP_PFILTER "arp"

#define FRAG_MASK 0x1fff

static int lc_s;

void *r_queue=NULL, *p_queue=NULL;

void recv_packet(void) {
	char errbuf[PCAP_ERRBUF_SIZE], pfilter[512], base_filter[256], addr_filter[64], defhost[64];
	struct bpf_program filter;
	struct sockaddr_in lsin;
	bpf_u_int32 net, mask;
	int ac_s=0, ret=0;
	uint32_t foct=0, defport=0;
	uint8_t msg_type=0, status=0, *ptr=NULL;
	size_t msg_len=0;
	xpoll_t spdf[2];
	union {
		void *ptr;
		uint8_t *cr;
		uint16_t *r_magic;
	} r_u;
	union {
		recv_udp_workunit_t *u;
		recv_tcp_workunit_t *t;
		recv_arp_workunit_t *a;
		uint8_t *cr;
		uint32_t *magic;
	} wku;
	union {
		listener_info_t *l;
		uint8_t *ptr;
	} l_u;

	r_queue=fifo_init();

	close_output_modules();
	close_report_modules();
	close_payload_modules();

	if (s->verbose > 3) MSG(M_DBG1, "Creating server socket");

	CLEAR(defhost); CLEAR(defport);

	/* heh */
	if (sscanf(DEF_LISTENER, "%63[0-9.]:%u", defhost, &defport) != 2) {
		MSG(M_ERR, "Cant parse default listener data `%s'", DEF_LISTENER);
		terminate(TERM_ERROR);
	}

	if (inet_aton(defhost, &lsin.sin_addr) < 0) {
		MSG(M_ERR, "Can't parse default host `%s'", defhost);
		terminate(TERM_ERROR);
	}
	if (defport > 0xFFFF) {
		MSG(M_ERR, "Default listening port is out of range");
		terminate(TERM_ERROR);
	}

	lsin.sin_port=htons(defport);
	lsin.sin_addr.s_addr=htonl(INADDR_ANY);

	if ((ac_s=create_server_socket((const struct sockaddr_in *)&lsin)) < 0) {
		MSG(M_ERR, "cant create listener socket");
		terminate(TERM_ERROR);
	}

	if (s->verbose > 3) MSG(M_DBG1, "Waiting for main to connect");

	lc_s=wait_for_client(ac_s);
	if (lc_s < 0) {
		MSG(M_ERR, "main didnt connect, exiting");
		terminate(TERM_ERROR);
	}
	if (s->verbose > 3) MSG(M_DBG1, "Got connection");

	if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
		MSG(M_ERR, "Unexpected sequence of messages from parent waiting for ident request, exiting");
		terminate(TERM_ERROR);
	}

	if (msg_type != MSG_IDENT || status != MSG_STATUS_OK) {
		MSG(M_VERB, "Got an unknown message type `%s' or bad status %d from parent, exiting", strmsgtype(msg_type), status);
	}

	if (send_message(lc_s, MSG_IDENTLISTENER, MSG_STATUS_OK, NULL, 0) < 0) {
		MSG(M_ERR, "Can't send back msgident to parent");
		terminate(TERM_ERROR);
	}

	if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
		MSG(M_ERR, "Can't read ident ack message from parent, exiting");
		terminate(TERM_ERROR);
	}
	if (msg_type != MSG_ACK || status != MSG_STATUS_OK) {
		MSG(M_VERB, "Got an unknown message type `%s' or bad status %d from parent, exiting", strmsgtype(msg_type), status);
	}

	if (s->verbose > 3) MSG(M_DBG1, "Sending ready message to parent");

	l_u.l=(listener_info_t *)xmalloc(sizeof(listener_info_t));
	l_u.l->myaddr=s->vi->myaddr.sin_addr.s_addr;
	memcpy(l_u.l->hwaddr, s->vi->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
	l_u.l->mtu=s->vi->mtu;

	if (send_message(lc_s, MSG_READY, MSG_STATUS_OK, l_u.ptr, sizeof(listener_info_t)) < 0) {
		MSG(M_ERR, "Cant send message ready");
		terminate(TERM_ERROR);
	}

	xfree(l_u.l);

	/* XXX */
	s->_low_ip=0;
	s->_high_ip=0;
	s->repeats=0;
	s->pps=0;
	s->port_str=NULL;
	s->ss->syn_key=0;

	memset(s->ss, 0, sizeof(scan_settings_t));

	if (get_singlemessage(lc_s, &msg_type, &status, &(wku.cr), &msg_len) != 1) {
		MSG(M_ERR, "Unexpected sequence of messages from parent looking for a workunit");
		terminate(TERM_ERROR);
	}

	if (msg_type == MSG_QUIT || status != MSG_STATUS_OK) terminate(0);

	if (msg_type != MSG_WORKUNIT) {
		MSG(M_ERR, "I was expecting a work unit or quit message, i got a `%s' message", strmsgtype(msg_type));
		terminate(TERM_ERROR);
	}

	assert(wku.magic != NULL);
	if (*wku.magic == UDP_RECV_MAGIC) {
		if (s->verbose > 5) MSG(M_DBG2, "Got udp workunit");

		s->ss->mode=MODE_UDPSCAN;
		s->ss->recv_timeout=wku.u->recv_timeout;
		s->vi->mtu=wku.u->mtu;
		s->recv_opts=wku.u->recv_opts;
	}
	else if (*wku.magic == TCP_RECV_MAGIC) {
		if (s->verbose > 5) MSG(M_DBG2, "Got tcp workunit");

		s->ss->mode=MODE_TCPSCAN;
		s->ss->recv_timeout=wku.t->recv_timeout;
		s->vi->mtu=wku.t->mtu;
		s->recv_opts=wku.t->recv_opts;

		s->ss->syn_key=wku.t->syn_key;
	}
	else if (*wku.magic == ARP_RECV_MAGIC) {
		if (s->verbose > 5) MSG(M_DBG2, "Got arp workunit");

		s->ss->mode=MODE_ARPSCAN;
		s->ss->recv_timeout=wku.a->recv_timeout;
		s->vi->mtu=wku.a->mtu;
		s->recv_opts=wku.a->recv_opts;
	}
	else {
		MSG(M_ERR, "Unknown workunit type `%c'", *wku.cr);
		terminate(0);
	}

	s->mode=s->ss->mode; /* XXX */

	if (s->verbose > 3) {
		if (s->ss->mode == MODE_TCPSCAN) {
			MSG(M_DBG1, "FROM IPC: TCP scan recv_timeout %d mtu %d recv_opts %x syn_key %.08x", s->ss->recv_timeout, s->vi->mtu, s->recv_opts, s->ss->syn_key);
		}
		else if (s->ss->mode == MODE_UDPSCAN) {
			MSG(M_DBG1, "FROM IPC: UDP scan recv_timeout %d mtu %d recv_opts %x", s->ss->recv_timeout, s->vi->mtu, s->recv_opts);
		}
		else if (s->ss->mode == MODE_ARPSCAN) {
			MSG(M_DBG1, "FROM IPC: ARP scan recv_timeout %d mtu %d recv_opts %x", s->ss->recv_timeout, s->vi->mtu, s->recv_opts);
		}
	}

	if (GET_RETPACKET()) {
		if (s->verbose > 3) MSG(M_DBG2, "Setting up packet queue");
		p_queue=fifo_init();
	}
	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		foct=(htonl(s->vi->myaddr.sin_addr.s_addr) >> 24);
		if (foct == 0x7f) {
			snprintf(addr_filter, sizeof(addr_filter) -1, "dst %s", s->vi->myaddr_s);
		}
		else {
			snprintf(addr_filter, sizeof(addr_filter) -1, "dst %s and ! src %s", s->vi->myaddr_s, s->vi->myaddr_s);
		}
	}

	CLEAR(base_filter);
	switch (s->ss->mode) {
		case MODE_UDPSCAN:
			if (GET_WATCHERRORS()) {
				snprintf(base_filter, sizeof(base_filter) -1, "%s %s", UDP_PFILTER, UDP_EFILTER);
			}
			else {
				snprintf(base_filter, sizeof(base_filter) -1, "%s", UDP_PFILTER);
			}
			break;
		case MODE_TCPSCAN:
			if (GET_WATCHERRORS()) {
				snprintf(base_filter, sizeof(base_filter) -1, "%s %s", TCP_PFILTER, TCP_EFILTER);
			}
			else {
				snprintf(base_filter, sizeof(base_filter) -1, "%s", TCP_PFILTER);
			}
			break;
		case MODE_ARPSCAN:
			snprintf(base_filter, sizeof(base_filter) -1, "%s", ARP_PFILTER);
			break;
		default:
			MSG(M_ERR, "Unknown mode");
			terminate(TERM_ERROR);
	}

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		/* XXX multicast */
		if (s->extra_pcapfilter && strlen(s->extra_pcapfilter)) {
			snprintf(pfilter, sizeof(pfilter) -1, "%s and (%s and %s)", addr_filter, base_filter, s->extra_pcapfilter);
		}
		else {
			if (s->pcap_readfile == NULL) {
				snprintf(pfilter, sizeof(pfilter) -1, "%s and (%s)", addr_filter, base_filter);
			}
			else {
				/* the pcap tracefile could have someone elses address in it.... */
				snprintf(pfilter, sizeof(pfilter) -1, "%s", base_filter);
			}
		}
	}
	else {
		snprintf(pfilter, sizeof(pfilter) -1, "%s", base_filter);
	}

	if (s->verbose > 1) {
		MSG(M_VERB, "using pcap filter: `%s'", pfilter);
	}

	assert(s->interface_str != NULL);

	CLEAR(errbuf);
	if (pcap_lookupnet(s->interface_str, &net, &mask, errbuf) < 0) {
		MSG(M_ERR, "pcap lookup net fails: %s", errbuf);
		terminate(TERM_ERROR);
	}

	CLEAR(errbuf);
	if (s->pcap_readfile == NULL) {
		s->pdev=pcap_open_live(s->interface_str, s->vi->mtu, 1, 0, errbuf);
		if (s->pdev == NULL) {
			MSG(M_ERR, "pcap open live: %s", errbuf);

			if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				MSG(M_ERR, "Cant send message ready error");
				terminate(TERM_ERROR);
			}
			terminate(TERM_ERROR);
		}
	}
	else {
		s->pdev=pcap_open_offline(s->pcap_readfile, errbuf);
		if (s->pdev == NULL) {
			MSG(M_ERR, "pcap open offline: %s", errbuf);

			if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				MSG(M_ERR, "Cant send message ready error");
				terminate(TERM_ERROR);
			}
			terminate(TERM_ERROR);
		}
	}

	ret=util_getheadersize(s->pdev, errbuf);
	if (ret < 0 || ret > 0xFFFF) {
		MSG(M_ERR, "Error getting link header size: %s", errbuf);

		if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			MSG(M_ERR, "Cant send message ready error");
			terminate(TERM_ERROR);
		}
		terminate(TERM_ERROR);
	}
	s->ss->header_len=(uint16_t)ret;
	if (s->ss->mode == MODE_ARPSCAN) {
		if (s->ss->header_len != 14) {
			MSG(M_ERR, "Incompatible link type for arp scan");

			if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				MSG(M_ERR, "Cant send message ready error");
				terminate(TERM_ERROR);
			}
			terminate(TERM_ERROR);
		}
	}

	if (pcap_compile(s->pdev, &filter, pfilter, 0, net) < 0) {
		MSG(M_ERR, "Error compiling filter: %s",  pcap_geterr(s->pdev));

		if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			MSG(M_ERR, "Cant send message ready error");
			terminate(TERM_ERROR);
		}
		terminate(TERM_ERROR);
	}

	if (pcap_setfilter(s->pdev, &filter) < 0) {
		MSG(M_ERR, "Error setting compiled filter: %s", pcap_geterr(s->pdev));

		if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			MSG(M_ERR, "Cant send message ready error");
			terminate(TERM_ERROR);
		}
		terminate(TERM_ERROR);
	}

	pcap_freecode(&filter);

	if (s->pcap_dumpfile != NULL) {
		if (s->verbose > 1) {
			MSG(M_VERB, "Opening `%s' for pcap log", s->pcap_dumpfile);
		}
		s->pdump=pcap_dump_open(s->pdev, s->pcap_dumpfile);
		if (s->pdump == NULL) {
			MSG(M_ERR, "can't log to pcap file `%s'", pcap_geterr(s->pdev));
			if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				MSG(M_ERR, "Cant send message ready error");
				terminate(TERM_ERROR);
			}
			terminate(TERM_ERROR);
		}
	}
	else {
		if (s->verbose > 3) {
			MSG(M_DBG1, "Not logging to pcap file");
		}
	}

	if (util_preparepcap(s->pdev, errbuf) < 0) {
		MSG(M_ERR, "Can't setup pcap filedesc to immediate mode: %s", errbuf);

		if (s->verbose > 3) MSG(M_DBG1, "Sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			MSG(M_ERR, "Cant send message ready error");
			terminate(TERM_ERROR);
		}
		terminate(TERM_ERROR);
	}

	if (s->verbose > 3) MSG(M_DBG1, "listener dropping privs");

	drop_privs();

	/* pcap_fd will be -1 for a pcap file */
	s->pcap_fd=pcap_fileno(s->pdev);
	if (s->verbose > 5) MSG(M_DBG2, "Sniffer socket is %d", s->pcap_fd);

	if (GET_RETPACKET() && s->verbose > 2) {
		MSG(M_DBG1, "Returning whole packet via ipc");
	}

	if (s->verbose > 3) MSG(M_DBG1, "Sending ready message to parent");
	if (send_message(lc_s, MSG_READY, MSG_STATUS_OK, NULL, 0) < 0) {
		MSG(M_ERR, "Cant send message ready");
		terminate(TERM_ERROR);
	}

	while (1) {
		spdf[0].fd=lc_s;
		spdf[1].fd=s->pcap_fd;

		/* if pdev is a socket  ( ! -1 ) */
		if (xpoll(&spdf[0], 2, -1) < 0) {
			MSG(M_ERR, "xpoll fails: %s", strerror(errno));
		}

		if (spdf[1].rw & XPOLL_READABLE) {
			pcap_dispatch(s->pdev, -1, parse_packet, NULL);
		}

		/* no packets, better drain the queue by one */
		if ((r_u.ptr=fifo_pop(r_queue)) != NULL) {
			size_t r_size=0;

			if (*r_u.r_magic == IP_REPORT_MAGIC) {
				r_size=sizeof(ip_report_t);
			}
			else if (*r_u.r_magic == ARP_REPORT_MAGIC) {
				r_size=sizeof(arp_report_t);
			}
			else {
				PANIC("report size/type unknown [%.04x magic]", *r_u.r_magic);
			}

			if (GET_RETPACKET()) {
				union {
					uint16_t *length;
					void *data;
					uint8_t *inc;
				} packet_u;
				union {
					void *data;
					uint8_t *inc;
				} nr_u;
				uint16_t pk_len=0;

				packet_u.data=fifo_pop(p_queue);
				if (packet_u.data == NULL) PANIC("packet queue empty, mismatch with report queue");
				if (s->verbose > 4) MSG(M_DBG2, "Packet length is %u", *packet_u.length);
				pk_len=*packet_u.length;

				/* this should be impossible */
				if (pk_len > (uint16_t)(s->vi->mtu - s->ss->header_len)) PANIC("impossible packet length in queue");

				nr_u.data=xmalloc(r_size + pk_len + sizeof(pk_len));

				memcpy(nr_u.data, (const void *)r_u.ptr, r_size);
				memcpy(nr_u.inc + r_size, (const void *)packet_u.data, pk_len + sizeof(pk_len));

				if (send_message(lc_s, MSG_OUTPUT, MSG_STATUS_OK, nr_u.inc, r_size + pk_len + sizeof(pk_len)) < 0) {
					MSG(M_ERR, "Cant send message output");
					terminate(TERM_ERROR);
				}

				xfree(nr_u.data);
				xfree(packet_u.data);
			}
			else {
				if (send_message(lc_s, MSG_OUTPUT, MSG_STATUS_OK, r_u.cr, r_size) < 0) {
					MSG(M_ERR, "Cant send message output");
					terminate(TERM_ERROR);
				}
			}
			xfree(r_u.ptr);
		} /* if we can ipc a packet */

		if (spdf[0].rw & XPOLL_READABLE) {
			if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
				MSG(M_ERR, "Unexpected sequence of messages from parent in main read loop, exiting");
				terminate(TERM_ERROR);
			}

			if (msg_type == MSG_TERMINATE) {
				if (s->verbose > 5) MSG(M_DBG2, "Parent wants me to stop listening, breaking");
				break;
			}
			else {
				MSG(M_VERB, "Got strange message `%s' from parent, exiting", strmsgtype(msg_type));
			}
		}
	}

	if (GET_NOPATIENCE() || s->verbose > 0) {
		struct pcap_stat pcs;

		if (pcap_stats(s->pdev, &pcs) != -1) {
			MSG(M_VERB, "Packets recieved: %u Packets Dropped: %u Interface Drops: %u", pcs.ps_recv, pcs.ps_drop, pcs.ps_ifdrop);
		}
	}

	pcap_close(s->pdev);
	if (s->pcap_dumpfile) {
		pcap_dump_close(s->pdump);
	}

	if (s->verbose > 3) MSG(M_DBG2, "listener exiting");

	if (send_message(lc_s, MSG_QUIT, MSG_STATUS_OK, NULL, 0) < 0) {
		MSG(M_ERR, "Can't send message quit");
		terminate(TERM_ERROR);
	}

	shutdown(lc_s, SHUT_RDWR);
	close(lc_s);

	terminate(TERM_NORMAL);
}
