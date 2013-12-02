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

#include <time.h>
#include <stdlib.h>
#include <errno.h>

#include <libnet.h>

#include <scanopts.h>
#include <scan_export.h>
#include <settings.h>
#include <workunits.h>
#include <packets.h>

#ifdef __linux__
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/arc4random.h>
#include <unilib/xpoll.h>
#include <unilib/xipc.h>
#include <unilib/output.h>
#include <unilib/xdelay.h>
#include <unilib/panic.h>
#include <unilib/tutil.h>
#include <payload.h>
#include <modules.h>
#include <portfunc.h>
#include <parse.h>
#include <init_packet.h>

#define CTVOID 1
#define CTPAYL 2

typedef struct fl_t {
	void (*init)(void);
	uint8_t c_t;
	union {
		int (*cmp)(void);
		int (*gpl)(uint16_t /* dport */, uint8_t ** /* data */, uint32_t * /* dsize */, int32_t * /* local_port */, int (** /*create payload */)(uint8_t **, uint32_t *), uint16_t /* payload_flags */);
	} c_u;
	void (*inc)(void);
	struct fl_t *next;
} fl_t;
static fl_t *flhead=NULL;

static int add_loop_logic(const fl_t * /* new loop logic to add, added to end */);
static void _send_packet(void);
static void loop_list(fl_t * /* start of loop logic list */);
static void priority_send_packet(const send_pri_workunit_t *);

static struct {
	uint32_t curround;
	uint32_t curhost;
	int32_t curport;
	int16_t plindex;

	int32_t local_port;

	int c_socket;
	int read_cnt;

	libnet_t *libnet_h;

	/* udp payload stuff */
	int (*create_payload)(uint8_t **, uint32_t *);
	uint8_t *payload;
	uint32_t payload_size;

	uint8_t esrc[THE_ONLY_SUPPORTED_HWADDR_LEN];
	libnet_ptag_t tcp, tcpo, udp, ip, ipo, arp, eth;
} sl;

#undef IDENT
#define IDENT "[SEND]"

/* for ( init; cmp; inc ) { logic for ttl requested */
void init_nextttl(void);
int   cmp_nextttl(void);
void  inc_nextttl(void);

/* for ( init; cmp; inc ) { logic for scan repeats requested */
void init_nextround(void);
int   cmp_nextround(void);
void  inc_nextround(void);

void init_nextround(void) {
	sl.curround=0;
}
int   cmp_nextround(void) {
	if (sl.curround >= s->repeats) {
		return 0;
	}
	return 1;
}
void  inc_nextround(void) {
	++sl.curround;
}

/* for ( init; cmp; inc ) { logic for scan port list requested */
void init_nextport(void);
int   cmp_nextport(void);
void  inc_nextport(void);

void init_nextport(void) {
	reset_getnextport();
}
int   cmp_nextport(void) {
	if (get_nextport(&sl.curport) == -1) {
		return 0;
	}
	return 1;
}
void  inc_nextport(void) {
	/* XXX do nothing, get_nextport incr's itself */
	return;
}

/* for ( init; cmp; inc ) { logic for scan payloads requested */
void init_payload(void);
int   cmp_payload(uint16_t /*port*/, uint8_t ** /*data*/, uint32_t * /*payload_s*/, int32_t * /*local_port*/, int (** /*create payload */)(uint8_t **, uint32_t *), uint16_t /* payload_flags */);
void  inc_payload(void);

void init_payload(void) {
	sl.plindex=0;
}
int   cmp_payload(uint16_t port, uint8_t **data, uint32_t *payload_size, int32_t *lport, int (**create_payload)(uint8_t ** /*data*/, uint32_t * /*size*/), uint16_t payload_f/* payload flags */) {
	return get_payload(sl.plindex, port, data, payload_size, lport, create_payload, payload_f);
}
void  inc_payload(void) {
	sl.plindex++;
}

/* for ( init; cmp; inc ) { logic for scan hosts requested */
void init_nexthost(void);
int   cmp_nexthost(void);
void  inc_nexthost(void);

void init_nexthost(void) {
	sl.curhost=s->_low_ip;
	return;
}
int   cmp_nexthost(void) {
	if (sl.curhost > s->_high_ip) {
		return 0;
	}
	return 1;
}
void  inc_nexthost(void) {
	++sl.curhost;
}

void send_packet(void) {
	char buf[LIBNET_ERRBUF_SIZE], defhost[64];
	struct libnet_stats libnet_s;
	struct sockaddr_in lsin;
	float pps=0.000000;

	uint8_t msg_type=0, *tmpptr=NULL, status=0;
	uint32_t defport=0;
	int s_socket=0;

	size_t msg_len=0;
	union {
		send_udp_workunit_t *u;
		send_tcp_workunit_t *t;
		send_arp_workunit_t *a;
		send_pri_workunit_t *p;
		uint8_t *cr;
		uint32_t *magic;
	} wku;
	size_t wku_len=0, port_str_len=0;

	struct timeval start, end, total_time;
	fl_t fnew;

	close_output_modules();
	close_report_modules();

	memset(&libnet_s, 0, sizeof(libnet_s));
	memset(&lsin, 0, sizeof(lsin));

	if (sscanf(DEF_SENDER, "%63[0-9.]:%u", defhost, &defport) != 2) {
		MSG(M_ERR, "Cant parse default listener data `%s'", DEF_SENDER);
		terminate(TERM_ERROR);
	}

	if (inet_aton(defhost, &lsin.sin_addr) < 0) {
		MSG(M_ERR, "Can't parse default host `%s'", defhost);
		terminate(TERM_ERROR);
        }
	if (defport > 0xFFFF) {
		MSG(M_ERR, "Listener port out of range");
		terminate(TERM_ERROR);
	}

	lsin.sin_port=htons(defport);
	lsin.sin_addr.s_addr=htonl(INADDR_ANY);

	if ((s_socket=create_server_socket((const struct sockaddr_in *)&lsin)) < 0) {
		MSG(M_ERR, "cant create listener socket");
		terminate(TERM_ERROR);
	}

	if (s->verbose > 3) MSG(M_DBG1, "Waiting for main to connect");

	sl.c_socket=wait_for_client(s_socket);
	if (sl.c_socket < 0) {
		MSG(M_ERR, "main didnt connect, exiting");
		terminate(TERM_ERROR);
	}
	if (s->verbose > 3) MSG(M_DBG1, "Got connection");

	if (get_singlemessage(sl.c_socket, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		MSG(M_ERR, "Unexpected message sequence from parent while looking for ident request, exiting");
		terminate(TERM_ERROR);
	}
	if (msg_type != MSG_IDENT || status != MSG_STATUS_OK) {
		MSG(M_ERR, "Bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
		terminate(TERM_ERROR);
	}

	if (send_message(sl.c_socket, MSG_IDENTSENDER, MSG_STATUS_OK, NULL, 0) < 0) {
		MSG(M_ERR, "Can't send back msgident to parent");
		terminate(TERM_ERROR);
	}

	if (get_singlemessage(sl.c_socket, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		MSG(M_ERR, "Unexpected message sequence from parent while looking for ident request, exiting");
		terminate(TERM_ERROR);
	}
	if (msg_type != MSG_ACK || status != MSG_STATUS_OK) {
		MSG(M_ERR, "Bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
		terminate(TERM_ERROR);
	}

#if 0
	/* we dont want to pick a fight with the tasklets here, they are running at 19, so we will too */
	if (s->verbose > 3) MSG(M_DBG2, "Adjusting process priority to 19");
	if (setpriority(PRIO_PROCESS, 0, 19) < 0) {
		MSG(M_ERR, "Cant adjust priority, expect some evilness: %s", strerror(errno));
	}
#endif

	if (send_message(sl.c_socket, MSG_READY, MSG_STATUS_OK, NULL, 0) < 0) {
		MSG(M_ERR, "Can't send ready message to parent");
		terminate(TERM_ERROR);
	}

	sl.tcp=0; sl.tcpo=0; sl.udp=0; sl.ip=0; sl.ipo=0; sl.arp=0; sl.eth=0;
	sl.read_cnt=0;

	while (1) {

		memset(s->ss, 0, sizeof(scan_settings_t));

		if (get_singlemessage(sl.c_socket, &msg_type, &status, &(wku.cr), &msg_len) != 1) {
			MSG(M_ERR, "Unexpected sequence of messages from parent looking for a workunit");
			terminate(TERM_ERROR);
		}

		if (msg_type == MSG_QUIT) break;

		if (msg_type != MSG_WORKUNIT) {
			MSG(M_ERR, "I was expecting a work unit or quit message, i got a `%s' message", strmsgtype(msg_type));
			break;
		}

		assert(wku.magic != NULL);
		if (*wku.magic == TCP_SEND_MAGIC) {
			s->_low_ip=0;
			s->_high_ip=0;
			s->repeats=0;
			s->vi->mtu=0;
			s->vi->myaddr.sin_addr.s_addr=0;
			s->pps=0;
			s->port_str=NULL;

			if (s->verbose > 5) MSG(M_DBG2, "Got tcp workunit");
			s->ss->mode=MODE_TCPSCAN;

			s->repeats=wku.t->repeats;
			s->send_opts=wku.t->send_opts;
			s->pps=wku.t->pps;
			s->delay_type=wku.t->delay_type;
			s->vi->myaddr.sin_addr=wku.t->myaddr.sin_addr;
			s->vi->mtu=wku.t->mtu;

			s->_low_ip=wku.t->low_ip;
			s->_high_ip=wku.t->high_ip;
			s->ss->tos=wku.t->tos;
			s->ss->ttl=wku.t->ttl;
			s->ss->ip_off=wku.t->ip_off;
			s->ss->fingerprint=wku.t->fingerprint;
			s->ss->src_port=wku.t->src_port;
			sl.local_port=s->ss->src_port;

			s->ss->tcphdrflgs=wku.t->tcphdrflgs;
			s->ss->tcpoptions_len=wku.t->tcpoptions_len;
			memcpy(s->ss->tcpoptions, wku.t->tcpoptions, sizeof(s->ss->tcpoptions));
			s->ss->window_size=wku.t->window_size;
			s->ss->syn_key=wku.t->syn_key;

			wku_len=sizeof(send_tcp_workunit_t);
			port_str_len=wku.t->port_str_len;

			if (s->ss->tcpoptions_len > sizeof(s->ss->tcpoptions) || s->ss->tcpoptions_len < 1) {
				/* constant vigilance!! */
				s->ss->tcpoptions_len=0;
			}
		}
		else if (*wku.magic == UDP_SEND_MAGIC) {
			s->_low_ip=0;
			s->_high_ip=0;
			s->repeats=0;
			s->vi->mtu=0;
			s->vi->myaddr.sin_addr.s_addr=0;
			s->pps=0;
			s->port_str=NULL;

			if (s->verbose > 5) MSG(M_DBG2, "Got udp workunit");
			s->ss->mode=MODE_UDPSCAN;

			s->repeats=wku.u->repeats;
			s->send_opts=wku.u->send_opts;
			s->pps=wku.u->pps;
			s->delay_type=wku.u->delay_type;
			s->vi->myaddr.sin_addr=wku.u->myaddr.sin_addr;
			s->vi->mtu=wku.u->mtu;

			s->_low_ip=wku.u->low_ip;
			s->_high_ip=wku.u->high_ip;
			s->ss->tos=wku.u->tos;
			s->ss->ttl=wku.u->ttl;
			s->ss->ip_off=wku.u->ip_off;
			s->ss->fingerprint=wku.u->fingerprint;
			s->ss->src_port=wku.u->src_port;
			sl.local_port=s->ss->src_port;

			wku_len=sizeof(send_udp_workunit_t);
			port_str_len=wku.u->port_str_len;
		}
		else if (*wku.magic == ARP_SEND_MAGIC) {
			s->_low_ip=0;
			s->_high_ip=0;
			s->repeats=0;
			s->vi->mtu=0;
			s->vi->myaddr.sin_addr.s_addr=0;
			s->pps=0;
			s->port_str=NULL;

			if (s->verbose > 5) MSG(M_DBG2, "Got arp workunit");
			s->ss->mode=MODE_ARPSCAN;

			s->repeats=wku.a->repeats;
			s->send_opts=wku.a->send_opts;
			s->pps=wku.a->pps;
			s->delay_type=wku.a->delay_type;
			s->vi->myaddr.sin_addr=wku.a->myaddr.sin_addr;
			memcpy(s->vi->hwaddr, wku.a->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
			memcpy(sl.esrc, wku.a->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
			s->vi->mtu=wku.a->mtu;

			s->_low_ip=wku.a->low_ip;
			s->_high_ip=wku.a->high_ip;
			s->ss->fingerprint=wku.a->fingerprint;

			wku_len=sizeof(send_arp_workunit_t);
		}
		else if (*wku.magic == PRI_SEND_MAGIC) {
			struct in_addr ia;
			char tcpflags[32];

			if (s->verbose > 5) MSG(M_DBG2, "Got priority send workunit");
                                                                                                                                     
			if (msg_len != sizeof(send_pri_workunit_t)) {
				PANIC("I SAID NO SALT, NO SALT!");
			}

			if (wku.p->magic != PRI_SEND_MAGIC) PANIC("what kind of squirrel are you??");

			ia.s_addr=wku.p->dhost;
			str_tcpflags(&tcpflags[0], wku.p->flags);

			if (s->verbose > 4) MSG(M_DBG2, "Send %s to host seq %.08x %u -> %s:%u flags %.08x seq %u window size %u", tcpflags, wku.p->mseq, wku.p->sport, inet_ntoa(ia), wku.p->dport, wku.p->flags, wku.p->tseq, wku.p->window_size);

			start_tslot();

			priority_send_packet((const send_pri_workunit_t *)wku.p);

			end_tslot();
			continue;
		}
		else {
			MSG(M_ERR, "Unknown workunit type 0x%.08x", *wku.magic);
			terminate(TERM_ERROR);
		}

		/* s->pps shouldnt be negative, but well just check anyhow */
		assert(s->pps > 0);

		init_packet(); /* setup tcpoptions, ip chars etc */
		init_tslot(s->pps, s->delay_type);

		if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
			char tport_str[1024];
			uint8_t *psrc=NULL;

			CLEAR(tport_str);
			psrc=wku.cr;
			psrc += wku_len;
			if ((size_t)(wku_len + port_str_len) < msg_len) {
				MSG(M_ERR, "mismatched msg_len of %u compared to length of packet %d\n", (uint32_t)msg_len, (uint32_t)(wku_len + port_str_len));
				terminate(TERM_ERROR);
			}
			memcpy(tport_str, psrc, port_str_len);
			s->port_str=xstrdup(tport_str);
		}

		snprintf(s->vi->myaddr_s, sizeof(s->vi->myaddr_s) -1, "%s", inet_ntoa((struct in_addr)(s->vi->myaddr.sin_addr)));

		if (s->verbose > 3) {
			char str1[32], str2[32];
			struct in_addr ia;

			CLEAR(str1); CLEAR(str2);

			ia.s_addr=ntohl(s->_low_ip);
			snprintf(str1, sizeof(str1) -1, "%s", inet_ntoa(ia));
			ia.s_addr=ntohl(s->_high_ip);
			snprintf(str2, sizeof(str2) -1, "%s", inet_ntoa(ia));

			if (s->ss->mode == MODE_TCPSCAN) {
				char tcphdrflgs_s[16];

				str_tcpflags(tcphdrflgs_s, s->ss->tcphdrflgs);

				MSG(M_DBG1, "FROM IPC: Low ip: %s, high ip: %s ports %s tcp hdrflags '%s' MTU %d repeats %d tos %d ttl %d window size %d my_addr %s synkey %.08x pps %u src_port %d send_opts %x delay_type %u fingerprint %u", str1, str2, s->port_str, tcphdrflgs_s, s->vi->mtu, s->repeats, s->ss->tos, s->ss->ttl, s->ss->window_size, s->vi->myaddr_s, s->ss->syn_key, s->pps, s->ss->src_port, s->send_opts, s->delay_type, s->ss->fingerprint);
			}
			else if (s->ss->mode == MODE_UDPSCAN) {
				MSG(M_DBG1, "FROM IPC: Low ip: %s, high ip: %s ports `%s' repeats %d tos %d ttl %d my_addr %s pps %u src_port %d send_opts %x delay %u fingerprint %u", str1, str2, s->port_str, s->repeats, s->ss->tos, s->ss->ttl, s->vi->myaddr_s, s->pps, s->ss->src_port, s->send_opts, s->delay_type, s->ss->fingerprint);
			}
			else if (s->ss->mode == MODE_ARPSCAN) {
				MSG(M_DBG1, "FROM IPC: Low ip: %s, high ip: %s repeats %d my_addr %s pps %u send_opts %x delay %u fingerprint %u src hwaddr %.02x:%.02x:%.02x:%.02x:%.02x:%.02x", str1, str2, s->repeats, s->vi->myaddr_s, s->pps, s->send_opts, s->delay_type, s->ss->fingerprint, sl.esrc[0], sl.esrc[1], sl.esrc[2], sl.esrc[3], sl.esrc[4], sl.esrc[5]);
			}
		}

		if (s->ss->mode == MODE_UDPSCAN || s->ss->mode == MODE_TCPSCAN) {
			if (s->port_str[0] == 'q' || s->port_str[0] == 'Q') {
				init_portsquick();
			}
			else {
				if (s->verbose > 5) MSG(M_DBG1, "User port range requested, range `%s'", s->port_str);
				parse_pstr(s->port_str);
			}

			if (GET_SHUFFLE()) {
				shuffle_ports();
			}
		}

		if (ipc_init() < 0) {
			MSG(M_ERR, "cant initialize IPC");
			terminate(TERM_ERROR);
		}

		/*                     inject type  eth0            */
		CLEAR(buf);
		if (s->ss->mode == MODE_UDPSCAN || s->ss->mode == MODE_TCPSCAN) {
			sl.libnet_h=libnet_init(LIBNET_RAW4, s->interface_str, buf);
		}
		else if (s->ss->mode == MODE_ARPSCAN) {
			sl.libnet_h=libnet_init(LIBNET_LINK, s->interface_str, buf);
		}

		if (sl.libnet_h == NULL) {
			MSG(M_ERR, "libnet_init fails, `%s'", buf);
			terminate(TERM_ERROR);
		}

		if (s->ss->mode == MODE_UDPSCAN) {
			if (init_payloads() < 0) {
				MSG(M_ERR, "Can't initialize payload structures, quiting");
				terminate(TERM_ERROR);
			}
			if (init_payload_modules() < 0) {
				MSG(M_ERR, "Can't initialize module payload structures, quiting");
				terminate(TERM_ERROR);
			}
			/* get some payloads from the config files hopefully */
			readconf(CONF_FILE);
		}

		start.tv_sec=0; start.tv_usec=0;
		if (gettimeofday(&start, NULL) < 0) {
			MSG(M_ERR, "gettimeofday fails with :%s", strerror(errno));
			/* *shrug*, we shall keep going? , ctrl-c rules the day here */
		}

		if (s->verbose > 2) {
			MSG(M_DBG1, "Sender pid `%d' starting", getpid());
		}

		/* repeats */
		fnew.init=&init_nextround;
		fnew.c_t=CTVOID;
		fnew.c_u.cmp=&cmp_nextround;
		fnew.inc=&inc_nextround;
		fnew.next=NULL;
		add_loop_logic((const fl_t *)&fnew);

		if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
			/* port */
			fnew.init=&init_nextport;
			fnew.c_t=CTVOID;
			fnew.c_u.cmp=&cmp_nextport;
			fnew.inc=&inc_nextport;
			fnew.next=NULL;
			add_loop_logic((const fl_t *)&fnew);
		}

		/* payload */
		if (s->ss->mode == MODE_UDPSCAN) {
			fnew.init=&init_payload;
			fnew.c_t=CTPAYL;
			fnew.c_u.gpl=&cmp_payload;
			fnew.inc=&inc_payload;
			fnew.next=NULL;
			add_loop_logic((const fl_t *)&fnew);
		}

		/* host */
		fnew.init=&init_nexthost;
		fnew.c_t=CTVOID;
		fnew.c_u.cmp=&cmp_nexthost;
		fnew.inc=&inc_nexthost;
		fnew.next=NULL;
		add_loop_logic((const fl_t *)&fnew);

		loop_list(flhead);

		end.tv_sec=0; end.tv_usec=0;
		if (gettimeofday(&end, NULL) < 0) {
			MSG(M_ERR, "gettimeofday[2] fails with :%s", strerror(errno));
			/* *shrug*, we shall keep going? , ctrl-c rules the day here */
		}

		if (s->verbose > 3) MSG(M_DBG1, "Sending workdone message to parent");

		if (send_message(sl.c_socket, MSG_WORKDONE, MSG_STATUS_OK, NULL, 0) < 0) {
			MSG(M_ERR, "cant send workdone message to parent, exiting");
			terminate(TERM_ERROR);
		}
		else {
			if (s->verbose > 4) MSG(M_DBG1, "Sent workunit done to parent");
		}
	} /* workunit */

	total_time.tv_sec=(end.tv_sec - start.tv_sec);
	total_time.tv_usec=(end.tv_usec - start.tv_usec);

	libnet_stats(sl.libnet_h, &libnet_s);

	pps=libnet_s.packets_sent / (float)((float)total_time.tv_sec + ((float)total_time.tv_usec / 1000000));

	if (GET_NOPATIENCE() || s->verbose > 1) {
		MSG(M_INFO, "average `%.2f' packets per second at end of run", pps);
	}

	libnet_destroy(sl.libnet_h);

	if (s->verbose > 0) MSG(M_VERB,
	"Packets Sent: %lld Packet Errors: %lld Bytes Sent: %lld "
	"took %lu.%lu seconds", libnet_s.packets_sent, libnet_s.packet_errors,
	libnet_s.bytes_written, (unsigned long)total_time.tv_sec, (unsigned long)total_time.tv_usec);

	terminate(TERM_NORMAL);
}

static void _send_packet(void) {
	uint16_t chksum=0, rport=0;
	uint32_t src=0;

	start_tslot();

	if (GET_SENDERINTR()) {
		xpoll_t intrp;
		int getret=0;
		uint8_t msg_type=0, status=0;
		size_t msg_len=0;
		union {
			uint8_t *ptr;
			send_pri_workunit_t *w;
		} w_u;

		if (s->verbose > 7) MSG(M_DBG2, "Sender can be interupted, checking for data");
		intrp.fd=sl.c_socket;

		if (xpoll(&intrp, 1, 0) < 0) {
			MSG(M_ERR, "xpoll fails: %s", strerror(errno));
		}

		if (intrp.rw & XPOLL_READABLE) {
			if (recv_messages(sl.c_socket) < 0) {
				MSG(M_ERR, "recv messages fails in send prio loop");
				return;
			}
			while (1) {
				getret=get_message(sl.c_socket, &msg_type, &status, &w_u.ptr, &msg_len);
				if (getret < 1) break;
				if (msg_type == MSG_WORKUNIT) {
					struct in_addr ia;
					char tcpflags[32];

					if (msg_len != sizeof(send_pri_workunit_t)) {
						PANIC("I SAID NO SALT, NO SALT!");
					}
					if (w_u.w->magic != PRI_SEND_MAGIC) PANIC("what kind of squirrel are you??");

					ia.s_addr=w_u.w->dhost;
					str_tcpflags(&tcpflags[0], w_u.w->flags);

					if (s->verbose > 4) MSG(M_DBG2, "Send %s to host seq %.08x %u -> %s:%u flags %.08x seq %u window size %u", tcpflags, w_u.w->mseq, w_u.w->sport, inet_ntoa(ia), w_u.w->dport, w_u.w->flags, w_u.w->tseq, w_u.w->window_size);
					priority_send_packet((const send_pri_workunit_t *)w_u.w);

					end_tslot();
					start_tslot();
				}
			}
		}
		else {
			if (s->verbose > 7) MSG(M_DBG2, "no data");
		}
	}

	s->ss->current_dst=ntohl(sl.curhost);

	if (s->verbose > 4 ) {
		if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
			MSG(M_DBG2, "sending to `%s:%d'", inet_ntoa((*(struct in_addr *)&s->ss->current_dst)), sl.curport);
		}
		else {
			MSG(M_DBG2, "asking for `%s'", inet_ntoa((*(struct in_addr *)&s->ss->current_dst)));
		}
	}


	if (GET_RNDSRCIP()) {
		uint32_t ret=0;

		ret=arc4random();
		memcpy(&src, &ret, 4);
	}
	else {
		src=s->vi->myaddr.sin_addr.s_addr;
	}

	if (s->ss->src_port == -1 && (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN)) {
		if (s->ss->src_port == -1) {
			sl.local_port=(uint16_t )(arc4random());
			if (sl.local_port < 4096) {
				sl.local_port += 4096;
			}
		}
		else {
			sl.local_port=(uint16_t)s->ss->src_port;
		}
	}

	/* else we a) are udp scanning b) have had local_port set by get_payload */

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		rport=(uint16_t)sl.curport;

		if (sl.create_payload != NULL) {
			if (s->verbose > 4) {
				MSG(M_DBG2, "running create payload");
			}
			if (sl.create_payload(&sl.payload, &sl.payload_size) < 0) {
				MSG(M_ERR, "Create payload for port %d fails", rport);
				return;
			}
		}
	}

	chksum=0;
	if (GET_BROKENTRANS()) {
		chksum=(uint16_t)arc4random();
	}

	if (s->ss->mode == MODE_UDPSCAN) {
		uint16_t pl_s=0;

		/****************************************************************
		 *			BUILD UDP HEADER			*
		 ****************************************************************/

		//MSG(M_DBG2, "payload size %u udp total %u chksum %u", sl.payload_size, LIBNET_UDP_H + sl.payload_size, chksum);

		pl_s=sl.payload_size;

		/* HOLY GOD FIX THIS, why is this doing this? */
		if ((sl.payload_size % 2) == 1) {
			pl_s=sl.payload_size + 1;
		}

		sl.udp=libnet_build_udp((uint16_t)sl.local_port, rport, (LIBNET_UDP_H + pl_s), chksum,
		sl.payload, pl_s, sl.libnet_h, sl.udp);
		if (sl.udp == -1) {
			MSG(M_ERR, "udphdr: `%s'", libnet_geterror(sl.libnet_h));
			terminate(TERM_ERROR);
		}
	}
	else if (s->ss->mode == MODE_TCPSCAN) {
		uint32_t seq=0;

		/****************************************************************
		 *			BUILD TCP HEADER			*
		 ****************************************************************/
		seq=(s->ss->syn_key ^ (s->ss->current_dst ^ (rport + sl.local_port)));

		if (s->ss->tcpoptions_len) {
			sl.tcpo=libnet_build_tcp_options(s->ss->tcpoptions, s->ss->tcpoptions_len, sl.libnet_h, sl.tcpo);
			if (sl.tcpo == -1) {
				MSG(M_ERR, "tcpoptions: `%s'", libnet_geterror(sl.libnet_h));
				terminate(TERM_ERROR);
			}
		}

		sl.tcp=libnet_build_tcp((uint16_t)sl.local_port, rport, seq, 0, s->ss->tcphdrflgs, s->ss->window_size, chksum, 0,
		LIBNET_TCP_H + s->ss->tcpoptions_len, NULL, 0, sl.libnet_h, sl.tcp);
		if (sl.tcp == -1) {
			MSG(M_ERR, "tcphdr: `%s'", libnet_geterror(sl.libnet_h));
			terminate(TERM_ERROR);
		}
	}
	else if (s->ss->mode == MODE_ARPSCAN) {
		/****************************************************************
		 *			BUILD ARP HEADER			*
		 ****************************************************************/
		uint8_t arpbk[6]={ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		sl.arp=libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST, (uint8_t *)sl.esrc,
		(uint8_t *)&src, (uint8_t *)&arpbk[0], (uint8_t *)&s->ss->current_dst, NULL, 0, sl.libnet_h, sl.arp);
	}


	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		/****************************************************************
		 *			BUILD IP HEADER				*
		 ****************************************************************/
		chksum=0;
		if (GET_BROKENNET()) {
			chksum=(uint16_t)arc4random();
		}

		if (s->ss->mode == MODE_UDPSCAN) {
			sl.ip=libnet_build_ipv4((LIBNET_IPV4_H + sl.payload_size + LIBNET_UDP_H), s->ss->tos /* TOS */,
			(uint16_t )arc4random() /*IPID*/, s->ss->ip_off/*FRAG*/, s->ss->ttl/*TTL*/, IPPROTO_UDP, chksum /*chksum*/,
			src, s->ss->current_dst, NULL /*payload*/, 0/*payload size*/, sl.libnet_h, sl.ip);
		}
		else if (s->ss->mode == MODE_TCPSCAN) {
			sl.ip=libnet_build_ipv4((LIBNET_IPV4_H + LIBNET_TCP_H + s->ss->tcpoptions_len), s->ss->tos /* TOS */,
			(uint16_t )arc4random() /*IPID*/, s->ss->ip_off /*FRAG*/, s->ss->ttl/*TTL*/, IPPROTO_TCP, chksum /*chksum*/,
			src, s->ss->current_dst, NULL /*payload*/, 0/*payload size*/, sl.libnet_h, sl.ip);
		}
		if (sl.ip == -1) {
			MSG(M_ERR, "iphdr: `%s'", libnet_geterror(sl.libnet_h));
			terminate(TERM_ERROR);
		}
	}
	else if (s->ss->mode == MODE_ARPSCAN) {
		uint8_t ethbk[6]={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

		/****************************************************************
		 *			BUILD ETH HEADER			*
		 ****************************************************************/
		sl.eth=libnet_build_ethernet(&ethbk[0], (uint8_t *)sl.esrc, ETHERTYPE_ARP, NULL, 0, sl.libnet_h, sl.eth);
		if (sl.eth < 0) {
			MSG(M_ERR, "ethhdr: `%s'", libnet_geterror(sl.libnet_h));
			terminate(TERM_ERROR);
		}
	}

	if (libnet_write(sl.libnet_h) == -1) {
		MSG(M_ERR, "send fails `%s'", libnet_geterror(sl.libnet_h));
	}

	if (sl.create_payload != NULL && sl.payload != NULL) {
		if (s->verbose > 5) {
			MSG(M_DBG2, "freeing payload");
		}
		xfree(sl.payload);
		sl.payload=NULL;
	}

	end_tslot();

	return;
}

static int add_loop_logic(const fl_t *fnew) {
	fl_t *item=NULL;

	if (flhead == NULL) {
		if (s->verbose > 5) MSG(M_DBG2, "Adding new logic list head");
		flhead=(fl_t *)xmalloc(sizeof(fl_t));
		item=flhead;
	}
	else {
		if (s->verbose > 5) MSG(M_DBG2, "Adding new logic list node");
		item=flhead;
		while (item->next != NULL) {
			item=item->next;
		}
		item->next=(fl_t *)xmalloc(sizeof(fl_t));
		item=item->next;
	}

	memset(item, 0, sizeof(fl_t));
	item->next=NULL;
	item->init=fnew->init;
	item->c_t=fnew->c_t;
	switch (item->c_t) {
		case CTVOID:
			item->c_u.cmp=fnew->c_u.cmp;
			break;
		case CTPAYL:
			item->c_u.gpl=fnew->c_u.gpl;
			break;
		default:
			MSG(M_ERR, "Unknown function prototype for loop logic %x", item->c_t);
			terminate(TERM_ERROR);
	}
	item->inc=fnew->inc;

	return 1;
}

void loop_list(fl_t *node) {
	assert(node != NULL);

	switch (node->c_t) {
		case CTVOID:
			for (node->init(); node->c_u.cmp(); node->inc()) {
				if (node->next) {
					loop_list(node->next);
				}
				else {
					/* inside function call */
					_send_packet();
				}
			}
			break;
		case CTPAYL:
			for (node->init(); node->c_u.gpl((uint16_t)sl.curport, &sl.payload, &sl.payload_size, &sl.local_port, &sl.create_payload, s->payload_flags); node->inc()) { 
				if (node->next) {
					loop_list(node->next);
				}
				else {
					/* inside function call */
					_send_packet();
				}
			}
			break;
		default:
			MSG(M_ERR, "runtime error looping list, unknown compare function prototype in list `%c'", node->c_t);
			terminate(TERM_ERROR);
	}

	return;
}


void priority_send_packet(const send_pri_workunit_t *w) {
	assert(w != NULL);
	assert(w->magic == PRI_SEND_MAGIC);

	/****************************************************************
	 *			BUILD TCP HEADER			*
	 ****************************************************************/
	get_postoptions();	/* inside init_packet for now */

	sl.tcpo=libnet_build_tcp_options(s->ss->posttcpoptions, s->ss->posttcpoptions_len, sl.libnet_h, sl.tcpo);
	if (sl.tcpo == -1) {
		MSG(M_ERR, "tcpoptions: `%s'", libnet_geterror(sl.libnet_h));
		return;
	}

	sl.tcp=libnet_build_tcp(w->sport, w->dport, w->mseq, w->tseq, w->flags, w->window_size, 0, 0,
	LIBNET_TCP_H, NULL, 0, sl.libnet_h, sl.tcp);

	if (sl.tcp == -1) {
		MSG(M_ERR, "tcphdr: `%s'", libnet_geterror(sl.libnet_h));
		return;
	}

	/****************************************************************
	 *			BUILD IP HEADER				*
	 ****************************************************************/
	sl.ip=libnet_build_ipv4((LIBNET_IPV4_H + LIBNET_TCP_H + s->ss->posttcpoptions_len), s->ss->tos /* TOS */,
	(uint16_t )arc4random()/*IPID*/, s->ss->ip_off /*FRAG*/, s->ss->ttl/*TTL*/, IPPROTO_TCP, 0/*chksum*/,
	s->vi->myaddr.sin_addr.s_addr, w->dhost, NULL /*payload*/, 0/*payload size*/, sl.libnet_h, sl.ip);

	if (sl.ip == -1) {
		MSG(M_ERR, "iphdr: `%s'", libnet_geterror(sl.libnet_h));
		return;
	}

	if (libnet_write(sl.libnet_h) == -1) {
		MSG(M_ERR, "send fails `%s'", libnet_geterror(sl.libnet_h));
		return;
	}

	return;
}
