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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <scanopts.h>
#include <scan_export.h>
#include <master.h>
#include <recv_packet.h>
#include <init_packet.h>
#include <packets.h>
#include <drone.h>

#include <settings.h>
#include <modules.h>
#include <portfunc.h>
#include <workunits.h>
#include <compare.h>
#include <unilib/tutil.h>
#include <unilib/qfifo.h>
#include <unilib/chtbl.h>
#include <unilib/rbtree.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/panic.h>
#include <unilib/xipc.h>
#include <unilib/xpoll.h>
#include <unilib/arc4random.h>
#include <master.h>

/* XXX ok so i need to move alot of this code out of here, this is getting out of control */

static void handle_ipoutput(void * /* message */);
static void handle_arpoutput(void * /* message */);
static void mark_dead(drone_t * /* drone */, uint8_t /* status, dead or done */);
static void do_report(void);
static void do_arpreport(void);
static char *get_report_extra(ip_report_t *r);
static void *rfifo=NULL;

/*
 * these are for the connection code, one is a "workunit" queue to send to the sender
 * the other is a tcp connection state table to base workunits from
 */
static void *pri_work=NULL /* qfifo */, *state_tbl=NULL; /* rbtree, or chtbl */

#define TBLFIND		chtfind
#define TBLINIT		chtinit
#define TBLINSERT	chtinsert

/* the connection code isnt fully implemented (yet) obviously */
typedef struct connection_status_t {
	int status;
#define U_TCP_ESTABLISHED	1
#define U_TCP_FIN_WAIT1		2
#define U_TCP_FIN_WAIT2		3
#define U_TCP_CLOSING		4
#define U_TCP_TIME_WAIT		5
#define	U_TCP_CLOSE_WAIT	6
#define U_TCP_LAST_ACK		7
#define U_TCP_CLOSE		8
	uint32_t window;
	uint16_t mss;
	uint32_t send_ip;
	size_t recv_len;
	uint8_t *recv_buf;
	size_t send_len;
	uint8_t *send_buf;
} connection_status_t;

static uint64_t get_connectionkey(const ip_report_t *);
static void do_connect(ip_report_t *);
static void try_and_extract_tcp_data(const uint8_t * /* packet data */, size_t /* packet length */, connection_status_t * /* connection */);

void run_mode(void) {
	void (*hook)(void)=NULL;

	switch (s->ss->mode) {
		case MODE_UDPSCAN:
		case MODE_TCPSCAN:
		case MODE_ARPSCAN:
			hook=&run_scan;
			break;
		default:
			MSG(M_ERR, "Unknown scanning mode %x", s->ss->mode);
			return;
	}
	hook();
	return;
}

void run_scan(void) {
	uint8_t msg_type=0, status=0, *ptr=NULL;
	size_t wk_len=0, msg_len=0;
	xpoll_t spdf[4]; /* XXX dynamic */
	union {
		uint8_t *cr;
		void *ptr;
	} w_k;
	drone_t *c=NULL;

	rfifo=fifo_init();

	if (GET_DOCONNECT()) {
		pri_work=fifo_init();
		state_tbl=TBLINIT(111);
	}

	if (s->ss->mode == MODE_TCPSCAN) s->ss->syn_key=arc4random();

	for (c=s->dlh->head  ; c != NULL ; c=c->next) {
		if (c->type == DRONE_TYPE_LISTENER && c->status == DRONE_STATUS_READY) {
			if ((w_k.ptr=get_lp_workunit(&wk_len)) != NULL) {
				if (s->verbose > 2) {
					if (s->verbose > 5) {
						MSG(M_DBG2, "Got listener workunit of size %d :]", wk_len);
					}
					MSG(M_DBG1, "sending workunit to listener");
				}

				if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, w_k.cr, wk_len) < 0) {
					MSG(M_ERR, "Cant Send Workunit to listener on fd %d", c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
				}

				if (c->s == -1) PANIC("WOW!!!!");

				if (get_singlemessage(c->s, &msg_type, &status, &ptr, &msg_len) != 1) {
					MSG(M_ERR, "Unexpected sequence of messages from listener on fd %d, marking dead", c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
				}

				if (status != MSG_STATUS_OK) {
					MSG(M_ERR, "bad status `%d' from listener on fd %d, marking as dead", status, c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
				}

				if (msg_type != MSG_READY) {
					MSG(M_ERR, "bad message `%s' from listener on fd %d, marking as dead", strmsgtype(msg_type), c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
				}

				else if (s->verbose > 3) {
					MSG(M_DBG1, "Sent workunits to listener on fd %d", c->s);
				}
			}
		}
	}

	if (s->listeners == 0) {
		MSG(M_ERR, "Not enough listeners to run scan, bailing out");
		return;
	}

	while (1) {
		int readorwrite=0, breakout=0, pret=0;
		uint32_t d_offset=0;

		c=s->dlh->head;
		assert(s->dlh->size <= sizeof(spdf)); /* XXX */

		/* write loop */
		for (c=s->dlh->head, d_offset=0 ; c != NULL ; c=c->next, d_offset++) {
			if (c->type == DRONE_TYPE_SENDER) {
				void *pw_ptr=NULL;

				if (GET_DOCONNECT()) {
					while ((pw_ptr=fifo_pop(pri_work)) != NULL) {
						if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, pw_ptr, sizeof(send_pri_workunit_t)) < 0) {
							MSG(M_ERR, "Cant send priority workunit to sender on fd %d, marking dead", c->s);
							mark_dead(c, DRONE_STATUS_DEAD);
						}
					}
				}

				if (c->status == DRONE_STATUS_READY) {
					/* get to work! */
					w_k.cr=NULL;
					if ((w_k.ptr=get_sp_workunit(&wk_len)) != NULL) {
						if (s->verbose > 2) {
							if (s->verbose > 5) {
								MSG(M_DBG2, "Got workunit of size %d :]", wk_len);
							}
							MSG(M_DBG1, "sending workunit to sender");
						}

						if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, w_k.cr, wk_len) < 0) {
							MSG(M_ERR, "Cant Send Workunit to sender on fd %d", c->s);
							mark_dead(c, DRONE_STATUS_DEAD);
						}
						else if (s->verbose > 3) {
							MSG(M_DBG1, "Sent workunits to senders");
						}
						c->status=DRONE_STATUS_WORKING;
						readorwrite=1;
					}
					else {
						if (s->verbose > 3) MSG(M_DBG1, "Marking sender on fd %d as done, no more workunits to send", c->s);
						send_message(c->s, MSG_QUIT, MSG_STATUS_OK, ptr, 0);
						mark_dead(c, DRONE_STATUS_DONE);
					}
				}
			}
			spdf[d_offset].fd=c->s;
		}
		if (!(s->senders)) {
			breakout++;
			break;
		}

		if ((pret=xpoll(&spdf[0], s->dlh->size, -1)) < 0) {
			MSG(M_ERR, "Poll drone fd's fail: %s", strerror(errno));
		}

		for (c=s->dlh->head, d_offset=0 ; c != NULL ; c=c->next, d_offset++) {
			c->s_rw=0;
			if (c->status != DRONE_STATUS_DEAD && c->status != DRONE_STATUS_DONE) {
				c->s_rw=spdf[d_offset].rw;
			}
			if (spdf[d_offset].rw & XPOLL_READABLE) {
				if (s->verbose > 4) MSG(M_DBG1, "Socket type %s is readable", (c->type == DRONE_TYPE_LISTENER) ? "Listener" : "Sender");
			}
		}

		/* read loop */
		for (c=s->dlh->head, d_offset=0 ; c != NULL ; c=c->next, d_offset++) {
			if (c->status != DRONE_STATUS_DEAD && c->status != DRONE_STATUS_DONE && c->s_rw & XPOLL_READABLE) {
				int getret=0;
				if (s->verbose > 5) MSG(M_DBG2, "Reading file descriptor %d type %s and %d senders left", c->s, (c->type == DRONE_TYPE_SENDER ? "Sender" : "Listener"), s->senders);

				if (recv_messages(c->s) < 0) {
					MSG(M_ERR, "Cant recieve messages from fd %d, marking as dead", c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
					continue;
				}

				while (1) {
					if (c->status == DRONE_STATUS_DONE || c->status == DRONE_STATUS_DEAD) break;
					getret=get_message(c->s, &msg_type, &status, &ptr, &msg_len);
					if (getret < 1) break;
					if (msg_type == MSG_ERROR || status != MSG_STATUS_OK) {
						MSG(M_ERR, "Drone on fd %d is dead, closing socket and marking dead", c->s);
						mark_dead(c, DRONE_STATUS_DEAD);
						break;
					}
					else if (msg_type == MSG_WORKDONE && c->type == DRONE_TYPE_SENDER) {
						if (s->verbose > 5) MSG(M_DBG2, "Setting sender back to ready state after workdone message");
						c->status=DRONE_STATUS_READY;
					}
					else if (msg_type == MSG_OUTPUT && c->type == DRONE_TYPE_LISTENER) {
						if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
							if (msg_len < sizeof(ip_report_t)) {
								MSG(M_ERR, "Unknown report format from listener");
							}
							else {
								handle_ipoutput(ptr);
							}
						}
						else if (s->ss->mode == MODE_ARPSCAN) {
							handle_arpoutput(ptr);
						}

					}
					else {
						MSG(M_ERR, "Unhandled message from `%s' drone message type `%s' with status %d", (c->type == DRONE_TYPE_SENDER ? "Sender" : "Listener"), strmsgtype(msg_type), status);
					}
					if (getret == 0) break;
				} /* multiple message read loop */
			} /* readable fd */
		}
		if (breakout) break;
	}

	if (s->verbose > 3) MSG(M_DBG1, "###### Waiting for listener packet timeout %d seconds", s->ss->recv_timeout);

	if (1) {
		unsigned int remain=s->ss->recv_timeout;

		while (1) {
			remain=sleep(remain);
			if (remain == 0) {
				break;
			}
		}
	}

	while (1) {
		uint32_t d_offset=0;
		int pret=0;

		for (c=s->dlh->head ; c != NULL ; c=c->next) {
			if (c->type != DRONE_TYPE_LISTENER) {
				if (s->verbose > 7) MSG(M_DBG2, "skipping drone type %d", c->type);
				continue;
			}
			if (c->status == DRONE_STATUS_DEAD) {
				if (s->verbose > 5) MSG(M_DBG2, "skipping dead drone type %d", c->type);
				continue;
			}

			if (c->status == DRONE_STATUS_READY && !(GET_LISTENDRONE())) {
				if (send_message(c->s, MSG_TERMINATE, MSG_STATUS_OK, NULL, 0) < 0) {
					MSG(M_ERR, "Can't tell listener to quit, this scan is useless");
					mark_dead(c, DRONE_STATUS_DEAD);
					continue;
				}
				if (s->verbose > 6) MSG(M_DBG2, "Told listener on fd %d to go into reporting mode", c->s);
				c->status=DRONE_STATUS_WORKING;
			}
		}

		for (c=s->dlh->head, d_offset=0 ; c != NULL ; c=c->next, d_offset++) {
			spdf[d_offset].fd=c->s;
		}

		if (s->listeners && (pret=xpoll(&spdf[0], s->dlh->size, -1)) < 0) {
			MSG(M_ERR, "Poll drone fd's fail: %s", strerror(errno));
		}

		for (c=s->dlh->head, d_offset=0 ; c != NULL ; c=c->next, d_offset++) {
			c->s_rw=0;
			if (c->status != DRONE_STATUS_DEAD) c->s_rw=spdf[d_offset].rw;
			if (spdf[d_offset].rw & XPOLL_READABLE) {
				if (s->verbose > 7) MSG(M_DBG1, "Socket type %s is readable", (c->type == DRONE_TYPE_LISTENER) ? "Listener" : "Sender");
			}
		}

		for (c=s->dlh->head ; c != NULL ; c=c->next) {
			if (c->status != DRONE_STATUS_DEAD && c->status != DRONE_STATUS_DONE && c->s_rw & XPOLL_READABLE) {
				int getret=0;

				if (recv_messages(c->s) < 0) {
					MSG(M_ERR, "read fd %d fails, marking as dead", c->s);
					mark_dead(c, DRONE_STATUS_DEAD);
					continue;
				}

				while (1) {
					if (c->status == DRONE_STATUS_DONE || c->status == DRONE_STATUS_DEAD) break;
					getret=get_message(c->s, &msg_type, &status, &ptr, &msg_len);
					if (getret < 1) break;
					if (s->verbose > 5) MSG(M_DBG2, "Got message type `%s [%d]' from a Listener Drone with status %d and %p data", strmsgtype(msg_type), msg_type, status, ptr);
					if (msg_type == MSG_ERROR || status != MSG_STATUS_OK) {
						MSG(M_ERR, "Got bad message from listener on fd %d, marking as dead", c->s);
						mark_dead(c, DRONE_STATUS_DEAD);
						continue;
					}
					else if (msg_type == MSG_OUTPUT) {
						if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
							if (msg_len < sizeof(ip_report_t)) {
								MSG(M_ERR, "Unknown report format from listener on fd %d", c->s);
							}
							else {
								handle_ipoutput(ptr);
							}
						}
						else if (s->ss->mode == MODE_ARPSCAN) {
							handle_arpoutput(ptr);
						}
					}
					else if (msg_type == MSG_QUIT) {
						mark_dead(c, DRONE_STATUS_DONE);
					}
					else {
						MSG(M_ERR, "Unknown message from listener %d on fd %d, marking as dead", msg_type, c->s);
						/* hrmm, welp i dont get this drone, lets stop talking to him */
						mark_dead(c, DRONE_STATUS_DEAD);
					}
					if (getret == 0) break;
				} /* while messages are read */
			}
		} /* for reading listeners */
		if (s->listeners == 0) break;
	}

	if (s->ss->mode == MODE_UDPSCAN || s->ss->mode == MODE_TCPSCAN) {
		do_report();
	}
	else if (s->ss->mode == MODE_ARPSCAN) {
		do_arpreport();
	}
		
}

static void handle_arpoutput(void *msg) {
	union {
		void *ptr;
		arp_report_t *a;
		uint8_t d;
	} a_u;

	a_u.ptr=(arp_report_t *)xmalloc(sizeof(arp_report_t));
	memcpy(a_u.ptr, msg, sizeof(arp_report_t));
	fifo_push(rfifo, a_u.ptr);
	if (GET_NOPATIENCE()) {
		struct in_addr ia;

		ia.s_addr=a_u.a->ipaddr;
		MSG(M_OUT, "Added %s at %.02x:%.02x:%.02x:%.02x:%.02x:%.02x", inet_ntoa(ia), a_u.a->hwaddr[0], a_u.a->hwaddr[1],
		a_u.a->hwaddr[2], a_u.a->hwaddr[3], a_u.a->hwaddr[4], a_u.a->hwaddr[5]);
	}
}

static void do_arpreport(void) {
	union {
		arp_report_t *a;
		void *ptr;
	} a_u;
	struct in_addr ia;

	while ((a_u.ptr=fifo_pop(rfifo)) != NULL) {
		ia.s_addr=a_u.a->ipaddr;

		MSG(M_OUT, "%16s\tis %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\t(%s)", inet_ntoa(ia), a_u.a->hwaddr[0], a_u.a->hwaddr[1],
		a_u.a->hwaddr[2], a_u.a->hwaddr[3], a_u.a->hwaddr[4], a_u.a->hwaddr[5],
		getouiname(a_u.a->hwaddr[0], a_u.a->hwaddr[1], a_u.a->hwaddr[2]));
	}
}

static void handle_ipoutput(void *msg) {
	union {
		void *ptr;
		ip_report_t *r;
		uint8_t *d;
	} r_u, r_um;
	struct in_addr ia;
	uint16_t pk_len;

	assert(msg != NULL);

	r_um.ptr=msg;
	if (s->verbose > 5) MSG(M_DBG2, "Report has a %d byte packet attached to it", r_um.r->doff);

	assert(r_um.r->doff < s->vi->mtu);

	if (r_um.r->doff) {
		pk_len=r_um.r->doff;
		r_u.ptr=xmalloc(sizeof(ip_report_t) + pk_len + sizeof(pk_len));
		memcpy(r_u.ptr, (const void *)r_um.ptr, sizeof(ip_report_t) + pk_len + sizeof(pk_len));
	}
	else {
		r_u.ptr=xmalloc(sizeof(ip_report_t));
		memcpy(r_u.ptr, (const void *)r_um.ptr, sizeof(ip_report_t));
	}

	if (r_u.r->proto == IPPROTO_TCP && GET_DOCONNECT()) {
		do_connect(r_u.r);
	}

	if (port_open(r_u.r->proto, r_u.r->type, r_u.r->subtype)) {
		ia.s_addr=r_u.r->host_addr;

		if (fifo_find(rfifo, (const void *)r_u.ptr, &compare_ip_report) == NULL) {
			r_u.r->od_q=fifo_init();
			fifo_push(rfifo, r_u.ptr);

			if (GET_NOPATIENCE()) {
				MSG(M_INFO, "Added     %s port %d ttl %d", inet_ntoa(ia), r_u.r->sport, r_u.r->ttl);
			}
		}
		else {
			if (s->verbose > 4) MSG(M_DBG2, "DUP port open on %s:%d", inet_ntoa(ia), r_u.r->sport);
			xfree(r_u.ptr);
		}
	}
	else if (port_closed(r_u.r->proto, r_u.r->type, r_u.r->subtype) && GET_SHOWERRORS()) {
		char tmp[32];

		ia.s_addr=r_u.r->host_addr;
		snprintf(tmp, sizeof(tmp) -1, "%s", inet_ntoa(ia));

		if (fifo_find(rfifo, (const void *)r_u.ptr, &compare_ip_report) == NULL) {
			r_u.r->od_q=fifo_init();
			fifo_push(rfifo, r_u.ptr);

			if (r_u.r->trace_addr != r_u.r->host_addr && GET_NOPATIENCE()) {
				struct in_addr ia2;
				/* treason uncloaked */
				ia2.s_addr=r_u.r->trace_addr;

				MSG(M_OUT, "Closed    %s port %d ttl %d From %s", tmp, r_u.r->sport, r_u.r->ttl, inet_ntoa(ia2));
			}
			else if (GET_NOPATIENCE()) {
				MSG(M_OUT, "Closed    %s port %d ttl %d", tmp, r_u.r->sport, r_u.r->ttl);
			}
		}
		else {
			if (s->verbose > 4) MSG(M_DBG2, "Dup close on %s:%d", inet_ntoa(ia), r_u.r->sport);
			xfree(r_u.ptr);
		}
	} /* end PORT CLOSED */
	else if (GET_SHOWERRORS()) {
		struct in_addr ia2;
		char tmp[32];

		ia2.s_addr=r_u.r->trace_addr;
		ia.s_addr=r_u.r->host_addr;

		snprintf(tmp, sizeof(tmp) -1, "%s", inet_ntoa(ia));

		if (fifo_find(rfifo, (const void *)r_u.ptr, &compare_ip_report) == NULL) {
			r_u.r->od_q=fifo_init();
			fifo_push(rfifo, r_u.ptr);

			if (r_u.r->trace_addr != r_u.r->host_addr && GET_NOPATIENCE()) {
				/* treason uncloaked */

				if (r_u.r->proto == IPPROTO_ICMP) {
					MSG(M_OUT, "T%.02dC%.02d    %s port %d ttl %d From %s", r_u.r->type, r_u.r->subtype, tmp, r_u.r->sport, r_u.r->ttl, inet_ntoa(ia2));
				}
				else if (r_u.r->proto == IPPROTO_TCP) {
					char tcpflags[16];

					str_tcpflags(tcpflags, r_u.r->type);
					MSG(M_OUT, "TCP%s %s port %d ttl %d From %s", tcpflags, tmp, r_u.r->sport, r_u.r->ttl, inet_ntoa(ia2));
				}
				else if (r_u.r->proto == IPPROTO_UDP) {
					MSG(M_ERR, "<gh0st> \"Upgrade\" from Unix to Windows, eh? You keep using that word. I do not think it means what you think it means.");
					PANIC("now this is silly [-1]");
				}
				else {
					PANIC("now this is silly [0]");
				}
			}
			else {
				if (r_u.r->proto == IPPROTO_ICMP) {
					MSG(M_OUT, "T%.02dC%.02d %s    port %d ttl %d", r_u.r->type, r_u.r->subtype, tmp, r_u.r->sport, r_u.r->ttl);
				}
				else if (r_u.r->proto == IPPROTO_TCP) {
					char tcpflags[16];

					str_tcpflags(tcpflags, r_u.r->type);
					MSG(M_OUT, "TCP%s %s port %d ttl %d", tcpflags, tmp, r_u.r->sport, r_u.r->ttl);
				}
				else if (r_u.r->proto == IPPROTO_UDP) {
					PANIC("YOU SHOULDNT BE HERE, WHAT ARE YOU DOING HERE?!?!? DONT YOU UNDERSTAND WHAT THIS MEANS?!?!?!");
				}
				else {
					PANIC("the sky is falling, the sky is falling, and dont call me shirley");
				}
			}
		}
		else {
			if (s->verbose > 4) MSG(M_DBG2, "Dup ? on %s:%d", inet_ntoa(ia), r_u.r->sport);
			xfree(r_u.ptr);
		}
	} /* end Not port OPEN or CLOSED */

	return;
}

static void do_report() {
	union {
		void *ptr;
		ip_report_t *r;
	} r_u;
	struct in_addr ia;

	fifo_order(rfifo, &compare_ip_report_port, 1); /* JZ */
	fifo_order(rfifo, &compare_ip_report_addr, 1); /* JZ */

	while ((r_u.ptr=fifo_pop(rfifo)) != NULL) {
		char *extra=NULL;

		push_report_modules((const void *)r_u.ptr); /* ADD to it */
		push_output_modules((const void *)r_u.ptr); /* display it somehow */

		extra=get_report_extra(r_u.r);

		if (port_open(r_u.r->proto, r_u.r->type, r_u.r->subtype)) {
			ia.s_addr=r_u.r->host_addr;
			if (extra != NULL) {
				MSG(M_OUT, "Open     \t%16s[%5d]\t\tFrom %s\tttl %d %s", getservname(r_u.r->sport), r_u.r->sport, inet_ntoa(ia), r_u.r->ttl, extra);
			}
			else {
				MSG(M_OUT, "Open     \t%16s[%5d]\t\tFrom %s\tttl %d", getservname(r_u.r->sport), r_u.r->sport, inet_ntoa(ia), r_u.r->ttl);
			}
		}
		else if (port_closed(r_u.r->proto, r_u.r->type, r_u.r->subtype)) {
			struct in_addr ia2;
			char tmp[32];

			memset(&ia2, 0, sizeof(ia2));
			ia2.s_addr=r_u.r->trace_addr;

			ia.s_addr=r_u.r->host_addr;
			snprintf(tmp, sizeof(tmp) -1, "%s", inet_ntoa(ia));

			if (r_u.r->trace_addr != r_u.r->host_addr) {
				/* treason uncloaked */

				if (extra != NULL) {
					MSG(M_OUT, "Closed   \t%16s[%5d]\t\tTo   %s\tttl %d From %s %s", getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2), extra);
				}
				else {
					MSG(M_OUT, "Closed   \t%16s[%5d]\t\tTo   %s\tttl %d From %s", getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2));
				}
			}
			else {
				if (extra != NULL) {
					MSG(M_OUT, "Closed   \t%16s[%5d]\t\tFrom %s\tttl %d %s", getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, extra);
				}
				else {
					MSG(M_OUT, "Closed   \t%16s[%5d]\t\tFrom %s\tttl %d", getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl);
				}
			}
		} /* end PORT CLOSED */
		else {
			struct in_addr ia2;
			char tmp[32];

			memset(&ia2, 0, sizeof(ia2));
			ia2.s_addr=r_u.r->trace_addr;

			ia.s_addr=r_u.r->host_addr;
			snprintf(tmp, sizeof(tmp) -1, "%s", inet_ntoa(ia));

			if (r_u.r->trace_addr != r_u.r->host_addr) {
				/* treason uncloaked */

				if (r_u.r->proto == IPPROTO_ICMP) {
					if (extra != NULL) {
						MSG(M_OUT, "T%.02dC%.02d   \t%16s[%5d]\t\tTo   %s\tttl %d From %s %s", r_u.r->type, r_u.r->subtype, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2), extra);
					}
					else {
						MSG(M_OUT, "T%.02dC%.02d   \t%16s[%5d]\t\tTo   %s\tttl %d From %s", r_u.r->type, r_u.r->subtype, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2));
					}
				}
				else if (r_u.r->proto == IPPROTO_TCP) {
					char tcpflags[16];

					str_tcpflags(tcpflags, r_u.r->type);
					if (extra != NULL) {
						MSG(M_OUT, "TCP%s\t%16s[%5d]\t\tTo   %s\tttl %d From %s %s", tcpflags, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2), extra);
					}
					else {
						MSG(M_OUT, "TCP%s\t%16s[%5d]\t\tTo   %s\tttl %d From %s", tcpflags, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, inet_ntoa(ia2));
					}
				}
				else if (r_u.r->proto == IPPROTO_UDP) {
					PANIC("now this is silly [1]");
				}
				else {
					PANIC("now this is silly [2]");
				}
			}
			else {
				if (r_u.r->proto == IPPROTO_ICMP) {
					if (extra != NULL) {
						MSG(M_OUT, "T%.02dC%.02d   \t%16s[%5d]\t\tTo   %s\tttl %d %s", r_u.r->type, r_u.r->subtype, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, extra);
					}
					else {
						MSG(M_OUT, "T%.02dC%.02d   \t%16s[%5d]\t\tTo   %s\tttl %d", r_u.r->type, r_u.r->subtype, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl);
					}
				}
				else if (r_u.r->proto == IPPROTO_TCP) {
					char tcpflags[16];

					str_tcpflags(tcpflags, r_u.r->type);
					if (extra != NULL) {
						MSG(M_OUT, "TCP%s\t%16s[%5d]\t\tTo   %s\tttl %d %s", tcpflags, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl, extra);
					}
					else {
						MSG(M_OUT, "TCP%s\t%16s[%5d]\t\tTo   %s\tttl %d", tcpflags, getservname(r_u.r->sport), r_u.r->sport, tmp, r_u.r->ttl);
					}
				}
				else if (r_u.r->proto == IPPROTO_UDP) {
					PANIC("now this is silly [3]");
				}
				else {
					PANIC("now this is silly [4]");
				}
			}
		} /* end Not port OPEN or CLOSED */
		fifo_destroy(r_u.r->od_q);
		xfree(r_u.ptr);
	}

	fifo_destroy(rfifo);

	return;
}


int port_open(uint8_t proto, uint16_t type, uint16_t subtype) {
	switch (proto) {
		case IPPROTO_TCP:
			if (s->ss->mode == MODE_TCPSCAN && (type & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) return 1;
			break;
		case IPPROTO_UDP:
			if (s->ss->mode == MODE_UDPSCAN) return 1;
			break;
		case IPPROTO_ICMP:
			break;
		default:
			MSG(M_ERR, "Unhandled protocol %d", proto);
	}
	return 0;
}

int port_closed(uint8_t proto, uint16_t type, uint16_t subtype) {
	switch (proto) {
		case IPPROTO_TCP:
			if (s->ss->mode == MODE_TCPSCAN && (type & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) return 1;
			break;
		case IPPROTO_UDP:
			break;
		case IPPROTO_ICMP:
			if (s->ss->mode == MODE_UDPSCAN && type == 3 && subtype == 3) return 1;
			break;
		default:
			MSG(M_ERR, "Unhandled protocol %d", proto);
	}
	return 0;
}

void mark_dead(drone_t *c, uint8_t status) {
	assert(c != NULL);

	c->status=status;
	shutdown(c->s, SHUT_RDWR);
	close(c->s);
	c->s=-1;
	if (c->type == DRONE_TYPE_SENDER) s->senders--;
	if (c->type == DRONE_TYPE_LISTENER) s->listeners--;
}

/* destructive */
static char *get_report_extra(ip_report_t *r) {
	static char out[512];
	size_t out_off=0;
	int sret=0;
	union {
		void *ptr;
		output_data_t *d;
	} d_u;

	assert(r != NULL);

	CLEAR(out);

	if (r->od_q == NULL) {
		PANIC("i have no legs");
	}

	while ((d_u.ptr=fifo_pop(r->od_q)) != NULL) {
		/* XXX this needs to be a bit more flexable than what it is (only checking 1 type, etc) */
		sret=snprintf(&out[out_off], (sizeof(out) - (out_off + 1)), "%s", (d_u.d->type == OD_TYPE_OS ? d_u.d->t_u.os : d_u.d->t_u.banner));
		if (sret < 1) break;
		out_off += sret;
		if (out_off >= (sizeof(out) -1)) {
			/* malloc is for girls ;] hide rms this function has serious limits */
			MSG(M_ERR, "Report Buffer is overflowing, breaking, ask author to not be so wordy next time");
			break;
		}
		xfree(d_u.ptr);
	}

	if (GET_DOCONNECT()) {
		uint64_t state_key=0;
		union {
			void *ptr;
			connection_status_t *c;
		} c_u;
		uint8_t pchars[256], *c_ptr=NULL;
		size_t p_off=0;
		size_t j=0;

		state_key=get_connectionkey(r);

		if (TBLFIND(state_tbl, state_key, &c_u.ptr) > 0) {
			memset(pchars, 0, sizeof(pchars));

			for (j=0, p_off=0, c_ptr=c_u.c->recv_buf ; j < c_u.c->recv_len ; j++, c_ptr++) {
				if (isprint(*c_ptr)) {
					pchars[p_off++]=*c_ptr;
				}
				if (p_off > (sizeof(pchars) -1)) break;
			}

			if (p_off > 0) {
				snprintf(&out[out_off], sizeof(out) - (out_off + 1), " `%s'", pchars);
			}
		}
	}

	if (strlen(out)) return &out[0];

	return NULL;
}

static uint64_t get_connectionkey(const ip_report_t *r) {
	union {
		uint64_t state_key;
		struct {
			uint32_t dhost;
			uint16_t sport;
			uint16_t dport;
		} s;
	} k_u;

	assert(r != NULL);

	k_u.s.dhost=r->host_addr;
	k_u.s.dport=r->dport;
	k_u.s.sport=r->sport;

	return k_u.state_key;
}

static void do_connect(ip_report_t *r) {
	char tcpflags[32];
	union {
		void *ptr;
		send_pri_workunit_t *w;
	} w_u;
	union {
		void *ptr;
		connection_status_t *c;
	} c_u;
	union {
		uint8_t *packet;
		ip_report_t *r;
		uint16_t *len;
	} r_u;
	struct in_addr ia;
	size_t pk_len=0;
	uint64_t state_key=0;

	assert(r != NULL);

	state_key=get_connectionkey((const ip_report_t *)r);

	str_tcpflags(&tcpflags[0], r->type);

	if (TBLFIND(state_tbl, state_key, &c_u.ptr) > 0) {
		if (c_u.ptr == NULL) PANIC("state table is a liar");

		if (s->verbose > 5) MSG(M_DBG2, "### I should (reset|ignore) this packet, flags are %s status is %d", tcpflags, c_u.c->status);

		w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
		w_u.w->magic=PRI_SEND_MAGIC;
		w_u.w->dhost=r->host_addr;
		w_u.w->dport=r->sport;
		w_u.w->sport=r->dport;

		r_u.r=r;

		if (r_u.r->doff) {
			pk_len=r_u.r->doff;
			r_u.packet += sizeof(ip_report_t);
			if (*r_u.len != pk_len) {
				MSG(M_ERR, "report is damaged?!?!?, packet seems broken, sad bunny both ears down");
			}
			else {
				r_u.len++;
				if (pk_len > (sizeof(struct mytcphdr) + sizeof(struct myiphdr))) {
					try_and_extract_tcp_data(r_u.packet, pk_len, c_u.c);
				}
			}
		}

		switch (r->type) {
			case TH_ACK|TH_PSH:
				w_u.w->flags=TH_RST;
				break;
			case TH_ACK:
			case TH_ACK|TH_SYN:
				//xfree(w_u.ptr);
				return;
			default:
				w_u.w->flags=TH_RST;
				if (s->verbose > 4) MSG(M_ERR, "reseting, nothing better to do here yet, flags are `%s'", tcpflags);
				break;
		}

		w_u.w->mseq=r->mseq;
		w_u.w->tseq=r->tseq + (r->window_size / 2); /* increment inside the window somewhere */
		w_u.w->window_size=r->window_size;

		fifo_push(pri_work, w_u.ptr);
	}
	else if ((r->type & (TH_ACK|TH_SYN)) == (TH_ACK|TH_SYN)) {
		if (s->verbose > 5) MSG(M_DBG2, "I should ack this packet, flags are %s", tcpflags);

		w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
		w_u.w->magic=PRI_SEND_MAGIC;
		w_u.w->dhost=r->host_addr;
		w_u.w->dport=r->sport;
		w_u.w->sport=r->dport;
		w_u.w->tseq=r->tseq + 1;
		w_u.w->mseq=r->mseq;
		w_u.w->window_size=r->window_size;
		w_u.w->flags=TH_ACK;
		fifo_push(pri_work, w_u.ptr);

		c_u.ptr=xmalloc(sizeof(connection_status_t));
		memset(c_u.ptr, 0, sizeof(connection_status_t));

		c_u.c->status=U_TCP_ESTABLISHED;

		c_u.c->recv_len=0;
		c_u.c->send_len=0;
		c_u.c->send_buf=NULL;
		c_u.c->recv_buf=NULL;

		ia.s_addr=w_u.w->dhost;

		if (s->verbose) MSG(M_VERB, "connected %u -> %s:%u", w_u.w->sport, inet_ntoa(ia), w_u.w->dport);

		TBLINSERT(state_tbl, state_key, c_u.ptr);
	}
	else {
		if (s->verbose > 6) MSG(M_DBG2, "do_connect Ignoring packet with flags %s", tcpflags);
	}

	return;
}


static void try_and_extract_tcp_data(const uint8_t *packet, size_t pk_len, connection_status_t *c) {
	union {
		const struct myiphdr *ih;
		const struct mytcphdr *th;
		const uint8_t *data;
	} p_u;
	uint16_t fragoff=0, totlen=0;
	size_t opt_len=0, data_len=0, tcpopt_len=0;
	uint8_t doff=0;

	assert(packet != NULL); assert(pk_len > sizeof(struct myiphdr) + sizeof(struct mytcphdr)); assert(c != NULL);

	p_u.data=packet;

	if (p_u.ih->ihl < 5) {
		MSG(M_ERR, "Packet has stupid ihl, ignoring it");
		return;
	}

	fragoff=ntohs(p_u.ih->frag_off);
	totlen=ntohs(p_u.ih->tot_len);

	if (totlen > pk_len) {
		MSG(M_ERR, "this packet is on drugs, sorry");
		return;
	}

	if (fragoff & IP_OFFMASK) {
		MSG(M_ERR, "man, this packet is fragmented, thats lame, what do you think i am? a STACK!?!?");
		return;
	}

	if (pk_len > totlen) {
		MSG(M_ERR, "Packet has junk, truncating");
		pk_len=totlen;
	}

	opt_len=(p_u.ih->ihl - (sizeof(struct myiphdr) / 4)) * 4;

	if ((opt_len + sizeof(struct myiphdr) + sizeof(struct mytcphdr)) > pk_len) {
		MSG(M_ERR, "Lies lies lies lies lies lies lies lies");
		return;
	}

	p_u.data += sizeof(struct myiphdr) + opt_len;
	pk_len -= sizeof(struct myiphdr) + opt_len;

	doff=p_u.th->doff;
	if (doff == 0) {
		/* this is not the packet you are looking for */
		return;
	}

	if ((size_t)(doff * 4) > pk_len) {
		MSG(M_ERR, "Datalength exceeds capture length, ignoring");
		return;
	}
	if ((size_t )(doff * 4) < sizeof(struct mytcphdr)) {
		MSG(M_ERR, "Datalength is too small");
		return;
	}

	tcpopt_len=(doff * 4) - sizeof(struct mytcphdr);
	data_len=pk_len - (doff * 4);

	if (data_len == 0) {
		if (s->verbose> 3) MSG(M_DBG2, "No data on this packet");
		return;
	}

	if (tcpopt_len + data_len + sizeof(struct mytcphdr) > pk_len) {
		MSG(M_ERR, "hAHAHAHAHAHA");
		return;
	}
	p_u.data += sizeof(struct mytcphdr) + tcpopt_len;
	pk_len -= sizeof(struct mytcphdr) + tcpopt_len;

	if (pk_len > 1280) {
		if (s->verbose > 4) MSG(M_ERR, "packet is really big, ignoring");
		return;
	}
	if (c->recv_len) {
		xfree(c->recv_buf);

		c->recv_buf=xmalloc(pk_len);
		memcpy(c->recv_buf, p_u.data, pk_len);
		c->recv_len=pk_len;
	}
	else {
		c->recv_buf=xmalloc(pk_len);
		memcpy(c->recv_buf, p_u.data, pk_len);
		c->recv_len=pk_len;
	}

	return;
}
