/**********************************************************************
 * Copyright (C) (2004) (Jack Louis) <jack@rapturesecurity.org>       *
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
#ifndef _SETTINGS_H
# define _SETTINGS_H

#include <drone.h>
#include <config.h> /* for sockaddr stuff */

/* XXX shouldnt be here at ALL, move this stuff out into scan_modules */
#include <pcap.h>

#define FORK_LOCAL_LISTENER	1
#define FORK_LOCAL_SENDER	2

#ifndef SCANSETTINGS
 /* this is the public interface then */
# define SCANSETTINGS void
#endif

#define IDENT_MASTER	1
#define IDENT_MASTER_NAME	"Main"
#define IDENT_SEND	2
#define IDENT_SEND_NAME		"Send"
#define IDENT_RECV	3
#define IDENT_RECV_NAME		"Recv"

extern int ident;
extern const char *ident_name_ptr;

typedef struct interface_info_t {
	uint16_t mtu;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	char hwaddr_s[32];
	struct sockaddr_in myaddr;
	char myaddr_s[32];
	struct interface_info_t *next;
} interface_info_t;


typedef struct settings_s {
	uint32_t _low_ip;	/* in network order */
	uint32_t _high_ip;	/* in network order */

	char *port_str;
	char *host_str;

	uint32_t repeats;

	SCANSETTINGS *ss;

	char *interface_str;
	interface_info_t *vi;

	char *pcap_dumpfile;
	char *pcap_readfile;
	pcap_dumper_t *pdump;
	pcap_t *pdev;
	int pcap_fd;
	char *extra_pcapfilter;

	/* its a copy from the scan settings seeing as how im trying to get this to work again, duct tape alert XXX */
	uint8_t mode;

	/* if this is a forked process, read when terminating */
	uint8_t forked;

	uint16_t options;
	uint16_t send_opts;
	uint16_t recv_opts;

	uint8_t verbose;
	uint32_t pps;
	time_t s_time;
	time_t e_time;

	char *mod_dir;
	uint16_t payload_flags;

	char *idle_hosts;
	char *drone_str;
	uint8_t delay_type;

	drone_list_head_t *dlh;

	uint8_t forklocal;
	uint8_t senders;
	uint8_t listeners;
	uint8_t covertness;

	char *module_enable;
	int (*display)(const char, const char *, int , const char *, ...);
} settings_t;


extern settings_t *s;

/* sender thread constants */
#define SHUFFLE_PORTS	1
#define SRC_OVERRIDE	2
#define RND_SRCIP	4
#define DEFAULT_PAYLOAD	8
#define BROKEN_TRANS	16
#define BROKEN_NET	32
#define SENDER_INTR	64 /* we can interrupt the sender with new work (high priority) */

/* master thread constants */
#define SHOW_ERRORS	1
#define NO_PATIENCE	2
#define LISTEN_DRONE	4
#define SEND_DRONE	8
#define OUTPUT_DRONE	16
#define IDLE_SCAN	32
#define DO_CONNECT	64

/* recv thread constants */
#define WATCH_ERRORS	1
#define RETURN_PACKET	2

/* sender thread options */
#define GET_SHUFFLE()		(s->send_opts & SHUFFLE_PORTS)
#define GET_OVERRIDE()		(s->send_opts & SRC_OVERRIDE)
#define GET_RNDSRCIP()		(s->send_opts & RND_SRCIP)
#define GET_DEFAULT()		(s->send_opts & DEFAULT_PAYLOAD)
#define GET_BROKENNET()		(s->send_opts & BROKEN_NET)
#define GET_BROKENTRANS()	(s->send_opts & BROKEN_TRANS)
#define GET_SENDERINTR()	(s->send_opts & SENDER_INTR)

#define SET_SHUFFLE()		(s->send_opts |= SHUFFLE_PORTS)
#define SET_OVERRIDE()		(s->send_opts |= SRC_OVERRIDE)
#define SET_RNDSRCIP()		(s->send_opts |= RND_SRCIP)
#define SET_DEFAULT()		(s->send_opts |= DEFAULT_PAYLOAD)
#define SET_BROKENNET()		(s->send_opts |= BROKEN_NET)
#define SET_BROKENTRANS()	(s->send_opts |= BROKEN_TRANS)
#define SET_SENDERINTR()	(s->send_opts |= SENDER_INTR)

#define SET_NOSHUFFLE()	(s->send_opts &= ~(SHUFFLE_PORTS))
#define SET_NODEFAULT()	(s->send_opts &= ~(DEFAULT_PAYLOAD))

/* master thread options */
#define GET_SHOWERRORS()	(s->options & SHOW_ERRORS)
#define GET_NOPATIENCE()	(s->options & NO_PATIENCE)
#define GET_LISTENDRONE()	(s->options & LISTEN_DRONE)
#define GET_SENDDRONE()		(s->options & SEND_DRONE)
#define GET_OUTPUTDRONE()	(s->options & OUTPUT_DRONE)
#define GET_IDLESCAN()		(s->options & IDLE_SCAN)
#define GET_DOCONNECT()		(s->options & DO_CONNECT)

#define SET_PATIENCE()		(s->options &= ~(NO_PATIENCE))
#define SET_DOCONNECT()		(s->options |= DO_CONNECT)
#define SET_SHOWERRORS()	(s->options |= SHOW_ERRORS)
#define SET_NOPATIENCE()	(s->options |= NO_PATIENCE)
#define SET_LISTENDRONE()	(s->options |= LISTEN_DRONE)
#define SET_SENDDRONE()		(s->options |= SEND_DRONE)
#define SET_OUTPUTDRONE()	(s->options |= OUTPUT_DRONE)
#define SET_IDLESCAN()		(s->options |= IDLE_SCAN)

/* listener options */
#define GET_RETPACKET()		(s->recv_opts & RETURN_PACKET)
#define GET_WATCHERRORS()	(s->recv_opts & WATCH_ERRORS)

#define SET_RETPACKET()		(s->recv_opts |= RETURN_PACKET)
#define SET_WATCHERRORS()	(s->recv_opts |= WATCH_ERRORS)

#endif
