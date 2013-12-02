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
#include <fcntl.h>
#include <unistd.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <modules.h>

/*
working! check sip.stanaphone.com
*/

#define PACKET "OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060\r\nFrom: Bob <sip:%s:5060>\r\nTo: <sip:%s:5060>\r\nCall-ID: 12312312@%s\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"

int create_payload(uint8_t **, uint32_t *);
int init_module(mod_entry_t *);

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "SIP unicast payload");

	m->iver=0x0102; /* 1.1 */
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.payload_flags=0;
	m->param_u.payload_s.sport=5060;
	m->param_u.payload_s.dport=5060;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen) {
	char pack[1024];
	char src_ip[17], dst_ip[17];
	union {
		uint8_t ocs[4];
		uint32_t nfab;
	} k_u;

	k_u.nfab=s->ss->current_dst;
	memset(dst_ip, 0, sizeof(dst_ip));
	snprintf(dst_ip, sizeof(dst_ip) -1, "%d.%d.%d.%d", k_u.ocs[0], k_u.ocs[1], k_u.ocs[2], k_u.ocs[3]);
	k_u.nfab=s->vi->myaddr.sin_addr.s_addr;
	snprintf(src_ip, sizeof(src_ip) -1, "%d.%d.%d.%d", k_u.ocs[0], k_u.ocs[1], k_u.ocs[2], k_u.ocs[3]);
	snprintf(pack, sizeof(pack) -1, PACKET, src_ip, dst_ip, dst_ip, dst_ip, dst_ip);

	*dlen=strlen(pack);
	*data=(uint8_t *)xstrdup(pack);

	return 1;
}
