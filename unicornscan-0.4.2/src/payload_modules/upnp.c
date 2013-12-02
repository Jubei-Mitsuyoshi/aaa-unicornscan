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

#define PACKET "M-SEARCH * HTTP/1.1\r\nHOST: %d.%d.%d.%d:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"

int create_payload(uint8_t **, uint32_t *);
int init_module(mod_entry_t *);

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "UPnP unicast payload");

	m->iver=0x0102; /* 1.1 */
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.payload_flags=0;
	m->param_u.payload_s.sport=1900;
	m->param_u.payload_s.dport=1900;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen) {
	char pack[1024];
	union {
		uint8_t ocs[4];
		uint32_t nfab;
	} k_u;

	k_u.nfab=s->ss->current_dst;

	memset(pack, 0, sizeof(pack));

	snprintf(pack, sizeof(pack) -1, PACKET, k_u.ocs[0], k_u.ocs[1], k_u.ocs[2], k_u.ocs[3]);

	*dlen=strlen(pack);
	*data=(uint8_t *)xstrdup(pack);

	return 1;
}
