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

#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>

#include <scan_progs/scan_export.h>
#include <modules.h>

typedef struct _PACKED_ ntalk_msg_t {
	uint8_t			vers;		/* version (1 default)		*/
	int8_t			type;		/* message type			*/
	uint16_t		pad;		/*				*/
	uint32_t		idnum;		/* server set ID number		*/
	struct sockaddr_in	dest;		/* IP mostly for dest		*/
	struct sockaddr_in	src;		/* IP+port of the local		*/
	uint32_t		pid;		/* callers PID			*/
	char			s_user[12];	/* caller's user name		*/
	char			d_user[12];	/* remote user			*/
	char			d_tty[16];	/* remote tty			*/
} ntalk_msg_t;

int create_payload(uint8_t **, uint32_t *);
int init_module(mod_entry_t *);
void delete_module(void);

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "ntalk request");
	m->type=MI_TYPE_PAYLOAD;
	m->iver=0x0102;

	m->param_u.payload_s.sport=518;
	m->param_u.payload_s.dport=518;
	m->param_u.payload_s.payload_flags=0;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen) {
	ntalk_msg_t nm;
	struct sockaddr_in src_addr;

	*dlen=sizeof(ntalk_msg_t);

	*data=(uint8_t *)xmalloc(*dlen);
	memset(*data, 0, *dlen);

	nm.vers=1;
	nm.type=2;
	nm.pad=0xfade;
	nm.idnum=0; /* server fills this out */
	memcpy(&nm.src, &src_addr, sizeof(struct sockaddr_in));

	src_addr.sin_port=htons(518);
	src_addr.sin_addr.s_addr=s->vi->myaddr.sin_addr.s_addr;
	sprintf(nm.s_user, "%s", "scan");
	sprintf(nm.d_user, "%s", "root");

	memcpy(*data, &nm, *dlen);
	return 1;
}
