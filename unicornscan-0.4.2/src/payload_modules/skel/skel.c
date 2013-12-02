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

#include <scan_modules/scan_export.h>
#include <settings.h>
#include <payload.h>
#include <xmalloc.h>
#include <modules.h>
#include <output.h>

int create_payload(uint8_t **, uint32_t *);
int init_module(mod_entry_t *);

typedef struct _PACKED_ test_msg_t {
	uint8_t id1;
	uint8_t id2;
	uint16_t pad;
	char msg[16];
} test_msg_t;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "yourname");
	snprintf(m->desc, sizeof(m->desc) -1, "SKEL (EXAMPLE) MODULE");

	m->iver=0x0101; /* 1.1 */
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.payload_flags=0;
	m->param_u.payload_s.sport=6666;
	m->param_u.payload_s.dport=6666;
	return 1;
}

int create_payload(uint8_t **data, uint32_t *dlen) {
	test_msg_t bm;

	*dlen=sizeof(test_msg_t);

	*data=xmalloc(*dlen);
	memset(*data, 0, *dlen);
	bm.id1=0xde;
	bm.id2=0xad;
	bm.pad=0x4141;
	memset(&bm.msg, 'B', sizeof(bm.msg));

	memcpy(*data, &bm, *dlen);
	return 1;
}
