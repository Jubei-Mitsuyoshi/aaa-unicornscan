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

#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/arc4random.h>
#include <unilib/output.h>
#include <unilib/panic.h>
#include <payload.h>
#include <settings.h>
#include <modules.h>

static listhead_t *lh=NULL;

int init_payloads(void) {

	lh=(listhead_t *)xmalloc(sizeof(listhead_t));
	memset(lh, 0, sizeof(listhead_t));

	lh->bottom=NULL;
	lh->top=NULL;

	if (s->verbose > 3) {
		MSG(M_DBG1, "Setting up default payload");
	}
	lh->def=(payload_t *)xmalloc(sizeof(payload_t));
	memset(lh->def, 0, sizeof(payload_t));

	lh->def->port=0;
	lh->def->local_port=-1;
	lh->def->payload=(uint8_t *)xstrdup("AAAAAAAAAAAAAAAA\r\n");
	lh->def->payload_size=18;
	lh->def->next=NULL;
	lh->def->over=NULL;

	return 1;
}

int add_payload(uint16_t port, int32_t local_port, const uint8_t *payload, uint32_t payload_size, int (*create_payload)(uint8_t **, uint32_t *), uint16_t payload_flags) {
	payload_t *pnew=NULL;

	if (lh == NULL) {
		PANIC("add_payload called before init_payloads!");
	}

	pnew=(payload_t *)xmalloc(sizeof(payload_t));
	memset(pnew, 0, sizeof(payload_t));
	pnew->port=port;
	pnew->local_port=local_port;
	if (payload_size) {
		pnew->payload=(uint8_t *)xmalloc(payload_size);
		memcpy(pnew->payload, payload, payload_size);
	}
	else {
		pnew->payload=NULL;
	}
	pnew->payload_size=payload_size;
	pnew->create_payload=create_payload;
	pnew->next=NULL;
	pnew->over=NULL;

	if (lh->top != NULL) {
		payload_t *current=NULL;

		current=lh->top;

		while (1) {
			if (current->port == port) {
				if (s->verbose > 4) MSG(M_DBG2, "extra payload for port %d", port);
				while (current->over != NULL) {
					if (s->verbose > 5) MSG(M_DBG2, "steping over on payload list");
					current=current->over;
				}
				assert(current->over == NULL);
				current->over=pnew;
				pnew->over=NULL;
			}
			if (current->next == NULL) break;
			current=current->next;
		}
		assert(current->next == NULL);
		current->next=pnew;
		assert(lh->bottom == current);
		lh->bottom=pnew;
	}
	else {
		if (s->verbose > 4) MSG(M_DBG2, "added first node to payload list");
		lh->bottom=pnew;
		lh->top=pnew;
	}


	return 1;
}

int get_payload(uint16_t indx, uint16_t port, uint8_t **data, uint32_t *payload_s, int32_t *local_port, int (**payload_init)(uint8_t **, uint32_t *), uint16_t payload_flags) {
	payload_t *current=NULL;

	current=lh->top;
	if (s->verbose > 5) MSG(M_DBG2, "Payload for port %d searching starting at %p...", port, current);

	while (current != NULL && current->next != NULL) {
		if (current->port == port) {
			if (indx == 0) {
				if (s->verbose > 5) MSG(M_DBG2, "found a payload");
				*payload_s=current->payload_size;
				*local_port=current->local_port;
				*payload_init=current->create_payload;
				*data=current->payload;
				return 1;
			}
			else {
				uint16_t pos=0;

				while (current->over != NULL) {
					current=current->over;
					pos++;
					if (pos == indx) {
						*payload_s=current->payload_size;
						*local_port=current->local_port;
						*payload_init=current->create_payload;
						*data=current->payload;
						return 1;
					}
				}
				return 0;
			}
		}
		current=current->next;
	}

	if (indx == 0 && (GET_DEFAULT())) {
		assert(lh->def->payload != NULL);
		*payload_s=lh->def->payload_size;
		*local_port=lh->def->local_port;
		if (s->verbose > 5) MSG(M_DBG2, "Found default payload at %p index 0 and port %d local_port %d and size %d", lh->def->payload, port, lh->def->local_port, lh->def->payload_size);
		*data=lh->def->payload;
		return 1;
	}
	if (s->verbose > 4) MSG(M_DBG2, "No payload found for port %d index %d", port, indx);

	return 0;
}
