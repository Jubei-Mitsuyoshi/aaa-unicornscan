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
#ifndef _PAYLOAD_H
# define _PAYLOAD_H

#define PAY_DANGEROUS 0x01

int init_payloads(void);

typedef struct payload_struct {
	uint16_t port;							/* 2 */
	int32_t local_port;						/* 2 */
	uint8_t *payload;						/* 4 */
	uint32_t payload_size;						/* 4 */
	int (*create_payload)(uint8_t **, uint32_t *);			/* 4 */
	uint16_t payload_flags;						/* 2 */
	struct payload_struct *next;					/* 4 */
	struct payload_struct *over;					/* 4 */
} payload_t;

typedef struct list_head {
	payload_t *top;
	payload_t *bottom;
	payload_t *def;
} listhead_t;

#endif
