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
#ifndef _OUTPUT_H
# define _OUTPUT_H

/* output types:
	INFO: informational messages (program blah starting [version blah])
	DATA: port 5632[blah] open ttl 200
	WARN: unknown interface link type foo!
	ERR : permission denied
	VERB: loading module blah
	DBG1: recv icmp error type 5 code 222
	DBG2: sending to host blah:345
*/

#define M_INFO	0
#define M_OUT	1
#define M_WARN	2
#define M_ERR	3
#define M_VERB	4
#define M_DBG1	5
#define M_DBG2	6

#define MSG(type, fmt, args...) display_builtin(type, __FILE__, __LINE__, fmt, ## args);
void display_builtin(unsigned int, const char *, int, const char *, ...) _PRINTF45_;
void hexdump(const uint8_t *, size_t );

#endif
