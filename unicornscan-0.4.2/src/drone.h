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
#ifndef _DRONE_H
# define _DRONE_H

#include <config.h> /* for sockaddr_in */

#define DRONE_STATUS_UNKNOWN	0
#define DRONE_STATUS_CONNECTED	1
#define DRONE_STATUS_IDENT	2
#define DRONE_STATUS_READY	4
#define DRONE_STATUS_DEAD	5
#define DRONE_STATUS_WORKING	6
#define DRONE_STATUS_WORKDONE	7
#define DRONE_STATUS_DONE	9

#define DRONE_TYPE_UNKNOWN	0
#define DRONE_TYPE_SENDER	1
#define DRONE_TYPE_LISTENER	2
#define DRONE_TYPE_OUTPUT	4

#define THE_ONLY_SUPPORTED_HWADDR_LEN 6

typedef struct drone_s {
	uint8_t status;
	uint8_t type;
	struct sockaddr_in dsa;
	int s;
	int s_rw;
	struct drone_s *next;
} drone_t;

typedef struct drone_list_head_s {
	drone_t *head;
	drone_t *bottom;
	uint8_t size;
} drone_list_head_t;

typedef struct listener_info_t {
	uint32_t myaddr;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint16_t mtu;
} listener_info_t;

/*
 * takes a string of drones to use for a scan, and constructs the drone_list structure in the settings structure
 */
int parse_drone_list(const char *);
#endif
