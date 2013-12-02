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
#ifndef _ARCH_H
# define _ARCH_H

#include <settings.h>

/* pointer to interface name (will be malloced) */
/* returns 1 for good or -1 for bad */
int get_default_route_interface(char ** /* interface string name */);

/*
 * takes string for interface name, and a interface_into structure pointer to return information found.
 */
int get_interface_info(const char *, interface_info_t *);

/*
 * sets real and effective user to NOPRIV_USER (nobody?) and returns or aborts the program if it fails
 * or something completely different.
 */
void drop_privs(void);

#endif
