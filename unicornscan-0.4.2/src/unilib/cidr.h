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
#ifndef _CIDR_H
# define _CIDR_H

/*
 *	returns:
 *		1: no error
 *		-1: error condition with error message in error string pointer
 *	arguments:
 *		[output] 32bit unsigned lowip range (eg: the int value of 192.168.1.1)
 *		[output] 32bit unsigned highip range (eg: the int value of 192.168.2.255)
 *		[input] ascii character string for sscanf to read in format X.X.X.X/Y
 *		[output] pointer to char buffer in case of error
 *		[input] size of output buffer (ALL will be written to)
 */

int get_cidr(uint32_t * /* lowip */  , uint32_t * /* highip  */, const char * /* in str */,
		 char *	/* err str */, size_t	  /* str len */);

#endif /* _CIDR_H */
