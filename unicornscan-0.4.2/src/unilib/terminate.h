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
#ifndef _TERMINATE_H
# define _TERMINATE_H

#define TERM_NORMAL	0
#define TERM_ERROR	1

/*
 *	returns:
 *		N/A
 *
 *	arguments:
 *		[input] integer code, 0 assumed to be somewhat normal, otherwise an error is
 *		implied. if it is not a normal exit, then a system error will also be printed
 *		as a dignostic. also as some versions of _exit do not flush file descriptors
 *		fflush will be called with NULL as a file stream for this reason.
 */

void terminate(int /* code */) _NORETURN_;

#endif /* _TERMINATE_H */
