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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <panic.h>

void *_xmalloc(size_t n, const char *func, const char *file, int lineno) {
	void *p=NULL;

	//printf("Xmalloc in %s %s:%d\n", func, file, lineno);
	if (n < 1) {
		PANIC("attempt to allocate 0 or less bytes of memory");
	}

	p=malloc(n);

	if (p == NULL) {
		PANIC("malloc failed");
	}
	return(p);
}

void _xfree(void *p) {
	if (p == NULL) {
		PANIC("attempt to free a NULL pointer");
	}
	free(p);
	return;
}

char *xstrdup(const char *p) {
	char *_p=NULL;

	_p=strdup(p);
	if (_p == NULL) {
		PANIC("strdup failed");
	}
	return _p;
}
