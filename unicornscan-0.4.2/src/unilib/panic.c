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

#include <stdarg.h>
#ifdef WITH_BACKTRACE
#include <execinfo.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

void panic(const char *func, const char *file, int lineno, const char *msg, ...) {
	va_list ap;
	char pbuf[2048];
#ifdef WITH_BACKTRACE
	void *array[50];
	int size; /* not size_t */
#endif

	va_start(ap, msg);
	vsnprintf(pbuf, sizeof(pbuf) -1, msg, ap);


	fprintf(stderr, "PANIC IN %s [%s:%d]: %s\n", func, file, lineno, pbuf);

#ifdef WITH_BACKTRACE
	size=backtrace(array, 50);
	/* similar to backtrace_symbols but avoids malloc */
	fprintf(stderr, "Obtained %d stack frames.\n", size);
	backtrace_symbols_fd(array, size, 2);
#endif

	abort();
}
