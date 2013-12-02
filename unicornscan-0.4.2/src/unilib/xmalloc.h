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
#ifndef XMALLOC_H
 #define XMALLOC_H

#include <config.h>

#define xfree(ptr) _xfree(ptr); ptr=NULL
#define xmalloc(size) _xmalloc(size, __FUNCTION__, __FILE__, __LINE__);

void *_xmalloc(size_t , const char *, const char *, int) _MALLOC_;
void _xfree(void *);
char *xstrdup(const char *) _MALLOC_;

#endif
