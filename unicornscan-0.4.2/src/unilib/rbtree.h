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
#ifndef _RBTREE_H
# define _RBTREE_H

void     *rbinit  (uint32_t /* expected size (nop here)*/);

int      rbinsert (void * /* rh */, uint64_t /* key */, void *  /* data */    );
int      rbdelete (void * /* rh */, uint64_t /* key */                        );
int      rbfind   (void * /* rh */, uint64_t /* key */, void ** /* data_ptr */);
uint32_t rbgetsize(void * /* rh */);
void     rbdestroy(void * /* rh */);
uint32_t rbstats  (void * /* rh */);

#endif /* _RBTREE_H */
