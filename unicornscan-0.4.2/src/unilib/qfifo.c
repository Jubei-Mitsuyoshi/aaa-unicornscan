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

#include <panic.h>
#include <qfifo.h>
#include <xmalloc.h>

#define qnode		qfifo_node_t
#define qfifo		qfifo_head_t

#define QFIFOMAGIC	0xdeafbabe
#define MALLOC(x)	xmalloc(x)
#define FREE(x)		_xfree(x)

/* q cause its cute, even though c != q */

typedef struct qnode {
	struct qnode *last;
	struct qnode *next;
	void *bucket;
} qnode;

typedef enum { pfifo, plifo } personality_t;

typedef struct qfifo {
	uint32_t magic;
	personality_t pers;
	qnode *top;
	qnode *bottom;
	uint32_t len;
} qfifo;

/* INTERNAL PROTOTYPES */
static void *_qfifo_init(personality_t ) _MALLOC_;

/* FUNCTIONS */
void *fifo_init(void) {
	return _qfifo_init(pfifo);
}
void *lifo_init(void) {
	return _qfifo_init(plifo);
}

static void *_qfifo_init(personality_t type) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;

	f_u.ptr=MALLOC(sizeof(qfifo));

	f_u.fifo->magic=QFIFOMAGIC;
	f_u.fifo->pers=type;
	f_u.fifo->top=NULL;
	f_u.fifo->bottom=NULL;
	f_u.fifo->len=0;
	return f_u.ptr;
}

void fifo_destroy(void *fifo) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;

	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");
	if (f_u.fifo->len == 0) {
		xfree(f_u.ptr);
	}
	else {
		PANIC("attempt to destroy non-empty %s", f_u.fifo->pers == pfifo ? "fifo" : "lifo");
	}
	return;
}

/*
 * Function: fifo_push O(1)
 * we always add to the top. dont ask why. i dont know. i guess any normal person would have put it at the bottom,
 * but thats just what they would expect me to do.
 */
uint32_t fifo_push(void *fifo, void *water) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	qnode *qnew=NULL;

	assert(fifo != NULL); assert(water != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	qnew=(qnode *)MALLOC(sizeof(qnode));
	qnew->bucket=water;

	if (f_u.fifo->top == NULL) {		/* The fifo is empty. */
		assert(f_u.fifo->bottom == NULL);
		f_u.fifo->top=qnew;
		f_u.fifo->bottom=qnew;
		qnew->last=NULL;
	}
	else {
		assert(f_u.fifo->top->next == NULL);
		f_u.fifo->top->next=qnew;
		qnew->last=f_u.fifo->top;
		f_u.fifo->top=qnew;
	}
	qnew->next=NULL; /* nothing on top of this node */

	return ++f_u.fifo->len;
}

/*
 * Function: fifo_pop O(1)
 */
void *fifo_pop(void *fifo) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	void *data=NULL; /* the data we return */
	qnode *node=NULL; /* could be top or bottom depending on personality */

	assert(fifo != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	if (f_u.fifo->len == 0) {
		return NULL; /* well that was easy */
	}

	if (f_u.fifo->len == 1) {
		if (f_u.fifo->top != f_u.fifo->bottom) {
			PANIC("fifo top and bottom pointers should be the same for a 1 length fifo");
		}
		node=f_u.fifo->top;
		f_u.fifo->top=NULL;
		f_u.fifo->bottom=NULL;
	}
	else if (f_u.fifo->pers == pfifo) {
		/*
		 * first in first out so remove from the bottom where old data is
		 */
		if (f_u.fifo->bottom == NULL) {
			PANIC("fifo->bottom is NULL on pop");
		}
		node=f_u.fifo->bottom;
		/* the new bottom is one higher */
		f_u.fifo->bottom=f_u.fifo->bottom->next;
		f_u.fifo->bottom->last=NULL;
	}
	else { /* its a lifo then, remove from the top where new data is */
		if (f_u.fifo->top == NULL) {
			PANIC("fifo->top is NULL on pop");
		}
		node=f_u.fifo->top;
		/* the new top is one lower */
		f_u.fifo->top=f_u.fifo->top->last;
		f_u.fifo->top->next=NULL;
	}
	data=node->bucket;
	--f_u.fifo->len;

	FREE(node);

	return data;
}
/*
 * Function: fifo_walk O(n)
 */
void fifo_walk(void *fifo, void (*walk_func)(const void *)) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	qnode *walk=NULL; /* could be top or bottom depending on personality */

	assert(fifo != NULL); assert(walk_func != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	if (f_u.fifo->len == 0) {
		return; /* well that was easy */
	}

	if (f_u.fifo->top == NULL) PANIC("fifo pointers broken in fifo_walk");

	for (walk=f_u.fifo->bottom ; walk != NULL; walk=walk->next) {
		walk_func((const void *)walk->bucket);
	}

	return;
}

/* Function: fifo_delete_first O(n)
 * XXX this doesnt obey fifo/lifo search ordering
 * This function traces through the fifo and removes the first node which matches the data structure
 * pointed to by water. An integer value for the length of the fifo after this operation has completed
 * will be returned.
 */
uint32_t fifo_delete_first(void *fifo, const void *water, int (*compare)(const void *, const void *), int freedata) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	qnode *cur=NULL, *next=NULL;

	assert(fifo != NULL);
	assert(water != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	if (f_u.fifo->len == 0) {
		return 0;
	}

	assert(f_u.fifo->bottom->bucket != NULL);
	cur=f_u.fifo->bottom;

	if (f_u.fifo->len == 1) {
		if (compare((const void *)cur->bucket, water) == 0) {
			if (freedata) FREE(cur->bucket);	/* The only node in the fifo is a match so empty it. */
			FREE(cur);
			f_u.fifo->top=NULL;
			f_u.fifo->bottom=NULL;
			--f_u.fifo->len;
		}
		return f_u.fifo->len;
	}

	while (1) {
		if (compare((const void *)cur->bucket, water) == 0) {
			qnode *node=NULL;
			void *data=NULL;
			node=cur;
			data=cur->bucket;
			if (cur == f_u.fifo->top) {		/* The last node in the fifo matches. */
				f_u.fifo->top=cur->last;
				f_u.fifo->top->next=NULL;
			}
			else if (cur == f_u.fifo->bottom) {	/* The first node in the fifo matches. */
				f_u.fifo->bottom=cur->next;
				f_u.fifo->bottom->last=NULL;
			}
			else { /* remove from list */
				next=cur->next;
				cur=cur->last;
				cur->next=next;
				next->last=cur;
			}
			FREE(node);
			if (freedata) FREE(data);
			return --f_u.fifo->len;
		}
		if (cur->next == NULL) break;
		cur=cur->next;
	}
	return f_u.fifo->len;
}

/* Function: fifo_find O(n)
 * This function searches for the first node in the fifo which matches the structure pointed
 * to by water and returns a pointer to this node. A NULL pointer is returned if there is no
 * match.
 */
void *fifo_find(void *fifo, const void *water, int (*compare)(const void *, const void *)) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	qnode *cur=NULL;

	assert(fifo != NULL);
	assert(water != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	if (f_u.fifo->len == 0) {
		return NULL;
	}
	assert(f_u.fifo->bottom->bucket != NULL);
	cur=f_u.fifo->bottom;

	if (f_u.fifo->len == 1) {
		if (compare((const void *)cur->bucket, water) == 0) {
			return cur;
		}
		return NULL;
	}

	while (1) {
		if (compare((const void *)cur->bucket, water) == 0) {
			return cur;
		}
		if (cur->next == NULL) break;
		cur=cur->next;
	}
	return NULL;
}


/*
 * Function: order_fifo
 * This function performs a single radix ordering operation on the fifo based on the
 * function pointer compare and the direction (ascending|descending) specified by the
 * caller, the return value is the integer length of the list.
 */
uint32_t fifo_order(void *fifo, int (*compare)(const void *, const void *), int direction) {
	union {
		void *ptr;
		qfifo *fifo;
	} f_u;
	qnode *cur=NULL;
	void *data=NULL;
	uint32_t i=0, j=0;

	assert(fifo != NULL);
	f_u.ptr=fifo;
	if (f_u.fifo->magic != QFIFOMAGIC) PANIC("fifo has wrong magic number");

	if (f_u.fifo->len == 0 || f_u.fifo->len == 1) return f_u.fifo->len;	/* It is necessarily ordered. */

	for (i=f_u.fifo->len ; i > 0 ; i--) {
		cur=f_u.fifo->bottom;
		data=cur->bucket;
		for (j=1 ; j < i ; j++) {
			cur=cur->next;
			if (compare(data, (const void *)cur->bucket) == direction) { data=cur->bucket; }
		}
		assert((f_u.fifo->len - 1) == fifo_delete_first(f_u.ptr, data, compare, 0));
		assert((f_u.fifo->len + 1) == fifo_push(f_u.ptr, data));
	}
	return f_u.fifo->len;
}

#undef qfifo
#undef qnode
