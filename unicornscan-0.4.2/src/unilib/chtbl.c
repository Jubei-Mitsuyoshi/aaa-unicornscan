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
#include <fcntl.h>

#include <xmalloc.h>
#include <chtbl.h>

#ifdef DEBUG
# define DBG(fmt, args...) \
	fprintf(stderr, "DEBUG[%s at %s:%d]: ", __FUNCTION__, __FILE__, __LINE__);\
	fprintf(stderr, fmt, ## args); \
	fprintf(stderr, "\n");
#else
# define DBG(fmt, args...)
#endif

#define chead		chtbl_head_t
#define cnode		chtbl_node_t

#define CHTMAGIC	(uint32_t)0xdefaced1

#define MALLOC(x)	xmalloc(x)
#define FREE(x)		_xfree(x)

typedef struct cnode {
	void *data;
	uint64_t key;
	struct cnode *next;
} cnode;

typedef struct chead {
	uint32_t magic;
	uint32_t tsize;
	uint32_t size;
	cnode **table;
} chead;

/* exported */
void *chtinit(uint32_t exp_size) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;

	h_u.ptr=MALLOC(sizeof(chead));
	h_u.th->magic=CHTMAGIC;
	h_u.th->tsize=0;
	h_u.th->size=exp_size;
	h_u.th->table=(cnode **)MALLOC(sizeof(cnode *) * exp_size);
	for (j=0 ; j < exp_size ; j++) {
		h_u.th->table[j]=(cnode *)NULL;
	}

	return h_u.ptr;
}

void chtdestroy(void *lh) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;
	cnode *n=NULL, *save=NULL;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.th->magic == CHTMAGIC);

	if (h_u.th->tsize == 0) {
		return;
	}

	for (j=0 ; j < h_u.th->size ; j++) {
		DBG("freeing bucket %u\n", j);
		n=h_u.th->table[j];
		if (n == NULL) continue; /* nothing to see here, please move along */
		while (n->next != NULL) {
			save=n;
			n=n->next;
			DBG("deleting node in chain");
			FREE(save);
			save=NULL;
		}
		DBG("deleting last node in chain");
		FREE(n);
	}

	FREE(h_u.ptr);
	h_u.ptr=NULL;

	return;
}

uint32_t chtgetsize(void *th) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	return h_u.th->tsize;
}

int chtinsert(void *th, uint64_t key, void *data) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *newn=NULL, *prev=NULL;

	assert(data != NULL);
	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=(key % h_u.th->size);

	bucket=h_u.th->table[offset];

	while (bucket != NULL && key != bucket->key) {
		prev=bucket;
		bucket=bucket->next;
	}
	if (bucket != NULL && bucket->key == key) {
		return CHEXIT_KEYCOLLIDE;
	}

	newn=(cnode *)MALLOC(sizeof(cnode));
	newn->key=key;
	newn->data=data;

	if (!(prev)) {
		h_u.th->table[offset]=newn;
	}
	else {
		prev->next=newn;
	}
	newn->next=NULL;
	++h_u.th->tsize;

	return CHEXIT_SUCCESS;
}

int chtdelete(void *th, uint64_t key) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *prev=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=(key % h_u.th->size);
	bucket=h_u.th->table[offset];

	while (bucket != NULL && bucket->key != key) {
		prev=bucket;
		bucket=bucket->next;
	}
	if (bucket == NULL || bucket->key != key) {
		return CHEXIT_FAILURE;
	}
	if (prev != NULL) {
		prev->next=bucket->next;
	}
	else {
		h_u.th->table[offset]=bucket->next;
	}
	FREE(bucket->data);
	FREE(bucket);
	--h_u.th->tsize;

	return CHEXIT_SUCCESS;
}

int chtfind(void *th, uint64_t key, void **udata) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *prev=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=(key % h_u.th->size);
	bucket=h_u.th->table[offset];

	while (bucket != NULL && bucket->key != key) {
		prev=bucket;
		bucket=bucket->next;
	}

	if (bucket == NULL || bucket->key != key) {
		*udata=NULL;
		return CHEXIT_FAILURE;
	}

	*udata=bucket->data;
	return CHEXIT_SUCCESS;
}

#ifdef DEBUG
void chtstats(void *th) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;
	uint32_t clen=0;
	cnode *step=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	printf("Load Factor %f [%u items in %u slots]\n", (float)(h_u.th->tsize / h_u.th->size), h_u.th->tsize, h_u.th->size);

	for (j=0 ; j < h_u.th->size ; j++) {
		if (h_u.th->table[j]) {
			step=h_u.th->table[j]; ++clen;
			while (step->next != NULL) {
				++clen;
				step=step->next;
			}
			printf("%u [%u] ", j, clen); clen=0;
		}
	}
}
#endif

#undef chead
#undef cnode
