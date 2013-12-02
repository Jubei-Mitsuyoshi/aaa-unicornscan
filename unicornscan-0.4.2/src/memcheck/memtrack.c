#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <stdint.h>

static size_t _m_malloced=0;
static size_t _m_nodes=0;

typedef struct memory_track_t {
	void *chunk;
	size_t size;
	uint8_t cntrl;

	char func[64];
	char file[64];
	int lineno;

	struct memory_track_t *next;
} mem_track_t;

static mem_track_t *memtrk=NULL;

#ifdef MEMTRACK_DEBUG
#define DPRINT(fmt, args...) printf("DEBUG: %s():%s:%d: ", __FUNCTION__, __FILE__, __LINE__); printf(fmt, ## args); printf("\n"); fflush(stdout)
#else
#define DPRINT(fmt, args...)
#endif


/* internal */
static void insert_memlist(void *, size_t , const char *, const char *, int );
static size_t delete_memlist(void *);
static mem_track_t *find_memlist(void *, mem_track_t **);

static void insert_memlist(void *chunk, size_t size, const char *func, const char *file, int lineno) {
	mem_track_t *new=NULL;

	if (memtrk == NULL) {
		DPRINT("insert root memlist: adding ptr=%p size=%d from %s():%s:%d", chunk, size, func, file, lineno);
		memtrk=malloc(sizeof(mem_track_t));
		memset(memtrk, 0, sizeof(mem_track_t));

		memtrk->next=NULL;

		memtrk->chunk=chunk;
		memtrk->size=size;
		sprintf(memtrk->func, "%s", func);
		sprintf(memtrk->file, "%s", file);
		memtrk->lineno=lineno;

	}
	else {
		mem_track_t *old=NULL;

		DPRINT("insert memlist: adding ptr=%p size=%d from %s():%s:%d", chunk, size, func, file, lineno);
		for (new=memtrk ; new != NULL; old=new, new=new->next) {
		}

		new=malloc(sizeof(mem_track_t));
		memset(new, 0, sizeof(mem_track_t));
		old->next=new;
		new->next=NULL;
		new->size=size;
		new->chunk=chunk;
		sprintf(new->func, "%s", func);
		sprintf(new->file, "%s", file);
		new->lineno=lineno;
	}

	_m_nodes++;
	return;
}

static mem_track_t *find_memlist(void *chunk, mem_track_t **before) {
	mem_track_t *walk=NULL;

	*before=NULL;
	for (walk=memtrk; walk != NULL ; walk=walk->next) {
		if (walk->chunk == chunk) {
			DPRINT("returning from find memlist with walk %p and before %p", walk, before);
			return walk;
		}
		DPRINT("before = %p", *before); *before=walk;
	}

	return NULL;
}

static size_t delete_memlist(void *chunk) {
	mem_track_t *walk=NULL, *before=NULL;
	size_t ret=0;

	assert(chunk != NULL);

	walk=find_memlist(chunk, &before);
	if (walk == NULL) {
		return 0;
	}

	if (before != NULL) {
		DPRINT("deleting in the middle of the list");
		before->next=walk->next;
		ret=walk->size;
	}
	else if (walk->next != NULL) {
		DPRINT("must be the root node we are deleting, ill make a new one!");
		memtrk=walk->next;
	}
	else {
		DPRINT("killed the whole list");
		memtrk=NULL;
	}

	ret=walk->size;
	memset(walk->chunk, 0x58, walk->size);
	free(walk->chunk);
	memset(walk, 0, sizeof(mem_track_t));
	free(walk);
	_m_nodes--;

	return ret;
}

void *jmalloc(size_t size, const char *func, const char *file, int lineno) {
	void *ptr=NULL;

	ptr=malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "out of memory");
		abort();
	}

	_m_malloced += size;

	insert_memlist(ptr, size, func, file, lineno);

	DPRINT("malloc()'ed %d bytes %d total in %d allocations", size, _m_malloced, _m_nodes);

	return ptr;
}

void jfree(void *chunk, const char *func, const char *file, int lineno) {
	size_t sz=0;

	if (chunk == NULL) {
		fprintf(stderr, "refusing to free a NULL pointer");
		abort();
	}

	sz=delete_memlist(chunk);
	_m_malloced -= sz;

	if (sz == 0) {
		fprintf(stderr, "free a non-existant pointer from %s():%s:%d", func, file, lineno);
		abort();
	}
	DPRINT("free()'ed %d bytes %d left total (in %d allocations)", sz, _m_malloced, _m_nodes);

	return;
}

void jmemreport(void) {
	mem_track_t *walk=NULL;

	for (walk=memtrk ; walk != NULL ; walk=walk->next) {
		printf("Remaining chunk of %d bytes allocated from %s():%s:%d\n", walk->size, walk->func, walk->file, walk->lineno);
	}
	return;
}

char *jstrdup(const char *p, const char *func, const char *file, int lineno) {
	char *_p=NULL;
	size_t len=0;

	len=strlen(p);
	_p=malloc(len + 1);
	if (_p == NULL) {
		fprintf(stderr, "strdup: out of memory");
		abort();
	}
	memcpy(_p, (const void *)p, len);
	_p[len]='\0';

	_m_malloced += len;

	insert_memlist(_p, len, func, file, lineno);

        DPRINT("malloc()'ed %d bytes %d total in %d allocations", size, _m_malloced, _m_nodes);

	return _p;
}
