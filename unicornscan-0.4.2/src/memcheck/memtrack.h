#ifndef _MEMTRACK_H
# define _MEMTRACK_H

/* exported to be used with macros that add info */
void *jmalloc(size_t /* size */, const char * /* func */, const char * /* file */, int /* lineno */);
char *jstrdup(const char * /* string */, const char * /* func */, const char * /* file */, int /* lineno */);
void jfree(void * /* ptr */, const char * /* func */, const char * /* file */, int /* lineno */);
void jmemreport(void);

#define xmalloc(sz) jmalloc(sz, __FUNCTION__, __FILE__, __LINE__)
#define xstrdup(str) jstrdup(str, __FUNCTION__, __FILE__, __LINE__)

#define _xfree(ptr) jfree(ptr, __FUNCTION__, __FILE__, __LINE__)
#define xfree(ptr) _xfree(ptr); ptr=NULL

#endif /* included */
