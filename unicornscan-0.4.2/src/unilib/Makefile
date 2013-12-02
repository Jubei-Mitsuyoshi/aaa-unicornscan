include ../Makefile.inc

CFLAGS=$(MYCFLAGS) -I.. -I. -I../parse -I../../libs/fake/include

SRCS=arc4random.c arch.c chtbl.c cidr.c output.c panic.c pcaputil.c qfifo.c rbtree.c terminate.c tutil.c xipc.c xmalloc.c xpoll.c 
D_SRCS=gtod.c tsc.c sleep.c xdelay.c
D_HDRS=xdelay.h
OBJS=$(SRCS:.c=.o) $(D_SRCS:.c=.o)
HDRS=$(SRCS:.c=.h) $(D_HDRS)
LIBNAME=libuni.a

default: $(LIBNAME)

$(LIBNAME): $(OBJS)
	rm -f $(LIBNAME)
	$(AR) $(LIBNAME) $(OBJS)
	$(RANLIB) $(LIBNAME)

clean:
	rm -f $(OBJS) $(LIBNAME)

install:
	(cd ../../ && $(MAKE) install)
