include ../Makefile.inc

SRCS=parse.tab.c lex.yy.c putil.c
HDRS=putil.h
OBJS=$(SRCS:.c=.o)
CFLAGS=$(MYCFLAGS) -I.. -I../unilib -I. -I../../libs/fake/include
LIBNAME=libparse.a
BOB=parse.tab.c lex.yy.c

default: $(LIBNAME)

prepare: $(BOB)

$(LIBNAME): $(OBJS) $(HDRS)
	$(AR) $(LIBNAME) $(OBJS)
	$(RANLIB) $(LIBNAME)

parse.tab.c: parse.y
	bison -d parse.y

lex.yy.c: parse.l
	flex -8sB parse.l

clean:
	rm -f $(OBJS) parse.tab.c parse.tab.h lex.yy.c $(LIBNAME)
