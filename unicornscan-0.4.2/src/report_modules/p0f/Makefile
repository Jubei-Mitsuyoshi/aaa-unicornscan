include ../../Makefile.inc

CFLAGS=$(MYCFLAGS) -I../.. $(SOLINK) -I../../../libs/fake/include
#CC=gcc # this code wont compile with g++

SRCS=p0f.c module.c
HDRS=fpentry.h mtu.h p0f-config.h tcp.h tos.h 
OBJS=$(SRCS:.c=.o)

SOLIB=../shlibs/libp0f.so

default: $(SOLIB)

$(SOLIB): $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(SOLINK) -o $(SOLIB) $(OBJS)

install: $(SOLIB)
	./doinstall.sh $(PREFIX)

clean:
	rm -f $(SOLIB) $(OBJS)
