include ../../Makefile.inc

CFLAGS=$(MYCFLAGS) -I../.. -I../../../libs/fake/include $(SOLINK)

SRCS=module.c
HDRS=
OBJS=$(SRCS:.c=.o)

SOLIB=../shlibs/libudpstr.so

default: $(SOLIB)

$(SOLIB): $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(SOLINK) -o $(SOLIB) $(OBJS)

install: $(SOLIB)
	./doinstall.sh $(PREFIX)

clean:
	rm -f $(SOLIB) $(OBJS)
