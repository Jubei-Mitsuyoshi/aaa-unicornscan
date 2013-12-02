include ../../Makefile.inc

CFLAGS=$(MYCFLAGS) -I../.. -I../../../libs/fake/include $(SOLINK)

SRCS=database.c module.c pgsqldriv.c 
HDRS=database.h logininfo.h pgsqldriv.h sqlinterface.h 
OBJS=$(SRCS:.c=.o)

SOLIB=../shlibs/libsqldriv.so

default: $(SOLIB)

$(SOLIB): $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(SOLINK) -o $(SOLIB) $(OBJS) -lpq

clean:
	rm -f $(SOLIB) $(OBJS)
