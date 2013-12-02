include ../Makefile.inc

E_SRCS=compare.c master.c payload.c portfunc.c scanopts.c workunits.c
E_HDRS=$(E_SRCS:.c=.h)
E_LIBNAME=libscan.a
E_OBJS=$(E_SRCS:.c=.o)

C_SRCS=payload.c scanopts.c workunits.c
C_HDRS=$(C_SRCS:.c=.h)
C_OBJS=$(C_SRCS:.c=.o)

S_SRCS=send_packet.c portfunc.c init_packet.c
S_HDRS=$(S_SRCS:.c=.h)
S_OBJS=$(S_SRCS:.c=.o)

L_SRCS=compare.c recv_packet.c packet_parse.c
L_HDRS=$(L_SRCS:.c=.h)
L_OBJS=$(L_SRCS:.c=.o)

ENTRY=entry.c

G_HDRS=packets.h scan_export.h

G_LDADD=../modules.o ../options.o -L../parse -L../unilib -luni -lparse

CFLAGS=$(MYCFLAGS) -I.. -I../parse -I../../libs/fake/include

default: $(E_LIBNAME) $(SENDERNAME) $(LISTENERNAME)

$(E_LIBNAME): $(E_OBJS) $(E_HDRS) ../*.[ch] $(G_HDRS)
	rm -f $(E_LIBNAME)
	$(AR) $(E_LIBNAME) $(E_OBJS)
	$(RANLIB) $(E_LIBNAME)

$(SENDERNAME): $(S_OBJS) $(G_HDRS) $(S_HDRS) $(C_OBJS) $(ENTRY)
	$(CC) -c $(ENTRY) $(CFLAGS) -DBUILD_IDENT_SEND=1
	$(CC) $(CFLAGS) -o $(SENDERNAME) $(S_OBJS) $(C_OBJS) entry.o $(G_LDADD) -lpcap -lnet $(LDADD)

$(LISTENERNAME): $(L_OBJS) $(G_HDRS) $(L_HDRS) $(C_OBJS) $(ENTRY)
	$(CC) -c $(ENTRY) $(CFLAGS) -DBUILD_IDENT_RECV=1
	$(CC) $(CFLAGS) -o $(LISTENERNAME) $(L_OBJS) $(C_OBJS) entry.o $(G_LDADD) -lpcap $(LDADD)

clean:
	rm -f $(OBJS) $(E_OBJS) $(E_LIBNAME) $(L_OBJS) $(S_OBJS) $(C_OBJS) $(SENDERNAME) $(LISTENERNAME) $(ENTRY:.c=.o)

install:
	(cd ../../ && $(MAKE) install)
