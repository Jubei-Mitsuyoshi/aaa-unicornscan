include Makefile.inc

SRCS=drone.c getconfig.c main.c modules.c options.c
HDRS=$(SRCS:.c=.h) config.h settings.h
OBJS=$(SRCS:.c=.o)

CFLAGS=$(MYCFLAGS)
LIBS=-lscan -luni -lparse -lpcap -lnet $(LDADD)
LIBDIRS=-L./unilib -L./scan_progs -L./parse -L../libs/fake/lib
TARGETNAME=unicornscan

default: compile.h myversion.h $(OBJS) unilib_d parse_d scan_d Makefile p_modules p0f_module udpstr_module $(OPT_MODS) tools_d
	$(CC) $(CFLAGS) -o unicornscan $(OBJS) $(LIBDIRS) $(LIBS)

myversion.h: ../VERSION
	cat myversion.h.in | sed 's/#VERSION#/'"`cat ../VERSION`"'/' > myversion.h

compile.h:
	./compiledby.sh > compile.h

unilib_d:
	(cd unilib && $(MAKE))

parse_d:
	(cd parse && $(MAKE))

scan_d:
	(cd scan_progs && $(MAKE))

p_modules:
	(cd payload_modules && $(MAKE))

db_module:
	(cd output_modules/database && $(MAKE))

p0f_module:
	(cd report_modules/p0f && $(MAKE))

udpstr_module:
	(cd report_modules/udpstr && $(MAKE))

tools_d:
	(cd tools && $(MAKE))

clean:
	rm -f $(OBJS) $(TARGETNAME) myversion.h compile.h core core.* *.core
	cd unilib && $(MAKE) clean
	cd parse && $(MAKE) clean
	cd scan_progs && $(MAKE) clean
	cd output_modules/database && $(MAKE) clean
	cd report_modules/p0f && $(MAKE) clean
	cd report_modules/udpstr && $(MAKE) clean
	cd payload_modules && $(MAKE) clean
	cd tools && $(MAKE) clean

install: default
	(cd .. && $(MAKE) install)

splint: myversion.h
	splint -warnposix *.c -I. -I../libs/fake/include  -D__linux__ > warnings
