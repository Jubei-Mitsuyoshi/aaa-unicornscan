include ../Makefile.inc

CFLAGS=$(MYCFLAGS) -I.. -I../scan_modules -I../../libs/fake/include
LFLGS=-L../../libs/fake/lib -L../unilib -luni

default: fantaip

fantaip: fantaip.o
	$(CC) $(CFLAGS) -o fantaip fantaip.o -lnet -lpcap $(LDADD) $(LFLGS)

unisniff: unisniff.o
	$(CC) $(CFLAGS) -o unisniff unisniff.o -lpcap $(LDADD) $(LFLGS)

clean:
	rm -f fantaip.o fantaip unisniff unisniff.o
