include ../Makefile.inc

CFLAGS=$(MYCFLAGS) -I.. -I../../libs/fake/include $(SOLINK)
MODS=ntalk.so rdns.so upnp.so sip.so

default: $(MODS)

%.so: %.c
	$(CC) $(CFLAGS) -o $@ $<

#%.so: %.c
#	$(CC) $(CFLAGS) $(SOFLAGS) -o ../modules/$@ $<

clean:
	rm -rf *.o *.lo *.so .libs
