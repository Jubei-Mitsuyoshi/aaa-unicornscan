include ../src/Makefile.inc

PCAPVER=0.8.3
CFLAGS=$(MYCFLAGS)

default: pcap_test libnet_test

pcap_test: pcap_test.c
	($(CC) $(CFLAGS) -o pcap_test pcap_test.c -lpcap $(LDADD) 2>/dev/null || $(MAKE) libpcap)

libnet_test: libnet_test.c
	($(CC) $(CFLAGS) -o libnet_test libnet_test.c -lpcap -lnet $(LDADD) 2>/dev/null || $(MAKE) libnet)
	

libnet: libnet/stamp

libnet.tar.gz:
	wget http://www.packetfactory.net/libnet/dist/libnet.tar.gz

libnet/stamp: libnet.tar.gz
	zcat libnet.tar.gz | tar -xvf -
	cd libnet && patch -p1 < ../libnet-nosample.patch && CPPFLAGS="-I`pwd`/../fake/include" LDFLAGS="-L`pwd`/../fake/lib" CFLAGS="$(BASECFLAGS)" ./configure --prefix=`pwd`/../fake && CPPFLAGS="-I`pwd`/../fake/include" LDFLAGS="-L`pwd`/../fake/lib" CFLAGS="$(BASECFLAGS)" $(MAKE) && $(MAKE) install && touch stamp
	cd ..

libpcap: libpcap-$(PCAPVER)/stamp

libpcap-$(PCAPVER)/stamp: libpcap-$(PCAPVER).tar.gz
	zcat libpcap-$(PCAPVER).tar.gz | tar -xvf -
	cd libpcap-$(PCAPVER) && CFLAGS="$(BASECFLAGS)" ./configure --prefix=`pwd`/../fake && CFLAGS="$(BASECFLAGS)" $(MAKE) && $(MAKE) install && touch stamp

libpcap-$(PCAPVER).tar.gz:
	wget http://tcpdump.org/release/libpcap-$(PCAPVER).tar.gz

clean:
	rm -rf fake libnet libpcap-$(PCAPVER) pcap_test libnet_test
