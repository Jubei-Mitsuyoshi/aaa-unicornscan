default:
	(cd libs && make)
	(cd src && make)

clean:
	(cd src && make clean)
	find . -name ".*.swp" -exec ls -alh {} \;
	find . -name "*core*" -exec ls -lah {} \;

distclean: clean
	rm -f src/compile.h
	(cd libs && make clean)

dist: distclean
	find . -exec touch {} \; -print
	cd src/parse && make prepare
	./tarup.sh

install: default
	./doinstall.sh /usr/local /var

uninstall:
	./uninstall.sh /usr/local /var

src/unicornscan:
	(cd src && make)
