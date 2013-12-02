#!/bin/sh -x

PREFIX=${1}

if [ "x${PREFIX}" = "x" ]
then
	echo Error usage $0 PREFIX
	exit 1
fi

for g in p0f.fp p0fa.fp p0fr.fp 
do
	install -o root -m 644 ${g} ${PREFIX}/share/unicornscan/
done

install -o root -m 755 ../shlibs/libp0f.so ${PREFIX}/libexec/unicornscan/modules/
