#!/bin/sh -x

PREFIX=${1}

if [ "x${PREFIX}" = "x" ]
then
	echo Error usage $0 PREFIX
	exit 1
fi

ginstall -o root -m 755 ../shlibs/libudpstr.so ${PREFIX}/libexec/unicornscan/modules/
chcon system_u:object_r:shlib_t ${PREFIX}/libexec/unicornscan/modules/libudpstr.so 2>/dev/null
