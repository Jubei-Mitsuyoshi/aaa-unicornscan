#!/bin/sh -x

if [ $# != 2 ]
then
	echo usage: uninstall.sh PREFIX LOCALSTATEDIR
	exit
fi

PREFIX=${1}
LOCALSTATEDIR=${2}

TARGETNAME=unicornscan
export TARGETNAME

rm -f  ${PREFIX}/bin/${TARGETNAME}
rm -f  ${PREFIX}/bin/unisniff
rm -f  ${PREFIX}/bin/uniconfigtest
rm -f  ${PREFIX}/bin/fantaip
rm -rf ${PREFIX}/doc/${TARGETNAME}
rm -rf ${PREFIX}/libexec/${TARGETNAME}
rm -rf ${LOCALSTATEDIR}/${TARGETNAME}
rm -rf ${PREFIX}/share/${TARGETNAME}
rm -f ${PREFIX}/man/man1/unicornscan*
rm -f ${PREFIX}/man/cat1/unicornscan*

whereis ${TARGETNAME}
