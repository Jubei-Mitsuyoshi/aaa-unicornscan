#!/bin/sh -xe

if [ $# != 2 ]
then
	echo "Usage: doinstall.sh PREFIX LOCALSTATEDIR"
	exit 1
fi
	
TARGETNAME=unicornscan
SENDERNAME=unisend
LISTENERNAME=unilisten
PREFIX=${1}
LOCALSTATEDIR=${2}

if [ ! -d $PREFIX -o ! -d $LOCALSTATEDIR ]
then
	mkdir -p ${PREFIX} ${LOCALSTATEDIR}
fi


export TARGETNAME PREFIX LOCALSTATEDIR SENDERNAME LISTENERNAME


if [ ! -d ${PREFIX}/libexec/${TARGETNAME} ]
then
	mkdir ${PREFIX}/libexec/${TARGETNAME}
	chown 0.0 ${PREFIX}/libexec/${TARGETNAME}
fi

install -m 755 -o root src/${TARGETNAME} ${PREFIX}/bin/
install -m 755 -o root src/tools/fantaip ${PREFIX}/bin/
install -m 755 -o root src/scan_progs/${SENDERNAME} ${PREFIX}/libexec/${TARGETNAME}/
install -m 755 -o root src/scan_progs/${LISTENERNAME} ${PREFIX}/libexec/${TARGETNAME}/

mkdir -p ${PREFIX}/doc/${TARGETNAME} 2>/dev/null
chmod 755 ${PREFIX}/doc/${TARGETNAME}
mkdir -p ${PREFIX}/libexec/${TARGETNAME}/modules
mkdir -p ${PREFIX}/share/${TARGETNAME}
install -o root -m 644 fconf/*.conf ${PREFIX}/share/${TARGETNAME}/
install -o root -m 644 fconf/port-numbers ${PREFIX}/share/${TARGETNAME}/
install -o root -m 755 src/payload_modules/*.so ${PREFIX}/libexec/${TARGETNAME}/modules/
(cd src/report_modules/p0f && make install)
#install -o root -m 755 src/output_modules/shlibs/*.so ${PREFIX}/libexec/${TARGETNAME}/modules/
install -o root -m 755 src/report_modules/shlibs/*.so ${PREFIX}/libexec/${TARGETNAME}/modules/
install -o root -m 644 docs/unicornscan.1 ${PREFIX}/man/man1/unicornscan.1
chown root.bin ${PREFIX}/libexec/${TARGETNAME}/modules/*.so
chmod 755 ${PREFIX}/libexec/${TARGETNAME}/modules/*.so

install -o root -m 644 LICENSE README misc/UDP_PAYLOADS_NEEDED TODO_BUGSTOFIX README.database ${PREFIX}/doc/${TARGETNAME}/
#install -o root -m 755 scripts/* ${PREFIX}/doc/${TARGETNAME}/ empty for now

chown -R root.0 ${PREFIX}/doc/${TARGETNAME}
chmod 755 ${PREFIX}/doc/${TARGETNAME}

if [ ! -d ${LOCALSTATEDIR}/${TARGETNAME} ]
then
	mkdir -p ${LOCALSTATEDIR}/${TARGETNAME}
	chown -R root.0 ${LOCALSTATEDIR}/${TARGETNAME}
	find ${LOCALSTATEDIR}/${TARGETNAME} -type d -exec chmod 755 {} \;
fi

chcon --help >/dev/null 2>/dev/null
if [ $? = 0 ]
then
        echo "labeling files (hopefully you have added the policy file and reloaded) otherwise this will error"
	# close enough for goverment work
	#chcon system_u:object_r:netutils_exec_t ${PREFIX}/bin/{unisniff,fantaip}
        chcon -R system_u:object_r:lib_t ${PREFIX}/libexec/${TARGETNAME}
        chcon -R system_u:object_r:shlib_t ${PREFIX}/libexec/${TARGETNAME}/modules/*.so
	chcon -R system_u:object_r:usr_t ${PREFIX}/share/${TARGETNAME}
	chcon -R system_u:object_r:unicornscan_share_t ${PREFIX}/share/${TARGETNAME}/{port-numbers,*.conf,*.fp}
	chcon system_u:object_r:man_t ${PREFIX}/man/man1/unicornscan.1
        chcon system_u:object_r:${TARGETNAME}_exec_t ${PREFIX}/bin/${TARGETNAME}
	chcon system_u:object_r:${SENDERNAME}_exec_t ${PREFIX}/libexec/${TARGETNAME}/${SENDERNAME}
	chcon system_u:object_r:${LISTENERNAME}_exec_t ${PREFIX}/libexec/${TARGETNAME}/${LISTENERNAME}

	chmod 4711 ${PREFIX}/libexec/${TARGETNAME}/${SENDERNAME}
	chmod 4711 ${PREFIX}/libexec/${TARGETNAME}/${LISTENERNAME}
fi
