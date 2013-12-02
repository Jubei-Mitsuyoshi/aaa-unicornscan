#!/bin/sh

ver=`cat VERSION`
cd ..
test `whoami` = "root" && chown -R root.0 ./unicornscan-$ver
tar -cvf - ./unicornscan-$ver | gzip -c9 > unicornscan-$ver.tar.gz
