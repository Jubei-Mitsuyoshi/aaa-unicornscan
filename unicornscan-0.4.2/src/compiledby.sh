#!/bin/sh

printf '#define COMPILE_STR "Compiled by %s on %s at %s"\n' "`whoami`" "`uname -snrm`" "`date`"
