# gcc only
CC=gcc

PREFIX=/usr/local
LOCALSTATEDIR=/var
TARGETNAME=unicornscan
SENDERNAME=unisend
LISTENERNAME=unilisten

# its fine to do almost anything here, just dont remove the includes
MYCFLAGS=-O1 -ggdb -Wall -Wshadow -Wcast-align -Wcast-qual -Wchar-subscripts -Wno-deprecated-declarations -Wformat-security -Wimplicit -Wsign-compare -Wuninitialized -Wunused -Wwrite-strings -I. -rdynamic -I../libs/fake/include -I/usr/local/include -L/usr/local/lib -DPREFIX=\"$(PREFIX)\" -DLOCALSTATEDIR=\"$(LOCALSTATEDIR)\" -DTARGETNAME=\"$(TARGETNAME)\" -DSENDERNAME=\"$(SENDERNAME)\" -DLISTENERNAME=\"$(LISTENERNAME)\"

# sometimes you dont have a link to gmake, if your make _is_ gmake, you can use make then, but we need GNU make (for now)
MAKE=gmake

# If you have PostGreSQL installed, then uncomment this
#OPT_MODS=db_module

# solaris needs -lsocket -lnsl -lposix4 -lresolv
# solaris linux need -ldl

# solaris example
#LDADD=-lsocket -lnsl -ldl -lposix4 -lresolv

# freebsd, netbsd example
#LDADD=

# linux example
LDADD=-ldl

# selinux example
#LDADD=-ldl -lselinux

SOLINK=-rdynamic -shared -fpic

AR=ar cru
RANLIB=ranlib
