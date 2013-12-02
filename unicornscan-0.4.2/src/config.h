/**********************************************************************
 * Copyright (C) (2004) (Jack Louis) <jack@dyadsecurity.com>          *
 *                                                                    *
 * This program is free software; you can redistribute it and/or      *
 * modify it under the terms of the GNU General Public License        *
 * as published by the Free Software Foundation; either               *
 * version 2 of the License, or (at your option) any later            *
 * version.                                                           *
 *                                                                    *
 * This program is distributed in the hope that it will be useful,    *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
 * GNU General Public License for more details.                       *
 *                                                                    *
 * You should have received a copy of the GNU General Public License  *
 * along with this program; if not, write to the Free Software        *
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.          *
 **********************************************************************/

/*
 * you have selinux, or you dont. its not that complex
 * only enable this if you _always use_ selinux, you will know
 * if you do, otherwise comment this out
 */
//#define WITH_SELINUX

/*
 * define if you have __progname, solaris doesnt for example, youll error when you link if you dont
 * say yes, if you have link errors, comment it out.
 */
#define WITH_PROGNAME

/* 
 * GNU/Linux with /usr/include/execinfo.h, otherwise comment it out
 */
//#define WITH_BACKTRACE

/*
 * GNU/Linux and some other (newer) systems might have this, its ok to say no
 * even if you dont have this, you just wont have the -- options on the command line
 */
#define WITH_LONGOPTS

/*
 * lots of newer bsd'ish systems have this as well as some (newer?) linux systems. youll need this
 * but you _never need_ it with linux. if in doubt say no. it will still compile if you say no
 * and are not running linux, however it likely will not work arp scanning.
 * side note: dont use this on linux, its broken!
 */
/* #define WITH_IFADDRS */

/*
 * XXX
 * if you define WITH_IFADDRS you BETTER HAVE THE FILE /usr/include/net/if_dl.h otherwise dont bother
 * { and also /usr/include/ifaddrs.h }
 * (HINT: define both of none of WITH_IFADDRS and WITH_IF_DL, if you only define one, expect serious compile errors)
 * if you have solaris, then you need this, and pray things work out for you.
 */
/* #define WITH_IF_DL */

/*
 * bsd'ish boxes with bpf stuff included with the system, otherwise dont use it.
 * linux people dont need this really even if they think they have this
 */
/*#define HAVE_BPF_H */

/*
 * most people these days have this file, if you _dont_ have it, then youll need to put the "full path"
 * to a file that can be read that contains random data.
 */
#define RANDOM_DEVICE "/dev/urandom"

/*
 * if you have an early compile error with alot of uint?_t errors, try defining this.
 * but you shouldnt need it as inttypes normally will include stdint.h
 */
/* #define HAVE_STDINT_H */

/* FIXME
 * with linux, define this (or if you have /proc/net/route)
 * otherwise use we will make due, remeber to use -i if you dont have /proc/net/route
 */
#define HAVE_PROC_NET_ROUTE
/*
 * XXX
 * you shouldnt have to play with these, most likely
 * XXX
 */

/* tuneables */
#define SHLIB_EXT ".so"

#ifdef __linux__
# define LODEV "lo"
# define DEFAULT_NETDEV "eth0"
#else
# define DEFAULT_NETDEV "fxp0"
# define LODEV "lo0"
#endif

/*
 * used to find out when spawned processes or connected drones have given us a foul taste for execution, 
 * causing us to cease our existance on this cruel world
 */
#define MAX_ERRORS 32

/* umm yah, you can change this, it doesnt matter, think firewalls */
#define IPC_BINDPORT_START	8000

/*
 * by default, 2 processes will be forked, this is where they will listen
 */
#define DEF_SENDER	"127.0.0.1:12322"
#define DEF_LISTENER	"127.0.0.1:12323"

#if !defined(PREFIX)
#error PREFIX NOT DEFINED
#endif /* PREFIX */

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

#define MODULE_DIR	PREFIX "/libexec/" TARGETNAME "/modules"
#define PORT_NUMBERS	PREFIX "/share/" TARGETNAME "/port-numbers"
#define CONF_FILE	PREFIX "/share/" TARGETNAME "/unicorn.conf"
#define OUI_CONF	PREFIX "/share/" TARGETNAME "/oui.conf"
#define SENDER_PATH	PREFIX "/libexec/" TARGETNAME "/" SENDERNAME
#define LISTENER_PATH	PREFIX "/libexec/" TARGETNAME "/" LISTENERNAME

/* may or may not be used, depending */
#define NOPRIV_USER "nobody"
/* may or may not be used, depending */
#define CHROOT_DIR LOCALSTATEDIR "/" TARGETNAME

#define MAX_CONNS	32	/* MAX amount of ipc or pollable connections	*/
#define IPC_DSIZE	65536	/* MAX amount of bytes for an ipc message chunk	*/

/* if you gcc hates these attributes, then replace the __attribute__((foo)) with nothing */
#define _PACKED_ __attribute__((packed))
#define _MALLOC_ __attribute__((malloc))
#define _PRINTF45_ __attribute__((format(printf, 4, 5)));
#define _NORETURN_ __attribute__((noreturn))

#include <sys/types.h>
#include <assert.h> /* lots of these everywhere, so well put it here */
#include <string.h> /* if you dont have this try strings.h */
#include <stdio.h>

/* some older boxes will require this gross stuff here */
#ifndef suseconds_t
#define suseconds_t long
#endif


#if defined(HAVE_STDINT_H)
#include <stdint.h>
#else
#include <inttypes.h>
#endif

/* dont ask, its not worth trying to understand */
#ifndef u_int
#define u_int unsigned int
#endif
#ifndef u_short
#define u_short unsigned short
#endif
#ifndef u_char
#define u_char unsigned char
#endif

#define CLEAR(m) memset(&m, 0, sizeof(m))

/* perhaps youll need to fix these, not likely though */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef WITH_IFADDRS
# include <net/if.h>
# include <ifaddrs.h>
#endif

#ifndef BYTE_ORDER

# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN 1234
#  define BIG_ENDIAN 4321
# endif

/* ok now this stuff is just ugly try our best untill we have a configure */
#if defined(solaris) || (defined(__SVR4) && defined(sun))
# define SOLARIS 1
#endif

#if (BSD >= 199103) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#  include <machine/endian.h>
# else
#  ifdef linux
#   include <endian.h>
#  elif defined(vax) || defined(ns32000) || defined(sun386) || defined(i386) || \
        defined(__ia64) || defined(MIPSEL) || defined(_MIPSEL) || \
        defined(BIT_ZERO_ON_RIGHT) || defined(__alpha__) || defined(__alpha)
#   define BYTE_ORDER	LITTLE_ENDIAN
#  else
#   define BYTE_ORDER	BIG_ENDIAN
#  endif /* ! linux */
# endif /* BSD > 199103 */

#endif
