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
#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>

#include <pcap.h>

#include <scan_progs/scan_export.h>
#include <settings.h>
#include <myversion.h>
#include <getconfig.h>
#include <parse/parse.h>
#include <options.h>
#include <drone.h>

#include <unilib/xmalloc.h>
#include <unilib/terminate.h>
#include <unilib/arch.h>
#include <unilib/cidr.h>
#include <unilib/output.h>
#include <unilib/xdelay.h>
#include <unilib/arch.h>

#ifdef WITH_LONGOPTS
#include <getopt.h>
#endif


#include <compile.h>

/*
 * inputs: NONE
 * outputs: NONE
 * terminates the program with an error code with a description of the arguments
 * the program accepts, currently only used inside getconfig.c
 */
static void usage(void);

/*
 */
static void display_version(void);

/* YUCK */
extern void __libnet_print_vers(void);

void getconfig_argv(int argc, char ** argv) {
	extern char *optarg;
	extern int optind;
	char ch, *ptr=NULL, *start=NULL;
	char errstr[512];
	ssize_t errlen;

#define OPTS	"b:" "B:" "d:" "D" "e:" "E" "F" "h" "i:" "L:" "m:" "M:" "p" "P:" "q:" "r:" "R:" "s:" "S" "t:" "T:" "w:" "W:" "v" "V" "Z:"

#ifdef WITH_LONGOPTS
	const struct option long_opts[]={
		{"broken-crc",		1, NULL, 'b'},
		{"source-port",		1, NULL, 'B'},
		{"no-defpayload",	0, NULL, 'D'},
		{"delay-type",		1, NULL, 'd'},
		{"enable-modules",	1, NULL, 'e'},
		{"show-errors",		0, NULL, 'E'},
		{"help",		0, NULL, 'h'},
		{"interface",		1, NULL, 'i'},
		{"packet-timeout",	1, NULL, 'L'},
		{"mode",		1, NULL, 'm'},
		{"module-dir",		1, NULL, 'M'},
		{"no-patience",		0, NULL, 'p'},
		{"pcap-filter",		1, NULL, 'P'},
		{"covertness",		1, NULL, 'q'}, /*
							*`Q' is Covert for Covertness, If you rot13 Clandestineness The fith character
							* Is `q' (Your count starting From One of Course), if you Rotate This option
							* List Upside-down (Counting only the Lower Case Options) go past Five Options,
							* You arive Here. It should be Obvious Why.
							*/
		{"pps",			1, NULL, 'r'},
		{"repeats",		1, NULL, 'R'},
		{"source-addr",		1, NULL, 's'},
		{"no-shuffle",		0, NULL, 'S'},
		{"ip-ttl",		1, NULL, 't'},
		{"ip-tos",		1, NULL, 'T'},
		{"savefile",		1, NULL, 'w'},
		{"fingerprint",		1, NULL, 'W'},
		{"verbose",		1, NULL, 'v'}, /* this is different in the long / short opts */
		{"version",		0, NULL, 'V'},
		{"drone-type",		1, NULL, 'Z'},
		{NULL,			0, NULL,  0 }
	};
#endif /* LONG OPTION SUPPORT */

	errlen=sizeof(errstr) -1;

	scan_setdefaults();

	readconf(CONF_FILE);

#ifdef WITH_LONGOPTS
	while ((ch=getopt_long(argc, argv, OPTS, long_opts, NULL)) != -1) {
#else
	while ((ch=getopt(argc, argv, OPTS)) != -1) {
#endif
		switch (ch) {
			case 'b':
				/* XXX this logic shouldnt be here, but im lazy, and usage _is_ here */
				if (scan_setbroken(optarg) < 0) usage();
				break;
			case 'B':
				/* we use B for source port cause it doesnt make any sense */
				if (scan_setsrcp(atoi(optarg)) < 0) usage();
				break;
			case 'D':
				/* set no default payload (only proble known things) (i know, its for udp mostly so shutup ok?) */
				if (scan_setnodefpayload() < 0) usage();
				break;
			case 'd':
				if (scan_setdelaytype(atoi(optarg)) < 0) usage();
				break;
			case 'e':
				/* enable  modules */
				if (scan_setenablemodule(optarg) < 0) usage();
				break;
			case 'E':
				/* recieve icmp errors and report them (tcp resets and such too) */
				if (scan_seticmp() < 0) usage();
				break;
			case 'F':
				/* try to send frag packets */
				if (scan_settryfrags() < 0) usage();
				break;
			case 'h':
				/* confuse the user with ranting about options and scattered notes in various places */
				usage();
				break;
			case 'i':
				/* interface name */
				if (scan_setinterface(optarg) < 0) usage();
				break;
			case 'L':
				if (scan_setrecvtimeout(atoi(optarg)) < 0) usage();
				break;
			case 'm':
				if (scan_setmode(optarg) < 0) usage();
				break;
			case 'M':
				/* so modules are in this directory */
				if (scan_setmoddir(optarg) < 0) usage();
				break;
			case 'p':
				/* display ports as they are found, and some stats */
				if (scan_setnopatience() < 0) usage();
				break;
			case 'P':
				/* as in *cough* ! port 162 etc */
				if (scan_setpcapfilter(optarg) < 0) usage();
				break;
			case 'q':
				/* covertness */
				if (scan_setcovertness(atoi(optarg)) < 0) usage();
				break;
			case 'r':
				if (scan_setpps(optarg) < 0) usage();
				break;
			case 'R':
				/* repeat scan X times */
				if (scan_setrepeats(atoi(optarg)) < 0) usage();
				/* it is true that wheat grass is gross, but not at first, strangely	*
				 * only afterwards can you truely appreciate how foul the taste is	*/
				break;
			case 's':
				/* set source ip to something else, r for random */
				if (scan_setsrcaddr(optarg) < 0) usage();
				break;
			case 'S':
				/* DONT shuffle ports */
				if (scan_setnoshuffle() < 0) usage();
				break;
			case 't':
				/* ttl on crafted packets */
				if (scan_setttl(atoi(optarg)) < 0) usage();
				break;
			case 'T':
				/* TOS on crafted packets */
				if (scan_settos(atoi(optarg)) < 0) usage();
				break;
			case 'w':
				/* pcap save file */
				if (scan_setsavefile(optarg) < 0) usage();
				break;
			case 'W':
				/* stack fingerprint emulation */
				if (scan_setfingerprint(atoi(optarg)) < 0) usage();
				break;
			case 'v':
				/* verbose */
				if (optarg != NULL) {
					if (scan_setverbose(atoi(optarg)) < 0) usage();
				}
				else if (scan_setverboseinc() < 0) usage();
				break;
			case 'V':
				display_version();
				break;
			case 'Z':
				if (scan_setdronetype(optarg) < 0) usage();
				break;
			default:
				usage();
		} /* switch */
	}

	/* its not set if its null, so set it, otherwise it is */
	if (s->mod_dir == NULL) {
		scan_setmoddir(MODULE_DIR);
	}

	/* if we are going to send */
	if (!(GET_LISTENDRONE())) {
		uint8_t seen_c=0;

		/* require a hostname formated like (hostname|ip address)[/cidr]:ports */
		if (!(optind < argc && argv[optind] != NULL && strlen(argv[optind]))) {
			MSG(M_INFO, "what host(s) should i scan?");
			usage();
		}

		ptr=xstrdup(argv[optind]);

		seen_c=0;
		/* take the argument and break it into 2 strings, a cidr address and a port range */
		for (start=ptr ; *ptr != '\0' ; ptr++) {
			if (*ptr == ':') {
				*ptr='\0'; ptr++;
				seen_c=1;
				break;
			}
		}

		if (s->verbose > 5) MSG(M_DBG1, "start: `%s' ptr: `%s'", start, ptr);

		/* get the network address with the first part of the argument */
		if (start) {
			if (scan_setdesthosts(start) < 0) usage();
		}
		else {
			/* not in config file? */
			if (scan_getdesthosts() == NULL) usage();
		}

		if (ptr == NULL || *ptr == '\0') {
			/* could be already set by the config file(s) */
			if (scan_getportstr() == NULL) scan_setports("q");
		}
		else {
			scan_setports(ptr);
		}
		xfree(start);
	}

	return;
}

static void usage(void) {
#ifdef WITH_PROGNAME
	extern char *__progname;
#else
	const char *__progname=TARGETNAME;
#endif

	if (stderr) MSG(M_INFO, "%s [dyadsecurity] (Version %s)\n"
	"Usage: %s [options `%s' ] X.X.X.X/YY:S-E\n"
	"\t-b, --broken-crc    *[Set broken crc sums on [T]ransport layer, [N]etwork layer, or both[TN]]\n"
	"\t-B, --source-port   *[Set source port? or whatever the scan module expects as a number]\n"
	"\t-d, --delay-type    *[Set delay type (numeric value, valid options are `%s')]\n"
	"\t-D, --no-defpayload  [No default Payload, only probe known protocols]\n"
	"\t-e, --enable-module *[enable modules listed as arguments (output and report currently)]\n"
	"\t-E, --show-errors    [for tracking icmp errors (*non-firewalled hosts normally) and rst packets]\n"
	"\t-h, --help           [help (you are reading it)]   <---- YOU ARE HERE\n"
	"\t-i, --interface     *[interface name, like eth0 or fxp1, not normally required]\n"
	"\t-m, --mode          *[scan mode, tcp (syn) scan is default, U for udp T for tcp `sf' for tcp connect scan and A for arp]\n"
	"\t                      for -mT you can also specify tcp flags following the T like -mTsFpU for example\n"
	"\t                      that would send tcp syn packets with (NO Syn|FIN|NO Push|URG)\n"
	"\t-M, --module-dir    *[directory modules are found at (defaults to %s)]\n"
	"\t-p, --no-patience    [No patience, display things as we find them]\n"
	"\t-P, --pcap-filter   *[Extra pcap filter string for reciever]\n"
	"\t-q, --covertness    *[Covertness value from 0 to 255]\n"
	"\t-r, --pps           *[packets per second (total, not per host, and as you go higher it gets less accurate)]\n"
	"\t-R, --repeats       *[Repeat packet scan N times]\n"
	"\t-s, --source-addr   *[Source address for packets `r' for random]\n"
	"\t-S, --no-shuffle     [DON'T shuffle ports]\n"
	"\t-t, --ip-ttl        *[Set TTL on sent packets]\n"
	"\t-T, --ip-tos        *[set TOS on sent packets]\n"
	"\t-w, --safefile      *[Write pcap file of recieved packets]\n"
	"\t-W, --fingerprint   *[OS fingerprint 0=cisco(def) 1=openbsd 2=WindowsXP 3=p0fsendsyn 4=FreeBSD 5=nmap]\n"
	"\t                     [6=linux 7:Crazy lint tcp header (use with p0f hopefully)]\n"
	"\t-v, --verbose        [verbose (each time more verbose so -vvvvv is really verbose)]\n"
	"\t-V, --version        [Display version]\n"
	"\t-Z, --drone-type    *[L or S]\n"
	"*:\tOptions with `*' require an argument following them\n\n"
	"  Address ranges are cidr like 1.2.3.4/8 for all of 1.?.?.?\n"
	"  if you omit the cidr mask then /32 is implied\n"
	"  port ranges are like 1-4096 with 53 only scanning one port, a for all 65k and p for 1-1024\n"
	"example: %s -i eth1 208.47.125.0/24:1-4000 -pr 160 -E",
	__progname, VERSION, __progname, OPTS, delay_getopts(), MODULE_DIR, __progname);

	terminate(TERM_NORMAL);
}

static void display_version(void) {
	uint8_t min, maj;

	MOD_VERSION(MODULE_IVER, maj, min);
	MSG(M_OUT, "%s version `%s' using module version %d.%.02d", TARGETNAME, VERSION, maj, min);

	/* libnet is missing a good interface for this (or is it?) */
	/* (void) __libnet_print_vers(); */

	MSG(M_OUT, "pcap version %s", pcap_lib_version());
	MSG(M_OUT, "%s", COMPILE_STR);
	terminate(TERM_NORMAL);
}
