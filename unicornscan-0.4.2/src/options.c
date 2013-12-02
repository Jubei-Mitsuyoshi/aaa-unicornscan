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

#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <settings.h>

#include <unilib/panic.h>
#include <unilib/xdelay.h>
#include <unilib/cidr.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/arch.h>

#include <scan_progs/scan_export.h>

int scan_setdefaults(void) {
	s->repeats=1;
	s->forklocal=FORK_LOCAL_LISTENER|FORK_LOCAL_SENDER;
	s->pps=300;
	s->drone_str=NULL;
	s->covertness=0;
	s->delay_type=XDELAY_DEFAULT;

	/* the default is to have the ports shuffled */
	SET_SHUFFLE();

	/* the default is to have a default payload 16 A's or whatever */
	SET_DEFAULT();
	SET_PATIENCE();

	scan_setprivdefaults();
	return 1;
}

int scan_setnodefpayload(void) {

	SET_NODEFAULT();

	return 1;
}

int scan_setdelaytype(int type) {

	if (type > 0xFF || type < 0) {
		MSG(M_ERR, "delay type out of range");
		return -1;
	}

	s->delay_type=(uint8_t)type;
	return 1;
}

int scan_setrecvpacket(void) {

	SET_RETPACKET();

	return 1;
}

int scan_setreadfile(const char *file) {

	if (access(file, R_OK) < 0) {
		MSG(M_ERR, "file `%s' cant be read: %s", file, strerror(errno));
		return -1;
	} 

	if (s->pcap_readfile != NULL) {
		xfree(s->pcap_readfile);
	}

	s->pcap_readfile=xstrdup(file);

	return 1;
}

int scan_settryfrags(void) {

	PANIC("not implemented anymore");
	return 1;
}

int scan_setinterface(const char *intf) {

	/* XXX check this? */

	if (s->interface_str != NULL) {
		xfree(s->interface_str);
	}
	s->interface_str=xstrdup(intf);

	return 1;
}

int scan_seticmp(void) {

	SET_SHOWERRORS();
	SET_WATCHERRORS();

	return 1;
}

int scan_setlistendrone(void) {

	if (GET_SENDDRONE()) {
		MSG(M_ERR, "Send and Listen drones are mutually exclusive, these are not the droids you are looking for");
		return -1;
	}

	SET_LISTENDRONE();

	s->forklocal=FORK_LOCAL_LISTENER;

	return 1;
}

int scan_setsenddrone(void) {

	if (GET_LISTENDRONE()) {
		MSG(M_ERR, "Send and Listen drones are mutually exclusive, these are not the droids you are looking for");
		return -1;
	}

	SET_SENDDRONE();

	s->forklocal=FORK_LOCAL_SENDER;

	return 1;
}

int scan_setscantype(const char *type) {

	if (type[0] == 't') {
		scan_setmode("T");
	}
	else if (type[0] == 'u') {
		scan_setmode("U");
	}
	else {
		MSG(M_ERR, "Unknown scanning mode `%s'", type);
		return -1;
	}

	return 1;
}

int scan_setmoddir(const char *dir) {

	if (access(dir, R_OK|X_OK) < 0) {
		MSG(M_ERR, "cant read module directory `%s': %s", dir, strerror(errno));
		return -1;
	}

	if (s->mod_dir != NULL) {
		xfree(s->mod_dir);
	}

	s->mod_dir=xstrdup(dir);

	return 1;
}

int scan_setnopatience(void) {

	SET_NOPATIENCE();

	return 1;
}

int scan_setpcapfilter(const char *filter) {

	if (s->extra_pcapfilter != NULL) {
		xfree(s->extra_pcapfilter);
	}
	s->extra_pcapfilter=xstrdup(filter);

	return 1;
}

int scan_setsrcaddr(const char *addr) {
	struct in_addr ia;

	if (addr[0] == 'r') {
		SET_OVERRIDE();
		SET_RNDSRCIP();
		return 1;
	}

	if (inet_aton(addr, &ia) == 0) {
		MSG(M_ERR, "Address `%s' is invalid, use X.X.X.X or `r'", addr);
		return -1;
	}

	SET_OVERRIDE();

	s->vi->myaddr.sin_family=AF_INET;
	s->vi->myaddr.sin_addr.s_addr=ia.s_addr;
	snprintf(s->vi->myaddr_s, sizeof(s->vi->myaddr_s) -1, "%s", addr);

	return 1;
}

int scan_setsavefile(const char *sfile) {
	char newfname[PATH_MAX], *opos=NULL;
	const char *cptr=NULL;
	size_t olen=0;
	time_t curtime;
	int sret=0, tfd=0;

	memset(newfname, 0, sizeof(newfname));

	for (cptr=sfile, opos=&newfname[0] ; *cptr != '\0' ; cptr++) {
		switch(*cptr) {
			case '%':
				if (*(cptr + 1) == '\0') {
					*(opos++)='%'; olen++;
					break;
				}
				cptr++;
				switch (*cptr) {
					case 'd':
						if ((olen + 11) >= sizeof(newfname)) {
							fprintf(stderr, "source filename too long");
							return -1;
						}
						time(&curtime);
						sret=snprintf(opos, (sizeof(newfname) - olen - 1), "%d", (int)curtime);
						olen += sret; opos += sret;
						break;
					case '%': /* this turns into a % then */
						*(opos++)='%'; olen++;
						break;
					default:
						fprintf(stderr, "Unknown escape char `%c' in filename ", *cptr);
						return -1;
				}
				break;
			default:
				if ((olen + 1) >= sizeof(newfname)) {
					fprintf(stderr, "source filename too long");
					return -1;
				}
				*(opos++)=*cptr; olen++;
				break;
		}
	}

	if (s->pcap_dumpfile != NULL) {
		xfree(s->pcap_dumpfile);
	}

	tfd=open(newfname, O_CREAT|O_WRONLY|O_EXCL);
	if (tfd < 0) {
		MSG(M_ERR, "Can't open file `%s': %s", newfname, strerror(errno));
		return -1;
	}

	s->pcap_dumpfile=xstrdup(newfname);

	return 1;
}

int scan_setdrones(const char *dones) {

	MSG(M_ERR, "Not implemented yet");
	return -1;
}

int scan_setcovertness(int level) {
	if (level < 0 || level > 0xFF) {
		MSG(M_ERR, "Covertness value `%d' of of range", level);
		return -1;
	}
	s->covertness=(uint8_t)level;
	return 1;
}

int scan_setrepeats(int repeats) {

	if (repeats < 1) {
		MSG(M_ERR, "Scan repeats is less than one");
		return -1;
	}
	s->repeats=(uint32_t)repeats;

	return 1;
}

int scan_setnoshuffle(void) {

	SET_NOSHUFFLE();

	return 1;
}

int scan_setports(const char *ports) {
	if ((ports == NULL || *ports == '\0') && s->port_str == NULL) {
		s->port_str=xstrdup("q");
		return 1;
	}

	if (s->port_str != NULL) {
		xfree(s->port_str);
	}

	s->port_str=xstrdup(ports);

	return 1;
}

int scan_setdesthosts(const char *hosts) {
	char errstr[1024];

	CLEAR(errstr);
	if (get_cidr(&s->_low_ip, &s->_high_ip, hosts, errstr, sizeof(errstr)) < 0) {
		MSG(M_ERR, "Address `%s' isnt something that i understand: %s", hosts, errstr);
		return -1;
	}

	return 1;
}

int scan_setidlehosts(const char *ihosts) {

	if (s->idle_hosts != NULL) {
		xfree(s->idle_hosts);
	}
	s->idle_hosts=xstrdup(ihosts);

	return 1;
}

int scan_setidlescan(void) {

	MSG(M_ERR, "Not implemented");
	return -1;
}

int scan_setverbose(int verbl) {
	if (verbl < 0) {
		s->verbose=0;
		return 1;
	}
	if (verbl > 0xFF) {
		s->verbose=255;
		return 1;
	}

	s->verbose=(uint8_t)verbl;

	return 1;
}

int scan_setverboseinc(void) { /* kludge for getconfig.c */

	if (s->verbose > 0xFE) {
		MSG(M_ERR, "stop that, stop saying that.");
		return -1;
	}

	++s->verbose;

	return 1;
}

/* XXX this should be const char * returns */
char *scan_getportstr(void) {
	return s->port_str;
}

/* XXX this should be const char * returns */
char *scan_getdesthosts(void) {
	return s->host_str;
}

int scan_setpps(const char *ppsstr) {

	s->pps=(uint64_t) atol(ppsstr);

	return 1;
}

int scan_setppsn(int ppsn) {

	if (ppsn < 1) {
		MSG(M_ERR, "Bad pps value");
		return -1;
	}
	s->pps=ppsn;

	return 1;
}

int scan_setenablemodule(const char *modules) {
	if (s->module_enable != NULL) {
		xfree(s->module_enable);
	}
	s->module_enable=xstrdup(modules);
	return 1;
}

int scan_setdronetype(const char *type) {
	if (type == NULL) {
		return -1;
	}
	if (type[0] == 'L') {
		SET_LISTENDRONE();
	}
	else if (type[0] == 'S') {
		SET_SENDDRONE();
	}
	else {
		MSG(M_ERR, "Unknown Drone type! `%c'", type[0]);
		return -1;
	}
	return 1;
}
