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

#include <stdlib.h>
#include <unistd.h>

#include <scanopts.h>
#include <scan_export.h>

#include <options.h>

#include <settings.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc.h>
#include <unilib/output.h>
#include <modules.h>
#include <portfunc.h>
#include <workunits.h>

#define DEF_SCANTIMEOUT 7

int get_scanopts(seo_t *seo) {

	assert(seo != NULL);
	assert(s->ss != NULL);

	seo->fingerprint=s->ss->fingerprint;
	seo->tos=s->ss->tos;
	seo->ttl=s->ss->ttl;
	seo->ip_off=s->ss->ip_off;
	seo->tcphdrflgs=s->ss->tcphdrflgs;
	seo->src_port=s->ss->src_port;

	return 1;
}

void scan_setprivdefaults() {

	s->ss=(SCANSETTINGS *)xmalloc(sizeof(SCANSETTINGS));

	memset(s->ss, 0, sizeof(SCANSETTINGS));

	/* default mode is tcp syn scan */
	s->ss->mode=MODE_TCPSCAN;
	s->mode=s->ss->mode;
	s->ss->tcphdrflgs=TH_SYN; /* FSRPAUEC */
	s->ss->src_port=-1;
	s->ss->recv_timeout=DEF_SCANTIMEOUT; /* 7 seconds */

	return;
}

int scan_setsrcp(int port) {

	if (port < -1 || port > 0xFFFF) {
		MSG(M_ERR, "Source port `%d' out of range", port);
		return -1;
	}
	s->ss->src_port=(int32_t)port;

	return 1;
}

int scan_setfingerprint(int fp) {
	if (fp < 0 || fp > 0xFFFF) {
		MSG(M_ERR, "bad fingerprint value");
		return -1;
	}
	s->ss->fingerprint=(uint16_t)fp;

	return 1;
}

int scan_setttl(int ttl) {
	if (ttl > 0xFF || ttl < 1) {
		return -1;
	}
	s->ss->ttl=(uint8_t)ttl;
	return 1;
}

int scan_settos(int tos) {
	if (tos > 0xFF || tos < 0) {
		return -1;
	}
	s->ss->tos=(uint8_t)tos;
	return 1;
}

int scan_setbroken(const char *instr) {

	if (instr[0] == 'N') {
		SET_BROKENNET();
	}
	else if (instr[0] == 'T') {
		SET_BROKENTRANS();
	}
	else {
		return -1;
	}

	if (strlen(instr) == 2) {
		if (instr[1] == 'N') {
			SET_BROKENNET();
		}
		else if (instr[1] == 'T') {
			SET_BROKENTRANS();
		}
		else {
			return -1;
		}
	}

	return 1;
}

int scan_settcpflags(int flags) {

	if (flags < 0 || flags > 0xFF) {
		MSG(M_ERR, "TCP flags out of range");
		return -1;
	}

	s->ss->tcphdrflgs=flags;
	return 1;
}

int scan_setrecvtimeout(int seconds) {

	if (seconds < 0 || seconds > 0xFF) {
		return -1;
	}

	s->ss->recv_timeout=seconds;

	return 1;
}

int scan_setmode(const char *str) {
	int j=0;

	assert(str != NULL);

	if (str[0] == 'T') {

		s->ss->mode=MODE_TCPSCAN;

		/* check to see if the user specified TCP flags with TCP mode */
		if (strlen(str) > 1) {
			/* set the tcp flags that user requested then */
			for (j=1 ; j < (int)strlen(str) ; j++) {
				switch (str[j]) {
					case 'F':
						s->ss->tcphdrflgs |= TH_FIN;
						break;
					case 'f':
						s->ss->tcphdrflgs &= ~(TH_FIN);
						break;
					case 'S':
						s->ss->tcphdrflgs |= TH_SYN;
						break;
					case 's':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_SYN));
						break;
					case 'R':
						s->ss->tcphdrflgs |= TH_RST;
						break;
					case 'r':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_RST));
						break;
					case 'P':
						s->ss->tcphdrflgs |= TH_PSH;
						break;
					case 'p':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_PSH));
						break;
					case 'A':
						s->ss->tcphdrflgs |= TH_ACK;
						break;
					case 'a':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_ACK));
						break;
					case 'U':
						s->ss->tcphdrflgs |= TH_URG;
						break;
					case 'u':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_URG));
						break;
					case 'E':
						s->ss->tcphdrflgs |= TH_ECE;
						break;
					case 'e':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_ECE));
						break;
					case 'C':
						s->ss->tcphdrflgs |= TH_CWR;
						break;
					case 'c':
						s->ss->tcphdrflgs=(s->ss->tcphdrflgs & ~(TH_CWR));
						break;
					default:
						MSG(M_ERR, "Unknown TCP flag `%c' (FfSsRrPpAaUuEeCc are valid)", str[j]);
						return -1;
				} /* switch str[j] */
			} /* for strlen(str) */
		} /* if strlen(str) > 1 */
	} /* str[0] == 'T' */
	else if (str[0] == 'U') {
		s->ss->mode=MODE_UDPSCAN;
	}
	else if (str[0] == 'A') {
		s->ss->mode=MODE_ARPSCAN;
	}
	else if (str[0] == 's' && str[1] == 'f') {
		s->ss->mode=MODE_TCPSCAN;
		SET_DOCONNECT();
		SET_SENDERINTR();

		if (scan_setrecvpacket() < 0) {
			MSG(M_ERR, "Unable to request packet transfer though IPC, exiting");
	                return -1;
		}
	}
	else {
		MSG(M_ERR, "Unknown scanning mode `%c'", str[1]);
		return -1;
	}

	s->mode=s->ss->mode;

	return s->ss->mode;
}
