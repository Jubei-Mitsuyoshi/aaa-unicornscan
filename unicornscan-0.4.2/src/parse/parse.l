%{
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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <terminate.h>
#include <xmalloc.h>
#include <output.h>
#include <scan_progs/scan_export.h>

#include <putil.h>

#include "parse.tab.h"

#define INCLUDE_DEPTH 16

static char tmpbuf[2048], *tmpptr=NULL;
char section[1024];

struct incf_s {
	char filename[PATH_MAX];
	int lineno;
	FILE *fp;
};

int incs_index=0;
struct incf_s incs[INCLUDE_DEPTH];
void switchfiles(const char *);

%}

OT	([0-9]{1,3})

%x scomment


%option yylineno

%%
[ \t\f\r\n]+			/* ignore whitespace */
\/\*				{ BEGIN(scomment); }
<scomment>{
.				/* ignore */
\n				/* ignore */
}
<scomment>\*\/			{ BEGIN(INITIAL); }
(:wq|:wq!|:q|:q!)		/* :wq! requested by pipes */
0x[0-9A-Fa-f][0-9A-Fa-f]*	{ sscanf(yytext, "%x", &yylval.inum); return NUMBER; }
\\[0-7][0-7]*			{ sscanf(yytext, "%o", &yylval.inum); return NUMBER; }
-?[0-9][0-9]*			{ sscanf(yytext, "%d", &yylval.inum); return NUMBER; }
\"[^\"]+\"			{ yylval.buf.ptr=NULL; yylval.buf.len=0; return yyescapestr(yytext, &(yylval.buf)); }
\'[^\']*\'			{ yylval.ptr=xstrdup(yytext); return STR; }
({OT}\.){3,3}{OT}		{ yylval.ptr=xstrdup(yytext); return DOTQUAD; }
:				return COLON;
\{				return SBRACE;
\}				return EBRACE;
(false|no)			{ yylval.inum=0; return BOOL; }
(true|yes)			{ yylval.inum=1; return BOOL; }
(syn|fin|urg|psh|rst|ack|ece|cwr)	{
					yylval.inum=0;
					if (yytext[0] == 'f') yylval.inum=TH_FIN;
					if (yytext[0] == 's') yylval.inum=TH_SYN;
					if (yytext[0] == 'r') yylval.inum=TH_RST;
					if (yytext[0] == 'p') yylval.inum=TH_PSH;
					if (yytext[0] == 'a') yylval.inum=TH_ACK;
					if (yytext[0] == 'u') yylval.inum=TH_URG;
					if (yytext[0] == 'e') yylval.inum=TH_ECE;
					if (yytext[0] == 'c') yylval.inum=TH_CWR;
					return TCPFLAG;
				}
;				return SEMICOLON;
global				return GLOBAL;
payloads			return PAYLOADS;
pps				{ yylval.inum=atoi(yytext); return PPS; }
brokencrc			return BROKENCRC;
(sourceport|srcport)		return SOURCEPORT;
(destport|dstport|destinationport)	return DESTPORT;
dangerous			return DANGEROUS;
readfile			return READFILE;
sendfrags			return SENDFRAGS;
interface			return INTERFACE;
watchicmp			return WATCHICMP;
listendrone			return LISTENDRONE;
senddrone			return SENDDRONE;
scanmode			return SCANMODE;
tcpflags			return TCPFLAGS;
defaultpayload			return DEFPAYLOAD;
moduledir			return MODULEDIR;
(transport|network)		{ snprintf(tmpbuf, sizeof(tmpbuf) -1, "%s", yytext); yylval.ptr=&tmpbuf[0]; return STACKLAYER;}
(udpscan|tcpscan)		{ snprintf(tmpbuf, sizeof(tmpbuf) -1, "%s", yytext); yylval.ptr=&tmpbuf[0]; return SCANTYPE; }
(nopatience|robert)		return NOPATIENCE;
,				return COMMA;
(pcapfilter|filter)		return PCAPFILTER;
repeats				return REPEATS;
srcaddr				return SRCADDR;
random				return RANDOM;
shuffle				return SHUFFLE;
ipttl				return IPTTL;
iptos				return IPTOS;
fingerprint			return FINGERPRINT;
savefile			return SAVEFILE;
verbose				return VERBOSE;
drones				return DRONES;
idlehosts			return IDLEHOSTS;
idlescan			return IDLESCAN;
(recvtimeout|receivetimeout)	return RECVTIMEOUT;
(udp|tcp|icmp)			{ snprintf(tmpbuf, sizeof(tmpbuf) -1, "%512s", yytext); yylval.ptr=&tmpbuf[0]; return IPPROTOCOLS; }
include[ \t]+\"[^\"]*\";	{
					if (sscanf(yytext, "include %512s", tmpbuf) != 1) {
						return NOTHING;
					}
					if (tmpbuf[0] == '"' && tmpbuf[1] != '\0') {
						tmpptr=&tmpbuf[1];
					}
					if (tmpptr[strlen(tmpptr) -2] == '"') {
						tmpptr[strlen(tmpptr) -2]='\0';
					}
					switchfiles((const char *)tmpptr);
				}

%%

void switchfiles(const char *newfile) {
	if (incs_index > (INCLUDE_DEPTH - 2)) {
		MSG(M_ERR, "includes too complex %d max", INCLUDE_DEPTH);
		return;
	}
	if (access(newfile, R_OK) != 0) {
		MSG(M_ERR, "include file `%s' is not readable", newfile);
		return;
	}
	incs[incs_index].lineno=yylineno;
	incs[incs_index].fp=yyin;

	incs_index++;

	yylineno=0;
	incs[incs_index].lineno=0;

	snprintf(incs[incs_index].filename, sizeof(incs[incs_index].filename) -1, "%s", newfile);
	incs[incs_index].fp=fopen(incs[incs_index].filename, "r");
	if (incs[incs_index].fp == NULL) {
		MSG(M_ERR, "cant open file, though i thought i could");
		terminate(TERM_ERROR);
	}

	yyin=incs[incs_index].fp;

	return;
}

int yywrap(void) {
	if (incs_index) {
		assert(incs[incs_index].fp != NULL);
		fclose(incs[incs_index].fp);
		incs_index--;
		yyin=incs[incs_index].fp;
		yylineno=incs[incs_index].lineno;
		return 0;
	}
	else {
		return 1;
	}
}

/* lib entry point */
int readconf(const char *in) {
	yyin=fopen(in, "r");

	if (yyin == NULL) {
		MSG(M_ERR, "Error opening file `%s': %s", in, strerror(errno));
		return -1;
	}

	incs_index=0;
	snprintf(incs[incs_index].filename, sizeof(incs[incs_index].filename) -1, "%s", in);
	incs[incs_index].fp=yyin;
	incs[incs_index].lineno=0;
	yyparse();
	if (yyin) fclose(yyin);
	return 1;
}

void yyerror(const char *instr) {
	extern int yylineno;

	MSG(M_ERR, "ERROR: `%s' at token `%s' in file `%s' line %d", instr, yytext, incs[incs_index].filename, yylineno);
	terminate(TERM_ERROR);
}

void yywarn(const char *instr) {
	extern int yylineno;

	MSG(M_ERR, "WARN: `%s' at token `%s' in file `%s' line %d", instr, yytext, incs[incs_index].filename, yylineno);
	terminate(TERM_ERROR);
}
