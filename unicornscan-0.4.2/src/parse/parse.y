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

#include <putil.h>

#include <scan_progs/scan_export.h>
#include <settings.h>
#include <options.h>

#define MAIN (ident == IDENT_MASTER)
#define SEND (ident == IDENT_SEND)

extern int yywarn(const char *);
extern void yyerror(const char *);

%}

%union {
	int inum;
	char *ptr;
	buf_t buf;
}

%token NUMBER COLON SBRACE EBRACE BOOL TCPFLAG
%token BROKENCRC SOURCEPORT DESTPORT READFILE
%token INTERFACE WATCHICMP LISTENDRONE SCANMODE
%token TCPFLAGS DEFPAYLOAD MODULEDIR STACKLAYER
%token NOPATIENCE COMMA SRCADDR RANDOM SENDFRAGS
%token SHUFFLE IPTTL IPTOS FINGERPRINT SAVEFILE
%token DRONES IDLEHOSTS IDLESCAN STR BSTR PPS
%token PAYLOADS IPPROTOCOLS DANGEROUS RECVTIMEOUT
%token SEMICOLON SENDDRONE SCANTYPE PCAPFILTER
%token VERBOSE DOTQUAD GLOBAL REPEATS NOTHING


%token <inum> BOOL NUMBER TCPFLAG
%token <ptr> STR SCANTYPE STACKLAYER DOTQUAD IPPROTOCOLS
%token <buf> BSTR

%{


%}
%%
cfgfile: section
	;

section: sections
	| section sections
	;

sections:
	| GLOBAL SBRACE glines EBRACE SEMICOLON
	| PAYLOADS SBRACE plines EBRACE SEMICOLON
	;

glines: g_statement
	| g_statement glines
	;

plines: p_statement
	| p_statement plines
	;

g_statement:
	| PPS COLON NUMBER SEMICOLON { scan_setppsn($3); }
	| BROKENCRC COLON STACKLAYER SEMICOLON {
		if (MAIN) {
			if (strstr($3, "network") != NULL) {
				if (scan_setbroken("N") < 0) { yyerror("no broken network for you!"); }
			}
			else {
				if (scan_setbroken("T") < 0) { yyerror("no broken transport for you!"); }
			}
		}
	}
	| BROKENCRC COLON STACKLAYER COMMA STACKLAYER SEMICOLON { if (MAIN) { if (scan_setbroken("TN") < 0) yyerror("Cant set broken crc option"); } }
	| DEFPAYLOAD COLON BOOL SEMICOLON { if (MAIN) { if (!($3))  { if (scan_setnodefpayload() < 0) yyerror("Cant set nodefault payload"); } } }
	| READFILE COLON STR SEMICOLON { if (MAIN) { if (scan_setreadfile((const char *)$3) < 0) yyerror("Cant set readfile"); } }
	| SENDFRAGS COLON BOOL SEMICOLON { if (MAIN) { if ($3)  { if (scan_settryfrags() < 0) yyerror("Cant set try frags"); } } }
	| SOURCEPORT COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setsrcp($3) < 0) yyerror("Cant set source port"); } }
	| INTERFACE COLON STR SEMICOLON { if (MAIN) { if (scan_setinterface((const char *)$3) < 0) yyerror("Cant set interface"); } }
	| WATCHICMP COLON BOOL SEMICOLON { if (MAIN) { if ($3)  { if (scan_seticmp() < 0) yyerror("Cant set watchicmp"); } } }
	| LISTENDRONE COLON BOOL SEMICOLON { if (MAIN) { if ($3)  { if (scan_setlistendrone() < 0) yyerror("Cant set listendrone"); } } }
	| SENDDRONE COLON BOOL SEMICOLON { if (MAIN) { if ($3) { if (scan_setsenddrone() < 0) yyerror("Cant set senddrone"); } } }
	| NOPATIENCE COLON BOOL SEMICOLON { if (MAIN) { if ($3) { if (scan_setnopatience() < 0) yyerror("Cant set nopatience"); } } }
	| SCANMODE COLON SCANTYPE SEMICOLON { if (MAIN) { if (scan_setscantype((const char *)$3) < 0) yyerror("Cant set scantype"); } }
	| TCPFLAGS COLON flaglist SEMICOLON {
		if (MAIN) {
			int flags=0;

			flags=get_tcpflags();
			scan_settcpflags(flags);
		}
	}
	| REPEATS COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setrepeats((uint8_t )$3) < 0) yyerror("Cant set repeats"); } }
	| RECVTIMEOUT COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setrecvtimeout((int) $3) < 0) yyerror("Cant set recvtimeout"); } }
	| MODULEDIR COLON STR SEMICOLON { if (MAIN) { if (scan_setmoddir((const char *)$3) < 0) yyerror("Cant set moddir"); } }
	| PCAPFILTER COLON STR SEMICOLON { if (MAIN) { if (scan_setpcapfilter((const char *)$3) < 0) yyerror("Cant set pcap filter"); } }
	| SRCADDR COLON DOTQUAD SEMICOLON { if (MAIN) { if (scan_setsrcaddr((const char *)$3) < 0) yyerror("Cant set srcaddr"); } }
	| SRCADDR COLON RANDOM SEMICOLON { if (MAIN) { if (scan_setsrcaddr("r") < 0) yyerror("Cant set srcaddr"); } }
	| IPTTL COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setttl($3) < 0) yyerror("Cant set ttl"); } }
	| IPTOS COLON NUMBER SEMICOLON { if (MAIN) { if (scan_settos($3) < 0) yyerror("Cant set tos"); } }
	| SHUFFLE COLON BOOL SEMICOLON { if (MAIN) { if (!($3)) { if (scan_setnoshuffle() < 0) yyerror("Cant set noshuffle"); } } }
	| SAVEFILE COLON STR SEMICOLON { if (MAIN) { if (scan_setsavefile((const char *)$3) < 0) yyerror("Cant set savefile"); } }
	| FINGERPRINT COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setfingerprint($3) < 0) yyerror("Cant set fingerprint"); } }
	| VERBOSE COLON NUMBER SEMICOLON { if (MAIN) { if (scan_setverbose($3) < 0) yyerror("Cant set verbosity"); } }
	| DRONES COLON STR SEMICOLON { if (MAIN) { if (scan_setdrones($3) < 0) yyerror("Cant set drones"); } }
	| IDLEHOSTS COLON STR SEMICOLON { if (MAIN) { if (scan_setidlehosts($3) < 0) yyerror("Cant set idlehosts"); } }
	| IDLESCAN COLON BOOL SEMICOLON { if (MAIN) { if ($3) { if (scan_setidlescan() < 0) yyerror("Cant set idlescan"); } } }
	;

p_statement:
	IPPROTOCOLS DESTPORT NUMBER SOURCEPORT NUMBER DANGEROUS BOOL SBRACE pdata SEMICOLON EBRACE SEMICOLON {
		if (SEND) {
			uint16_t dstport=0;
			buf_t data;
			uint16_t plf=0;

			if ($3 > 0xFFFF || $3 < 0) {
				yyerror("dest port out of range");
			}
			else {
				dstport=(uint16_t)$3;
				pbuffer_get(&data);
				if ($7) plf=1;
				add_payload(dstport, $5, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plf);
			}

			pbuffer_reset();
		}
	}
	;

pdata:
	BSTR {
		if (SEND) pbuffer_append(&$1);
	}
	| pdata BSTR {
		if (SEND) pbuffer_append(&$2);
	}
	| STR {
		if (SEND) {
			buf_t data;

			data.len=strlen($1);
			data.ptr=(char *)$1;
			pbuffer_append(&data);
		}
	}
	| pdata STR {
		if (SEND) {
			buf_t data;

			data.len=strlen($2);
			data.ptr=(char *)$2;
			pbuffer_append(&data);
		}
	}
	;

flaglist: 
	TCPFLAG {
		add_tcpflag($1);
	}
	| flaglist TCPFLAG {
		add_tcpflag($2);
	}
	| flaglist COMMA {
	}
	;

