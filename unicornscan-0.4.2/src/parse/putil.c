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

#include <terminate.h>
#include <output.h>
#include <xmalloc.h>
#include <putil.h>
#include "parse.tab.h"

#undef LAZY_GDB

static int buffer_size=0;
static char *bbuf=NULL;

static int ptcpflags=0;

extern void yyerror(const char *);

#define PPBLOCK_SIZE 64

int yyescapestr(const char *in, buf_t *bout) {
	char *out=NULL, bstr=0;
	int j=0, j1=0;
#define BIN bstr=1

	assert(in != NULL);
	if (*in == '"' && *(in + 1) != '\0') in++;

	/* we'll do better down there */
	out=xstrdup(in);

	for (j=0, j1=0 ; j < (int)strlen(in) ; j++) {
		if (in[j] == '\\' && in[j + 1] != '\0') {
			const char *tmpptr=NULL;
			int oweight=0, result=0;

			++j;
			switch (in[j]) {
				case 'a':
					out[j1++]='\a'; BIN; break;
				case 'b':
					out[j1++]='\b'; BIN; break;
				case 'f':
					out[j1++]='\f'; BIN; break;
				case 'n':
					out[j1++]='\n'; BIN; break;
				case 'r':
					out[j1++]='\r'; BIN; break;
				case 't':
					out[j1++]='\t'; BIN; break;
				case 'v':
					out[j1++]='\v'; BIN; break;
				case '\'': /* " and ' are escaped to be the same thing */
				case '"':
					out[j1++]=in[j]; j++; break;
				case '\\':
					out[j1++]='\\'; break;
				case '0': case '1': case '2': case '3':
				case '4': case '5': case '6': case '7':
					BIN;
					/* start at index 0, go to max 3 spaces with all chars being 0 - 7 */
					for (tmpptr=&in[j], oweight=0;
					 *tmpptr != '\0' && (*tmpptr >= 0x30 && *tmpptr <= 0x37) && oweight < 65;
					tmpptr++) {
						if (oweight) {
							oweight=(oweight * 8);
						}
						else {
							oweight++;
						}
					}

					for (tmpptr=&in[j], result=0;
					*tmpptr != '\0' && (*tmpptr >= 0x30 && *tmpptr <= 0x37) && oweight > 0;
					tmpptr++, j++, oweight=(oweight / 8)) {
						int add=0; char bob[2];

						bob[0]=*tmpptr; bob[1]='\0';
						add=atoi(bob);
						result += (add * oweight);
					}
					/* truncate \777 to 0xFF like \377 */
					out[j1++]=(result & 0xFF); --j;
					/* im too lazy to refactor this so i dont need the -- so :P */
					break;
				case 'x':
					BIN;
					/* start at index 0, go to max 2 spaces with all chars being 0 - 7 */
					j++;
					tmpptr=&in[j];
					if (*tmpptr == '\0' || *(tmpptr + 1) == '\0') {
						MSG(M_ERR, "Broken hex escape, its late, sorry\n");
						terminate(TERM_ERROR);
					}
					if (1) {
						char str[3];
						int num=0;

						str[0]=*tmpptr; str[1]=*(tmpptr + 1); str[2]='\0'; j++;

						if (sscanf(str, "%x", &num) != 1) {
							MSG(M_ERR, "Broken hex escape (from sscanf), sorry `%s'\n", str);
							terminate(TERM_ERROR);
						}
						out[j1++]=(uint8_t)(num & 0xFF);
					}
					break;
				default:
					MSG(M_WARN, "Warning unhandled escapechar `%c'\n", in[j]);
					break;
			}
		}
		else {
			if ((j + 1) != (int)strlen(in)) { /* no trailing " from string */
				out[j1++]=in[j];
			}
		}
	}

	if (bstr) {
		bout->len=0;
		bout->ptr=NULL;
		bout->len=j1;
		bout->ptr=(char *)xmalloc((size_t)j1);
		memset(bout->ptr, 0, (size_t)j1);
		memcpy(bout->ptr, out, (size_t)j1);
	}
	else {
		/* terminate with a \0 if non-binary */
		bout->len=j1;
		bout->ptr=(char *)xmalloc((size_t)(j1 + 1));
		memset(bout->ptr, 0, (size_t)(j1 + 1));
		memcpy(bout->ptr, out, (size_t)j1);
	}
	xfree(out);

	if (bstr) {
		return BSTR;
	}
	return STR;
}

void pbuffer_get(buf_t *in) {
	in->len=buffer_size;
	in->ptr=bbuf;
}

void pbuffer_append(buf_t *in) {
	assert(in != NULL);

	if (bbuf == NULL) {
		bbuf=(char *)xmalloc(in->len);
		memcpy(bbuf, in->ptr, in->len);
		buffer_size=in->len;
	}
	else {
		char *newbuf=NULL;

		newbuf=(char *)xmalloc(buffer_size + in->len);
		memcpy(newbuf, bbuf, (size_t)buffer_size);
		memcpy(newbuf + buffer_size, in->ptr, in->len);
		xfree(bbuf);
		bbuf=newbuf;
		buffer_size=(buffer_size + in->len);
	}
	return;
}

void pbuffer_reset(void) {
	buffer_size=0;
	if (bbuf) {
		xfree(bbuf);
	}
	bbuf=NULL;
	return;
}

void add_tcpflag(int flag) {
	if (flag < 0 || flag > 0xFF) {
		yyerror("tcp flag out of range");
		return;
	}
	ptcpflags |= flag;
}

int get_tcpflags(void) {
	if (ptcpflags < 0 || ptcpflags > 0xFF) {
		yyerror("combined tcp flags are out of range");
		return 0;
	}
	return ptcpflags;
}
