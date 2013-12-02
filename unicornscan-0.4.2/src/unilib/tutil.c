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

#include <scan_progs/packets.h>
#include <tutil.h>

/* XXX if you use this function wrong (with buf too short) I will happily overflow it, too bad,	*
 * good luck controlling the return address or stack frame pointer though			*/
void str_tcpflagsp(char *buf, const struct mytcphdr *tcp) {
	int val=0;

	assert(tcp != NULL);

	if (tcp->fin) val |= TH_FIN;
	if (tcp->syn) val |= TH_SYN;
	if (tcp->rst) val |= TH_RST;
	if (tcp->psh) val |= TH_PSH;
	if (tcp->ack) val |= TH_ACK;
	if (tcp->urg) val |= TH_URG;
	if (tcp->ece) val |= TH_ECE;
	if (tcp->cwr) val |= TH_CWR;

	str_tcpflags(buf, val);
	return;
}

void str_tcpflags(char *buf, int flags) {
	assert(buf != NULL);

	memset(buf, '-', 7);

	if (flags & TH_FIN) *buf='F';
	buf++;
	if (flags & TH_SYN) *buf='S';
	buf++;
	if (flags & TH_RST) *buf='R';
	buf++;
	if (flags & TH_PSH) *buf='P';
	buf++;
	if (flags & TH_ACK) *buf='A';
	buf++;
	if (flags & TH_URG) *buf='U';
	buf++;
	if (flags & TH_ECE) *buf='E';
	buf++;
	if (flags & TH_CWR) *buf='C';
	*++buf='\0';

	return;
}
