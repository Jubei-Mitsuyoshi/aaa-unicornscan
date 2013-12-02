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

#include <scan_export.h>

int compare_ip_report(const void *a, const void *b) {
	int ret=1;
	union {
		ip_report_t *r;
		const void *v;
	} d_u1, d_u2;

	d_u1.v=a;
	d_u2.v=b;

	if (d_u1.r->sport == d_u2.r->sport) {
		if (
		d_u1.r->proto	   ==	d_u2.r->proto &&
		d_u1.r->type	   ==	d_u2.r->type &&
		d_u1.r->ttl	   ==	d_u2.r->ttl  &&
		d_u1.r->type	   ==	d_u2.r->type &&
		d_u1.r->subtype	   ==	d_u2.r->subtype &&
		d_u1.r->host_addr  ==	d_u2.r->host_addr &&
		d_u1.r->trace_addr ==	d_u2.r->trace_addr
		) {
			ret=0;
		}
	}

	return ret;
}

int compare_ip_report_addr(const void *a, const void *b) {
	int ret=0;
	union {
		ip_report_t *r;
		const void *v;
	} d_u1, d_u2;

	d_u1.v=a;
	d_u2.v=b;

	if (d_u1.r->host_addr == d_u2.r->host_addr) {
		ret=0;
	}
	else if (d_u1.r->host_addr > d_u2.r->host_addr) {
		ret=1;
	}
	else {
		ret=-1;
	}
	
	return ret;
}

int compare_ip_report_port(const void *a, const void *b) {
	int ret=1;
	union {
		ip_report_t *r;
		const void *v;
	} d_u1, d_u2;

	d_u1.v=a;
	d_u2.v=b;

	if (d_u1.r->sport == d_u2.r->sport) {
		ret=0;
	}
	else if (d_u1.r->sport > d_u2.r->sport) {
		ret=1;
	}
	else {
		ret=-1;
	}
	
	return ret;
}
