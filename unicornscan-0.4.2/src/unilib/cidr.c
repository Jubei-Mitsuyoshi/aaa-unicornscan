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
#include <netdb.h> /* gethost */

#include <xmalloc.h>
#include <settings.h>
#include <output.h>
#include <cidr.h>

static const uint32_t cidrmasktbl[]={
0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
};

int get_cidr(uint32_t *min_ip, uint32_t *max_ip, const char *data, char *errstr, size_t errlen) {
	uint32_t mask=0, netmask=0;
	uint32_t ioctets[4];
	union {
		uint8_t octets[4];
		uint32_t num;
	} na_u;

	if (sscanf(data, "%u.%u.%u.%u/%u", &ioctets[0], &ioctets[1], &ioctets[2], &ioctets[3], &mask) != 5) {
		if (sscanf(data, "%u.%u.%u.%u", &ioctets[0], &ioctets[1], &ioctets[2], &ioctets[3]) != 4) {
			/* ok so its a hostname? */
			struct hostent *s_hostinfo=NULL;
			struct in_addr *ia=NULL;
			char *ptr=NULL, *start=NULL;
			uint8_t s_seen=0;

			ptr=xstrdup(data);

			for (start=ptr ; *ptr != '\0' ; ptr++) {
				if (*ptr == '/') {
					s_seen=1;
					*ptr='\0'; ptr++;
					break;
				}
			}
			if (s_seen) {
				if (sscanf(ptr, "%u", &mask) != 1) {
					snprintf(errstr, errlen, "hostname/cidr format corrupt, usage is `host.dom.tld/24'");
					xfree(start);
					return -1;
				}
			}
			else {
				mask=32;
			}

			if (s->verbose > 4) MSG(M_DBG2, "Looking up hostname info for `%s'", start);
			s_hostinfo=gethostbyname(start);
			if (s_hostinfo == NULL) {
				snprintf(errstr, errlen, "gethostbyname `%s': %s", start, strerror(errno));
				xfree(start);
				return -1;
			}

			/* the right thing to do here would be to go though the list of hosts that match that	*
			 * a record, and add them to the targetlist, but i doubt people would expect that sort	*
			 * of thing, and might be upset about scanning 2 networks not 1 for a hostname		*/
			ia=(struct in_addr *)s_hostinfo->h_addr_list[0];
			na_u.num=ia->s_addr;

			ioctets[0]=na_u.octets[0];
			ioctets[1]=na_u.octets[1];
			ioctets[2]=na_u.octets[2];
			ioctets[3]=na_u.octets[3];

			xfree(start);
		}
		else {
			mask=32;
		}
	}

	/* sanity checking */
	if (ioctets[0] > 255 || ioctets[1] > 255 || ioctets[2] > 255 || ioctets[3] > 255) {
		snprintf(errstr, errlen, "Octets should be 255 or lower");
		return -1;
	}

	if (mask > 32) {
		snprintf(errstr, errlen, "Network mask is too large"); /* the spoon is too big */
		return -1;
	}

	/* killing all the innocence, we wave goodbye to those times */
	if (mask < 1) {
		netmask=0;
	}
	else { /* And who will begin again? have we reached the end? */
		netmask=htonl(cidrmasktbl[(mask - 1)]);
	}

	na_u.octets[0]=ioctets[0];
	na_u.octets[1]=ioctets[1];
	na_u.octets[2]=ioctets[2];
	na_u.octets[3]=ioctets[3];

	*min_ip=htonl(na_u.num & netmask);
	*max_ip=htonl(na_u.num | ~(netmask));

	return 1;
}
