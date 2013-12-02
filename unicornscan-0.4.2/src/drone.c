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

#include <netdb.h>

#include <settings.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <drone.h>

int parse_drone_list(const char *input) {
	char *data=NULL, *start=NULL;
	size_t slen=0;
	int j=0;
	char hostbuf[128];
	uint32_t sport;

	assert(s->dlh == NULL);

	s->dlh=(drone_list_head_t *)xmalloc(sizeof(drone_list_head_t));

	s->dlh->head=NULL;
	s->dlh->bottom=NULL;
	s->dlh->size=0;

	data=xstrdup(input); start=data;

	slen=strlen(data);
	if (slen == 0) {
		MSG(M_ERR, "Drone list is too small or blank.");
		return -1;
	}

	if (s->verbose > 5) {
		MSG(M_DBG2, "Drone list `%s' is %d long, starting to parse it", s->drone_str, slen);
	}

	for (j=0 ; (size_t)j < slen ; j++) {
		if (data[j] == ',') {
			data[j]='\0';
		}
	}

	if (strlen(data)) {
		memset(hostbuf, 0, sizeof(hostbuf));
		if ((j=sscanf(data, "%127[a-zA-Z0-9_.-]:%u", hostbuf, &sport)) != 2) {
			MSG(M_ERR, "Corrupt drone address `%s' got %d parts host `%s' port %d, use 1.2.3.4:123 for host 1.2.3.4 port 123", data, j, hostbuf, sport);
			return -1;
		}
		else {
			struct hostent *dhe=NULL;

			dhe=gethostbyname(hostbuf);
			if (dhe == NULL) {
				MSG(M_ERR, "Unknown host `%s' in drone list", hostbuf);
				return -1;
			}
			else {
				struct in_addr *ia=NULL;

				drone_t *d=NULL;

				d=(drone_t *)xmalloc(sizeof(drone_t));
				memset(d, 0, sizeof(drone_t));

				d->status=0;
				d->type=0;
				ia=(struct in_addr *)dhe->h_addr_list[0];
				d->dsa.sin_addr.s_addr=ia->s_addr;
				d->dsa.sin_port=htons(sport);
				d->s=-1;
				d->next=NULL;

				s->dlh->head=d;
				s->dlh->bottom=d;
				s->dlh->size=1;

				if (s->verbose > 4) MSG(M_DBG1, "Added drone `%s:%d'", inet_ntoa(d->dsa.sin_addr), ntohs(d->dsa.sin_port));
			}
		}
	}

	for (j=0 ; (size_t)j < slen ; j++) {
		if (data[j] == '\0' && (unsigned int)(j + 1) < slen) {
			char *dptr=NULL;
			++j;
			dptr=(data + j);
			if (strlen(dptr)) {
				memset(hostbuf, 0, sizeof(hostbuf));
				if (sscanf(dptr, "%127[a-zA-Z0-9_.-]:%u", hostbuf, &sport) != 2) {
					MSG(M_ERR, "Corrupt drone address `%s' got host `%s' port %d, use 1.2.3.4:123 for host 1.2.3.4 port 123", data, hostbuf, sport);
					return -1;
				}
				else {
					struct hostent *dhe=NULL;

					dhe=gethostbyname(hostbuf);
					if (dhe == NULL) {
						MSG(M_ERR, "Unknown host `%s' in drone list", hostbuf);
						return -1;
					} /* hostname lookup failed */
					else {
						struct in_addr *ia=NULL;

						drone_t *d=NULL,*l=NULL;

						d=(drone_t *)xmalloc(sizeof(drone_t));
						memset(d, 0, sizeof(drone_t));

						d->status=0;
						d->type=0;
						ia=(struct in_addr *)dhe->h_addr_list[0];
						d->dsa.sin_addr.s_addr=ia->s_addr;
						d->dsa.sin_port=htons(sport);
						d->s=-1;
						d->next=NULL;

						l=s->dlh->bottom;
						s->dlh->bottom=d;
						l->next=d;
						s->dlh->size++;

						if (s->verbose > 4) MSG(M_DBG1, "Added drone `%s:%d'", inet_ntoa(d->dsa.sin_addr), ntohs(d->dsa.sin_port));
					} /* hostname lookup worked */
				} /* sscanf worked */
			} /* dptr strlen > 0 */
		} /* there is `stuff' after this '\0' */
	} /* the length of the string */

	data=start;
	xfree(data);

	return 1;
}
