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

#include <settings.h>
#include <scan_export.h>
#include <portfunc.h>

#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/arc4random.h>

static int32_t *ports=NULL;
static uint32_t num_ports=0;
static int32_t *user_index=0;

/* XXX TCP and UDP list */
static int32_t quick_ports[]={
/*  |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     | */
    7,    9,   11,   13,   18,   19,   21,   22,   23,   25,   37,   39,   42,   49,   50,   53,
   65,   67,   68,   69,   70,   79,   80,   81,   88,  105,  106,  107,  109,  110,  111,  113,
  123,  129,  135,  137,  138,  139,  143,  161,  162,  163,  164,  174,  177,  178,  179,  191, 
  199,  201,  202,  204,  206,  209,  210,  213,  220,  345,  346,  347,  369,  370,  371,  372,
  389,  406,  422,  443,  444,  445,  487,  500,  512,  513,  514,  517,  518,  520,  525,  533,
  538,  548,  563,  587,  610,  611,  612,  631,  636,  655,  666,  706,  750,  751,  752,  765,
  779,  808,  873,  901,  923,  941,  946,  992,  993,  994,  995, 1001, 1025, 1080, 1210, 1214,
 1234, 1241, 1349, 1352, 1423, 1424, 1425, 1433, 1434, 1524, 1525, 1645, 1646, 1649, 1701, 1718,
 1719, 1720, 1723, 1812, 1813, 2101, 2102, 2103, 2104, 2140, 2150, 2233, 2345, 2401, 2430, 2431,
 2432, 2433, 2583, 2628, 2776, 2777, 2988, 2989, 3050, 3130, 3150, 3306, 3456, 3456, 3493, 3542,
 3543, 3544, 3545, 3632, 3690, 3801, 4000, 4400, 4321, 4567, 4899, 5002, 5136, 5137, 5138, 5139,
 5222, 5269, 5308, 5354, 5355, 5422, 5423, 5424, 5425, 5432, 5503, 5555, 5556, 5678, 6000, 6001,
 6002, 6003, 6004, 6005, 6006, 6346, 6347, 6543, 6789, 6838, 6667, 6668, 6669, 6670, 7000, 7001,
 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7028, 7100, 7983, 8080, 8088, 8787, 8879, 9101,
 9102, 9103, 9325, 9359,10026,10027,10067,10080,10081,10167,10498,11201,15345,17001,17002,17003,
18753,20011,20012,21554,22273,26274,27374,27444,27573,31335,31337,31338,31787,31789,31790,31791,
32668,32768,32769,32770,32771,32771,32772,32773,32774,32775,32768,32776,33390,47262,49301,54320,
54321,57341,58008,58009,58666,59211,60000,60006,61000,61348,61466,61603,63485,63808,63809,64429, /* 288 */
65000,65506,65535,-1 /* 291 */
};
#define QUICK_PORT_COUNT 291

void init_portsquick(void) {
	num_ports=QUICK_PORT_COUNT;
	ports=&quick_ports[0];
}

void reset_getnextport(void) {
	user_index=&ports[0];
	/* ash */ return;
}

int get_nextport(int32_t *in) {
	assert(user_index != NULL);

	if (*user_index == -1) {
		return -1;
	}
	else {
		*in=*user_index;
		user_index++;
	}
	return 1;
}

void shuffle_ports(void) {
	uint32_t ss=0, d=0, indx=0;
	int j=0;

	if (s->verbose > 2) MSG(M_DBG1, "Shuffle ports at depth %d", num_ports);

	for (j=0 ; j < 2 ; j++) {
		for (indx=0 ; indx < num_ports ; indx++) {
			int32_t swap=0;

			ss=(arc4random() % num_ports); /* we use the low order bits, get over it */
			d=(arc4random() % num_ports); /* we use the low order bits, get over it */
			if (ss == d) {
				/* best effort */
				d=(arc4random() % num_ports); /* we use the low order bits, get over it */
			}
			swap=ports[ss];
			ports[ss]=ports[d];
			ports[d]=swap;
		}
	}
	return;
}

int parse_pstr(const char *input) {
	uint16_t port_index=0;
	char *ptrs[256], *data=NULL;
	uint8_t ptrs_i=0;
	char *string=NULL;
	int j=0;

	if (input[0] == 'a' || input[0] == 'A') {
		string=xstrdup("0-65535");
	}
	else if (input[0] == 'p' || input[0] == 'P') {
		string=xstrdup("1-1024");
	}
	else {
		string=xstrdup(input);
	}

	memset(&ptrs, 0, sizeof(ptrs));
	data=xstrdup(string);

	if ('0' <= *data && *data <= '9') ptrs[ptrs_i++]=data;

	for (ptrs_i=1 ; *data != '\0' ; data++) {
		if (*data == ',') {
			*data='\0';

			if (*(data + 1) == '\0') break;

			if ('0' <= *(data + 1) && *(data + 1) <= '9') {
				ptrs[ptrs_i++]=(data + 1);
				if (ptrs_i > 0xFE) break;
			}
		}
	}

	for (j=0 ; j < ptrs_i ; j++) {
		uint32_t low=0, high=0;

		if (ptrs[j] == NULL) break;
		if (sscanf(ptrs[j], "%u-%u", &low, &high) == 2) {
			if (low > high) {
				uint32_t swap;
				/* obviously someone is getting sleepy */
				swap=low; low=high; high=swap;
			}

			if (low > 0xFFFF || high > 0xFFFF) return -1;
			if (num_ports + (high - low) > 0xFFFF) return -1;
			num_ports += (high - low) + 1;
		}
		else if (sscanf(ptrs[j], "%u", &low) == 1) {
			if (low > 0xFFFF) return -1;
			if (num_ports + 1 > 0xFFFF) return -1;
			num_ports++;
		}
		else {
			return -1;
		}
	}

	ports=(int32_t *)xmalloc((num_ports * sizeof(int32_t)) + 2);

	for (j=0 ; j < ptrs_i ; j++) {
		int32_t low=0, high=0, cnt=0;

		if (ptrs[j] == NULL) break;

		if (sscanf(ptrs[j], "%d-%d", &low, &high) == 2) {
			if (low > high) {
				int32_t swap;
				/* obviously someone is getting sleepy */
				swap=low; low=high; high=swap;
			}

			for (cnt=low ; low <= high ; low++) {
				ports[port_index++]=low;
			}
		}
		else if (sscanf(ptrs[j], "%u", &low) == 1) {
			ports[port_index++]=low;
		}
		else {
			return -1;
		}
	}

	xfree(string);

	ports[num_ports]=-1;
	user_index=&ports[0];

	return 1;
}

char *getservname(uint16_t port) {
	char tmpstr[256];
	int sport=0;
	uint8_t proto=0;
	static FILE *uniservices=NULL;
	static char _name[64];

	if (s->mode == MODE_UDPSCAN) {
		proto=17;
	}
	else if (s->mode == MODE_TCPSCAN) {
		proto=6;
	}
	else {
		MSG(M_DBG2, "not tcp or udp, but `%d' this isnt going to work", s->mode);
		sprintf(_name, "Unknown");
		return &_name[0];
	}

	/* this is slow and bad, but its not critical so here it is */

	if (uniservices == NULL) {
		if (s->verbose > 5) MSG(M_DBG2, "Opening `%s' for port names", PORT_NUMBERS);
		uniservices=fopen(PORT_NUMBERS, "r");
		if (uniservices == NULL) {
			sprintf(_name, "Error");
			return &_name[0];
		}
	}
	else {
		rewind(uniservices);
	}

	while (fgets(tmpstr, sizeof(tmpstr) -1, uniservices) != NULL) {
		if (tmpstr[0] == '#') continue;

		memset(_name, 0, sizeof(_name));

		switch (proto) {
			case 17:
				if (sscanf(tmpstr, "%63s %d/udp", _name, &sport) == 2) {
					if (port == sport) {
						return &_name[0];
					}
				}
				break;
			case 6:
				if (sscanf(tmpstr, "%63s %d/tcp", _name, &sport) == 2) {
					if (port == sport) {
						return &_name[0];
					}
				}
				break;
		}
	}

	sprintf(_name, "Unknown");
	return &_name[0];
}

char *getouiname(uint8_t a, uint8_t b, uint8_t c) {
	char tmpstr[256];
	static FILE *ouiconf=NULL;
	static char _name[64];

	/* this is slow and bad, but its not critical so here it is */

	if (ouiconf == NULL) {
		if (s->verbose > 5) MSG(M_DBG2, "Opening `%s' for oui names", OUI_CONF);
		ouiconf=fopen(OUI_CONF, "r");
		if (ouiconf == NULL) {
			sprintf(_name, "Error");
			return &_name[0];
		}
	}
	else {
		rewind(ouiconf);
	}

	while (fgets(tmpstr, sizeof(tmpstr) -1, ouiconf) != NULL) {
		unsigned int fa=0, fb=0, fc=0;
		if (tmpstr[0] == '#') continue;

		memset(_name, 0, sizeof(_name));

		sscanf(tmpstr, "%x-%x-%x:%63[^\n]", &fa, &fb, &fc, _name);
		if ((uint8_t)fa == a && (uint8_t)fb == b && (uint8_t)fc == c) {
			return &_name[0];
		}
	}

	sprintf(_name, "Unknown");
	return &_name[0];
}
