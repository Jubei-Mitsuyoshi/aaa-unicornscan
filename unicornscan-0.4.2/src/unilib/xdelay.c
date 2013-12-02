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
/* XXX include check code for hpet, rtc, or tsc in that order, using first 2 if found > tsc */
#include <config.h>

#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <output.h>
#include <settings.h>
#include <xdelay.h>

static void (*r_start_tslot)(void)=NULL;
static void (*r_end_tslot)(void)=NULL;

/* tsc.c */
void tsc_init_tslot(uint32_t );
void tsc_start_tslot(void);
void tsc_end_tslot(void);

/* gtod.c */
void gtod_init_tslot(uint32_t );
void gtod_start_tslot(void);
void gtod_end_tslot(void);

/* sleep.c */
void sleep_init_tslot(uint32_t );
void sleep_start_tslot(void);
void sleep_end_tslot(void);

char *delay_getopts(void) {
	static char str[64];

	sprintf(str, "%d:tsc %d:gtod %d:sleep", XDELAY_TSC, XDELAY_GTOD, XDELAY_SLEEP);
	return str;
}

void init_tslot(uint32_t pps, uint8_t delay_type) {
	switch (delay_type) {
		case XDELAY_TSC:
			r_start_tslot=&tsc_start_tslot;
			r_end_tslot=&tsc_end_tslot;
			tsc_init_tslot(pps);
			if (s->verbose > 1) MSG(M_VERB, "Using TSC delay");
			break;
		case XDELAY_GTOD:
			r_start_tslot=&gtod_start_tslot;
			r_end_tslot=&gtod_end_tslot;
			gtod_init_tslot(pps);
			if (s->verbose > 1) MSG(M_VERB, "Using gtod delay");
			break;
		case XDELAY_SLEEP:
			r_start_tslot=&sleep_start_tslot;
			r_end_tslot=&sleep_end_tslot;
			sleep_init_tslot(pps);
			if (s->verbose > 1) MSG(M_VERB, "Using sleep delay");
			break;
		default:
			MSG(M_ERR, "Unknown delay type %d, defaulting to tsc delay", delay_type);
			r_start_tslot=&tsc_start_tslot;
			r_end_tslot=&tsc_end_tslot;
			tsc_init_tslot(pps);
			break;
	}
	return;
}

inline void start_tslot(void) {
	r_start_tslot();
}

inline void end_tslot(void) {
	r_end_tslot();
}
