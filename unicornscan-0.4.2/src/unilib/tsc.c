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

#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <settings.h>
#include <xdelay.h>
#include <panic.h>

/* XXX all this sucks */

#if defined(__i386__) || defined(__x86_64__)

#define tsc_t uint64_t

inline tsc_t get_tsc(void) {
	tsc_t j;

	asm volatile ("rdtsc" : "=A" (j));

	return j;
}

/* XXX but not as much as this */
inline void nop(void) {
	asm volatile (	"rep\n"
			"nop\n");
	return;
}

#elif defined(__powerpc__) || defined(__ppc__)

#define tsc_t uint64_t
	/*
	 * 64 bit idea taken from kernel/cycle.h from fftw-3.0.1
	 * by Matteo Frigo
	 */

inline tsc_t get_tsc(void) {
	uint32_t tbl, tbu0, tbu1;

	do {
		asm volatile ("mftbu %0" : "=r" (tbu0));
		asm volatile ("mftb  %0" : "=r" (tbl) );
		asm volatile ("mftbu %0" : "=r" (tbu1));
	} while (tbu0 != tbu1);

	return (((tsc_t)tbu0) << 32) | tbl;
}

inline void nop(void) {

	asm volatile ("nop");
	return;
}

#elif defined(__sparc_v9__)

#define tsc_t uint32_t /* shrug */

inline tsc_t get_tsc(void) {
	tsc_t j;

	asm volatile ("rd %%tick, %0" : "=r" (j));

	return j;
}

inline void nop(void) {
	asm volatile ("nop");
	return;
}

#else

#warning give me a shell, or send me some _tested_ asm timestamp counter code, i dont have 100 boxes to test with

#define tsc_t uint32_t /* shrug */

inline tsc_t get_tsc(void) {
	PANIC("give me a shell, or send me some _tested_ asm timestamp counter code, i dont have 100 boxes to test with");
}

inline void nop(void) {
	PANIC("give me a shell, or send me some _tested_ asm timestamp counter code, i dont have 100 boxes to test with");
}

#endif


static tsc_t tsc_delay=0;
static tsc_t tsc_s_time=0;

/***************************************************************************************
 * XXX TODO the new jersey approach you see here is just a figment of your imagination *
 ***************************************************************************************/
void tsc_init_tslot(uint32_t pps) {
	tsc_t start=0, end=0, cps=0;
	struct timespec s_time, rem;

	rem.tv_sec=0; rem.tv_nsec=0;
	s_time.tv_sec=0; s_time.tv_nsec=100000001;

	start=get_tsc();

	do {
		if (nanosleep((const struct timespec *)&s_time, &rem) != -1) break;
	} while (rem.tv_sec != 0 && rem.tv_nsec != 0);

	end=get_tsc();

	cps=(end - start) * 10;

	tsc_delay=(cps / pps);
}


void tsc_start_tslot(void) {
	tsc_s_time=get_tsc();
	return;
}

/***************************************************************************************
 * XXX TODO the new jersey approach you see here is just a figment of your imagination *
 ***************************************************************************************/
void tsc_end_tslot(void) {
	while (1) {
		if ((get_tsc() - tsc_s_time) >= tsc_delay) {
			break;
		}
		nop();
	}
	tsc_s_time=0;
	return;
}
