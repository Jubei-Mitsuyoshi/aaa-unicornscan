/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 *
 * modified for unicornscan
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <errno.h>

#include <xmalloc.h>

struct arc4_stream {
	uint8_t i;
	uint8_t j;
	uint8_t s[256];
};

static int rs_initialized;
static struct arc4_stream rs;
static pid_t arc4_stir_pid;

static uint8_t arc4_getbyte(struct arc4_stream *);

static void arc4_init(struct arc4_stream *as) {
	int	n;

	for (n = 0; n < 256; n++) {
		as->s[n] = n;
	}

	as->i = 0;
	as->j = 0;
}

static void arc4_addrandom(struct arc4_stream *as, uint8_t *dat, int datlen) {
	int	n;
	uint8_t si;

	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
	as->j = as->i;
}

static int arc4_stir(struct arc4_stream *as) {
	int rfd=0, i=0;
	uint8_t rdat[256];

	rfd=open(RANDOM_DEVICE, O_RDONLY);
	if (rfd < 0) {
		perror("open " RANDOM_DEVICE);
		return -1;
	}

	if (read(rfd, rdat, 256) != 256) {
		perror("read random seed data");
		return -1;
	}

	arc4_stir_pid = getpid();
	arc4_addrandom(as, rdat, 256);

	memset(rdat, 0, 256);
	/*
	 * Discard early keystream, as per recommendations in:
	 * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
	 */
	/* it would seem that people say >= 512 bytes now, so lets do 1k */
	for (i = 0; i < 1024; i++) {
		(void) arc4_getbyte(as);
	}
	return 1;
}

static uint8_t arc4_getbyte(struct arc4_stream *as) {
	uint8_t si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;
	return (as->s[(si + sj) & 0xff]);
}

static uint32_t arc4_getword(struct arc4_stream *as) {
	uint32_t val;
	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);
	return val;
}

void arc4random_stir(void) {
	if (!rs_initialized) {
		arc4_init(&rs);
		rs_initialized = 1;
	}
	arc4_stir(&rs);
}

void arc4random_addrandom(uint8_t *dat, int datlen) {
	if (!rs_initialized) {
		(void) arc4random_stir();
	}
	arc4_addrandom(&rs, dat, datlen);
}

uint32_t arc4random(void) {
	if (!rs_initialized || arc4_stir_pid != getpid()) {
		(void) arc4random_stir();
	}
	return arc4_getword(&rs);
}
