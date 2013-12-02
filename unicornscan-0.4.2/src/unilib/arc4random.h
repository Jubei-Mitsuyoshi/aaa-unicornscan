#ifndef _ARC4RANDOM
# define _ARC4RANDOM

void arc4random_stir(void);
void arc4random_addrandom(unsigned char *, int);
unsigned int arc4random(void);

#endif
