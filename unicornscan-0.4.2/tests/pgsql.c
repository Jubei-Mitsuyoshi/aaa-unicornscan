#include <stdio.h>
#include <libpq-fe.h>
#include <pg_config.h>

int main(int argc , char ** argv) {
	printf("%s\n", PG_VERSION);
}
