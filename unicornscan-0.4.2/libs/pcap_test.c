#include <stdio.h>
#include <pcap.h>

int main(void) {
	printf("%s\n", pcap_lib_version());
	exit(0);
}
