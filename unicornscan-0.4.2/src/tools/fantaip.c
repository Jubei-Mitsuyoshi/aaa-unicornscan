/*
 * AUTHOR: kiki, Wanta Fanta? ( gh0st <gh0st@rapturesecurity.org> )
 * "Yo man, i thought you was black!"
 *
 * this is GPL like the rest
 */
#include <config.h>

#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#ifdef __linux__
#include <net/ethernet.h>
#elif defined(SOLARIS)
#include <sys/ethernet.h>
#elif (BSD >= 199103) || defined(__NetBSD__) || defined(__DragonFly__)
#include <net/if_ether.h>
#elif defined(__FreeBSD__)
#include <netinet/if_ether.h>
#endif

#include <pcap.h>

#include <scan_progs/packets.h>
#include <unilib/pcaputil.h>
#include <unilib/tutil.h>
#include <libnet.h>

/* #define VERBOSE 1 */

struct  myetheraddr {
	uint8_t octet[ETHER_ADDR_LEN];
};

struct _a_ {
	struct myetheraddr shwaddr;
	uint32_t saddr;
	libnet_t *l;
	char *device;
	libnet_ptag_t arp, eth;
	int addr_cleared;
} bob;

int send_arp(struct myetheraddr *);
int broadcast_arp(uint16_t, uint32_t);
void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
void decode_mac(const uint8_t *);

static int breakloop=0;
static void alarm_hndlr(int signo) {
	if (signo == SIGALRM) {
		breakloop=1;
	}
}

int broadcast_arp(uint16_t type, uint32_t addr) {
	uint8_t broadcast[6];

	memset(broadcast, 0xFF, 6);

	bob.arp=libnet_build_arp(
				ARPHRD_ETHER,				/* ethernet		*/
				ETHERTYPE_IP,				/* proto for addr res	*/
				6,					/* hardware addr len	*/
				4,					/* proto addr len	*/
				type,					/* arp type		*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* source		*/
				(uint8_t *)&addr,			/* ip src		*/
				&broadcast[0],				/* dst hw		*/
				(uint8_t *)&bob.saddr,			/* src ip		*/
				NULL,					/* no pl		*/
				0,					/* zero len		*/
				bob.l,					/* libnet handle	*/
				bob.arp);				/* arp id?		*/

	if (bob.arp < 0) {
		fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(bob.l));
		return -1;
	}

	bob.eth=libnet_build_ethernet(
				&broadcast[0],				/* dest host hw addr	*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* dest host src addr	*/
				ETHERTYPE_ARP,				/* ethernet, arp	*/
				NULL,					/* no payload		*/
				0,					/* obviously is 0 len	*/
				bob.l,					/* libnet handle	*/
				bob.eth);				/* eth id?		*/
	if (bob.eth < 0) {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(bob.l));
		return -1;
	}

	if (libnet_write(bob.l) == -1) {
		fprintf(stderr, "%s", libnet_geterror(bob.l));
		return -1;
	}
	return 1;
}

int send_arp(struct myetheraddr *dst) {

	printf("Sending ARP resp to: "); decode_mac((uint8_t *)&dst->octet[0]); printf("\n"); fflush(stdout);

	bob.arp=libnet_build_arp(
				ARPHRD_ETHER,				/* ethernet follows	*/
				ETHERTYPE_IP,				/* proto for addr res	*/
				6,					/* hardware addr len	*/
				4,					/* proto addr len	*/
				ARPOP_REPLY,				/* duh			*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* source		*/
				(uint8_t *)&bob.saddr,			/* ip src		*/
				(uint8_t *)&dst->octet[0],		/* dst hw		*/
				(uint8_t *)&bob.saddr,			/* src ip		*/
				NULL,					/* no pl		*/
				0,					/* zero len		*/
				bob.l,					/* libnet handle	*/
				bob.arp);				/* arp id?		*/
	if (bob.arp < 0) {
		fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(bob.l));
		return -1;
	}

	bob.eth=libnet_build_ethernet(
				(uint8_t *)&dst->octet[0],		/* dest host hw addr	*/
				(uint8_t *)&bob.shwaddr.octet[0],	/* dest host src addr	*/
				ETHERTYPE_ARP,				/* ethernet, arp	*/
				NULL,					/* no payload		*/
				0,					/* obviously is 0 len	*/
				bob.l,					/* libnet handle	*/
				bob.eth);				/* eth id?		*/

	if (bob.eth < 0) {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(bob.l));
		return -1;
	}

	if (libnet_write(bob.l) == -1) {
		fprintf(stderr, "%s", libnet_geterror(bob.l));
		return -1;
	}
	return 1;
}

#define FILTER "arp"

int main(int argc, char ** argv) {
	char errbuf[LIBNET_ERRBUF_SIZE];
	char errors[PCAP_ERRBUF_SIZE], pfilter[2048];
	struct ifreq ifr;
	bpf_u_int32 mask=0, net=0;
	int st=-1, tries=0;
	struct bpf_program filter;
	struct myetheraddr *e=NULL;
	pcap_t *pdev=NULL;

	memset(&ifr, 0, sizeof(ifr));

	if (argc != 3) {
		printf("FantaIP by KIKI\nUsage: (example) %s eth0 192.168.13.211\n", argv[0]);
		exit(1);
	}

	bob.device=strdup(argv[1]);
	assert(bob.device != NULL);
	bob.saddr=(uint32_t)inet_addr(argv[2]);
	bob.addr_cleared=0;

	st=socket(AF_INET, SOCK_DGRAM, 0);
	if (st < 0) {
		fprintf(stderr, "create socket fails: %s", strerror(errno));
		exit(1);
	}

	bob.l=libnet_init(LIBNET_LINK_ADV, bob.device, errbuf);
	if (bob.l == NULL) {
		fprintf(stderr, "libnet_init: %s\n", strerror(errno));
		exit(1);
	}

	bob.arp=0;
	bob.eth=0;

	e=(struct myetheraddr *)libnet_get_hwaddr(bob.l);
	if (e == NULL) {
		perror("bad things batman");
		exit(1);
	}
	memcpy(&bob.shwaddr, e, sizeof(bob.shwaddr));

	snprintf(pfilter, sizeof(pfilter) -1, FILTER);

	memset(errors, 0, sizeof(errors));
	pcap_lookupnet(bob.device, &net, &mask, errors);

	memset(errors, 0, sizeof(errors));
	pdev=pcap_open_live(bob.device, 500, 1, 0, errors);

	if (util_getheadersize(pdev, errors) != 14) {
		fprintf(stderr, "You SURE this is an ethernet interface? doesnt look like one\n");
		exit(1);
	}

	if (util_preparepcap(pdev, errors) < 0) {
		fprintf(stderr, "Can't prepare bpf socket: %s\n", strerror(errno));
		exit(1);
	}

	pcap_compile(pdev, &filter, pfilter, 0, net);
	pcap_setfilter(pdev, &filter);

	/* look for dups */
	if (pcap_setnonblock(pdev, 1, errors) < 0) {
		fprintf(stderr, "Can't set pcap dev nonblocking: %s\n", errors);
		exit(1);
	}

	bob.addr_cleared=0;

	while (bob.addr_cleared == 0 && tries < 3) {
		/* lets be sure about this ;] */
		broadcast_arp(ARPOP_REQUEST, 0xFFFFFFFF);
		broadcast_arp(ARPOP_REQUEST, 0x00000000);
		broadcast_arp(ARPOP_REQUEST, bob.saddr);

		signal(SIGALRM, &alarm_hndlr);
		breakloop=0;
		alarm(1);
		while (1) {
			pcap_dispatch(pdev, -1, &process_packet, NULL);
			if (breakloop || bob.addr_cleared != 0) break;
		}
		alarm(0);
		signal(SIGALRM, SIG_DFL);
		tries++;
	}

	alarm(0);
	signal(SIGALRM, SIG_DFL);

	if (bob.addr_cleared == -1) {
		fprintf(stderr, "Error: Address already in use\n");
		exit(1);
	}

	bob.addr_cleared=1;

	printf("arping for %s [", inet_ntoa(*((const struct in_addr *)&bob.saddr))); fflush(stdout);
	decode_mac(&bob.shwaddr.octet[0]); printf(" ]\n"); fflush(stdout);

	/* ok block now */
	if (pcap_setnonblock(pdev, 0, errors) < 0) {
		fprintf(stderr, "Can't set pcap dev nonblocking: %s\n", errors);
		exit(1);
	}

	pcap_loop(pdev, 0, &process_packet, NULL);

	libnet_destroy(bob.l);
	exit(0);
}

struct _PACKED_ arp_packet {
	uint16_t hw_type;
	uint16_t protocol;
	uint8_t hwsize;
	uint8_t protosize;
	uint16_t opcode;
	uint8_t smac[ETHER_ADDR_LEN];
	uint32_t sip;
	uint8_t dmac[ETHER_ADDR_LEN];
	uint32_t dip;
};

void process_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	const struct ether_header *ehdr_ptr=NULL;
	const struct arp_packet *ap=NULL;

	if (phdr->caplen != phdr->len || phdr->caplen < sizeof(struct ether_header)) {
		return;
	}
 
	ehdr_ptr=(const struct ether_header *)packet;

	if (ntohs(ehdr_ptr->ether_type) != ETHERTYPE_ARP) {
		return;
	}
	ap=(const struct arp_packet *)(packet + sizeof(struct ether_header));
	if (phdr->caplen < (sizeof(struct ether_header) + sizeof(struct arp_packet))) {
		fprintf(stderr, "Short packet!!!!\n");
		return;
	}

	/* ethernet -> ip -> hwsize = 6 and ip size = 4 */
	if (ntohs(ap->hw_type) == 1 && ap->protocol == 8 && ap->hwsize == 6 && ap->protosize == 4) {
#ifdef VERBOSE
		char src[17], dst[17];

#endif
		switch (ntohs(ap->opcode)) {
			case 1:
				/* arp request */
#ifdef VERBOSE
				printf("Arp Request: Source Mac: ");
				decode_mac(ap->smac);
				printf(" Dest Mac: ");
				decode_mac(ap->dmac);
				/* hide the children, they will cry if they see this */
				snprintf(src, sizeof(src) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->sip)));
				snprintf(dst, sizeof(dst) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->dip)));
				printf(" [ %s -> %s ]\n", src, dst);
#endif
				if (bob.addr_cleared) {
					if (ap->dip == bob.saddr) {
						struct myetheraddr sea;

						memset(&sea, 0, sizeof(sea));

						memcpy(&(sea.octet[0]), &ap->smac[0], 6);

						send_arp((struct myetheraddr *)&sea);
					}
					else {
					}
				}
				break;
			case 2: /* reply */
#ifdef VERBOSE
				printf("Arp Reply: Source Mac: ");
				decode_mac(ap->smac);
				printf(" Dest Mac: ");
				decode_mac(ap->dmac);
				/* hide the children, they will cry if they see this */
				snprintf(src, sizeof(src) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->sip)));
				snprintf(dst, sizeof(dst) -1, "%s", inet_ntoa(*((const struct in_addr *)&ap->dip)));
				printf(" [ %s -> %s ]\n", src, dst);
#endif
				if (bob.addr_cleared == 0 && ap->sip == bob.saddr) {
					bob.addr_cleared=-1;
				}
				break;
			default:
				break;
		}
	}

	return;
}

void decode_mac(const uint8_t *ptr) {
	int j=0;

	j=ETHER_ADDR_LEN;
	do {
		printf("%s%.02x", (j == ETHER_ADDR_LEN) ? " " : ":", *ptr);
		ptr++;
	} while (--j > 0);
}
