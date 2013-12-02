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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/ioctl.h>

#include <pcap.h>

#include <packets.h>
#include <settings.h>
#include <scan_progs/workunits.h>
#include <scan_progs/scan_export.h>
#include <uarch/arch.h>
#include <xipc.h>
#include <pcaputil.h>
#include <util.h>

typedef struct _PACKED_ msg_head_s {
	uint32_t header;
	uint8_t type;
	uint8_t status;
	uint16_t len;
} ipc_msghdr_t;

#define FILTER "host 127.0.0.1 and (port 12321 or port 12322 or port 12323) and tcp"

void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

static int header_len=0;

int main(int argc, char ** argv) {
	char errbuf[PCAP_ERRBUF_SIZE], pfilter[2048];
	pcap_t *pdev=NULL;
	bpf_u_int32 mask=0, net=0;
	struct bpf_program filter;

	memset(errbuf, 0, sizeof(errbuf));

	snprintf(pfilter, sizeof(pfilter) -1, "%s", FILTER);

	pcap_lookupnet(LODEV, &net, &mask, errbuf);

	pdev=pcap_open_live(LODEV, 16436, 1, 0, errbuf);
	if (pdev == NULL) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(1);
	}

	if ((header_len=util_getheadersize(pdev, errbuf)) < 0) {
		fprintf(stderr, "Error getting header length: %s", errbuf);
		exit(1);
	}

	pcap_compile(pdev, &filter, pfilter, 0, net);
	pcap_setfilter(pdev, &filter);

	if (util_preparepcap(pdev, errbuf) < 0) {
		fprintf(stderr, "Error putting pcap fd into immediate mode: %s", errbuf);
		exit(1);
	}

	pcap_loop(pdev, 0, &process_packet, NULL);

	exit(0);
}

struct msg_names {
	char name[32];
	int type;
};

struct msg_names list[]={
{"MSG_VERSIONREQ", 1},
{"MSG_VERSIONREPL", 2},
{"MSG_QUIT", 3},
{"MSG_WORKUNIT", 4},
{"MSG_WORKDONE", 5},
{"MSG_OUTPUT", 6},
{"MSG_READY", 7},
{"MSG_ACK", 8},
{"MSG_IDENT", 9},
{"MSG_IDENT_SENDER", 10},
{"MSG_IDENT_LISTENER", 11},
{"MSG_IDENT_ANY", 12},
{"MSG_IDENTREQ_SENDER", 13},
{"MSG_IDENTREQ_LISTENER", 14},
{"MSG_NOP", 15},
{"MSG_TERMINATE", 16}
};

void process_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	const struct myiphdr *ip_ptr=NULL;
	const struct mytcphdr *tcp_ptr=NULL;
	const uint8_t *data=NULL;
	size_t hdrlen=0;
	char tcpflags[16];

	if (packet == NULL) return;

	hdrlen=(header_len + sizeof(struct myiphdr) + sizeof(struct mytcphdr));

	if (phdr->caplen < hdrlen) {
		fprintf(stderr, "Short packet at %d bytes\n", phdr->caplen);
		return;
	}

	ip_ptr=(const struct myiphdr *)(packet + header_len);
	tcp_ptr=(const struct mytcphdr *)(packet + header_len + sizeof(struct myiphdr));

	str_tcpflagsp(tcpflags, tcp_ptr);

	if (phdr->caplen > (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff))) {
		data=(const uint8_t *)(packet + header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff));
	}
	else {
		data=NULL;
	}

	printf("ip caplen %d datalen %d\n"
		"\tsrc port %d ip dst port %d\n"
		"\tflags %s doff %d\n"
		"\tseq %.08x ackseq %.08x\n"
		"\twindow %u checksum %.04x urg_ptr %d\n",
		phdr->caplen, (phdr->caplen - (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff))),
		ntohs(tcp_ptr->source), ntohs(tcp_ptr->dest), tcpflags, tcp_ptr->doff,
		tcp_ptr->seq, tcp_ptr->ack_seq, tcp_ptr->window, tcp_ptr->check,
		tcp_ptr->urg_ptr);

	if (data) {
		char type[32];
		union {
			const ipc_msghdr_t *msg;
			const uint8_t *ptr;
		} m_u;
		union {
			const uint8_t *ptr;
			const udp_workunit_t *uwu;
			const tcp_workunit_t *twu;
		} md_u;
		int j=0;

		m_u.ptr=data;
		memset(type, 0, sizeof(type));
		for (j=0 ; j < (int)sizeof(list) ; j++) {
			if (list[j].type == m_u.msg->type) {
				snprintf(type, sizeof(type) -1, "%s", list[j].name);
			}
		}
		if (strlen(type) < 1) {
			snprintf(type, sizeof(type) -1, "Unknown");
		}
		if (m_u.msg->header != 0xf3f2f1f0) {
			printf("BAD IPC PACKET, magic header wrong\n");
			return;
		}

		printf("#### Message type: %s status: %d len: %d ####\n", type, m_u.msg->status, m_u.msg->len);
		if (m_u.msg->len > 0) {
			if (m_u.msg->len != (phdr->caplen - (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff) + sizeof(ipc_msghdr_t)))) {
				printf("BAD IPC PACKET!\n");
				return;
			}
			md_u.ptr=data + sizeof(ipc_msghdr_t);
			switch (m_u.msg->type) {
				case MSG_WORKUNIT:
					if (md_u.uwu->magic  == UDP_MAGIC) {
						char ip1[32], ip2[32], ip3[32];
						struct in_addr ia;
						char port_str[64];

						sprintf(ip1, "%s", inet_ntoa(md_u.uwu->myaddr.sin_addr));
						ia.s_addr=ntohl(md_u.uwu->low_ip);
						sprintf(ip2, "%s", inet_ntoa(ia));
						ia.s_addr=ntohl(md_u.uwu->high_ip);
						sprintf(ip3, "%s", inet_ntoa(ia));
						printf("UDP WORKUNIT\nrepeats: %d tos: %d ttl: %d ip_off: %.04x fingerprint: %d src_port: %d\n",
						md_u.uwu->repeats, md_u.uwu->tos, md_u.uwu->ttl, md_u.uwu->ip_off, md_u.uwu->fingerprint,
						md_u.uwu->src_port);
						memset(port_str, 0, sizeof(port_str));
						memcpy(port_str, (md_u.ptr + sizeof(udp_workunit_t)), md_u.uwu->port_str_len);
						printf("imtu: %d my_addr: %s pps: %llu low_ip: %s high_ip: %s port_str: `%s'[%d]\n",
						md_u.uwu->interface_mtu, ip1, md_u.uwu->pps, ip2, ip3, port_str, md_u.uwu->port_str_len);
					}
					else if (md_u.uwu->magic  == TCP_MAGIC) {
						char ip1[32], ip2[32], ip3[32];
						struct in_addr ia;
						char port_str[64];

						sprintf(ip1, "%s", inet_ntoa(md_u.twu->myaddr.sin_addr));
						ia.s_addr=ntohl(md_u.twu->low_ip);
						sprintf(ip2, "%s", inet_ntoa(ia));
						ia.s_addr=ntohl(md_u.twu->high_ip);
						sprintf(ip3, "%s", inet_ntoa(ia));
						printf("TCP WORKUNIT\nrepeats: %d tos: %d ttl: %d ip_off: %.04x fingerprint: %d src_port: %d\n",
						md_u.twu->repeats, md_u.twu->tos, md_u.twu->ttl, md_u.twu->ip_off, md_u.twu->fingerprint,
						md_u.twu->src_port);
						memset(port_str, 0, sizeof(port_str));
						memcpy(port_str, (md_u.ptr + sizeof(tcp_workunit_t)), md_u.twu->port_str_len);
						printf("imtu: %d my_addr: %s pps: %llu low_ip: %s high_ip: %s port_str: `%s'[%d]\n",
						md_u.twu->interface_mtu, ip1, md_u.twu->pps, ip2, ip3, port_str, md_u.twu->port_str_len);
					}
					break;
				case MSG_OUTPUT:
					printf("msg_output\n");
					break;
			}
		}
	}
	printf("\n");
	return;
}
