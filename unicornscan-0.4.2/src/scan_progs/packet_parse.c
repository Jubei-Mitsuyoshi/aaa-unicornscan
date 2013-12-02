#include <config.h>

#include <scanopts.h>
#include <settings.h>
#include <scan_export.h>

#include <unilib/panic.h>
#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>

#include <packets.h>

#include <pcap.h>

static void report_init(int /* type */, const struct timeval * /* pcap recv time */);
static void inline packet_init(const uint8_t * /* packet */, size_t /* pk_len */);
static void report_push(void);

static void  decode_arp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_ip  (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_tcp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_udp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_icmp(const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_junk(const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);

static void decode_ipopts (const uint8_t * /* opt start */, size_t /* opt len */);
static void decode_tcpopts(const uint8_t * /* opt start */, size_t /* opt len */);

static char *decode_6mac(const uint8_t * /* macptr */);
static char *str_hwtype (uint16_t /* hw type */); /* return a pointer to a static string associated with the hw type */
static char *str_opcode (uint16_t /* arp opcode */); /* same as above but for arp opcode */
static char *str_hwproto(uint16_t /* arp proto  */); /* same as above but for proto */
static char *str_ipproto(uint8_t  /* ip proto   */);

static uint16_t do_ipchksum(const uint8_t * /* ptr */, size_t /* count */);
/* this is to make the pseudo header chksum()ing less work, and to avoid copying memory */
struct chksumv {
	const uint8_t *ptr;
	size_t len;
};
static uint16_t do_ipchksumv(const struct chksumv * /* chksum struct array */, int /* # of structs */);

static struct _PACKED_ ip_pseudo {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
} ipph; /* precalculated ip pseudo header read inside the tcp|udp areas for checksumming */

int r_type=0;
static union {
	arp_report_t a;
	ip_report_t i;
} r_u;

extern void *r_queue, *p_queue;

static const uint8_t *p_ptr=NULL;
static size_t p_len=0;
static void inline packet_init(const uint8_t *packet, size_t pk_len) {
	p_ptr=packet;
	p_len=pk_len;
	return;
}

static const uint8_t *trailgarbage=NULL; /* junk that follows past the end of the ip packet */
static size_t trailgarbage_len=0;

static void report_init(int type, const struct timeval *pcap_time) {
	/* called at layer 1 ;] */

	r_type=type;
	switch (type) {
		case REPORT_TYPE_IP:
			memset(&r_u.i, 0, sizeof(ip_report_t));

			r_u.i.magic=IP_REPORT_MAGIC;
			r_u.i.od_q=NULL; /* this is not used here */
			if (pcap_time) {
				r_u.i.recv_time.tv_sec=pcap_time->tv_sec;
				r_u.i.recv_time.tv_usec=pcap_time->tv_usec;
			}
			break;

		case REPORT_TYPE_ARP:
			memset(&r_u.a, 0, sizeof(arp_report_t));

			r_u.a.magic=ARP_REPORT_MAGIC;
			r_u.a.od_q=NULL; /* this is not used here */
			if (pcap_time) {
				r_u.a.recv_time.tv_sec=pcap_time->tv_sec;
				r_u.a.recv_time.tv_usec=pcap_time->tv_usec;
			}
			break;

		default:
			PANIC("Unknown report type requested");
	}
	return;
}

static void report_push(void) {
	union {
		arp_report_t *a;
		ip_report_t *i;
		void *ptr;
	} pr_u;

	if (s->verbose > 5) MSG(M_DBG2, "in report_push r_type %d", r_type);

	switch (r_type) {
		case REPORT_TYPE_ARP:

			pr_u.ptr=xmalloc(sizeof(arp_report_t));
			memcpy(pr_u.ptr, (const void *)&r_u.a, sizeof(arp_report_t));
			pr_u.a->doff=0;

			if (GET_RETPACKET()) {
				union {
					uint16_t *len;
					uint8_t *inc;
					void *ptr;
				} pk_u;

				if (p_len < 1) PANIC("saved packet size is incorrect");

				pk_u.ptr=xmalloc(p_len + sizeof(uint16_t));
				*pk_u.len=p_len;
				memcpy(pk_u.inc + sizeof(uint16_t), p_ptr, p_len);
				fifo_push(p_queue, pk_u.ptr);
				if (s->verbose > 4) MSG(M_DBG1, "Pushed packet into p_queue");
				pr_u.a->doff=p_len;
			}

			fifo_push(r_queue, pr_u.ptr);
			if (s->verbose > 4) MSG(M_DBG1, "Pushed report into r_queue");
			break;

		case REPORT_TYPE_IP:
			pr_u.ptr=xmalloc(sizeof(ip_report_t));
			memcpy(pr_u.ptr, (const void *)&r_u.i, sizeof(ip_report_t));
			pr_u.i->doff=0;

			if (GET_RETPACKET()) {
				union {
					uint16_t *len;
					uint8_t *inc;
					void *ptr;
				} pk_u;

				if (p_len < 1) PANIC("saved packet size is incorrect");

				pk_u.ptr=xmalloc(p_len + sizeof(uint16_t));
				*pk_u.len=p_len;
				memcpy(pk_u.inc + sizeof(uint16_t), p_ptr, p_len);
				fifo_push(p_queue, pk_u.ptr);
				if (s->verbose > 4) MSG(M_DBG1, "Pushed packet into p_queue");
				pr_u.i->doff=p_len;
			}

			fifo_push(r_queue, pr_u.ptr);

			if (s->verbose > 4) MSG(M_DBG1, "Pushed report into r_queue");
			break;

		default:
			PANIC("Bad report type %d", r_type);
	}
}

void parse_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	size_t pk_len=0;
	int pk_layer=0;

	if (packet == NULL || phdr == NULL) {
		MSG(M_ERR, "%s is null", (packet == NULL ? "Packet" : "Pcap Header"));
		return;
	}

	/* when you forget to put this here, it makes for really dull pcap log files */
	if (s->pcap_dumpfile) pcap_dump((uint8_t *)s->pdump, phdr, packet);

	pk_len=phdr->caplen;

	if (pk_len <= s->ss->header_len) {
		MSG(M_ERR, "This packet is too short [%d], header length is %d", pk_len, s->ss->header_len);
		return;
	}

	pk_len -= s->ss->header_len;
	packet += s->ss->header_len;
	pk_layer++;

	switch (s->ss->mode) {
		case MODE_ARPSCAN:
			report_init(REPORT_TYPE_ARP, &phdr->ts);
			packet_init(packet, pk_len);
			decode_arp(packet, pk_len, pk_layer);	/* the pcap filter should be arp only */
			break;
		case MODE_TCPSCAN:
		case MODE_UDPSCAN:
			report_init(REPORT_TYPE_IP, &phdr->ts);
			packet_init(packet, pk_len);
			decode_ip(packet, pk_len, pk_layer);	/* the pcap filter should be ip only */
			break;
	}

	return;
}

static void decode_arp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myarphdr *a;
		const uint8_t *d;
	} a_u;
	uint16_t hwtype=0, opcode=0;

	a_u.d=packet;
	r_u.a.flags=0;

	if (pk_len < sizeof(struct myarphdr)) {
		MSG(M_ERR, "Short arp packet");
		return;
	}

	hwtype=ntohs(a_u.a->hw_type);
	opcode=ntohs(a_u.a->opcode);

	if (a_u.a->protosize != 4 || a_u.a->hwsize != 6) {
		if (s->verbose > 3) MSG(M_DBG1, "Arp packet isnt 6:4, giving up");
		return;
	}

	if (opcode != ARPOP_REPLY) return;

	if (s->vi->hwaddr[0] == a_u.a->smac[0] &&
	s->vi->hwaddr[1] == a_u.a->smac[1] &&
	s->vi->hwaddr[2] == a_u.a->smac[2] &&
	s->vi->hwaddr[3] == a_u.a->smac[3] &&
	s->vi->hwaddr[4] == a_u.a->smac[4] &&
	s->vi->hwaddr[5] == a_u.a->smac[5]) return; /* we sent this */

	if (s->verbose  > 4) {
		char srcip[32], srcmac[32];
		struct in_addr ia;

		ia.s_addr=a_u.a->sip;
		sprintf(srcip, "%s", inet_ntoa(ia));
		ia.s_addr=a_u.a->dip;
		sprintf(srcmac, "%s", decode_6mac(a_u.a->smac));

		MSG(M_DBG1, "ARP : hw_type `%s' protocol `%s' hwsize %d protosize %d opcode `%s'",
		str_hwtype(hwtype), str_hwproto(a_u.a->protocol), a_u.a->hwsize, a_u.a->protosize, str_opcode(opcode));
		MSG(M_DBG1, "ARP : SRC HW %s SRC IP -> %s DST HW %s DST IP %s",
		srcmac, srcip, decode_6mac(a_u.a->dmac), inet_ntoa(ia));
	}

	pk_len -= sizeof(struct myarphdr);

	/* XXX */
	memcpy(&r_u.a.hwaddr[0], &a_u.a->smac[0], 6);
	memcpy(&r_u.a.ipaddr, &a_u.a->sip, 4);

	report_push();

	if (pk_len) {
		/* frame padding ;] */
		pk_layer++;
		packet += sizeof(struct myarphdr);
		decode_junk(packet, pk_len, pk_layer);
	}

	return;
}

static void decode_ip  (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myiphdr *i;
		const uint8_t *d;
	} i_u;
	uint16_t fragoff=0, totlen=0, ipid=0, chksum=0, c_chksum=0;
	uint32_t saddr=0, daddr=0;
	size_t opt_len=0;
	int bad_cksum=0;

	i_u.d=packet;
	r_u.i.flags=0;

	if (pk_len < sizeof(struct myiphdr)) {
		MSG(M_DBG1, "Short ip packet");
		return;
	}

	if (i_u.i->ihl < 5) {
		MSG(M_DBG1, "ihl is less than 5, this packet is likely confused/damaged");
		return;
	}

	ipid=ntohs(i_u.i->id);
	fragoff=ntohs(i_u.i->frag_off);
	totlen=ntohs(i_u.i->tot_len);
	chksum=ntohs(i_u.i->check);
	/* XXX everything expects addresses in network order */
	saddr=i_u.i->saddr;
	daddr=i_u.i->daddr;

	/* precalculated ip-pseudo header for transport layer checksumming */
	ipph.saddr=saddr;
	ipph.daddr=daddr;
	ipph.zero=0;
	ipph.proto=i_u.i->protocol;
	ipph.len=0;

	opt_len=(i_u.i->ihl - (sizeof(struct myiphdr) / 4)) * 4;

	if (fragoff & IP_OFFMASK) {
		if (s->verbose > 2) MSG(M_DBG1, "Ignoring fragmented packet");
		return;
	}

	if (totlen > pk_len && pk_layer == 1) {
		/* this packet has an incorrect ip packet length, stop processing */
		if (s->verbose > 2) MSG(M_ERR, "Packet has incorrect ip length, skipping it [ip total length claims %u and we have %u", totlen, pk_len);
		return;
	}
	else if (pk_layer == 3 && totlen > pk_len) {
		totlen=pk_len;
	}

	if (pk_len > totlen) {
		/* there is trailing junk past the end of the ip packet, save a pointer to it, and its length, then update pk_len */
		if (s->verbose > 4) MSG(M_DBG1, "Packet has trailing junk, saving a pointer to it and its length [%u]", pk_len - totlen);
		trailgarbage=packet + totlen;
		trailgarbage_len=pk_len - totlen;
		if (s->verbose > 4) hexdump(trailgarbage, trailgarbage_len);
		pk_len=totlen;
	}

	if (opt_len + sizeof(struct myiphdr) > pk_len) {
		if (s->verbose) MSG(M_VERB, "IP options seem to overlap the packet size, truncating and assuming no ip options");
		opt_len=0; /* must be a trick, assume no options then, in case this is a damaged ip header is under a icmp reply */
	}

	if ((c_chksum=do_ipchksum(packet, opt_len + sizeof(struct myiphdr))) != 0) {
		if (s->verbose > 3) MSG(M_DBG1, "Bad cksum, ipchksum returned %u", c_chksum);
		bad_cksum=1;
	}

	if (s->verbose > 4) {
		char frag_flags[32];
		char src_addr[32], dst_addr[32];
		struct in_addr ia;

		ia.s_addr=saddr;
		sprintf(src_addr, "%s", inet_ntoa(ia));

		ia.s_addr=daddr;
		sprintf(dst_addr, "%s", inet_ntoa(ia));

		CLEAR(frag_flags);
		if (fragoff & IP_DF) {
			strcat(frag_flags, "DF ");
		}
		if (fragoff & IP_MF) {
			strcat(frag_flags, "MF ");
		}
		if (fragoff & IP_RF) {
			strcat(frag_flags, "RF ");
		}

		MSG(M_DBG1, "IP  : ihl %u (opt len %u) size %u version %u tos 0x%.02x tot_len %u ipid %u frag_off %.04x %s",
		i_u.i->ihl, opt_len, pk_len, i_u.i->version, i_u.i->tos, totlen, ipid, fragoff & IP_OFFMASK, frag_flags);
		MSG(M_DBG1, "IP  : ttl %u protocol `%s' chksum 0x%.04x%s IP SRC %s IP DST %s",
		i_u.i->ttl, str_ipproto(i_u.i->protocol), chksum, (bad_cksum == 1 ? " [bad cksum]" : " [cksum ok]"), src_addr, dst_addr);
	}

	if (pk_layer == 1) {
		r_u.i.proto=i_u.i->protocol;
		r_u.i.host_addr=saddr;
		r_u.i.trace_addr=saddr;
		r_u.i.ttl=i_u.i->ttl;
		if (bad_cksum) r_u.i.flags |= REPORT_BADNETWORK_CKSUM;
	}
	else if (pk_layer == 3) { /* this is a ip header within an icmp header normally */
		r_u.i.host_addr=daddr; /* this was the _original host_ we sent to according to the icmp error reflection */
	}
	else {
		PANIC("FIXME decode IP at layer %d", pk_layer);
	}

	if (opt_len && s->verbose > 4) decode_ipopts(packet + sizeof(struct myiphdr), opt_len);

	pk_len -= sizeof(struct myiphdr) + opt_len;
	packet += sizeof(struct myiphdr) + opt_len;

	if (pk_len) {
		switch (i_u.i->protocol) {
			case IPPROTO_TCP:
				decode_tcp(packet, pk_len, ++pk_layer);
				break;
			case IPPROTO_UDP:
				decode_udp(packet, pk_len, ++pk_layer);
				break;
			case IPPROTO_ICMP:
				decode_icmp(packet, pk_len, ++pk_layer);
				break;
			default:
				MSG(M_ERR, "Filter is broken?");
				break;
		}
	}

	return;
}

static void decode_tcp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct mytcphdr *t;
		const uint8_t *d;
	} t_u;
	uint16_t sport=0, dport=0;
	uint32_t seq=0, ackseq=0;
	uint8_t doff=0, res1=0;
	uint16_t window=0, chksum=0, c_chksum=0, urgptr=0;
	size_t data_len=0, tcpopt_len=0;
	int bad_cksum=0;
	union {
		const struct ip_pseudo *ipph_ptr;
		const uint8_t *ptr;
	} ipph_u;
	struct chksumv c[2];

	t_u.d=packet;

	if (pk_layer == 4) { /* this is inside an icmp error reflection, check that */
		if (r_u.i.proto != IPPROTO_ICMP) {
			PANIC("FIXME in TCP not inside a ICMP error?");
		}
		/* ok so why the special treatment? well the packet may be incomplete, so its ok if we dont have	*
		 * a full udp header, we really are only looking for the source and dest ports, we _need_ those		*
		 * everything else is optional at this point								*/
		if (pk_len < 4) {
			MSG(M_ERR, "TCP header too incomplete to get source and dest ports, halting processing");
			return;
		}
		if (pk_len >= 4 && pk_len < sizeof(struct mytcphdr)) {
			MSG(M_DBG2, "TRUNCATED TCP PACKET, I HAVE ENOUGH DATA FOR SOURCE DEST PORTS, VERIFY");
			/* this is reversed from a response, the host never responded so flip src/dest ports */
			r_u.i.sport=ntohs(t_u.t->dest);
			r_u.i.dport=ntohs(t_u.t->source);

			return;
		}
	}

	if (pk_len < sizeof(struct mytcphdr)) {
		MSG(M_ERR, "Short tcp header");
		return;
	}

	sport=ntohs(t_u.t->source);
	dport=ntohs(t_u.t->dest);
	seq=ntohl(t_u.t->seq);
	ackseq=ntohl(t_u.t->ack_seq);
	doff=t_u.t->doff; res1=t_u.t->res1;
	window=ntohs(t_u.t->window);
	chksum=ntohs(t_u.t->check);
	urgptr=ntohs(t_u.t->urg_ptr);

	if (pk_layer == 2) {
		uint32_t eackseq=0;
		int res=0;

		eackseq=(s->ss->syn_key ^ (r_u.i.host_addr ^ (sport + dport)));

		res=ackseq - eackseq;

		switch (res) {
			case 0:
				MSG(M_DBG2, "hrmm what?");
				break;
			case 1:
				if (s->verbose > 6) MSG(M_DBG1, "cool, thats right");
				break;
			case 2:
				MSG(M_DBG2, "must be a connection?");
				break;
			default:
				if (s->verbose > 5) MSG(M_DBG2, "Not my packet ackseq %.08x expecting somewhere around %.08x", ackseq, eackseq);
				return;
				break;
		}
	}

	if (doff && ((size_t)(doff * 4) > pk_len)) {
		MSG(M_ERR, "Datalength exceeds capture length, truncating to zero (doff %u bytes pk_len %u)", doff * 4, pk_len);
		doff=0;
	}

	if (doff && (size_t )(doff * 4) < sizeof(struct mytcphdr)) {
		/* doff is wrong, this isnt really possible in the real world */
		MSG(M_ERR, "doff is totally whack, increasing to min size and hoping for no tcpoptions");
		doff=sizeof(struct mytcphdr) / 4;
	}

	if (doff) {
		tcpopt_len=((doff * 4) -  sizeof(struct mytcphdr));
		data_len=pk_len - (doff * 4);
	}
	else {
		tcpopt_len=pk_len - sizeof(struct mytcphdr);
		data_len=0;
	}

	ipph_u.ipph_ptr=&ipph;
	/* its not natural to use _this_ size... */
	ipph.len=ntohs(pk_len);

	c[0].len=sizeof(ipph);
	c[0].ptr=ipph_u.ptr;

	c[1].len=pk_len;
	c[1].ptr=packet;

	if ((c_chksum=do_ipchksumv((const struct chksumv *)&c[0], 2)) != 0) {
		if (s->verbose > 3) MSG(M_DBG1, "bad tcp checksum, ipchksumv returned 0x%x", c_chksum);
		bad_cksum=1;
	}

	if (s->verbose > 4) {
		char tcpflags[16];

		memset(tcpflags, '-', sizeof(tcpflags));
		tcpflags[8]='\0';
		if (t_u.t->fin) tcpflags[0]='F';
		if (t_u.t->syn) tcpflags[1]='S';
		if (t_u.t->rst) tcpflags[2]='R';
		if (t_u.t->psh) tcpflags[3]='P';
		if (t_u.t->ack) tcpflags[4]='A';
		if (t_u.t->urg) tcpflags[5]='U';
		if (t_u.t->ece) tcpflags[6]='E';
		if (t_u.t->cwr) tcpflags[7]='C';

		MSG(M_DBG1, "TCP : size %u sport %u dport %u seq 0x%.08x ack_seq 0x%.08x window %u",
		pk_len, sport, dport, seq, ackseq, window);
		MSG(M_DBG1, "TCP : doff %u res1 %u flags `%s' chksum 0x%.04x%s urgptr 0x%.04x",
		doff, res1, tcpflags, chksum, (bad_cksum != 0 ? " [bad cksum]" : " [cksum ok]"), urgptr);
	}

	packet += sizeof(struct mytcphdr);
	pk_len -= sizeof(struct mytcphdr);

	if (s->verbose > 5) MSG(M_DBG2, "TCP OPTIONS LENGTH %u DATA LENGTH %u", tcpopt_len, data_len);

	if (tcpopt_len && s->verbose > 5) {
		decode_tcpopts(packet, tcpopt_len);
	}

	if (data_len && s->verbose > 5) {
		MSG(M_DBG2, "Dumping packet data");
		hexdump(packet + tcpopt_len, data_len);
	}

	if (pk_layer == 2) {
		r_u.i.sport=sport;
		r_u.i.dport=dport;
		r_u.i.type=0;

		r_u.i.tseq=seq;
		r_u.i.mseq=ackseq;

		r_u.i.window_size=window;

		if (t_u.t->fin) r_u.i.type |= TH_FIN;
		if (t_u.t->syn) r_u.i.type |= TH_SYN;

		if (t_u.t->rst) r_u.i.type |= TH_RST;
		if (t_u.t->psh) r_u.i.type |= TH_PSH;

		if (t_u.t->ack) r_u.i.type |= TH_ACK;
		if (t_u.t->urg) r_u.i.type |= TH_URG;

		if (t_u.t->ece) r_u.i.type |= TH_ECE;
		if (t_u.t->cwr) r_u.i.type |= TH_CWR;

		r_u.i.subtype=0;

		if (bad_cksum) r_u.i.flags |= REPORT_BADTRANSPORT_CKSUM;

		report_push();
	}
	else if (pk_layer == 4) {
		r_u.i.sport=dport;
		r_u.i.dport=sport;
		r_u.i.mseq=ackseq;
		r_u.i.tseq=seq;
		r_u.i.window_size=0;
	}
	else {
		PANIC("fixme");
	}

	return;
}

static void decode_udp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myudphdr *u;
		const uint8_t *d;
	} u_u;
	uint16_t sport=0, dport=0, len=0, chksum=0, c_chksum=0;
	int bad_cksum=0;
	union {
		const struct ip_pseudo *ipph_ptr;
		const uint8_t *ptr;
	} ipph_u;
	struct chksumv c[2];

	u_u.d=packet;

	if (pk_layer == 4) { /* this is inside an icmp error reflection, check that */
		if (r_u.i.proto != IPPROTO_ICMP) {
			PANIC("FIXME in UDP not inside a ICMP error?");
		}
		/* ok so why the special treatment? well the packet may be incomplete, so its ok if we dont have	*
		 * a full udp header, we really are only looking for the source and dest ports, we _need_ those		*
		 * everything else is optional at this point								*/
		if (pk_len < 4) {
			MSG(M_ERR, "UDP header too incomplete to get source and dest ports, halting processing");
			return;
		}
		if (pk_len >= 4 && pk_len < sizeof(struct myudphdr)) {
			MSG(M_DBG2, "TRUNCATED UDP PACKET, I HAVE ENOUGH DATA FOR SOURCE DEST PORTS, VERIFY");
			/* this is reversed from a response, the host never responded so flip src/dest ports */
			r_u.i.sport=ntohs(u_u.u->dest);
			r_u.i.dport=ntohs(u_u.u->source);
			r_u.i.tseq=0;
			r_u.i.mseq=0;

			return;
		}
	}

	if (pk_len < sizeof(struct myudphdr)) {
		MSG(M_ERR, "Short udp header");
		return;
	}
	sport=ntohs(u_u.u->source);
	dport=ntohs(u_u.u->dest);
	len=ntohs(u_u.u->len);
	chksum=ntohs(u_u.u->check);

	ipph_u.ipph_ptr=&ipph;
	/* its not natural to use _this_ size... */
	ipph.len=ntohs(pk_len);

	c[0].len=sizeof(ipph);
	c[0].ptr=ipph_u.ptr;

	c[1].len=pk_len;
	c[1].ptr=packet;

	if ((c_chksum=do_ipchksumv((const struct chksumv *)&c[0], 2)) != 0) {
		if (s->verbose > 3) MSG(M_DBG1, "bad udp checksum, ipchksumv returned 0x%x", c_chksum);
		bad_cksum=1;
	}

	if (s->verbose > 4) {
		MSG(M_DBG1, "UDP : pklen %u sport %u dport %u len %u checksum %.04x%s",
		pk_len, sport, dport, len, chksum, (bad_cksum == 0 ? " [bad cksum]" : " [cksum ok]"));
	}

	if (pk_layer == 2) {
		r_u.i.sport=sport;
		r_u.i.dport=dport;
		r_u.i.type=0;
		r_u.i.subtype=0;
		r_u.i.tseq=0;
		r_u.i.mseq=0;

		report_push();
        }
	else if (pk_layer == 4) {
		/* this is reversed from a response, the host never responded so flip src/dest ports */
		r_u.i.sport=dport;
		r_u.i.dport=sport;
		r_u.i.tseq=0;
		r_u.i.mseq=0;
	}
	else {
		PANIC("FIXME at decode UDP at layer %d", pk_layer);
	}

	pk_len -= sizeof(struct myudphdr);
	packet += sizeof(struct myudphdr);

	if (pk_len && s->verbose > 4) {
		MSG(M_DBG1, "Dumping UDP payload");
		hexdump(packet, pk_len);
	}

	return;
}

static void decode_icmp(const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myicmphdr *i;
		const uint8_t *d;
	} ic_u; /* ;] */
	uint8_t type=0, code=0;
	uint16_t chksum=0;

	ic_u.d=packet;

	if (pk_len < 4) {
		MSG(M_DBG1, "Short icmp header");
		return;
	}

	if (s->verbose > 5) MSG(M_DBG2, "Decode icmp with %d bytes at layer %d", pk_len, pk_layer);

	type=ic_u.i->type;
	code=ic_u.i->code;
	chksum=ntohs(ic_u.i->checksum);

	if (s->verbose > 4) {
		MSG(M_DBG1, "ICMP: type %u code %u chksum %.04x%s", type, code, chksum, "[?]");
	}

	if (type == 3 || type == 5 || type == 11) {
		/* dest unreachable, the packet that generated this error should be after the icmpheader	*/
		/* redirect message, same as with unreachable							*/
		/* time exceeded, same as with above								*/

		if (pk_len > sizeof(struct myicmphdr)) { /* there _could_ be data there, try to process it */
			const uint8_t *newpacket=NULL;
			size_t newpk_len=0;

			newpacket=packet + sizeof(struct myicmphdr);
			newpk_len=pk_len - sizeof(struct myicmphdr);

			decode_ip(newpacket, newpk_len, (pk_layer + 1));
		}
	}
	else if (type == 0 || type == 8) {
		/* pings ignore */
		if (s->verbose > 5) MSG(M_DBG2, "Ignoring ping request or response");
	}

	if (pk_layer == 2) {
		r_u.i.type=type;
		r_u.i.subtype=code;

		report_push();
	}

	return;
}

static void decode_junk(const uint8_t *packet, size_t pk_len, int pk_layer) {
	MSG(M_DBG1, "Dumping trailing junk at end of packet at layer %d length %u", pk_layer, pk_len);

	hexdump(packet, pk_len);
	return;
}

/*
 * misc functions
 */
static void decode_ipopts(const uint8_t *data, size_t len) {
	MSG(M_DBG1, "Dumping ipoptions");
	hexdump(data, len);
}

static void decode_tcpopts(const uint8_t *data, size_t len) {
	MSG(M_DBG1, "Dumping tcpoptions");
	hexdump(data, len);
}

/*
 * type -> name mapping functions
 * all return pointers to static buffers, carefull
 */

static char *decode_6mac(const uint8_t *mac) {
	static char str[32];

	sprintf(str, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x", *mac, *(mac + 1), *(mac + 2), *(mac + 3), *(mac + 4), *(mac + 5));

	return &str[0];
}

static char *str_opcode(uint16_t opcode) {
	static char name[32];

	switch (opcode) {
		case ARPOP_REQUEST:
			sprintf(name, "ARP Request"); break;
		case ARPOP_REPLY:
			sprintf(name, "ARP Reply"); break;
		case ARPOP_RREQUEST:
			sprintf(name, "RARP Request"); break;
		case ARPOP_RREPLY:
			sprintf(name, "RARP Reply"); break;
		case ARPOP_INREQUEST:
			sprintf(name, "InARP Request"); break;
		case ARPOP_INREPLY:
			sprintf(name, "InARP Request"); break;
		case ARPOP_NAK:
			sprintf(name, "ARM ARP NAK"); break;
		default:
			sprintf(name, "Unknown [%u]", opcode); break;
	}
	return &name[0];
}

static char *str_hwtype(uint16_t hw_type) {
	static char name[32];

	switch (hw_type) {
		case ARPHRD_ETHER:
			sprintf(name, "10/100 Ethernet"); break;
		case ARPHRD_NETROM:
			sprintf(name, "NET/ROM pseudo"); break;
		case ARPHRD_EETHER:
			sprintf(name, "Exp Ethernet"); break;
		case ARPHRD_AX25:
			sprintf(name, "AX.25 Level 2"); break;
		case ARPHRD_PRONET:
			sprintf(name, "PROnet token ring"); break;
		case ARPHRD_CHAOS:
			sprintf(name, "ChaosNET"); break;
		case ARPHRD_IEEE802:
			sprintf(name, "IEE 802.2 Ethernet"); break;
		case ARPHRD_ARCNET:
			sprintf(name, "ARCnet"); break;
		case ARPHRD_APPLETLK:
			sprintf(name, "APPLEtalk"); break;
		case ARPHRD_DLCI:
			sprintf(name, "Frame Relay DLCI"); break;
		case ARPHRD_ATM:
			sprintf(name, "ATM"); break;
		case ARPHRD_METRICOM:
			sprintf(name, "Metricom STRIP"); break;
		default:
			sprintf(name, "NON-ARP? Unknown [%u]", hw_type); break;
	}
	return &name[0];
}

static char *str_hwproto(uint16_t proto) {
	static char name[32];

	switch (proto) {
		case 8:
			sprintf(name, "Ether Arp IP"); break;
		default:
			sprintf(name, "Unknown [%u]", proto); break;
	}

	return &name[0];
}

static char *str_ipproto(uint8_t proto) {
	static char name[32];

	switch (proto) {
		case IPPROTO_TCP:
			sprintf(name, "IP->TCP"); break;
		case IPPROTO_UDP:
			sprintf(name, "IP->UDP"); break;
		case IPPROTO_ICMP:
			sprintf(name, "IP->ICMP"); break;
		default:
			sprintf(name, "Unknown [%.02x]", proto); break;
	}
	return &name[0];
}

/*
 * Compute Internet Checksum for "count" bytes
 * beginning at location "addr".
 * adapted from rfc1071
 */
static uint16_t do_ipchksum(const uint8_t *addr, size_t len) {
	union {
		const uint16_t *hw;
		const uint8_t *c;
	} a_u;
	int sum=0;
	uint16_t checksum=0;

	a_u.c=addr;

	while (len > 1) {
		sum += *a_u.hw; len -= 2; a_u.hw++;
	}

	if (len) {
		sum += htons(*a_u.c << 8);
	}

	sum=(sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);

	checksum=~(sum);

	return checksum;
}

static uint16_t do_ipchksumv(const struct chksumv *array, int stlen) {
	union {
		const uint16_t *hw;
		const uint8_t *c;
	} a_u;
	int j=0, sum=0;
	size_t len=0;
	uint16_t checksum=0;

	if (stlen < 1) return 0x0d1e; /* ;] */

	for (j=0 ; j < stlen ; j++) {
		len=array[j].len;
		a_u.c=array[j].ptr;

		while (len > 1) {
			sum += *a_u.hw; len -= 2; a_u.hw++;
		}

		if (len) {
			sum += htons(*a_u.c << 8);
		}
	}

	sum=(sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);

	checksum=~(sum);

	return checksum;
}
