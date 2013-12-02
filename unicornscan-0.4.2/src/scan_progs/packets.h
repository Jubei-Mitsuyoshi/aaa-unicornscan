#ifndef _PACKETS_H
# define _PACKETS_H

/* taken from the /usr/include/netinet/ * headers from a GNU/Linux system, so its GPL like the orig headers	*
 * i take no credit for this only bug responsibility								*/

#include <config.h>

#ifndef BYTE_ORDER
#error Byte Order not defined in packets.h
#endif

struct _PACKED_ myiphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t	ihl:4;
	uint32_t	version:4;
#else
	uint32_t	version:4;
	uint32_t	ihl:4;
#endif
	uint8_t		tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
};

#define IP_RF		0x8000	/* reserved fragment flag	*/
#define IP_DF		0x4000	/* dont fragment flag		*/
#define IP_MF		0x2000	/* more fragments flag		*/
#define IP_OFFMASK	0x1fff	/* mask for fragmenting bits	*/

struct _PACKED_ myudphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
};

#ifndef TH_FIN
#define TH_FIN  0x01    /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN  0x02    /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST  0x04    /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08    /* push data to the app layer */
#define TH_PSH  0x08    /* its too irritating to not have this */
#endif
#ifndef TH_ACK
#define TH_ACK  0x10    /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG  0x20    /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE  0x40
#endif
#ifndef TH_CWR
#define TH_CWR  0x80
#endif
struct _PACKED_ mytcphdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint16_t	res1:4;
	uint16_t	doff:4;
	uint16_t	fin:1;
	uint16_t	syn:1;
	uint16_t	rst:1;
	uint16_t	psh:1;
	uint16_t	ack:1;
	uint16_t	urg:1;
	uint16_t	ece:1;
	uint16_t	cwr:1;
#else
	uint16_t	doff:4;
	uint16_t	res1:4;
	uint16_t	cwr:1;
	uint16_t	ece:1;
	uint16_t	urg:1;
	uint16_t	ack:1;
	uint16_t	psh:1;
	uint16_t	rst:1;
	uint16_t	syn:1;
	uint16_t	fin:1;
#endif
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
};

struct _PACKED_ myicmphdr {
	uint8_t		type;			/* message type */
	uint8_t		code;			/* type sub-code */
	uint16_t	checksum;
	union {
		struct {
			uint16_t	id;
			uint16_t	sequence;
		} echo;				/* echo datagram */
		uint32_t	gateway;	/* gateway address */
		struct {
			uint16_t ___unused;
			uint16_t mtu;
		} frag;				/* path mtu discovery */
	} un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/

struct _PACKED_ myarphdr {
	uint16_t hw_type;
	uint16_t protocol;
	uint8_t hwsize;
	uint8_t protosize;
	uint16_t opcode;
	/* assume ethernet with len 6 and proto len 4 */
	uint8_t smac[6];
	uint32_t sip;
	uint8_t dmac[6];
	uint32_t dip;
};

#define ARPOP_REQUEST		1		/* ARP request.  */
#define ARPOP_REPLY		2		/* ARP reply.  */
#define ARPOP_RREQUEST		3		/* RARP request.  */
#define ARPOP_RREPLY		4		/* RARP reply.  */
#define ARPOP_INREQUEST		8		/* InARP request.  */
#define ARPOP_INREPLY		9		/* InARP reply.  */
#define ARPOP_NAK		10		/* (ATM)ARP NAK.  */

#define ARPHRD_NETROM		0		/* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER		1		/* Ethernet 10/100Mbps.  */
#define ARPHRD_EETHER		2		/* Experimental Ethernet.  */
#define ARPHRD_AX25		3		/* AX.25 Level 2.  */
#define ARPHRD_PRONET		4		/* PROnet token ring.  */
#define ARPHRD_CHAOS		5		/* Chaosnet.  */
#define ARPHRD_IEEE802		6		/* IEEE 802.2 Ethernet/TR/TB.  */
#define ARPHRD_ARCNET		7		/* ARCnet.  */
#define ARPHRD_APPLETLK		8		/* APPLEtalk.  */
#define ARPHRD_DLCI		15		/* Frame Relay DLCI.  */
#define ARPHRD_ATM		19		/* ATM.  */
#define ARPHRD_METRICOM		23		/* Metricom STRIP (new IANA id).  */


#endif /* _PACKETS_H */
