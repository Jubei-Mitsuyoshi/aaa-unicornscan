#include <config.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <settings.h>

#include <unilib/qfifo.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>

#include <modules.h>
#include <options.h>
#include <scan_progs/packets.h>
#include <scan_progs/scan_export.h>

void m_udpstr_init(void);
void m_udpstr_fini(void);

static int udpstr_disabled=0;

int init_module(mod_entry_t *m) {
	if (s->verbose > 2) MSG(M_DBG1, "udpstr module initializing");

	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "banner grabbing udpstr v0.1.0");
	snprintf(m->enable_str, sizeof(m->enable_str), "udpstr");

	m->iver=0x0102; /* 1.0 */
	m->type=MI_TYPE_REPORT;

	m->param_u.report_s.init_report=&m_udpstr_init;
	m->param_u.report_s.fini_report=&m_udpstr_fini;
	m->param_u.report_s.ip_proto=IPPROTO_UDP;
	m->param_u.report_s.sport=-1;
	m->param_u.report_s.dport=-1;

	return 1;
}

int delete_module(void) {
	return 1;
}

void m_udpstr_init(void) {
	if (s->verbose > 5) MSG(M_DBG2, "INITING UDPVER!");

	if (scan_setrecvpacket() < 0) {
		MSG(M_ERR, "Unable to request packet transfer though IPC, disabling module");
		udpstr_disabled=1;
		return;
	}
	else if (s->verbose > 3) {
		MSG(M_DBG1, "requested listener to send entire packet though ipc");
	}

	return;
}

void m_udpstr_fini(void) {
	if (s->verbose > 5) MSG(M_DBG2, "UNLOADING UDPVER!");
	return;
}

int create_report(const void *r) {
	union {
		const uint16_t *st;
		const uint8_t *d;
		const ip_report_t *ir;
		const arp_report_t *ar;
		const void *ptr;
		const struct myiphdr *ip_ptr;
		const struct myudphdr *udp_ptr;
	} r_u;
	uint16_t pk_len=0, port=0, datalen=0, writestart=0;
	output_data_t *e_out=NULL;
	char ustr_buf[64]; size_t ustr_off=0;

	if (udpstr_disabled) return 1;

	r_u.ptr=r;

	if (*r_u.st != IP_REPORT_MAGIC) return 0;

	pk_len=r_u.ir->doff;
	assert(pk_len > 0 && pk_len < s->vi->mtu);

	r_u.d += sizeof(ip_report_t);
	r_u.d += sizeof(uint16_t); /* length */

	if (pk_len <= sizeof(struct myiphdr)) {
		MSG(M_ERR, "Short ip packet");
		return 0;
	}

	if (r_u.ip_ptr->version != 4) return 0;

	if (r_u.ip_ptr->protocol != IPPROTO_UDP) {
		return 0;
	}

	if (pk_len < (sizeof(struct myiphdr) + sizeof(struct myudphdr) + 1)) {
		MSG(M_ERR, "Short udp packet, or no data");
		return 0;
	}
	/* yah ok whatever, this is an example, skip this header */
	r_u.d += sizeof(struct myiphdr);
	pk_len -= sizeof(struct myiphdr);
	port=ntohs(r_u.udp_ptr->source);
	/* MSG(M_DBG2, "source : %u dest : %u datalen : %u", port, ntohs(r_u.udp_ptr->dest), pk_len - (sizeof(struct myudphdr))); */
	datalen=pk_len - sizeof(struct myudphdr);
	pk_len -= sizeof(struct myudphdr);

	memset(ustr_buf, 0, sizeof(ustr_buf));
	for (r_u.d += sizeof(struct myudphdr) ; pk_len != 0 ; pk_len--, r_u.d++) {
		if (isprint(*r_u.d)) {
			ustr_buf[ustr_off++]=*r_u.d;
			writestart=1;
		}
		else {
			if (writestart) {
				ustr_buf[ustr_off++]=' ';
				writestart=0;
			}
		}
		if ((ustr_off + 2) > sizeof(ustr_buf)) break;
	}

	if (strlen(ustr_buf)) {
		e_out=(output_data_t *)xmalloc(sizeof(output_data_t));
		e_out->type=OD_TYPE_BANNER;
		e_out->t_u.os=xstrdup(ustr_buf);
		r_u.ptr=r; /* reset */
		fifo_push(r_u.ir->od_q, (void *)e_out);
	}

	return 1;
}
