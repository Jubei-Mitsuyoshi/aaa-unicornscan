#include <config.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <settings.h>

#include <unilib/qfifo.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <modules.h>
#include <options.h>
#include <scan_progs/packets.h>
#include <scan_progs/scan_export.h>

#include "p0fexport.h"

void m_p0f_init(void);
void m_p0f_fini(void);

static int p0f_disabled=0;

int init_module(mod_entry_t *m) {
	if (s->verbose > 2) MSG(M_DBG1, "p0f module initializing");

	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "OS detection from p0f v0.1.0");
	snprintf(m->enable_str, sizeof(m->enable_str), "p0f");

	m->iver=0x0102; /* 1.0 */
	m->type=MI_TYPE_REPORT;

	m->param_u.report_s.init_report=&m_p0f_init;
	m->param_u.report_s.fini_report=&m_p0f_fini;
	m->param_u.report_s.ip_proto=IPPROTO_TCP;
	m->param_u.report_s.sport=-1;
	m->param_u.report_s.dport=-1;

	return 1;
}

int delete_module(void) {
	return 1;
}

void m_p0f_init(void) {
	if (s->verbose > 5) MSG(M_DBG2, "INITING P0F!");
	set_fuzzy();

	if (strstr(s->module_enable, "p0fr") == NULL) {
		if (s->verbose > 2) MSG(M_DBG1, "Using p0f syn+ack mode");
		set_ackmode();
	}
	else {
		if (s->verbose > 2) MSG(M_DBG1, "Using p0f rst mode");
		set_rstmode();
	}

	load_config();

	if (scan_setrecvpacket() < 0) {
		MSG(M_ERR, "Unable to request packet transfer though IPC, disabling module");
		p0f_disabled=1;
		return;
	}
	else if (s->verbose > 3) {
		MSG(M_DBG1, "requested listener to send entire packet though ipc");
	}

	return;
}

void m_p0f_fini(void) {
	if (s->verbose > 5) MSG(M_DBG2, "UNLOADING P0F!");
	return;
}

int create_report(const void *r) {
	union {
		uint16_t *st;
		const uint8_t *d;
		const void *r;
		const ip_report_t *ir;
	} r_u;
	uint16_t pk_len=0;
	output_data_t *e_out=NULL;
	char *result=NULL;

	if (p0f_disabled) return 1;

	r_u.r=r;
	pk_len=r_u.ir->doff;
	assert(pk_len > 0 && pk_len < s->vi->mtu);

	if (*r_u.st != IP_REPORT_MAGIC) return 0;

	r_u.d += sizeof(ip_report_t);
	r_u.d += sizeof(uint16_t); /* length of packet */

	if (s->verbose > 5) hexdump(r_u.d, pk_len);

	result=p0f_parse(r_u.d, pk_len);

	if (result != NULL) {
		e_out=(output_data_t *)xmalloc(sizeof(output_data_t));
		e_out->type=OD_TYPE_OS;
		e_out->t_u.os=xstrdup(result);
		r_u.ir=r; /* reset */
		fifo_push(r_u.ir->od_q, (void *)e_out);
	}

	return 1;
}
