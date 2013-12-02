#include <config.h>

#include <unistd.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <sqlinterface.h>
#include <settings.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>

static int db_disable=0;
static uint64_t scanid;

static void database_walk_func(const void *);

void m_database_init(void) {
	int results=0;
	char query[2048];
	seo_t scanopts;

	if (s->verbose > 3) MSG(M_DBG1, "Database module is enabled");

	if (initdb() < 0) {
		db_disable=1;
		return;
	}

	CLEAR(query);
	if (get_scanopts(&scanopts) < 0) {
		MSG(M_ERR, "Serious problems getting scan options for insertion into database");
		_exit(1);
	}
	snprintf(query, sizeof(query) -1, "insert into scan(s_time, e_time, srcaddr, portstr, addrmin, addrmax, scanmode, pps, "
	"active_plgroups, pcapfilter, dronestr, fingerprint, iptos, ipttl, ipoffset, tcpflags, srcport, repeats)"
	" values(%lld, %lld, %llu, '%s', %llu, %llu, %u, %u, %u, '%s', '%s', %u, %u, %u, %u, %u, %d, %u); "
	"select currval('scan_id_seq') as myid;",
	(long long int)s->s_time, (long long int)0, (uint64_t )ntohl(s->vi->myaddr.sin_addr.s_addr), s->port_str,
	(uint64_t )s->_low_ip, (uint64_t )s->_high_ip, (uint8_t)s->mode, s->pps, s->payload_flags,
	(s->extra_pcapfilter != NULL ? s->extra_pcapfilter : "None"), s->drone_str,
	scanopts.fingerprint, scanopts.tos, scanopts.ttl, scanopts.ip_off, scanopts.tcphdrflgs, scanopts.src_port, s->repeats);

	aquerydb(query);
	results=dbnumrows();
	if (results == 1) {
		char *res_ptr=NULL;

		res_ptr=dbgetvalue(0, 0);
		if (sscanf(res_ptr, "%llu", &scanid) != 1) {
			MSG(M_ERR, "Malformed scanid from database");
			_exit(1);
		}
	}
	else {
			MSG(M_ERR, "Database is acting very weird, exiting");
			_exit(1);
	}
	aquerydb("begin;");

	return;
}

static char db_banner[256];
static char db_os[256];

int m_database_output(const void *r) {
	union {
		const ip_report_t *ir;
		const arp_report_t *ar;
		const void *ptr;
		const uint16_t *r_magic;
	} r_u;
	char query[2048];
	uint64_t sb_id=0;
	int results=0;

	if (db_disable) return 1;

	CLEAR(db_banner);
	CLEAR(db_os);
	CLEAR(query);

	r_u.ptr=r;
	if (*r_u.r_magic != IP_REPORT_MAGIC) {
		return 0;
	}

	fifo_walk(r_u.ir->od_q, &database_walk_func);

	snprintf(query, sizeof(query) -1, "insert into scan_bucket(scan_id, protocol, type, subtype, dport, sport, ttl, host_addr, trace_addr, u_tstamp, u_utstamp) "
	"values(%lld, %u, %u, %u, %u, %u, %u, %u, %u, %lld, %llu); select currval('scan_bucket_id_seq') as myid;",
	scanid, r_u.ir->proto, r_u.ir->type, r_u.ir->subtype, r_u.ir->dport, r_u.ir->sport, r_u.ir->ttl,
	htonl(r_u.ir->host_addr), htonl(r_u.ir->trace_addr), (long long unsigned int )r_u.ir->recv_time.tv_sec,
	(long long unsigned int)r_u.ir->recv_time.tv_usec);

	aquerydb(query);
	results=dbnumrows();
	if (results == 1) {
		char *res_ptr=NULL;

		res_ptr=dbgetvalue(0, 0);
		if (sscanf(res_ptr, "%llu", &sb_id) != 1) {
			MSG(M_ERR, "Malformed scanid from database");
			db_disable=1;
			return 0;
		}
	}

	if (strlen(db_banner)) {
		CLEAR(query);
		snprintf(query, sizeof(query) -1, "insert into banner(scan_bucket_id, banner) values(%llu, '%s');", sb_id, db_banner);
		aquerydb(query);
	}
	else {
		/*
		 * right about now, you are likely wondering why in gods name anyone would do this?
		 * well it turns out this is a hack, that was requested to make sure the views
		 * are more _portable_, even though the other db code is missing, it wont be for long.
		 */
		CLEAR(query);
		snprintf(query, sizeof(query) -1, "insert into banner(scan_bucket_id) values(%llu);", sb_id);
		aquery(query);
	}

	if (strlen(db_os)) {
		CLEAR(query);
		snprintf(query, sizeof(query) -1, "insert into os_fingerprint(scan_bucket_id, os) values(%llu, '%s');", sb_id, db_os);
		aquerydb(query);
	}
	else {
		CLEAR(query);
		snprintf(query, sizeof(query) -1, "insert into os_fingerprint(scan_bucket_id) values(%llu);", sb_id);
		aquery(query);
	}

	return 1;
}

void m_database_fini(void) {
	char query[512];

	if (db_disable) return;
	CLEAR(query);
	snprintf(query, sizeof(query) -1, "update scan set e_time=%lld where scan_id=%lld;commit;", (long long int)s->e_time, scanid);
	aquerydb(query);

	closedb();

	return;
}

static void database_walk_func(const void *item) {
	union {
		const void *ptr;
		const output_data_t *d;
	} d_u;

	d_u.ptr=item;
	switch (d_u.d->type) {
		case OD_TYPE_BANNER:
			CLEAR(db_banner);
			snprintf(db_banner, sizeof(db_banner) -1, "%s", d_u.d->t_u.banner);
			break;
		case OD_TYPE_OS:
			CLEAR(db_os);
			snprintf(db_os, sizeof(db_os) -1, "%s", d_u.d->t_u.os);
			break;
		default:
			MSG(M_ERR, "Unknown output format type %d in database push", d_u.d->type);
			break;
	}

	return;
}
