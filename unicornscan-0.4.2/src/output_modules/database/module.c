#include <config.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <settings.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <modules.h>
#include <database.h>

int init_module(mod_entry_t *m) {

	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "Output to SQL Database (PostGreSQL)");
	snprintf(m->enable_str, sizeof(m->enable_str) -1, "database");

	m->iver=0x0102; /* 1.0 */
	m->type=MI_TYPE_OUTPUT;

	m->param_u.output_s.init_output=&m_database_init;
	m->param_u.output_s.fini_output=&m_database_fini;

	return 1;
}

int delete_module(void) {
	return 1;
}

int send_output(const void *r) {
	return m_database_output(r);
}
