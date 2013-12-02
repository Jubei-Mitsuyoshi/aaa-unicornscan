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

#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

#include <scan_progs/scan_export.h>
#include <modules.h>
#include <myversion.h>
#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>

static mod_entry_t *mod_list_head=NULL;

int init_modules(void) {
	DIR *moddir=NULL;
	struct dirent *de=NULL;
	mod_entry_t *mnew=NULL, *last=NULL;

	if (s->verbose > 5) MSG(M_DBG1, "Opening dir `%s'", s->mod_dir);

	moddir=opendir(s->mod_dir);
	if (s->verbose > 5) MSG(M_DBG2, "Directory `%s' open", s->mod_dir);
	if (moddir == NULL) {
		MSG(M_ERR, "opendir `%s' fails: %s", s->mod_dir, strerror(errno));
		return -1;
	}
	while ((de=readdir(moddir)) != NULL) {
		struct stat sb;
		int ret=0;

		/* ignore . dirs and files and non .so files */
		if (de->d_name[0] == '.' || strstr(de->d_name, SHLIB_EXT) == NULL) {
			continue;
		}

		mnew=(mod_entry_t *)xmalloc(sizeof(mod_entry_t));
		memset(mnew, 0, sizeof(mod_entry_t));

		snprintf(mnew->fname, sizeof(mnew->fname) -1, "%s/%s", s->mod_dir, de->d_name);

		if (stat(mnew->fname, &sb) < 0) {
			MSG(M_ERR, "stat `%s': %s", mnew->fname, strerror(errno));
			xfree(mnew);
			continue;
		}

		/* XXX check parent directories too */
		if (S_ISREG(sb.st_mode) && 
		((S_IWGRP|S_IWOTH) & sb.st_mode) == 0) {
			if (s->verbose > 2) MSG(M_VERB, "Loading module `%s'", mnew->fname);
		}
		else {
			MSG(M_ERR, "Ignoring module `%s', check file type and permissions (no group write or other write permissions allowed)", mnew->fname);
			xfree(mnew);
			continue;
		}

		mnew->handle=dlopen(mnew->fname, RTLD_LAZY);
		if (mnew->handle == NULL) {
			MSG(M_ERR, "Can't load shared object `%s': %s", mnew->fname, dlerror());
			xfree(mnew);
			continue;
		}

		mnew->dl_init_module=(int (*)(mod_entry_t *))dlsym(mnew->handle, "init_module");
		if (dlerror() != NULL) {
			MSG(M_ERR, "Can't find initialization hook for module `%s': %s", mnew->fname, dlerror());
			dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		mnew->dl_delete_module=(void (*)(void))dlsym(mnew->handle, "delete_module");
		if (dlerror() != NULL) {
			MSG(M_ERR, "Can't find shutdown hook for module `%s': %s", mnew->fname, dlerror());
			dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		if (s->verbose > 5) MSG(M_DBG1, "init_module: %p delete_module: %p", mnew->dl_init_module, mnew->dl_delete_module);

		if ((ret=mnew->dl_init_module(mnew)) != 1) {
			MSG(M_ERR, "Module `%s' failed to initialize, failure code %d [%s]", mnew->fname, ret, mnew->errstr);
			dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		if (s->verbose > 1) {
			uint8_t bad=0;
			uint8_t	maj, min;
			char type[32];

			switch (mnew->type) {
				case MI_TYPE_PREFILTER:
					sprintf(type, "PreFilter");
					break;
				case MI_TYPE_PAYLOAD:
					sprintf(type, "Payload");
					break;
				case MI_TYPE_FILTER:
					sprintf(type, "Filter");
					break;
				case MI_TYPE_REPORT:
					sprintf(type, "Report");
					break;
				case MI_TYPE_OUTPUT:
					sprintf(type, "Output");
					break;
				default:
					MSG(M_ERR, "Module `%s' UNKNOWN TYPE, unloading ...", mnew->fname);
					dlclose(mnew->handle);
					xfree(mnew);
					bad=1;
			}
			if (bad) continue;
			MOD_VERSION(mnew->iver, maj, min);

			MSG(M_VERB, "Module `%s' license `%s' author `%s' description `%s' type `%s' interface version %d.%.02d Loaded!", mnew->fname, mnew->license, mnew->author, mnew->desc, type, maj, min);
		}

		if (mnew->iver != MODULE_IVER) {
			uint8_t	maj[2], min[2];

			MOD_VERSION(MODULE_IVER, maj[0], min[0]);
			MOD_VERSION(mnew->iver, maj[1], min[1]);

			MSG(M_ERR, "Module version mismatch for `%s', expected version %d.%.02d and found version %d.%.02d", mnew->fname, maj[0], min[0], maj[1], min[1]);
			dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		mnew->state=MI_STATE_INITED;

		if (last) {
			last->next=mnew;
		}
		else {
			mod_list_head=mnew;
		}
		mnew->next=NULL;
		last=mnew;
		mnew=NULL;
	}
	closedir(moddir);
	return 1;
}

int init_payload_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return 1;

	walk=mod_list_head;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_PAYLOAD) {
			walk->func_u.dl_create_payload=(int (*)(uint8_t **, uint32_t *))dlsym(walk->handle, "create_payload");
			if (dlerror() != NULL) {
				MSG(M_ERR, "Can't find payload initialization hook for module `%s': %s", walk->fname, dlerror());
				dlclose(walk->handle);
				continue;
			}

			if (s->verbose > 5) MSG(M_DBG1, "create_payload: found at %p", walk->func_u.dl_create_payload);

			walk->state=MI_STATE_HOOKED;

			/* XXX */
			if (add_payload((uint16_t)walk->param_u.payload_s.dport, walk->param_u.payload_s.sport, NULL, 0, walk->func_u.dl_create_payload, walk->param_u.payload_s.payload_flags) != 1) {
				MSG(M_ERR, "Can't register payload for module `%s'", walk->fname);
				dlclose(walk->handle);
				continue;
			}
			else {
				if (s->verbose > 1) MSG(M_VERB, "Added shlib payload for port %d", walk->param_u.payload_s.dport);
			}
		}
	}

	return 1;
}

int init_output_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return 1;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT) {
			walk->func_u.dl_send_output=(int (*)(const void *))dlsym(walk->handle, "send_output");

			if (s->module_enable == NULL || strstr(s->module_enable, walk->enable_str) == NULL) {
				walk->state=MI_STATE_DISABL;
				dlclose(walk->handle);
				continue;
			}

			if (dlerror() != NULL) {
				MSG(M_ERR, "Can't find output initialization hook for module `%s': %s", walk->fname, dlerror());
				dlclose(walk->handle);
				continue;
			}

			if (s->verbose > 5) MSG(M_DBG1, "send_output: found at %p", walk->func_u.dl_send_output);

			if (walk->param_u.output_s.init_output != NULL) {
				void (*fp)(void)=NULL;

				fp=walk->param_u.output_s.init_output;

				fp();
			}
			walk->state=MI_STATE_HOOKED;
		}
	}
	return 1;
}

int init_report_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return 1;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT) {
			walk->func_u.dl_create_report=(int (*)(const void *))dlsym(walk->handle, "create_report");

			if (s->module_enable == NULL || strstr(s->module_enable, walk->enable_str) == NULL) {
				walk->state=MI_STATE_DISABL;
				dlclose(walk->handle);
				continue;
			}

			if (dlerror() != NULL) {
				MSG(M_ERR, "Can't find report initialization hook for module `%s': %s", walk->fname, dlerror());
				dlclose(walk->handle);
				continue;
			}

			if (s->verbose > 5) MSG(M_DBG1, "create_report: found at %p", walk->func_u.dl_create_report);

			if (walk->param_u.report_s.init_report != NULL) {
				void (*fp)(void)=NULL;

				fp=walk->param_u.report_s.init_report;

				fp();
			}
			walk->state=MI_STATE_HOOKED;
		}
	}
	return 1;
}

void close_payload_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_PAYLOAD && walk->state == MI_STATE_HOOKED) {
			dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}
	return;
}

void close_output_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}
	return;
}

void close_report_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED) {
			dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}
	return;
}

void push_report_modules(const void *r) {
	mod_entry_t *walk=NULL;

	assert(r != NULL);
	if (mod_list_head == NULL) return;

	if (s->verbose > 5) MSG(M_DBG2, "In push report modules");

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED) {
			if (walk->func_u.dl_create_report != NULL) {
				int (*fp)(const void *)=NULL;

				fp=walk->func_u.dl_create_report;

				fp(r);

				if (s->verbose > 5) MSG(M_DBG2, "Pushed report module");
			}
		}
	}
	return;
}

void push_output_modules(const void *r) {
	mod_entry_t *walk=NULL;

	assert(r != NULL);
	if (mod_list_head == NULL) return;

	if (s->verbose > 5) MSG(M_DBG2, "In push output modules");

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			if (walk->func_u.dl_send_output != NULL) {
				int (*fp)(const void *)=NULL;

				fp=walk->func_u.dl_send_output;

				fp(r);

				if (s->verbose > 5) MSG(M_DBG2, "Pushed output module");
			}
		}
	}
	return;
}

int fini_output_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return 1;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			if (walk->param_u.output_s.fini_output != NULL) {
				void (*fp)(void)=NULL;

				fp=walk->param_u.output_s.fini_output;

				fp();
			}
		}
	}
	return 1;
}

int fini_report_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) return 1;

	for (walk=mod_list_head ; walk != NULL ; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED) {
			if (walk->param_u.report_s.fini_report != NULL) {
				void (*fp)(void)=NULL;

				fp=walk->param_u.report_s.fini_report;

				fp();
			}
		}
	}
	return 1;
}
