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
#ifndef _MODULES_H
# define _MODULES_H

#define MI_TYPE_PAYLOAD		1
#define MI_TYPE_REPORT		2
#define MI_TYPE_OUTPUT		3
#define MI_TYPE_PREFILTER	4
#define MI_TYPE_FILTER		5

#define MI_STATE_INITED	1
#define MI_STATE_HOOKED	2
#define MI_STATE_DISABL	3

typedef struct mod_entry_t {
	/* */
	char license[64];
	/* name, (company) (<email>) */
	char author[64];
	/* this is a brief description of what it does */
	char desc[64];
	/* the full path to the file */
	char fname[2048];
	/* the module can write errors to here */
	char errstr[256];
	char enable_str[32]; /* mostly for report and output modules that are default to disabled currently */

	/* interface version */
	uint16_t iver; /* 0x01 0x00 = 1.0 */
	/* state as in init_module has been run, or its hooked into the correct place already */
	uint8_t state;
	/* dlopen handle return */
	void *handle;

	int (*dl_init_module)(struct mod_entry_t *);
	void (*dl_delete_module)(void);

	/* what type of module is this? a payload generator? an output module? */
	uint8_t type;
	union {
		struct payload_mod {
			int32_t sport;
			uint16_t dport;
			uint16_t payload_flags;
		} payload_s;
		struct report_mod {
			int32_t	ip_proto; /* -1 for all */
			int32_t sport; /* -1 for all */
			int32_t dport; /* -1 for all */
			/* XXX need a better way to do this */
			void (*init_report)(void);
			void (*fini_report)(void);
		} report_s;
		struct output_mod {
			void (*init_output)(void);
			void (*fini_output)(void);
		} output_s;
	} param_u;
	union {
		int (*dl_create_payload)(uint8_t **, uint32_t *);
		int (*dl_create_report)(const void * /* report */);
		int (*dl_send_output)(const void * /* report */);
	} func_u;
	struct mod_entry_t *next;
} mod_entry_t;

int init_modules(void);

/* these guys currently act a bit different than the rest */
int init_payload_modules(void);
void close_payload_modules(void);

int init_output_modules(void);
int init_report_modules(void);

void push_output_modules(const void * /* report */);
void push_report_modules(const void * /* report */);

int fini_output_modules(void);
int fini_report_modules(void);

void close_output_modules(void);
void close_report_modules(void);

#endif
