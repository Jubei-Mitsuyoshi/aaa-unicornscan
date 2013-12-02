#include <config.h>
#include <unistd.h>
#include <stdlib.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif
#include <errno.h>

#include <settings.h>

#include <send_packet.h>
#include <recv_packet.h>

#include <unilib/panic.h>
#include <unilib/output.h>
#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc.h>
#include <unilib/arc4random.h>
#include <unilib/arch.h>

#include <modules.h>
#include <options.h>

#include <parse/parse.h>

const char *ident_name_ptr=NULL;
int ident=0;

settings_t *s=NULL;

#define PROCTYPE_SENDER		1
#define PROCTYPE_LISTENER	2

int main(int argc, char ** argv) {
	void (*run_mode)(void)=NULL;

#ifdef WITH_SELINUX
	security_context_t c_con, p_con;
#endif

	s=xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi, 0, sizeof(interface_info_t));

	s->forked=1;

	scan_setdefaults();

#ifdef BUILD_IDENT_SEND
	ident=IDENT_SEND;
	ident_name_ptr=IDENT_SEND_NAME;
	run_mode=&send_packet;

	if (argc != 4) {
		MSG(M_ERR, "arguments for this program are incorrect, fatal");
		terminate(TERM_ERROR);
	}

	if (scan_setmoddir(argv[1]) < 0) {
		MSG(M_ERR, "Cant set module directory, fatal");
		terminate(TERM_ERROR);
	}
	if (scan_setverbose(atoi(argv[2])) < 0) {
		MSG(M_ERR, "Cant set verbose level, fatal");
		terminate(TERM_ERROR);
	}
	if (scan_setinterface(argv[3]) < 0) {
		MSG(M_ERR, "Cant set interface, fatal");
		terminate(TERM_ERROR);
	}

#elif BUILD_IDENT_RECV
	ident=IDENT_RECV;
	ident_name_ptr=IDENT_RECV_NAME;
	run_mode=&recv_packet;

	if (argc != 6) {
		MSG(M_ERR, "arguments for this program are incorrect, fatal");
		terminate(TERM_ERROR);
	}

	if (scan_setmoddir(argv[1]) < 0) {
		MSG(M_ERR, "Cant set module directory, fatal");
		terminate(TERM_ERROR);
	}
	if (scan_setverbose(atoi(argv[2])) < 0) {
		MSG(M_ERR, "Cant set verbose level, fatal");
		terminate(TERM_ERROR);
	}
	if (scan_setinterface(argv[3]) < 0) {
		MSG(M_ERR, "Cant set interface, fatal");
		terminate(TERM_ERROR);
	}

	if (get_interface_info(s->interface_str, s->vi) < 0) {
		MSG(M_ERR, "Cant get interface information");
		terminate(TERM_ERROR);
	}

	if (strcmp(argv[4], "0.0.0.0") != 0) {
		struct in_addr ia;

		if (s->verbose > 2) {
			MSG(M_DBG1, "ok so im spoofing `%s' then", argv[4]);
		}
		snprintf(s->vi->myaddr_s, sizeof(s->vi->myaddr_s) -1, "%s", argv[4]);
		if (inet_aton(s->vi->myaddr_s, &ia) == 0) {
			MSG(M_ERR, "My ip address doesnt seem valid, fatal");
			terminate(TERM_ERROR);
		}
		s->vi->myaddr.sin_addr.s_addr=ia.s_addr;
	}

	if (strcmp(argv[5], "00:00:00:00:00:00") != 0) {
		unsigned int a,b,c,d,e,f;

		if (s->verbose > 2) MSG(M_DBG1, "ok so im spoofing my mac then `%s'", argv[5]);
		/* XXX ugly */
		if (sscanf(argv[5], "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6) {
			MSG(M_ERR, "My Mac address doesnt seem valid, fatal");
			terminate(TERM_ERROR);
		}
		if (a > 0xFF || b > 0xFF || c > 0xFF || d > 0xFF || e > 0xFF || f > 0xFF) {
			MSG(M_ERR, "Part or all of Mac address is out of range, fatal");
			terminate(TERM_ERROR);
		}

		snprintf(s->vi->hwaddr_s, sizeof(s->vi->hwaddr_s) -1, "%s", argv[5]);
	}

#else
	PANIC("make is broken?");
#endif

	if (s->verbose > 4) {
		int sret=0, j=0;
		size_t doff=0;
		char cmdline[128];

		CLEAR(cmdline);
		for (j=0 ; j < argc ; j++) {
			sret=snprintf(cmdline + doff, sizeof(cmdline) - (doff + 1), "%s ", argv[j]);
			if ((sret < 1) || (doff + 1 >= sizeof(cmdline))) break;
			doff += (size_t) sret;
		}
		MSG(M_DBG2, "Command line `%s'", cmdline);
	}


	if (s->verbose > 5) {
		MSG(M_DBG2, "%s with pid of %d", (ident == IDENT_RECV ? "Listener" : "Sender"), getpid());
	}

#ifdef WITH_SELINUX
	/*
	 * obviously none of this is required, but if we are in selinux mode, lets just
	 * make sure that we are in a sane selinux env, in case the policy isnt added,
	 * it will make troubleshooting more obvious if we fail with an error regarding
	 * a broken selinux setup.
	 */
	if (getpidcon(getpid(), &c_con) < 0) {
		MSG(M_ERR, "getpidcon fails");
		terminate(TERM_ERROR);
	}

	if (getprevcon(&p_con) < 0) {
		MSG(M_ERR, "getprevcon fails");
		terminate(TERM_ERROR);
	}

	if (!(security_check_context(c_con))) {
		MSG(M_ERR, "My security context is invalid, exiting");
		terminate(TERM_ERROR);
	}

	if (ident == IDENT_RECV) {
		if (strstr(c_con, LISTENERNAME) != NULL) {
		}
	}
	else {
		if (strstr(c_con, SENDERNAME) != NULL) {
		}
	}

	if (s->verbose > 2) MSG(M_DBG2, "current context `%s' prev context `%s'", c_con, p_con);

	if (!(security_getenforce())) {
		/*
		 * once again this is not something that should ever happen in a sane env, but well just check
		 * anyhow to prevent serious mistakes
		 */
		MSG(M_ERR, "This program is not compiled to run without the protection of selinux, enforcing mode must be on, perhaps you should recompile without selinux support if you do not plan to use it");
		terminate(TERM_ERROR);
	}

	if (setreuid(0, 0) == -1) {
		MSG(M_ERR, "setreuid fails: %s", strerror(errno));
	}
#endif

	arc4random_stir();

	if (init_modules() < 0) {
		MSG(M_ERR, "Can't initialize module structures, quiting");
		terminate(TERM_ERROR);
	}
                                                                                                                   
	if (ipc_init() < 0) {
		MSG(M_ERR, "Cant initialize IPC, quiting");
		terminate(TERM_ERROR);
	}

	run_mode(); /* shouldnt return */

	MSG(M_DBG2, "Im a little teapot short and stout, here is my handle and here is my spout");
	terminate(TERM_ERROR);
}
