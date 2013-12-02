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

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>

#include <settings.h>
#include <getconfig.h>

#include <unilib/terminate.h>
#include <unilib/panic.h>
#include <unilib/xmalloc.h>
#include <unilib/arc4random.h>
#include <unilib/output.h>
#include <unilib/xipc.h>
#include <unilib/arch.h>

#include <drone.h>
#include <modules.h>

#include <scan_progs/scan_export.h>


static uint8_t child_running=0;
static void child_dead(int);

static const char _lid[]="$Id: main,c 1.0 13/15/17 lightdark Exp captive";

/* used when the drone doesnt behave correctly, to remove it from further consideration */
void mark_dead(drone_t *);

static void child_dead(int signo) {
	int status=0;
	pid_t chld_pid=0;

	if (signo == SIGCHLD) {
		chld_pid=wait(&status);
		if (s->verbose > 3) MSG(M_DBG1, "Child %d Exited with status %d Signaled %d", chld_pid, WEXITSTATUS(status), WIFSIGNALED(status));
		if (WIFSIGNALED(status)) {
			child_running=0;
		}
		else {
			child_running--;
		}
	}

	return;
}

settings_t *s=NULL;
int ident=0;
const char *ident_name_ptr=NULL;

int main(int argc, char **argv) {
	char buf[4096];
	pid_t chld_listener=-1, chld_sender=-1;
	uint8_t status=0, msg_type=0, ecount=0;
	size_t msg_len=0;
	struct sigaction chsa;
	uint8_t *ptr=NULL;
	int lports=IPC_BINDPORT_START;
	uint8_t all_done=0;
	char verbose_level[4];
	drone_t *c=NULL;

	ident=IDENT_MASTER;
	ident_name_ptr=IDENT_MASTER_NAME;

	CLEAR(buf);

	s=(settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi, 0, sizeof(interface_info_t));

	s->forked=0; /* not required, for clarity */

	/* s->display=&display_builtin; */

	getconfig_argv(argc, argv);

	if (s->interface_str == NULL) {
		if (get_default_route_interface(&s->interface_str) != 1) {
			MSG(M_WARN, "Can't find default route, and matching device, using default interface `%s'", DEFAULT_NETDEV);
			s->interface_str=xstrdup(DEFAULT_NETDEV);
		}
		if (s->verbose > 1) {
			MSG(M_VERB, "Using interface %s", s->interface_str);
		}
	}

	if (!(GET_OVERRIDE())) {
		/* let the listener tell us then, the user didnt request a specific address */
		CLEAR(s->vi->myaddr_s); CLEAR(s->vi->hwaddr_s);
		sprintf(s->vi->myaddr_s, "0.0.0.0");
		sprintf(s->vi->hwaddr_s, "00:00:00:00:00:00");
		memset(&s->vi->myaddr, 0, sizeof(s->vi->myaddr));
		memset(&s->vi->hwaddr, 0, sizeof(s->vi->hwaddr));
        }
	else {
		/* complete the information we need like hwaddr, cause its impossible to specify that currently */
		if (s->verbose > 1) MSG(M_DBG2, "Spoofing from `%s [%s]'", s->vi->myaddr_s, s->vi->hwaddr_s);

		/* the ip info is already filled in, so just complete the rest */
		CLEAR(s->vi->hwaddr_s);
		sprintf(s->vi->hwaddr_s, "00:00:00:00:00:00");
		memset(&s->vi->hwaddr, 0, sizeof(s->vi->hwaddr));
	}
	s->vi->mtu=0; /* the listener HAS to tell us this, seeing as how the real limitation is there */

	time(&(s->s_time));

	if (s->forklocal) {
		if (s->verbose > 5) MSG(M_DBG2, "children will be forked, setting up signal handler for them");

		memset(&chsa, 0, sizeof(chsa));
		chsa.sa_handler=&child_dead;
		if (sigaction(SIGCHLD, &chsa, NULL) < 0) {
			MSG(M_ERR, "Cant register SIGCHLD handler");
			terminate(TERM_ERROR);
		}
	}

	arc4random_stir();

	if (init_modules() < 0) {
		MSG(M_ERR, "Can't initialize module structures, quiting");
		terminate(TERM_ERROR);
	}

	if (ipc_init() < 0) {
		MSG(M_ERR, "Cant initialize IPC, quiting");
		terminate(TERM_ERROR);
	}

	if (s->verbose > 0) {
		char low[32], high[32];
		uint32_t ips=0;

		CLEAR(low); CLEAR(high);
		ips=ntohl(s->_low_ip);
		snprintf(low, sizeof(low) -1, "%s", inet_ntoa((*(struct in_addr *)&ips)));
		ips=ntohl(s->_high_ip);
		snprintf(high, sizeof(high) -1, "%s", inet_ntoa((*(struct in_addr *)&ips)));

		MSG(M_VERB, "Scanning: %s -> %s : %s from %s [%s] at %u pps", low, high, (s->mode == MODE_ARPSCAN ? "Arp" : s->port_str), s->vi->myaddr_s, s->vi->hwaddr_s, s->pps);
	}

	if (s->verbose > 3) MSG(M_DBG1, "Main process id is %d", getpid());

	snprintf(verbose_level, sizeof(verbose_level) -1, "%d", s->verbose);

	/* initialize senders */
	if ((s->forklocal & FORK_LOCAL_SENDER) == FORK_LOCAL_SENDER) {
		if (s->drone_str == NULL) {
			s->drone_str=xstrdup(DEF_SENDER);
			if (s->verbose > 5) MSG(M_DBG2, "Added default sender to drone list `%s'", s->drone_str);
		}
		else {
			char newstr[128];

			CLEAR(newstr);
			snprintf(newstr, sizeof(newstr) -1, "%s,%s", s->drone_str, DEF_SENDER);
			xfree(s->drone_str);
			s->drone_str=xstrdup(newstr);
		}

		chld_sender=fork();
		if (chld_sender < 0) {
			MSG(M_ERR, "Can't fork sender: %s", strerror(errno));
			terminate(TERM_ERROR);
		}
		if (chld_sender == 0) {
			char *argz[5];
			char *envz[2];

			argz[0]=SENDERNAME;
			argz[1]=s->mod_dir;
			argz[2]=verbose_level;
			argz[3]=s->interface_str;
			argz[4]=NULL;

			envz[0]='\0';

			execve(SENDER_PATH, argz, envz);
			MSG(M_ERR, "execve %s fails", SENDER_PATH);
			terminate(TERM_ERROR);
		}
		child_running++;
		s->forklocal &= ~(FORK_LOCAL_SENDER);
	}
	else if (s->verbose > 5) {
		MSG(M_DBG2, "No local sender will be forked");
	}

	/* initialize listeners */
	if ((s->forklocal & FORK_LOCAL_LISTENER) == FORK_LOCAL_LISTENER) {
		if (s->drone_str == NULL) {
			s->drone_str=xstrdup(DEF_LISTENER);
			if (s->verbose > 5) MSG(M_DBG2, "Adding default listener to drone list");
		}
		else {
			char newstr[128];

			CLEAR(newstr);
			snprintf(newstr, sizeof(newstr) -1, "%s,%s", s->drone_str, DEF_LISTENER);
			xfree(s->drone_str);
			s->drone_str=xstrdup(newstr);
		}

		chld_listener=fork();
		if (chld_listener < 0) {
			MSG(M_ERR, "Can't fork listener: %s", strerror(errno));
			terminate(TERM_ERROR);
		}
		if (chld_listener == 0) {
			char *argz[7];
			char *envz[2];
			char mtu[8];

			CLEAR(mtu);
			snprintf(mtu, sizeof(mtu) -1, "%u", s->vi->mtu);

			argz[0]=LISTENERNAME;
			argz[1]=s->mod_dir;
			argz[2]=verbose_level;
			argz[3]=s->interface_str;
			argz[4]=s->vi->myaddr_s;
			argz[5]=s->vi->hwaddr_s;
			argz[6]=NULL;

			envz[0]='\0';

			execve(LISTENER_PATH, argz, envz);
			MSG(M_ERR, "execve %s fails", LISTENER_PATH);
			terminate(TERM_ERROR);
		}
		child_running++;
		s->forklocal &= ~(FORK_LOCAL_LISTENER);
	}
	else if (s->verbose > 5) {
		MSG(M_DBG2, "No local listener will be forked");
	}

	/* we need these modules cause we are hardcoded as a output conduit for now XXX */
	if (init_output_modules() < 0) {
		MSG(M_ERR, "Can't initialize output module structures, quiting");
		terminate(TERM_ERROR);
	}
	if (init_report_modules() < 0) {
		MSG(M_ERR, "Can't initialize report module structures, quiting");
		terminate(TERM_ERROR);
	}

	if (s->verbose > 2) MSG(M_DBG1, "drones: %s", s->drone_str);

	if (parse_drone_list((const char *)s->drone_str) < 0) {
		terminate(TERM_ERROR);
	}
	else if (s->verbose > 5) {
		MSG(M_DBG1, "Drone list `%s' parsed correctly", s->drone_str);
	}

	/* do stuff to figure out if there are working drones */
	if (s->verbose > 4) MSG(M_DBG1, "Drone list is %d big, connecting to them.", s->dlh->size);

	do {
		uint8_t *dummy=NULL;
		struct sockaddr_in lbind;

		c=s->dlh->head;

		if (c == NULL) {
			MSG(M_ERR, "no drones?, thats not going to work");
			terminate(TERM_ERROR);
		}

		for (c=s->dlh->head ; c != NULL ; c=c->next) {
			if (s->verbose > 6) MSG(M_DBG1, "THIS NODE -> status: %d type: %s host: %s port: %d socket: %d (%d out of %d ready)", c->status, (c->type == DRONE_TYPE_SENDER ? "Sender" : "Listener") , inet_ntoa(c->dsa.sin_addr), ntohs(c->dsa.sin_port), c->s, all_done, s->dlh->size);

			if (ecount > MAX_ERRORS) {
				MSG(M_ERR, "Too many errors, exiting now");
				terminate(TERM_ERROR);
			}

			switch (c->status) {

				/* connect to it */
				case DRONE_STATUS_UNKNOWN:
					memset(&lbind, 0, sizeof(lbind));
					lbind.sin_port=htons(lports++);

					if (c->s == -1 && create_client_socket(c, (struct sockaddr_in *)&lbind) < 0) {
						c->s=-1;
						usleep(50000);
						ecount++;
					}
					else {
						c->status=DRONE_STATUS_CONNECTED;
					}
					break;

				/* find out what it is */
				case DRONE_STATUS_CONNECTED:
					c->type=DRONE_TYPE_UNKNOWN;
					if (send_message(c->s, MSG_IDENT, MSG_STATUS_OK, dummy, 0) < 0) {
						ecount++;
						MSG(M_ERR, "Cant ident message node, marking as dead");
						if (ecount > MAX_ERRORS) {
							mark_dead(c);
							break;
						}
					}
					else {
						if (get_singlemessage(c->s, &msg_type, &status, &ptr, &msg_len) != 1) {
							MSG(M_ERR, "Unexpected message response from fd %d, marking as dead", c->s);
							mark_dead(c);
						}
						switch (msg_type) {
							case MSG_IDENTSENDER:
								c->type=DRONE_TYPE_SENDER;
								s->senders++;
								break;
							case MSG_IDENTLISTENER:
								c->type=DRONE_TYPE_LISTENER;
								s->listeners++;
								break;
							default:
								MSG(M_ERR, "Unknown drone type from message %s", strmsgtype(msg_type));
								c->type=DRONE_TYPE_UNKNOWN;
						}

						if (send_message(c->s, MSG_ACK, MSG_STATUS_OK, dummy, 0) < 0) {
							MSG(M_ERR, "Cant ack ident message from node on fd %d, marking as dead", c->s);
							mark_dead(c);
						}

						c->status=DRONE_STATUS_IDENT;
					}
					break;

				/* wait for it to say its ready */
				case DRONE_STATUS_IDENT:
					if (get_singlemessage(c->s, &msg_type, &status, &ptr, &msg_len) != 1) {
						MSG(M_ERR, "Unexpected message reply from drone on fd %d, marking as dead", c->s);
						mark_dead(c);
					}
					else if (msg_type == MSG_READY) {
						c->status=DRONE_STATUS_READY;
						if (s->verbose > 3) MSG(M_DBG1, "drone on fd %d is ready", c->s);
						if (c->type == DRONE_TYPE_LISTENER) {
							union {
								listener_info_t *l;
								uint8_t *ptr;
							} l_u;
							struct in_addr ia;

							if (msg_len != sizeof(listener_info_t)) {
								MSG(M_ERR, "Listener didnt send me the correct information, marking dead");
								mark_dead(c);
							}
							l_u.ptr=ptr;
							s->vi->myaddr.sin_addr.s_addr=l_u.l->myaddr;
							ia.s_addr=s->vi->myaddr.sin_addr.s_addr;
							s->vi->mtu=l_u.l->mtu;
							memcpy(s->vi->hwaddr, l_u.l->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
							snprintf(s->vi->hwaddr_s, sizeof(s->vi->hwaddr_s) -1, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x", l_u.l->hwaddr[0], l_u.l->hwaddr[1], l_u.l->hwaddr[2], l_u.l->hwaddr[3], l_u.l->hwaddr[4], l_u.l->hwaddr[5]);
							snprintf(s->vi->myaddr_s, sizeof(s->vi->myaddr_s) -1, "%s", inet_ntoa(ia));

							if (s->verbose > 2) MSG(M_DBG1, "Listener info gave me the following address information `%s [%s]' with mtu %u", s->vi->myaddr_s, s->vi->hwaddr_s, s->vi->mtu);
						}
					}
					else {
						MSG(M_ERR, "drone isnt ready on fd %d, marking as dead", c->s);
						mark_dead(c);
					}
					break;

				case DRONE_STATUS_READY:
					all_done++;
					break;

				case DRONE_STATUS_DEAD:
					all_done++;
					MSG(M_WARN, "Dead drone in list on fd %d", c->s);
					break;

			} /* switch node status */
		} /* step though list */
	} while (all_done < s->dlh->size);

	/* XXX remove this and fix */
	if (s->senders == 0 && GET_SENDDRONE()) {
		/* XXX */
		MSG(M_ERR, "No senders for scan, giving up and rudley disconnecting from other drones without warning");
		terminate(TERM_ERROR);
	}

	if (s->listeners == 0 && GET_LISTENDRONE()) {
		/* XXX */
		MSG(M_ERR, "No listeners for scan, giving up and rudley disconnecting from other drones without warning");
		terminate(TERM_ERROR);
	}

	if (s->verbose > 5) MSG(M_DBG2, "Running scan");
	run_mode();

	time(&(s->e_time));

	if (s->verbose > 4) MSG(M_DBG2, "Main shuting down output modules");
	fini_output_modules();
	fini_report_modules();
	if (s->verbose > 4) MSG(M_DBG2, "Main exiting");

	terminate(TERM_NORMAL);
}

void mark_dead(drone_t *c) {

	if (c == NULL) PANIC("mark dead passed a NULL drone");

	c->status=DRONE_STATUS_DEAD;

	if (c->type == DRONE_TYPE_SENDER) s->senders--;
	if (c->type == DRONE_TYPE_LISTENER) s->listeners--;

	shutdown(c->s, SHUT_RDWR);
	close(c->s);
	c->s=-1;
}
