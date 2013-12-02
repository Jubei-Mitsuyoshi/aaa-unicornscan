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

#include <errno.h>
#include <unistd.h>
#include <signal.h>
/* #include <netinet/tcp.h>  for TCP_NODELAY */

#include <panic.h>
#include <settings.h>
#include <output.h>
#include <xmalloc.h>
#include <xipc.h>

#define MAX_SLACKSIZE		1024
#define IPC_MAGIC_HEADER	0xf0f1f2f3	/* to make endian mis-matches fault, as this is not mis-matched endian safe yet */
#define MAX_MSGS		(IPC_DSIZE / 8)	/* close to maximum allowed */

typedef struct _PACKED_ ipc_msghdr_t {
	uint32_t header;
	uint8_t type;
	uint8_t status;
	uint16_t len;
} ipc_msghdr_t;

struct _PACKED_ message_s {
	ipc_msghdr_t hdr;
	uint8_t data[IPC_DSIZE - sizeof(ipc_msghdr_t)];
};

static union {
	struct message_s *m;
	void *ptr;
	uint8_t *hdr;
} m_u[MAX_CONNS][MAX_MSGS];

static void wait_timeout(int );

static int setup_mptrs(int /* sock */);

static uint8_t *msg_buf[MAX_CONNS], *save_buf[MAX_CONNS];
static size_t m_off[MAX_CONNS], m_max[MAX_CONNS];
static ssize_t readsize[MAX_CONNS];
static size_t save_size[MAX_CONNS], ureadsize[MAX_CONNS];

int ipc_init(void) {
	int j=0;

	for (j=0 ; j < MAX_CONNS ; j++) {
		msg_buf[j]=NULL; save_buf[j]=NULL;
		m_off[j]=0; m_max[j]=0;
		readsize[j]=-1;
		save_size[j]=0; ureadsize[j]=0;
	}

	return 1;
}

/* there is alot of new stuff to merge here, wear hardhats at all times, watch where you step */

int create_server_socket(const struct sockaddr_in *saddr) {
	int s_sock=-1;
	int param=0;
	int sbufsz=0;

	assert(saddr != NULL);

	if (s->verbose > 3) MSG(M_DBG1, "Creating Server socket");

	if ((s_sock=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		MSG(M_ERR, "Can't create socket: %s", strerror(errno));
		return -1;
	}

	param=1;
	if (setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&param, sizeof(param)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_REUSEADDR: %s", strerror(errno));
		return -1;
	}

	sbufsz=IPC_DSIZE;
	if (setsockopt(s_sock, SOL_SOCKET, SO_RCVBUF, (void *)&sbufsz, sizeof(sbufsz)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_RCVBUF: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(s_sock, SOL_SOCKET, SO_SNDBUF, (void *)&sbufsz, sizeof(sbufsz)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_RCVBUF: %s", strerror(errno));
		return -1;
	}

	/*
	param=1;
	if (setsockopt(s_sock, SOL_SOCKET, TCP_NODELAY, (void *)&param, sizeof(param)) < 0) {
		MSG(M_ERR, "Cant setsockopt: TCP_NODELAY: %s", strerror(errno));
	}
	*/

	if (bind(s_sock, (const struct sockaddr *)saddr, sizeof(struct sockaddr_in)) == -1) {
		MSG(M_ERR, "bind() port %u fails: %s", ntohs(saddr->sin_port), strerror(errno));
		return -1;
	}

	if (s->verbose > 5) MSG(M_DBG2, "Listening on port %d", ntohs(saddr->sin_port));

	return s_sock;
}

int create_client_socket(drone_t *drone, struct sockaddr_in *s_bind) {
	union {
		struct sockaddr *ptr;
		struct sockaddr_in *bin;
	} s_u;
	int ret=0, sbufsz=0;

	int param=0;

	if (drone == NULL) PANIC("drone null!");

	s_u.bin=s_bind;

	drone->dsa.sin_family=AF_INET;
	if ((drone->s=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		MSG(M_ERR, "Can't create socket: %s", strerror(errno));
		return -1;
	}

	param=1;
	if (setsockopt(drone->s, SOL_SOCKET, SO_REUSEADDR, (void *)&param, sizeof(param)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_REUSEADDR: %s", strerror(errno));
		return -1;
	}

	if (s_u.bin != NULL) {
		if (s->verbose > 5) MSG(M_DBG2, "Binding local conenction to port %d", ntohs(s_u.bin->sin_port));
		if (bind(drone->s, s_u.ptr, sizeof(struct sockaddr_in)) < 0) {
			MSG(M_ERR, "Cant bind client connection: %s", strerror(errno));
			/* return -1; */
		}
	}

	sbufsz=IPC_DSIZE;
	if (setsockopt(drone->s, SOL_SOCKET, SO_RCVBUF, (void *)&sbufsz, sizeof(sbufsz)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_RCVBUF: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(drone->s, SOL_SOCKET, SO_SNDBUF, (void *)&sbufsz, sizeof(sbufsz)) < 0) {
		MSG(M_ERR, "Can't setsockopt: setsockopt SO_RCVBUF: %s", strerror(errno));
		return -1;
	}

	/*
	param=1;
	if (setsockopt(drone->s, SOL_SOCKET, TCP_NODELAY, (void *)&param, sizeof(param)) < 0) {
		MSG(M_ERR, "Cant setsockopt: TCP_NODELAY: %s", strerror(errno));
	}
	*/

	s_u.bin=&drone->dsa;

	if (s->verbose > 3) {
		MSG(M_DBG1, "Creating Client socket to %s:%d", inet_ntoa(s_u.bin->sin_addr), ntohs(s_u.bin->sin_port));
	}

	ret=connect(drone->s, s_u.ptr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (s->verbose > 1) MSG(M_ERR, "connect() fails: %s", strerror(errno));
		return -1;
	}

	return 1;
}

/* dfghdfjdgh */
static int wait_error=0;

int wait_for_client(int s_socket) {
	int cli_fd;
	struct sockaddr_in usin;
	socklen_t sin_len=0;
	struct sigaction timeoutsa;

	wait_error=0;

	memset(&usin, 0, sizeof(usin));
	memset(&timeoutsa, 0, sizeof(timeoutsa));

	if (listen(s_socket, 1) < 0) {
		MSG(M_ERR, "listen fails: %s", strerror(errno));
		return -1;
	}

	timeoutsa.sa_handler=&wait_timeout;
	if (sigaction(SIGALRM, &timeoutsa, NULL) < 0) {
		MSG(M_ERR, "Cant register timeout handler for wait for client: %s", strerror(errno));
		return -1;
	}

	alarm(5);
	cli_fd=-1;
	cli_fd=accept(s_socket, (struct sockaddr *)&usin, &sin_len);
	if (wait_error) {
		return -1;
	}

	if (cli_fd) {
		if (getpeername(cli_fd, (struct sockaddr *)&usin, &sin_len)) {
			MSG(M_VERB, "Connection from `%s'", inet_ntoa(usin.sin_addr));
		}
	}
	alarm(0);


	close(s_socket);
	return cli_fd;
}

static void wait_timeout(int signo) {
	if (signo == SIGALRM) {
		MSG(M_ERR, "Timed out waiting for main to connect");
		wait_error=1;
	}
}

static void reset_messages(int sock) {
	int j=0;

	for (j=0 ; j < MAX_MSGS ; j++) {
		m_u[sock][j].ptr=NULL;
	}

	if (msg_buf[sock] != NULL) {
		xfree(msg_buf[sock]);
		msg_buf[sock]=NULL;
	}

	ureadsize[sock]=0; readsize[sock]=0;
	return;
}


int recv_messages(int sock) {
	if (s->verbose > 5) {
		MSG(M_DBG1, "recv_messages on socket %d", sock);
	}

	assert(sock > -1 && sock < MAX_CONNS);

	reset_messages(sock);

	msg_buf[sock]=(uint8_t *)xmalloc(IPC_DSIZE);
	memset(msg_buf[sock], 0, IPC_DSIZE);

	assert(save_size[sock] <= MAX_SLACKSIZE);

	if (save_size[sock]) {
		if (save_buf[sock] == NULL) PANIC("save_size is not zero but save_buf is null");

		if (s->verbose > 6) MSG(M_DBG2, "Saved data in buffer, saving it in beginning of read buffer");
		memcpy(msg_buf[sock], save_buf[sock], save_size[sock]);
		if (s->verbose > 6) {
			MSG(M_DBG2, "DUMPING SAVED DATA"); hexdump(save_buf[sock], save_size[sock]);
		}
		xfree(save_buf[sock]);
	}

	/* reading from a dead socket will produce a ipc error, that can be confusing */
	readsize[sock]=
	read(sock,
	&msg_buf[sock][save_size[sock]],
	IPC_DSIZE - save_size[sock]);

	if (readsize[sock] < 0) {
		msg_buf[sock]=NULL;
		MSG(M_ERR, "read fails: %s", strerror(errno));
		return -1;
	}

	ureadsize[sock]=(size_t)readsize[sock];
	ureadsize[sock] += save_size[sock];
	save_size[sock]=0;

	/* XXX */
	if (ureadsize[sock] < sizeof(ipc_msghdr_t)) {
		MSG(M_ERR, "undersized ipc message, only %d bytes [min required %d]", (int)ureadsize[sock], sizeof(ipc_msghdr_t));
		return -1;
	}

	if (s->verbose > 5) MSG(M_DBG2, "Read %u bytes of data from fd %d", (unsigned int)ureadsize[sock], sock);

	/* now setup the m_u strucure to point to the messages */
	setup_mptrs(sock);

	m_off[sock]=0;

	return 1;
}

/* returns 1 (more to read) or 0 (done reading), or -1 for error */
/* if a sender sends 2 messages, then the last will be read first, and the second to last next, etc */

int get_message(int sock, uint8_t *type, uint8_t *status, uint8_t **data, size_t *data_len) {
	assert(data != NULL); *data=NULL; *type=0; *data_len=0;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("someone called me incorrectly with sock = %d", sock);

	assert(m_off[sock] < (MAX_MSGS - 1));

	if (m_u[sock][m_off[sock]].ptr == NULL) {
		if (s->verbose > 5) MSG(M_DBG2, "get_message: returning 0 end of messages");
		*type=0;
		*status=0;
		*data=NULL;
		*data_len=0;
		return 0;
	}


	if (s->verbose > 5) MSG(M_DBG2, "get_message: message type %d status %d data_len %u and m_off %u out of m_max %u", m_u[sock][m_off[sock]].m->hdr.type, m_u[sock][m_off[sock]].m->hdr.status, m_u[sock][m_off[sock]].m->hdr.len, m_off[sock], m_max[sock]);

	if (m_u[sock][m_off[sock]].m->hdr.header != IPC_MAGIC_HEADER) {
		PANIC("WRONG MAGIC NUMBER FOR IPC MESSAGE");
	}
	*type=m_u[sock][m_off[sock]].m->hdr.type;
	*status=m_u[sock][m_off[sock]].m->hdr.status;
	*data=&m_u[sock][m_off[sock]].m->data[0];
	*data_len=m_u[sock][m_off[sock]].m->hdr.len;
	++m_off[sock];

	return 1;
}

int get_singlemessage(int sock, uint8_t *type, uint8_t *status, uint8_t **data, size_t *data_len) {
	assert(data != NULL); *data=NULL; *type=0; *data_len=0;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("someone called me incorrectly with sock = %d", sock);

	recv_messages(sock);
	if (m_max[sock] > 1) PANIC("too many messages m_max is %u", m_max[sock]);

	if (m_u[sock][m_off[sock]].ptr == NULL) {
		PANIC("NULL MESSAGE");
	}

	if (s->verbose > 5) MSG(M_DBG2, "get_message: message type %s status %d data_len %u and m_off %u out of m_max %u", strmsgtype(m_u[sock][0].m->hdr.type), m_u[sock][0].m->hdr.status, m_u[sock][0].m->hdr.len, m_off[sock], m_max[sock]);

	*type=m_u[sock][0].m->hdr.type;
	*status=m_u[sock][0].m->hdr.status;
	*data=&m_u[sock][0].m->data[0];
	*data_len=m_u[sock][0].m->hdr.len;

	return 1;
}

static int setup_mptrs(int sock) {
	size_t mptr_off=0, gmptr_off=0;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("someone called me incorrectly with sock = %d", sock);

	if (ureadsize[sock] < sizeof(ipc_msghdr_t)) PANIC("setup mptrs called with too small read buffer %u bytes", ureadsize[sock]);

	if (s->verbose > 7) MSG(M_DBG2, "SETUP POINTERS");

	for (m_off[sock]=0, mptr_off=0, m_max[sock]=0 ; mptr_off < ureadsize[sock] ; m_off[sock]++) {
		if (m_off[sock] >= MAX_MSGS) PANIC("too many messages in ipc read %u", m_off[sock]);

		if (s->verbose > 7) {
			MSG(M_DBG1, "m_u[%d].hdr=&msg_buf[%d] ureadsize %u, DUMPING MESSAGE", m_off[sock], mptr_off, ureadsize[sock]);
			//hexdump(&msg_buf[mptr_off], sizeof(ipc_msghdr_t));
		}

		if (mptr_off + sizeof(ipc_msghdr_t) > ureadsize[sock]) {
			//MSG(M_DBG2, "PARTIAL MESSAGE AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
			save_size[sock]=ureadsize[sock] - mptr_off;
			save_buf[sock]=(uint8_t *)xmalloc(save_size[sock]);
			memcpy(save_buf[sock], &msg_buf[sock][mptr_off], save_size[sock]);
			if (s->verbose > 7) {
				MSG(M_DBG2, "SAVE SAVE DUMPING THE SAVE BUFFER");
				hexdump(save_buf[sock], save_size[sock]);
			}
			m_u[sock][m_off[sock]].ptr=NULL;
			break;
		}
		m_u[sock][m_off[sock]].hdr=&msg_buf[sock][mptr_off];

		if (m_u[sock][m_off[sock]].m->hdr.header != IPC_MAGIC_HEADER) {
			PANIC("ipc message is damaged, wrong magic number `%x' m_off=%u mptr_off=%u", m_u[sock][m_off[sock]].m->hdr.header, m_off[sock], mptr_off);
		}
		if (s->verbose > 5) MSG(M_DBG2, "Got IPC Message header type %d[%s] status %d length %d", m_u[sock][m_off[sock]].m->hdr.type, strmsgtype(m_u[sock][m_off[sock]].m->hdr.type), m_u[sock][m_off[sock]].m->hdr.status, m_u[sock][m_off[sock]].m->hdr.len);
		gmptr_off=mptr_off;
		mptr_off += (m_u[sock][m_off[sock]].m->hdr.len + sizeof(ipc_msghdr_t)); /* INC */
	} /* for mptr_off < ureadsize */

	/* now figure out how many (if any) bytes were left trailing at the end, and save them */
	if (mptr_off > ureadsize[sock]) {
		save_size[sock]=ureadsize[sock] - gmptr_off;
		if (save_size[sock] > MAX_SLACKSIZE) PANIC("saved data is too big");

		save_buf[sock]=(uint8_t *)xmalloc(save_size[sock]);
		memcpy(save_buf[sock], &msg_buf[sock][gmptr_off], save_size[sock]);
		if (s->verbose > 7) {
			MSG(M_DBG2, "DUMPING THE SAVE BUFFER");
			hexdump(save_buf[sock], save_size[sock]);
		}
		/* the message we are on is incomplete, remove it from the recv area */
		m_off[sock]--;
		m_u[sock][m_off[sock]].ptr=NULL;
	}

	if (s->verbose > 7) MSG(M_DBG2, "m_max = m_off - 1[%u]", m_off[sock] - 1);
	m_max[sock]=(m_off[sock] - 1);
	m_off[sock]=0;

	return 1;
}


int send_message(int sock, int type, int status, uint8_t *data, uint32_t data_len) {
	union {
		struct message_s *m;
		void *ptr;
	} sm_u;
	ssize_t ret=0;
	struct message_s m;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("someone called me incorrectly with sock = %d", sock);

	memset(&m, 0, sizeof(m));
	sm_u.m=&m;

	sm_u.m->hdr.type=type;
	if (data_len > (IPC_DSIZE - sizeof(ipc_msghdr_t))) {
		MSG(M_ERR, "Attempt to send oversized packet of length %d from IPC", data_len);
		return -1;
	}

	if (type < 0 || type > 0xFF) {
		MSG(M_ERR, "Message type out of range `%d'", type);
		return -1;
	}
	if (status < 0 || status > 0xFF) {
		MSG(M_ERR, "Message status out of range `%d'", status);
		return -1;
	}

	sm_u.m->hdr.len=data_len;
	sm_u.m->hdr.header=IPC_MAGIC_HEADER;
	sm_u.m->hdr.status=(uint8_t)status;

	if (s->verbose > 5) {
		MSG(M_DBG2, "Sending ipc message type %d[%s] status %d len %d to fd %d", type, strmsgtype(type), status, data_len, sock);
	}

	if (data_len) {
		memcpy(sm_u.m->data, data, data_len);
	}
	ret=write(sock, sm_u.ptr, (sizeof(ipc_msghdr_t) + data_len));

	return ret;
}

struct msg_ntbl {
	int type;
	char hr[32];
};
struct msg_ntbl m_tbl[]={
/*					|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0 */
{MSG_ERROR,				"Error"				  },
{MSG_VERSIONREQ,			"VersionRequest"		  },
{MSG_VERSIONREPL,			"VersionReply"			  },
{MSG_QUIT,				"Quit"				  },
{MSG_WORKUNIT,				"Workunit"			  },
{MSG_WORKDONE,				"Workdone"			  },
{MSG_OUTPUT,				"Output"			  },
{MSG_READY,				"Ready"				  },
{MSG_ACK,				"Ack"				  },
{MSG_IDENT,				"Ident"				  },
{MSG_IDENTSENDER,			"IdentSender"			  },
{MSG_IDENTLISTENER,			"IdentListener"			  },
{MSG_NOP,				"Nop"				  },
{MSG_TERMINATE,				"Terminate"			  },
};

char *strmsgtype(int msgtype) {
	static char sbuf[32];
	uint32_t j=0;

	CLEAR(sbuf);
	for (j=0 ; m_tbl[j].type != -1 ; j++) {
		if (m_tbl[j].type == msgtype) {
			sprintf(sbuf, "%s", m_tbl[j].hr);
			return &sbuf[0];
		}
	}

	sprintf(sbuf, "UNKNOWN");
	return &sbuf[0];
}

#undef IPC_DSIZE
#undef IPC_MAGIC_HEADER
#undef MAX_MSGS
#undef MAX_SLACKSIZE
