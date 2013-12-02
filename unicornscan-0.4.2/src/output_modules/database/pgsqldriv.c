#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <libpq-fe.h>

#include <settings.h>
#include <pgsqldriv.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>

/* im sorry about this ;] */
#include <logininfo.h>

static PGconn *conn=NULL;
static PGresult *pres=NULL;

static int pg_connected=0;
static int abort_on_error=1;

static char lastquery[MAX_QUERYSIZE];

static void sql_error(const char *, const char *, int );

static int check_sql_error(const char *, int );

int check_sql_error(const char *file, int lineno) {
	ExecStatusType sret;

	assert(conn != NULL);

	if (pres == NULL) {
		sql_error("Result Pointer is NULL", file, lineno);
		_exit(1);
	}

	sret=PQresultStatus(pres);
	if (sret == PGRES_EMPTY_QUERY) {
		sql_error("Empty Query", file, lineno);
	}
	else if (sret == PGRES_BAD_RESPONSE) {
		sql_error("Unknown Server response", file, lineno);
	}
	else if (sret == PGRES_NONFATAL_ERROR) {
		fprintf(stderr, "Server Warning [%s] called from %s:%d\n", PQerrorMessage(conn), file, lineno);
	}
	else if (sret == PGRES_FATAL_ERROR) {
		sql_error("FATAL ERROR", file, lineno);
		if (abort_on_error) {
			fprintf(stderr, "sql error");
			_exit(1);
		}
	}

	return 1;
}

static dbsettings_t *cfg=NULL;

int initdb(const char *cfgfilename) {
	char connstr[1024];

	pres=NULL;

	cfg=(dbsettings_t *)xmalloc(sizeof(dbsettings_t));
	memset(cfg, 0, sizeof(dbsettings_t));

	/* XXX code removed */

	/* XXX this isnt correct logic */
	if (cfg->hostname == NULL) {
		cfg->hostname=xstrdup(DBHOST);
	}

	if (cfg->dbname == NULL) {
		cfg->dbname=xstrdup(DBNAME);
	}

	if (cfg->username == NULL) {
		cfg->username=xstrdup(USERNAME);
	}

	if (cfg->password == NULL) {
		cfg->password=xstrdup(PASSWORD);
	}

	memset(connstr, 0, sizeof(connstr));

	if (cfg->disable) {
		pg_connected=0;
		return 1;
	}

	if (cfg->hostname != NULL) {
		snprintf(connstr, sizeof(connstr) -1, "host=%s dbname=%s user=%s password=%s", cfg->hostname, cfg->dbname, cfg->username, cfg->password);
	}
	else {
		snprintf(connstr, sizeof(connstr) -1, "dbname=%s user=%s password=%s", cfg->dbname, cfg->username, cfg->password);
	}

	conn=PQconnectdb(connstr);
	assert(conn != NULL);

	if (PQstatus(conn) != CONNECTION_OK) {
		MSG(M_WARN, "Database connection fails: %s", PQerrorMessage(conn));
		pg_connected=0;
		return -1;
	}
	else if (s->verbose > 0) {
		MSG(M_INFO, "database: Connected to host %s, database %s, as user %s, with protocol version %d", PQhost((const PGconn *)conn), PQdb((const PGconn *)conn), PQuser((const PGconn *)conn), PQprotocolVersion(conn)); 
	}

	pg_connected=1;
	return 1;
}

void closedb(void) {
	if (!(pg_connected)) return;

	if (pres) PQclear(pres);
	if (conn) PQfinish(conn);
	return;
}

int dbnumrows(void) {
	if (!(pg_connected)) return 0;
	return PQntuples(pres);
}

char *dbgetvalue(int row, int col) {
	if (!(pg_connected)) return NULL;

	return PQgetvalue(pres, row, col);
}

int _aquerydb(const char * string, const char *file, int lineno) {
	int ret=0;

	if (!(pg_connected)) return 0;

	if (pres) PQclear(pres);

	memset(lastquery, 0, sizeof(lastquery));
	snprintf(lastquery, sizeof(lastquery) -1, "%s", string);

	pres=PQexec(conn, string);
	ret=check_sql_error(file, lineno);

	return ret;
}

static void sql_error(const char *desc, const char *file, int lineno) {
	if (strlen(lastquery)) {
		fprintf(stderr, "Error[%s:%d] in Query: '%s'\nPostgres Error: '%s'", file, lineno, lastquery, PQerrorMessage(conn));
	}
	else {
		fprintf(stderr, "Error[%s:%d] postgres says `%s'\n", file, lineno, PQerrorMessage(conn));
	}
	if (abort_on_error) {
		fprintf(stderr, "SQL FATAL ERROR, exiting\n");
		exit(1);
	}
	return;
}

void db_errorabort(int parm) {
	abort_on_error=parm;
	return;
};
