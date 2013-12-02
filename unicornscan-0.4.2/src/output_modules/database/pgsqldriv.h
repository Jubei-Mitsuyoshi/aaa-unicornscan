#ifndef MYPGSQL_H
# define MYPGSQL_H

typedef struct database_settings {
	char *hostname;
	int port;
	char *dbname;
	char *username;
	char *password;
	uint8_t disable;
} dbsettings_t;

#define MAX_QUERYSIZE 4096

int initdb(const char *);
void closedb(void);
int _aquerydb(const char *, const char *, int );
int dbnumrows(void);
char *dbgetvalue(int, int);
void db_errorabort(int );
#define aquerydb(query) _aquerydb(query, __FILE__, __LINE__)


#endif
