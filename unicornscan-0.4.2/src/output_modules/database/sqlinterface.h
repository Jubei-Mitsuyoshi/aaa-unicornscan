#ifndef _SQLINTERFACE_H
# define _SQLINTERFACE_H

int initdb(void);
void closedb(void);

int _aquerydb(const char *, const char *, int );
int dbnumrows(void);
char *dbgetvalue(int, int);
void db_errorabort(int );
#define aquerydb(query) _aquerydb(query, __FILE__, __LINE__)

#endif
