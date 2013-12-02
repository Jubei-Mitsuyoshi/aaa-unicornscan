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
#ifndef _OPTIONS_H
# define _OPTIONS_H

int scan_setdefaults(void);
int scan_setnodefpayload(void);
int scan_setdelaytype(int );
int scan_setrecvpacket(void);
int scan_setreadfile(const char *);
int scan_settryfrags(void);
int scan_setinterface(const char *);
int scan_seticmp(void);
int scan_setlistendrone(void);
int scan_setsenddrone(void);
int scan_setscantype(const char *);
int scan_setmoddir(const char *);
int scan_setnopatience(void);
int scan_setpcapfilter(const char *);
int scan_setsrcaddr(const char *);
int scan_setsavefile(const char *);
int scan_setdrones(const char *);
int scan_setcovertness(int );
int scan_setrepeats(int);
int scan_setnoshuffle(void);
int scan_setpps(const char *);
int scan_setppsn(int );
int scan_setenablemodule(const char *);
int scan_setdronetype(const char *);

int scan_setports(const char *);
int scan_setdesthosts(const char *);

int scan_setidlehosts(const char *);
int scan_setidlescan(void);

int scan_setverbose(int);
int scan_setverboseinc(void); /* kludge for getconfig.c */

char *scan_getportstr(void);
char *scan_getdesthosts(void);

#endif
