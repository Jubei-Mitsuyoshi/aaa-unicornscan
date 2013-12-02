#ifndef BISON_PARSE_TAB_H
# define BISON_PARSE_TAB_H

#ifndef YYSTYPE
typedef union {
	int inum;
	char *ptr;
	buf_t buf;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
# define	NUMBER	257
# define	COLON	258
# define	SBRACE	259
# define	EBRACE	260
# define	BOOL	261
# define	TCPFLAG	262
# define	BROKENCRC	263
# define	SOURCEPORT	264
# define	DESTPORT	265
# define	READFILE	266
# define	INTERFACE	267
# define	WATCHICMP	268
# define	LISTENDRONE	269
# define	SCANMODE	270
# define	TCPFLAGS	271
# define	DEFPAYLOAD	272
# define	MODULEDIR	273
# define	STACKLAYER	274
# define	NOPATIENCE	275
# define	COMMA	276
# define	SRCADDR	277
# define	RANDOM	278
# define	SENDFRAGS	279
# define	SHUFFLE	280
# define	IPTTL	281
# define	IPTOS	282
# define	FINGERPRINT	283
# define	SAVEFILE	284
# define	DRONES	285
# define	IDLEHOSTS	286
# define	IDLESCAN	287
# define	STR	288
# define	BSTR	289
# define	PPS	290
# define	PAYLOADS	291
# define	IPPROTOCOLS	292
# define	DANGEROUS	293
# define	RECVTIMEOUT	294
# define	SEMICOLON	295
# define	SENDDRONE	296
# define	SCANTYPE	297
# define	PCAPFILTER	298
# define	VERBOSE	299
# define	DOTQUAD	300
# define	GLOBAL	301
# define	REPEATS	302
# define	NOTHING	303


extern YYSTYPE yylval;

#endif /* not BISON_PARSE_TAB_H */
