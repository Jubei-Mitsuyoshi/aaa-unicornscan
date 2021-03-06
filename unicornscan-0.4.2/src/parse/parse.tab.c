/* A Bison parser, made from parse.y
   by GNU bison 1.35.  */

#define YYBISON 1  /* Identify Bison output.  */

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

#line 1 "parse.y"

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

#include <putil.h>

#include <scan_progs/scan_export.h>
#include <settings.h>
#include <options.h>

#define MAIN (ident == IDENT_MASTER)
#define SEND (ident == IDENT_SEND)

extern int yywarn(const char *);
extern void yyerror(const char *);


#line 37 "parse.y"
#ifndef YYSTYPE
typedef union {
	int inum;
	char *ptr;
	buf_t buf;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
#line 59 "parse.y"



#ifndef YYDEBUG
# define YYDEBUG 0
#endif



#define	YYFINAL		152
#define	YYFLAG		-32768
#define	YYNTBASE	50

/* YYTRANSLATE(YYLEX) -- Bison token number corresponding to YYLEX. */
#define YYTRANSLATE(x) ((unsigned)(x) <= 303 ? yytranslate[x] : 59)

/* YYTRANSLATE[YYLEX] -- Bison token number corresponding to YYLEX. */
static const char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49
};

#if YYDEBUG
static const short yyprhs[] =
{
       0,     0,     2,     4,     7,     8,    14,    20,    22,    25,
      27,    30,    31,    36,    41,    48,    53,    58,    63,    68,
      73,    78,    83,    88,    93,    98,   103,   108,   113,   118,
     123,   128,   133,   138,   143,   148,   153,   158,   163,   168,
     173,   178,   191,   193,   196,   198,   201,   203,   206
};
static const short yyrhs[] =
{
      51,     0,    52,     0,    51,    52,     0,     0,    47,     5,
      53,     6,    41,     0,    37,     5,    54,     6,    41,     0,
      55,     0,    55,    53,     0,    56,     0,    56,    54,     0,
       0,    36,     4,     3,    41,     0,     9,     4,    20,    41,
       0,     9,     4,    20,    22,    20,    41,     0,    18,     4,
       7,    41,     0,    12,     4,    34,    41,     0,    25,     4,
       7,    41,     0,    10,     4,     3,    41,     0,    13,     4,
      34,    41,     0,    14,     4,     7,    41,     0,    15,     4,
       7,    41,     0,    42,     4,     7,    41,     0,    21,     4,
       7,    41,     0,    16,     4,    43,    41,     0,    17,     4,
      58,    41,     0,    48,     4,     3,    41,     0,    40,     4,
       3,    41,     0,    19,     4,    34,    41,     0,    44,     4,
      34,    41,     0,    23,     4,    46,    41,     0,    23,     4,
      24,    41,     0,    27,     4,     3,    41,     0,    28,     4,
       3,    41,     0,    26,     4,     7,    41,     0,    30,     4,
      34,    41,     0,    29,     4,     3,    41,     0,    45,     4,
       3,    41,     0,    31,     4,    34,    41,     0,    32,     4,
      34,    41,     0,    33,     4,     7,    41,     0,    38,    11,
       3,    10,     3,    39,     7,     5,    57,    41,     6,    41,
       0,    35,     0,    57,    35,     0,    34,     0,    57,    34,
       0,     8,     0,    58,     8,     0,    58,    22,     0
};

#endif

#if YYDEBUG
/* YYRLINE[YYN] -- source line where rule number YYN was defined. */
static const short yyrline[] =
{
       0,    64,    67,    68,    71,    72,    73,    76,    77,    80,
      81,    84,    85,    86,    96,    97,    98,    99,   100,   101,
     102,   103,   104,   105,   106,   107,   115,   116,   117,   118,
     119,   120,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   132,   154,   158,   161,   170,   181,   185,   188
};
#endif


#if (YYDEBUG) || defined YYERROR_VERBOSE

/* YYTNAME[TOKEN_NUM] -- String name of the token TOKEN_NUM. */
static const char *const yytname[] =
{
  "$", "error", "$undefined.", "NUMBER", "COLON", "SBRACE", "EBRACE", 
  "BOOL", "TCPFLAG", "BROKENCRC", "SOURCEPORT", "DESTPORT", "READFILE", 
  "INTERFACE", "WATCHICMP", "LISTENDRONE", "SCANMODE", "TCPFLAGS", 
  "DEFPAYLOAD", "MODULEDIR", "STACKLAYER", "NOPATIENCE", "COMMA", 
  "SRCADDR", "RANDOM", "SENDFRAGS", "SHUFFLE", "IPTTL", "IPTOS", 
  "FINGERPRINT", "SAVEFILE", "DRONES", "IDLEHOSTS", "IDLESCAN", "STR", 
  "BSTR", "PPS", "PAYLOADS", "IPPROTOCOLS", "DANGEROUS", "RECVTIMEOUT", 
  "SEMICOLON", "SENDDRONE", "SCANTYPE", "PCAPFILTER", "VERBOSE", 
  "DOTQUAD", "GLOBAL", "REPEATS", "NOTHING", "cfgfile", "section", 
  "sections", "glines", "plines", "g_statement", "p_statement", "pdata", 
  "flaglist", 0
};
#endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives. */
static const short yyr1[] =
{
       0,    50,    51,    51,    52,    52,    52,    53,    53,    54,
      54,    55,    55,    55,    55,    55,    55,    55,    55,    55,
      55,    55,    55,    55,    55,    55,    55,    55,    55,    55,
      55,    55,    55,    55,    55,    55,    55,    55,    55,    55,
      55,    56,    57,    57,    57,    57,    58,    58,    58
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN. */
static const short yyr2[] =
{
       0,     1,     1,     2,     0,     5,     5,     1,     2,     1,
       2,     0,     4,     4,     6,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,    12,     1,     2,     1,     2,     1,     2,     2
};

/* YYDEFACT[S] -- default rule to reduce with in state S when YYTABLE
   doesn't specify something else to do.  Zero means the default is an
   error. */
static const short yydefact[] =
{
       4,     0,     0,     1,     2,     0,    11,     3,     0,     0,
       9,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     7,
       0,     0,    10,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     8,     0,     6,     0,     0,     0,     0,     0,     0,
       0,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     5,     0,     0,    13,    18,    16,    19,
      20,    21,    24,    47,    48,    25,    15,    28,    23,    31,
      30,    17,    34,    32,    33,    36,    35,    38,    39,    40,
      12,    27,    22,    29,    37,    26,     0,     0,     0,    14,
       0,     0,    44,    42,     0,    45,    43,     0,     0,    41,
       0,     0,     0
};

static const short yydefgoto[] =
{
     150,     3,     4,    38,     9,    39,    10,   144,    82
};

static const short yypact[] =
{
      -5,    -3,     8,    -5,-32768,    -8,    -9,-32768,    26,    32,
      -8,    39,    41,    42,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    -9,
      70,    33,-32768,    71,    73,    43,    44,    72,    74,    37,
      75,    77,    76,    78,     2,    79,    80,    85,    86,    87,
      81,    82,    83,    88,    89,    90,    91,    84,    93,    94,
      92,-32768,    95,-32768,    -7,    96,    97,    98,    99,   100,
     101,-32768,     3,   102,   103,   104,   105,   106,   107,   108,
     109,   110,   111,   112,   113,   114,   115,   116,   117,   118,
     119,   120,   121,-32768,   122,   143,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,   125,   124,   123,-32768,
     126,    -6,-32768,-32768,     6,-32768,-32768,   128,   127,-32768,
     129,   132,-32768
};

static const short yypgoto[] =
{
  -32768,-32768,   133,   130,   156,-32768,-32768,-32768,-32768
};


#define	YYLAST		169


static const short yytable[] =
{
      11,    12,     5,    13,    14,    15,    16,    17,    18,    19,
      20,   113,    21,     6,    22,   105,    23,    24,    25,    26,
      27,    28,    29,    30,    31,   114,    86,    32,   142,   143,
       8,    33,     1,    34,   106,    35,    36,    40,    41,    37,
     145,   146,     2,    43,   115,    44,    45,   147,    87,    46,
      47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    72,    73,    70,    75,    76,    77,    78,
      80,    79,     0,    81,    83,    85,    88,    89,    90,    91,
      92,    74,    97,    98,     0,    96,   101,   102,    99,     0,
       0,     0,     0,     0,     0,   104,     0,     0,     0,     0,
      84,     0,     0,     0,     0,    93,    94,    95,   100,     0,
       0,     0,     0,     0,     0,   136,     0,     0,     0,   151,
     140,   141,   152,   103,   148,     0,     7,   107,   108,   109,
     110,   111,   112,   116,   117,   118,   119,   120,   121,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   137,   138,   139,    42,     0,   149,    71
};

static const short yycheck[] =
{
       9,    10,     5,    12,    13,    14,    15,    16,    17,    18,
      19,     8,    21,     5,    23,    22,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    22,    24,    36,    34,    35,
      38,    40,    37,    42,    41,    44,    45,    11,     6,    48,
      34,    35,    47,     4,    41,     4,     4,    41,    46,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     3,    41,     6,     3,    34,    34,     7,
      43,     7,    -1,     8,     7,     7,     7,     7,     3,     3,
       3,    20,     3,     3,    -1,     7,     3,     3,     7,    -1,
      -1,    -1,    -1,    -1,    -1,    10,    -1,    -1,    -1,    -1,
      34,    -1,    -1,    -1,    -1,    34,    34,    34,    34,    -1,
      -1,    -1,    -1,    -1,    -1,     3,    -1,    -1,    -1,     0,
       7,     5,     0,    41,     6,    -1,     3,    41,    41,    41,
      41,    41,    41,    41,    41,    41,    41,    41,    41,    41,
      41,    41,    41,    41,    41,    41,    41,    41,    41,    41,
      41,    41,    41,    20,    39,    41,    10,    -1,    41,    39
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison/bison.simple"

/* Skeleton output parser for bison,

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser when
   the %semantic_parser declaration is not specified in the grammar.
   It was written by Richard Stallman by simplifying the hairy parser
   used when %semantic_parser is specified.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

#if ! defined (yyoverflow) || defined (YYERROR_VERBOSE)

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || defined (YYERROR_VERBOSE) */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYLTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
# if YYLSP_NEEDED
  YYLTYPE yyls;
# endif
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# if YYLSP_NEEDED
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE) + sizeof (YYLTYPE))	\
      + 2 * YYSTACK_GAP_MAX)
# else
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)
# endif

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif


#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).

   When YYLLOC_DEFAULT is run, CURRENT is set the location of the
   first token.  By default, to implement support for ranges, extend
   its range to the last symbol.  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)       	\
   Current.last_line   = Rhs[N].last_line;	\
   Current.last_column = Rhs[N].last_column;
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#if YYPURE
# if YYLSP_NEEDED
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, &yylloc, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval, &yylloc)
#  endif
# else /* !YYLSP_NEEDED */
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval)
#  endif
# endif /* !YYLSP_NEEDED */
#else /* !YYPURE */
# define YYLEX			yylex ()
#endif /* !YYPURE */


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif

#ifdef YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif
#endif

#line 315 "/usr/share/bison/bison.simple"


/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif

/* YY_DECL_VARIABLES -- depending whether we use a pure parser,
   variables are global, or local to YYPARSE.  */

#define YY_DECL_NON_LSP_VARIABLES			\
/* The lookahead symbol.  */				\
int yychar;						\
							\
/* The semantic value of the lookahead symbol. */	\
YYSTYPE yylval;						\
							\
/* Number of parse errors so far.  */			\
int yynerrs;

#if YYLSP_NEEDED
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES			\
						\
/* Location data for the lookahead symbol.  */	\
YYLTYPE yylloc;
#else
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES
#endif


/* If nonreentrant, generate the variables here. */

#if !YYPURE
YY_DECL_VARIABLES
#endif  /* !YYPURE */

int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  /* If reentrant, generate the variables here. */
#if YYPURE
  YY_DECL_VARIABLES
#endif  /* !YYPURE */

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack. */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;

#if YYLSP_NEEDED
  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
#endif

#if YYLSP_NEEDED
# define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
# define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  YYSIZE_T yystacksize = YYINITDEPTH;


  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
#if YYLSP_NEEDED
  YYLTYPE yyloc;
#endif

  /* When reducing, the number of symbols on the RHS of the reduced
     rule. */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
#if YYLSP_NEEDED
  yylsp = yyls;
#endif
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  */
# if YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
	/* This used to be a conditional around just the two extra args,
	   but that might be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
# else
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);
# endif
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);
# if YYLSP_NEEDED
	YYSTACK_RELOCATE (yyls);
# endif
# undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
#if YYLSP_NEEDED
      yylsp = yyls + yysize - 1;
#endif

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

#if YYDEBUG
     /* We have to keep this `#if YYDEBUG', since we use variables
	which are defined only if `YYDEBUG' is set.  */
      if (yydebug)
	{
	  YYFPRINTF (stderr, "Next token is %d (%s",
		     yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise
	     meaning of a token, for further debugging info.  */
# ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
# endif
	  YYFPRINTF (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to the semantic value of
     the lookahead token.  This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

#if YYLSP_NEEDED
  /* Similarly for the default location.  Let the user run additional
     commands if for instance locations are ranges.  */
  yyloc = yylsp[1-yylen];
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
#endif

#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] > 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif

  switch (yyn) {

case 12:
#line 85 "parse.y"
{ scan_setppsn(yyvsp[-1].inum); ;
    break;}
case 13:
#line 86 "parse.y"
{
		if (MAIN) {
			if (strstr(yyvsp[-1].ptr, "network") != NULL) {
				if (scan_setbroken("N") < 0) { yyerror("no broken network for you!"); }
			}
			else {
				if (scan_setbroken("T") < 0) { yyerror("no broken transport for you!"); }
			}
		}
	;
    break;}
case 14:
#line 96 "parse.y"
{ if (MAIN) { if (scan_setbroken("TN") < 0) yyerror("Cant set broken crc option"); } ;
    break;}
case 15:
#line 97 "parse.y"
{ if (MAIN) { if (!(yyvsp[-1].inum))  { if (scan_setnodefpayload() < 0) yyerror("Cant set nodefault payload"); } } ;
    break;}
case 16:
#line 98 "parse.y"
{ if (MAIN) { if (scan_setreadfile((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set readfile"); } ;
    break;}
case 17:
#line 99 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum)  { if (scan_settryfrags() < 0) yyerror("Cant set try frags"); } } ;
    break;}
case 18:
#line 100 "parse.y"
{ if (MAIN) { if (scan_setsrcp(yyvsp[-1].inum) < 0) yyerror("Cant set source port"); } ;
    break;}
case 19:
#line 101 "parse.y"
{ if (MAIN) { if (scan_setinterface((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set interface"); } ;
    break;}
case 20:
#line 102 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum)  { if (scan_seticmp() < 0) yyerror("Cant set watchicmp"); } } ;
    break;}
case 21:
#line 103 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum)  { if (scan_setlistendrone() < 0) yyerror("Cant set listendrone"); } } ;
    break;}
case 22:
#line 104 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum) { if (scan_setsenddrone() < 0) yyerror("Cant set senddrone"); } } ;
    break;}
case 23:
#line 105 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum) { if (scan_setnopatience() < 0) yyerror("Cant set nopatience"); } } ;
    break;}
case 24:
#line 106 "parse.y"
{ if (MAIN) { if (scan_setscantype((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set scantype"); } ;
    break;}
case 25:
#line 107 "parse.y"
{
		if (MAIN) {
			int flags=0;

			flags=get_tcpflags();
			scan_settcpflags(flags);
		}
	;
    break;}
case 26:
#line 115 "parse.y"
{ if (MAIN) { if (scan_setrepeats((uint8_t )yyvsp[-1].inum) < 0) yyerror("Cant set repeats"); } ;
    break;}
case 27:
#line 116 "parse.y"
{ if (MAIN) { if (scan_setrecvtimeout((int) yyvsp[-1].inum) < 0) yyerror("Cant set recvtimeout"); } ;
    break;}
case 28:
#line 117 "parse.y"
{ if (MAIN) { if (scan_setmoddir((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set moddir"); } ;
    break;}
case 29:
#line 118 "parse.y"
{ if (MAIN) { if (scan_setpcapfilter((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set pcap filter"); } ;
    break;}
case 30:
#line 119 "parse.y"
{ if (MAIN) { if (scan_setsrcaddr((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set srcaddr"); } ;
    break;}
case 31:
#line 120 "parse.y"
{ if (MAIN) { if (scan_setsrcaddr("r") < 0) yyerror("Cant set srcaddr"); } ;
    break;}
case 32:
#line 121 "parse.y"
{ if (MAIN) { if (scan_setttl(yyvsp[-1].inum) < 0) yyerror("Cant set ttl"); } ;
    break;}
case 33:
#line 122 "parse.y"
{ if (MAIN) { if (scan_settos(yyvsp[-1].inum) < 0) yyerror("Cant set tos"); } ;
    break;}
case 34:
#line 123 "parse.y"
{ if (MAIN) { if (!(yyvsp[-1].inum)) { if (scan_setnoshuffle() < 0) yyerror("Cant set noshuffle"); } } ;
    break;}
case 35:
#line 124 "parse.y"
{ if (MAIN) { if (scan_setsavefile((const char *)yyvsp[-1].ptr) < 0) yyerror("Cant set savefile"); } ;
    break;}
case 36:
#line 125 "parse.y"
{ if (MAIN) { if (scan_setfingerprint(yyvsp[-1].inum) < 0) yyerror("Cant set fingerprint"); } ;
    break;}
case 37:
#line 126 "parse.y"
{ if (MAIN) { if (scan_setverbose(yyvsp[-1].inum) < 0) yyerror("Cant set verbosity"); } ;
    break;}
case 38:
#line 127 "parse.y"
{ if (MAIN) { if (scan_setdrones(yyvsp[-1].ptr) < 0) yyerror("Cant set drones"); } ;
    break;}
case 39:
#line 128 "parse.y"
{ if (MAIN) { if (scan_setidlehosts(yyvsp[-1].ptr) < 0) yyerror("Cant set idlehosts"); } ;
    break;}
case 40:
#line 129 "parse.y"
{ if (MAIN) { if (yyvsp[-1].inum) { if (scan_setidlescan() < 0) yyerror("Cant set idlescan"); } } ;
    break;}
case 41:
#line 133 "parse.y"
{
		if (SEND) {
			uint16_t dstport=0;
			buf_t data;
			uint16_t plf=0;

			if (yyvsp[-9].inum > 0xFFFF || yyvsp[-9].inum < 0) {
				yyerror("dest port out of range");
			}
			else {
				dstport=(uint16_t)yyvsp[-9].inum;
				pbuffer_get(&data);
				if (yyvsp[-5].inum) plf=1;
				add_payload(dstport, yyvsp[-7].inum, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plf);
			}

			pbuffer_reset();
		}
	;
    break;}
case 42:
#line 155 "parse.y"
{
		if (SEND) pbuffer_append(&yyvsp[0].buf);
	;
    break;}
case 43:
#line 158 "parse.y"
{
		if (SEND) pbuffer_append(&yyvsp[0].buf);
	;
    break;}
case 44:
#line 161 "parse.y"
{
		if (SEND) {
			buf_t data;

			data.len=strlen(yyvsp[0].ptr);
			data.ptr=(char *)yyvsp[0].ptr;
			pbuffer_append(&data);
		}
	;
    break;}
case 45:
#line 170 "parse.y"
{
		if (SEND) {
			buf_t data;

			data.len=strlen(yyvsp[0].ptr);
			data.ptr=(char *)yyvsp[0].ptr;
			pbuffer_append(&data);
		}
	;
    break;}
case 46:
#line 182 "parse.y"
{
		add_tcpflag(yyvsp[0].inum);
	;
    break;}
case 47:
#line 185 "parse.y"
{
		add_tcpflag(yyvsp[0].inum);
	;
    break;}
case 48:
#line 188 "parse.y"
{
	;
    break;}
}

#line 705 "/usr/share/bison/bison.simple"


  yyvsp -= yylen;
  yyssp -= yylen;
#if YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;
#if YYLSP_NEEDED
  *++yylsp = yyloc;
#endif

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[YYTRANSLATE (yychar)]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[YYTRANSLATE (yychar)]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* defined (YYERROR_VERBOSE) */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*--------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action |
`--------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;
      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;


/*-------------------------------------------------------------------.
| yyerrdefault -- current state does not do anything special for the |
| error token.                                                       |
`-------------------------------------------------------------------*/
yyerrdefault:
#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */

  /* If its default is to accept any token, ok.  Otherwise pop it.  */
  yyn = yydefact[yystate];
  if (yyn)
    goto yydefault;
#endif


/*---------------------------------------------------------------.
| yyerrpop -- pop the current state because it cannot handle the |
| error token                                                    |
`---------------------------------------------------------------*/
yyerrpop:
  if (yyssp == yyss)
    YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#if YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "Error: state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

/*--------------.
| yyerrhandle.  |
`--------------*/
yyerrhandle:
  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

/*---------------------------------------------.
| yyoverflowab -- parser overflow comes here.  |
`---------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}
#line 192 "parse.y"
