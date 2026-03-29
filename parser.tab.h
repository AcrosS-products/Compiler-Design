/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_PARSER_TAB_H_INCLUDED
# define YY_YY_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    IDENTIFIER = 258,              /* IDENTIFIER  */
    STRING_LITERAL = 259,          /* STRING_LITERAL  */
    TEMPLATE_LITERAL = 260,        /* TEMPLATE_LITERAL  */
    HTML_TEXT = 261,               /* HTML_TEXT  */
    HTML_CHAR = 262,               /* HTML_CHAR  */
    SCRIPT_START = 263,            /* SCRIPT_START  */
    SCRIPT_END = 264,              /* SCRIPT_END  */
    VAR_DECL = 265,                /* VAR_DECL  */
    NEW_TOK = 266,                 /* NEW_TOK  */
    URL_SEARCH_PARAMS = 267,       /* URL_SEARCH_PARAMS  */
    WIN_LOC_SEARCH = 268,          /* WIN_LOC_SEARCH  */
    LOCAL_STORAGE = 269,           /* LOCAL_STORAGE  */
    SESSION_STORAGE = 270,         /* SESSION_STORAGE  */
    DOC_COOKIE = 271,              /* DOC_COOKIE  */
    DOT_GET = 272,                 /* DOT_GET  */
    DOT_GET_ITEM = 273,            /* DOT_GET_ITEM  */
    DOC_GET_ID = 274,              /* DOC_GET_ID  */
    DOC_QUERY_SEL = 275,           /* DOC_QUERY_SEL  */
    DOC_GET_ELEM_BY_ID = 276,      /* DOC_GET_ELEM_BY_ID  */
    DOT_INNER_HTML = 277,          /* DOT_INNER_HTML  */
    DOT_OUTER_HTML = 278,          /* DOT_OUTER_HTML  */
    DOT_HREF = 279,                /* DOT_HREF  */
    EVAL_TOK = 280,                /* EVAL_TOK  */
    DOC_WRITE = 281,               /* DOC_WRITE  */
    DOC_WRITELN = 282,             /* DOC_WRITELN  */
    ASSIGN = 283,                  /* ASSIGN  */
    ASSIGN_PLUS = 284,             /* ASSIGN_PLUS  */
    PLUS = 285,                    /* PLUS  */
    SEMICOLON = 286,               /* SEMICOLON  */
    LPAREN = 287,                  /* LPAREN  */
    RPAREN = 288,                  /* RPAREN  */
    IF_TOK = 289,                  /* IF_TOK  */
    LBRACE = 290,                  /* LBRACE  */
    RBRACE = 291,                  /* RBRACE  */
    LOCATION_HREF = 292            /* LOCATION_HREF  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 99 "parser.y"
 char* str; 

#line 104 "parser.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_PARSER_TAB_H_INCLUDED  */
