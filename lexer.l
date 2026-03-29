%{
/*
 * XSS Detection & Auto-Sanitization Compiler
 * Lexer: lexer.l
 *
 * Recognises:
 *   - HTML text and tag boundaries
 *   - JavaScript inside <script>...</script>
 *   - Sources : URLSearchParams, localStorage, sessionStorage, document.cookie
 *   - Taint propagation via .get(), .getItem(), concat (+= / +)
 *   - Sinks   : innerHTML, outerHTML, eval(), document.write(), href
 */

#include "parser.tab.h"
#include <string.h>
#include <stdio.h>

int yylineno_js = 1;
%}

%option noyywrap
%x JS_MODE

%%

<INITIAL>"<script>"        { yylval.str = strdup(yytext); BEGIN(JS_MODE); return SCRIPT_START; }
<INITIAL>"<"               { yylval.str = strdup(yytext); return HTML_CHAR; }
<INITIAL>[^<]+             { yylval.str = strdup(yytext); return HTML_TEXT; }

<JS_MODE>"</script>"       { yylval.str = strdup(yytext); BEGIN(INITIAL); return SCRIPT_END; }

<JS_MODE>\n                { yylineno_js++; }
<JS_MODE>[ \t\r]+          { }

<JS_MODE>"//"[^\n]*        { }
<JS_MODE>"/*"[^*]*\*+([^*/][^*]*\*+)*"/" { }

<JS_MODE>"const"|"let"|"var"         { return VAR_DECL; }
<JS_MODE>"new"                        { return NEW_TOK; }

<JS_MODE>"URLSearchParams"            { return URL_SEARCH_PARAMS; }
<JS_MODE>"window.location.search"     { return WIN_LOC_SEARCH; }
<JS_MODE>"localStorage"               { return LOCAL_STORAGE; }
<JS_MODE>"sessionStorage"             { return SESSION_STORAGE; }
<JS_MODE>"document.cookie"            { return DOC_COOKIE; }

<JS_MODE>"document.getElementById"    { return DOC_GET_ELEM_BY_ID; }
<JS_MODE>"document.write"             { return DOC_WRITE; }
<JS_MODE>"document.writeln"           { return DOC_WRITELN; }

<JS_MODE>".innerHTML"                 { return DOT_INNER_HTML; }
<JS_MODE>".outerHTML"                 { return DOT_OUTER_HTML; }
<JS_MODE>".getItem"                   { return DOT_GET_ITEM; }
<JS_MODE>".getElementById"            { return DOC_GET_ID; }
<JS_MODE>".querySelector"             { return DOC_QUERY_SEL; }
<JS_MODE>".href"                      { return DOT_HREF; }
<JS_MODE>".get"                       { return DOT_GET; }

<JS_MODE>"eval"                       { return EVAL_TOK; }
<JS_MODE>"if"                         { return IF_TOK; }
<JS_MODE>"location.href"              { return LOCATION_HREF; }

<JS_MODE>"{"                          { return LBRACE; }
<JS_MODE>"}"                          { return RBRACE; }

<JS_MODE>"+="                         { return ASSIGN_PLUS; }
<JS_MODE>"="                          { return ASSIGN; }
<JS_MODE>"+"                          { return PLUS; }
<JS_MODE>";"                          { return SEMICOLON; }
<JS_MODE>"("                          { return LPAREN; }
<JS_MODE>")"                          { return RPAREN; }

<JS_MODE>\"([^\"\\]|\\.)*\"           { yylval.str = strdup(yytext); return STRING_LITERAL; }
<JS_MODE>'([^'\\]|\\.)*'              { yylval.str = strdup(yytext); return STRING_LITERAL; }
<JS_MODE>`([^`\\]|\\.)*`             { yylval.str = strdup(yytext); return TEMPLATE_LITERAL; }
<JS_MODE>[a-zA-Z_$][a-zA-Z0-9_$]*    { yylval.str = strdup(yytext); return IDENTIFIER; }

<JS_MODE>.                            { }

%%
