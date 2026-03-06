%{
#include "parser.tab.h"
#include <string.h>
%}

%%
"string"                { return STRING_TYPE; }
"input"                 { return INPUT_FUNC; }
"render"                { return RENDER_FUNC; }
"sanitize"              { return SANITIZE_FUNC; }
"="                     { return ASSIGN; }
";"                     { return SEMICOLON; }
"("                     { return LPAREN; }
")"                     { return RPAREN; }
[a-zA-Z_][a-zA-Z0-9_]* { yylval.str = strdup(yytext); return IDENTIFIER; }
[ \t\n]                 { /* ignore whitespace */ }
.                       { return yytext[0]; }
%%

int yywrap() { return 1; }