%{
/*
 * XSS Detection & Auto-Sanitization Compiler
 * Parser: parser.y
 *
 * Risk levels
 *   0 = clean / untainted
 *   1 = source  (URLSearchParams, localStorage, sessionStorage, document.cookie)
 *   2 = tainted (propagated from a level-1 variable via .get / .getItem / concat)
 *   3 = confirmed sink hit with tainted data → auto-remediated
 *
 * Scoring
 *   Start at 100.
 *   Each CRITICAL (tainted → dangerous sink)  costs 40 points.
 *   Each WARNING  (tainted concat or template) costs 10 points.
 *   Floor at 0.
 *
 * Output
 *   hardened_output.html   – rewritten source with safe API substitutions
 *   Stdout lines parsed by the Python UI:
 *     SCORE:<n>
 *     [CRITICAL] ...
 *     [WARNING]  ...
 *     [INFO]     ...
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
using namespace std;

/* ── Taint bookkeeping ─────────────────────────────────────────────────── */
map<string, int>    risk_map;      // variable name → risk level (0-2)
map<string, string> origin_map;    // variable name → human description of origin

/* ── Output buffers ────────────────────────────────────────────────────── */
vector<string> full_doc;           // rewritten HTML document lines
vector<string> audit_logs;         // structured audit entries

/* ── Counters ──────────────────────────────────────────────────────────── */
int criticals = 0;
int warnings  = 0;

/* ── Helpers ───────────────────────────────────────────────────────────── */
extern int yylex();
extern int yylineno_js;

void yyerror(const char* s) {
    // Silent: keep reconstruction moving even on partial parses
}

void emit(const string& s) {
    full_doc.push_back(s);
}

void log_critical(const string& msg) {
    criticals++;
    audit_logs.push_back("[CRITICAL] " + msg);
}

void log_warning(const string& msg) {
    warnings++;
    audit_logs.push_back("[WARNING]  " + msg);
}

void log_info(const string& msg) {
    audit_logs.push_back("[INFO]     " + msg);
}

/* Return a safe API replacement string for a known dangerous sink */
string safe_sink(const string& sink_prop, const string& target_id,
                 const string& var_name, const string& elem_expr) {
    if (sink_prop == ".innerHTML" || sink_prop == ".outerHTML") {
        // Prefer textContent for simple display; recommend DOMPurify comment for rich HTML
        return elem_expr + ".textContent = " + var_name
               + "; // AUTO-FIXED: innerHTML → textContent";
    }
    if (sink_prop == ".href") {
        return "/* AUTO-FIXED: unsafe href assignment blocked for tainted var '"
               + var_name + "' */";
    }
    if (sink_prop == "eval") {
        return "/* AUTO-FIXED: eval() blocked for tainted var '"
               + var_name + "' */";
    }
    if (sink_prop == "document.write" || sink_prop == "document.writeln") {
        return "/* AUTO-FIXED: " + sink_prop + "() blocked for tainted var '"
               + var_name + "' */";
    }
    return "/* AUTO-FIXED: unsafe sink blocked */";
}

%}

/* ── Token union ───────────────────────────────────────────────────────── */
%union { char* str; }

%token <str> IDENTIFIER STRING_LITERAL TEMPLATE_LITERAL
%token <str> HTML_TEXT HTML_CHAR SCRIPT_START SCRIPT_END

/* Keywords / API tokens (no semantic value needed) */
%token VAR_DECL NEW_TOK
%token URL_SEARCH_PARAMS WIN_LOC_SEARCH
%token LOCAL_STORAGE SESSION_STORAGE DOC_COOKIE
%token DOT_GET DOT_GET_ITEM
%token DOC_GET_ID DOC_QUERY_SEL
%token DOC_GET_ELEM_BY_ID
%token DOT_INNER_HTML DOT_OUTER_HTML DOT_HREF
%token EVAL_TOK DOC_WRITE DOC_WRITELN
%token ASSIGN ASSIGN_PLUS PLUS SEMICOLON LPAREN RPAREN
%token IF_TOK LBRACE RBRACE
%token LOCATION_HREF

%%

/* ═══════════════════════════════════════════════════════════════════════ */
program
    : elements {
        /* ── Write hardened output file ──────────────────────────────── */
        ofstream out("hardened_output.html");
        for (const auto& line : full_doc)
            out << line;
        out.close();

        /* ── Compute score ───────────────────────────────────────────── */
        int score = 100 - (criticals * 40) - (warnings * 10);
        if (score < 0) score = 0;

        /* ── Emit for Python UI ──────────────────────────────────────── */
        cout << "SCORE:" << score << endl;
        for (const auto& entry : audit_logs)
            cout << entry << endl;

        /* ── Summary ─────────────────────────────────────────────────── */
        cout << "[SUMMARY]  Criticals=" << criticals
             << " Warnings=" << warnings
             << " Score=" << score << endl;
    }
    ;

elements
    : /* empty */
    | elements element
    ;

element
    : HTML_TEXT    { emit(string($1)); }
    | HTML_CHAR    { emit(string($1)); }
    | SCRIPT_START { emit("\n<script>\n"); }
    | SCRIPT_END   { emit("\n</script>\n"); }
    | js_statement
    ;

/* ═══════════════════════════════════════════════════════════════════════ */
js_statement

    /* ── RULE 1a: URLSearchParams source ─────────────────────────────── */
    : VAR_DECL IDENTIFIER ASSIGN NEW_TOK URL_SEARCH_PARAMS LPAREN WIN_LOC_SEARCH RPAREN SEMICOLON {
        string name($2);
        risk_map[name]   = 1;
        origin_map[name] = "URLSearchParams(window.location.search)";
        log_info("Source identified: '" + name + "' ← URLSearchParams");
        emit("  const " + name + " = new URLSearchParams(window.location.search);\n");
    }

    /* ── RULE 1b: localStorage source ────────────────────────────────── */
    | VAR_DECL IDENTIFIER ASSIGN LOCAL_STORAGE SEMICOLON {
        string name($2);
        risk_map[name]   = 1;
        origin_map[name] = "localStorage";
        log_info("Source identified: '" + name + "' ← localStorage");
        emit("  const " + name + " = localStorage;\n");
    }

    /* ── RULE 1c: sessionStorage source ──────────────────────────────── */
    | VAR_DECL IDENTIFIER ASSIGN SESSION_STORAGE SEMICOLON {
        string name($2);
        risk_map[name]   = 1;
        origin_map[name] = "sessionStorage";
        log_info("Source identified: '" + name + "' ← sessionStorage");
        emit("  const " + name + " = sessionStorage;\n");
    }

    /* ── RULE 1d: document.cookie source ─────────────────────────────── */
    | VAR_DECL IDENTIFIER ASSIGN DOC_COOKIE SEMICOLON {
        string name($2);
        risk_map[name]   = 1;
        origin_map[name] = "document.cookie";
        log_warning("Source identified: '" + name
                    + "' ← document.cookie (high sensitivity)");
        emit("  const " + name + " = document.cookie;\n");
    }

    /* ── RULE 2a: Taint propagation via .get() ───────────────────────── */
    | VAR_DECL IDENTIFIER ASSIGN IDENTIFIER DOT_GET LPAREN STRING_LITERAL RPAREN SEMICOLON {
        string dest($2), src($4), key($7);
        if (risk_map[src] >= 1) {
            risk_map[dest]   = 2;
            origin_map[dest] = "'" + src + "'.get(" + key + ")";
            log_info("Taint propagated: '" + dest + "' ← " + origin_map[dest]);
        }
        emit("  const " + dest + " = " + src + ".get(" + key + ");\n");
    }

    /* ── RULE 2b: Taint propagation via .getItem() ───────────────────── */
    | VAR_DECL IDENTIFIER ASSIGN IDENTIFIER DOT_GET_ITEM LPAREN STRING_LITERAL RPAREN SEMICOLON {
        string dest($2), src($4), key($7);
        if (risk_map[src] >= 1) {
            risk_map[dest]   = 2;
            origin_map[dest] = "'" + src + "'.getItem(" + key + ")";
            log_info("Taint propagated: '" + dest + "' ← " + origin_map[dest]);
        }
        emit("  const " + dest + " = " + src + ".getItem(" + key + ");\n");
    }

    /* ── RULE 2c: Taint propagation via string concatenation (=) ─────── */
    | VAR_DECL IDENTIFIER ASSIGN IDENTIFIER PLUS STRING_LITERAL SEMICOLON {
        string dest($2), src($4), suffix($6);
        if (risk_map[src] >= 1) {
            risk_map[dest]   = 2;
            origin_map[dest] = "concat of tainted '" + src + "'";
            log_warning("Taint via concatenation: '" + dest + "' = '" + src + "' + literal");
        }
        emit("  const " + dest + " = " + src + " + " + suffix + ";\n");
    }

    /* ── RULE 2d: Taint propagation via string concatenation (+=) ────── */
    | IDENTIFIER ASSIGN_PLUS IDENTIFIER SEMICOLON {
        string dest($1), src($3);
        if (risk_map[src] >= 1 && risk_map[dest] < 2) {
            risk_map[dest]   = 2;
            origin_map[dest] = "concat-assign from tainted '" + src + "'";
            log_warning("Taint via += assignment: '" + dest + "' now tainted");
        }
        emit("  " + dest + " += " + src + ";\n");
    }

    /* ── RULE 2e: Taint propagation — var-to-var: let b = a ─────────── */
    | VAR_DECL IDENTIFIER ASSIGN IDENTIFIER SEMICOLON {
        string dest($2), src($4);
        if (risk_map[src] >= 1) {
            risk_map[dest]   = risk_map[src];
            origin_map[dest] = "copy of tainted '" + src + "'";
            log_info("Taint copied: '" + dest + "' ← '" + src + "'");
        }
        emit("  const " + dest + " = " + src + ";\n");
    }

    /* ── RULE 2f: Plain identifier reassign — a = b ──────────────────── */
    | IDENTIFIER ASSIGN IDENTIFIER SEMICOLON {
        string dest($1), src($3);
        if (risk_map[src] >= 1 && risk_map[dest] < risk_map[src]) {
            risk_map[dest]   = risk_map[src];
            origin_map[dest] = "reassign from tainted '" + src + "'";
            log_info("Taint propagated via reassign: '" + dest + "' ← '" + src + "'");
        }
        emit("  " + dest + " = " + src + ";\n");
    }

    /* ── RULE 2g: if-block passthrough (single-stmt body) ────────────── */
    | IF_TOK LPAREN IDENTIFIER RPAREN LBRACE js_statement RBRACE {
        emit("");
    }

    /* ── RULE 3a: Sink — .innerHTML ──────────────────────────────────── */
    | DOC_GET_ELEM_BY_ID LPAREN STRING_LITERAL RPAREN DOT_INNER_HTML ASSIGN IDENTIFIER SEMICOLON {
        string elem_id($3), var($7);
        string elem_expr = "document.getElementById(" + elem_id + ")";
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK .innerHTML: tainted var '" + var
                         + "' (origin: " + origin_map[var] + ") → elem #"
                         + elem_id);
            emit("  " + safe_sink(".innerHTML", elem_id, var, elem_expr) + "\n");
        } else {
            emit("  " + elem_expr + ".innerHTML = " + var + ";\n");
        }
    }

    /* ── RULE 3b: Sink — .outerHTML ──────────────────────────────────── */
    | DOC_GET_ELEM_BY_ID LPAREN STRING_LITERAL RPAREN DOT_OUTER_HTML ASSIGN IDENTIFIER SEMICOLON {
        string elem_id($3), var($7);
        string elem_expr = "document.getElementById(" + elem_id + ")";
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK .outerHTML: tainted var '" + var
                         + "' → elem #" + elem_id);
            emit("  " + safe_sink(".outerHTML", elem_id, var, elem_expr) + "\n");
        } else {
            emit("  " + elem_expr + ".outerHTML = " + var + ";\n");
        }
    }

    /* ── RULE 3c: Sink — eval() ──────────────────────────────────────── */
    | EVAL_TOK LPAREN IDENTIFIER RPAREN SEMICOLON {
        string var($3);
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK eval(): tainted var '" + var
                         + "' (origin: " + origin_map[var] + ")");
            emit("  " + safe_sink("eval", "", var, "") + "\n");
        } else {
            emit("  eval(" + var + ");\n");
        }
    }

    /* ── RULE 3d: Sink — document.write() ───────────────────────────── */
    | DOC_WRITE LPAREN IDENTIFIER RPAREN SEMICOLON {
        string var($3);
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK document.write(): tainted var '" + var + "'");
            emit("  " + safe_sink("document.write", "", var, "") + "\n");
        } else {
            emit("  document.write(" + var + ");\n");
        }
    }

    /* ── RULE 3e: Sink — identifier.href assignment ──────────────────── */
    | IDENTIFIER DOT_HREF ASSIGN IDENTIFIER SEMICOLON {
        string target($1), var($4);
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK .href: tainted var '" + var
                         + "' assigned to '" + target + ".href'");
            emit("  " + safe_sink(".href", "", var, target) + "\n");
        } else {
            emit("  " + target + ".href = " + var + ";\n");
        }
    }

    /* ── RULE 3f: Sink — location.href = x (location is a keyword-like) */
    | LOCATION_HREF ASSIGN IDENTIFIER SEMICOLON {
        string var($3);
        if (risk_map[var] >= 2) {
            log_critical("XSS SINK location.href: tainted var '" + var + "'");
            emit("  /* AUTO-FIXED: location.href blocked for tainted var '"
                 + var + "' */\n");
        } else {
            emit("  location.href = " + var + ";\n");
        }
    }

    ;

%%

int main() {
    yyparse();
    return 0;
}
