%{
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <cstring>

using namespace std;

// --- GLOBAL SECURITY STRUCTURES ---
map<string, int> risk_table;    // 0=Safe, 1=Propagated, 2=Direct Input
int current_expr_risk = 0;
vector<string> audit_log;       // Persistent history for Week 8 Feature

// External function prototypes
extern int yylex();
void yyerror(const char *s);

// Helper to log events to the final report
void log_event(string msg) {
    audit_log.push_back(msg);
    cout << "[AUDIT] " << msg << endl;
}

// AI-Assisted Heuristic Fix Suggestion
void suggest_fix(string var_name, int risk) {
    cout << "\n--------------------------------------------------" << endl;
    cout << "[AI SECURITY ASSISTANT - REMEDIATION ADVICE]" << endl;
    cout << "Vulnerability: Cross-Site Scripting (XSS)" << endl;
    cout << "Severity: " << (risk == 2 ? "CRITICAL" : "HIGH") << endl;
    cout << "Root Cause: Variable '" << var_name << "' contains unvalidated web input." << endl;
    cout << "Recommended Action: Apply context-aware encoding using: sanitize(" << var_name << ");" << endl;
    cout << "--------------------------------------------------\n" << endl;
}
%}

// --- BISON CONFIGURATION ---
%union {
    char* str;
}

%token <str> IDENTIFIER
%token STRING_TYPE INPUT_FUNC RENDER_FUNC SANITIZE_FUNC ASSIGN SEMICOLON LPAREN RPAREN

%%

// --- GRAMMAR RULES ---

program:
    statements {
        // WEEK 8 EXTERNAL FEATURE: Final Audit Report Summary
        cout << "\n==========================================" << endl;
        cout << "   FINAL COMPILATION SECURITY REPORT      " << endl;
        cout << "==========================================" << endl;
        if(audit_log.empty()) {
            cout << "No security events recorded." << endl;
        } else {
            for(size_t i = 0; i < audit_log.size(); ++i) {
                cout << i+1 << ". " << audit_log[i] << endl;
            }
        }
        cout << "==========================================\n" << endl;
    }
    ;

statements:
    statement
    | statements statement
    ;

statement:
    declaration
    | assignment
    | sink_call
    ;

declaration:
    STRING_TYPE IDENTIFIER ASSIGN expression SEMICOLON {
        risk_table[$2] = current_expr_risk;
        if(current_expr_risk > 0) 
            log_event("Variable '" + string($2) + "' initialized with Risk Level " + to_string(current_expr_risk));
        else
            log_event("Variable '" + string($2) + "' initialized as SAFE.");
        current_expr_risk = 0;
    }
    ;

assignment:
    IDENTIFIER ASSIGN expression SEMICOLON {
        risk_table[$1] = current_expr_risk;
        if(current_expr_risk > 0)
            log_event("Taint spread to '" + string($1) + "' (Risk Level: " + to_string(current_expr_risk) + ")");
        else
            log_event("Variable '" + string($1) + "' reset to CLEAN.");
        current_expr_risk = 0;
    }
    ;

expression:
    INPUT_FUNC LPAREN RPAREN { 
        current_expr_risk = 2; // Direct input is CRITICAL
    }
    | IDENTIFIER { 
        if (risk_table.count($1) && risk_table[$1] > 0) {
            current_expr_risk = 1; // Propagated data is HIGH
        }
    }
    | SANITIZE_FUNC LPAREN IDENTIFIER RPAREN {
        risk_table[$3] = 0;
        current_expr_risk = 0;
        log_event("Sanitization verified for '" + string($3) + "'.");
    }
    ;

sink_call:
    RENDER_FUNC LPAREN IDENTIFIER RPAREN SEMICOLON {
        if (risk_table.count($3) && risk_table[$3] > 0) {
            log_event("!!! SECURITY VIOLATION !!! Rendered: " + string($3));
            suggest_fix($3, risk_table[$3]); 
        } else {
            log_event("Safe Render: " + string($3));
        }
    }
    ;

%%

// --- C++ FUNCTION DEFINITIONS (CRITICAL FOR LINKER) ---

void yyerror(const char *s) {
    fprintf(stderr, "Syntax Error: %s\n", s);
}

int main() {
    cout << "--- AI-Assisted Security Compiler: Taint Analysis Mode ---" << endl;
    cout << "Targeting: XSS Vulnerability Detection\n" << endl;
    yyparse();
    return 0;
}