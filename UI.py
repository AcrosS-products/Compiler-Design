"""
XSS-GUARD ENTERPRISE v4.1 - Windows compatible
Synchronized with lexer.l / parser.y compiler backend.

Setup (Windows):
  1. Install WinFlex-Bison: https://github.com/lexxmark/winflexbison/releases
  2. Install MinGW (GCC for Windows): https://www.mingw-w64.org/
  3. Make sure win_flex.exe, win_bison.exe, gcc.exe are all in your PATH
  4. Put all files (lexer.l, parser.y, Makefile) in the SAME folder as this script
  5. pip install customtkinter
  6. Run this script and click "BUILD COMPILER" first, then "RUN ANALYSIS"
"""

import customtkinter as ctk
import subprocess
import os
import threading
import sys
from datetime import datetime
from tkinter import filedialog, messagebox

# ---------------------------------------------------------------------------
# Resolve compiler path relative to this script's directory
# ---------------------------------------------------------------------------
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
EXE_NAME = "xss_analyzer.exe"
COMPILER_PATH = os.path.join(SCRIPT_DIR, EXE_NAME)

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
C = {
    "bg":      "#0d0f14",
    "panel":   "#13161f",
    "surface": "#1a1d28",
    "border":  "#252836",
    "green":   "#00e5a0",
    "blue":    "#3b8eea",
    "amber":   "#f5a623",
    "red":     "#ff4d6d",
    "warning": "#ffd166",
    "info":    "#70c1b3",
    "muted":   "#5a5f73",
    "text":    "#e2e6f0",
    "dimtext": "#8890a4",
}

def score_to_grade(score: int):
    if score >= 90: return "A", C["green"]
    if score >= 75: return "B", "#84d46e"
    if score >= 60: return "C", C["amber"]
    if score >= 40: return "D", "#f07048"
    return "F", C["red"]

# ---------------------------------------------------------------------------
# TaggedTextbox — colour-coded audit log lines
# ---------------------------------------------------------------------------
class TaggedTextbox(ctk.CTkTextbox):
    def setup_tags(self):
        w = self._textbox
        w.tag_configure("critical", foreground=C["red"])
        w.tag_configure("warning",  foreground=C["warning"])
        w.tag_configure("info",     foreground=C["info"])
        w.tag_configure("summary",  foreground=C["green"])
        w.tag_configure("muted",    foreground=C["muted"])
        w.tag_configure("build_ok", foreground=C["green"])
        w.tag_configure("build_err",foreground=C["red"])
        w.tag_configure("normal",   foreground=C["text"])

    def insert_tagged(self, text: str, tag: str = "normal"):
        start = self._textbox.index("end-1c")
        self._textbox.insert("end", text)
        end   = self._textbox.index("end-1c")
        self._textbox.tag_add(tag, start, end)

# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
class XSSGuard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("XSS-GUARD ENTERPRISE v4.1")
        self.geometry("1220x860")
        self.minsize(900, 650)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=C["bg"])
        self._build_ui()
        self._check_compiler_exists()
        self._seed_placeholder()

    # =================================================================
    # UI construction
    # =================================================================
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self._build_header()
        self._build_toolbar()
        self._build_editors()
        self._build_audit()
        self._build_statusbar()

    # --- header -------------------------------------------------------
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C["panel"],
                           border_color=C["border"], border_width=1,
                           corner_radius=0, height=64)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)
        hdr.grid_propagate(False)

        ctk.CTkLabel(hdr, text=" XSS-GUARD ",
                     font=ctk.CTkFont("Courier", 13, "bold"),
                     fg_color=C["green"], text_color="#0d0f14",
                     corner_radius=4).grid(row=0, column=0, padx=16, pady=14, sticky="w")

        ctk.CTkLabel(hdr, text="Enterprise Security Compiler  |  v4.1",
                     font=ctk.CTkFont("Courier", 13),
                     text_color=C["dimtext"]).grid(row=0, column=1, padx=4, sticky="w")

        self.grade_badge = ctk.CTkLabel(
            hdr, text="  --  ",
            font=ctk.CTkFont("Courier", 26, "bold"),
            fg_color=C["surface"], text_color=C["muted"],
            corner_radius=6, width=90)
        self.grade_badge.grid(row=0, column=2, padx=6, pady=10)

        self.score_lbl = ctk.CTkLabel(
            hdr, text="Score\n--",
            font=ctk.CTkFont("Courier", 11),
            text_color=C["muted"], justify="center")
        self.score_lbl.grid(row=0, column=3, padx=(0, 16))

    # --- toolbar ------------------------------------------------------
    def _build_toolbar(self):
        bar = ctk.CTkFrame(self, fg_color=C["surface"],
                           border_color=C["border"], border_width=1,
                           corner_radius=0, height=50)
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_columnconfigure(5, weight=1)
        bar.grid_propagate(False)

        # Build compiler button
        self.btn_build = ctk.CTkButton(
            bar, text="⚙  BUILD COMPILER",
            font=ctk.CTkFont("Courier", 11, "bold"),
            fg_color=C["amber"], hover_color="#d4891e",
            text_color="#0d0f14", corner_radius=4,
            height=34, width=160,
            command=self._start_build)
        self.btn_build.grid(row=0, column=0, padx=12, pady=8)

        # Separator
        ctk.CTkLabel(bar, text="|", text_color=C["border"],
                     font=ctk.CTkFont("Courier", 18)).grid(row=0, column=1, padx=4)

        # Analyse button
        self.btn_run = ctk.CTkButton(
            bar, text="▶  RUN ANALYSIS",
            font=ctk.CTkFont("Courier", 12, "bold"),
            fg_color=C["green"], hover_color="#00b882",
            text_color="#0d0f14", corner_radius=4,
            height=34, width=160,
            command=self._start_analysis)
        self.btn_run.grid(row=0, column=2, padx=4, pady=8)

        self.btn_load = ctk.CTkButton(
            bar, text="↑  LOAD FILE",
            font=ctk.CTkFont("Courier", 11),
            fg_color=C["panel"], hover_color=C["border"],
            border_color=C["border"], border_width=1,
            text_color=C["dimtext"], corner_radius=4,
            height=34, width=120,
            command=self._load_file)
        self.btn_load.grid(row=0, column=3, padx=4, pady=8)

        self.btn_clear = ctk.CTkButton(
            bar, text="✕  CLEAR",
            font=ctk.CTkFont("Courier", 11),
            fg_color=C["panel"], hover_color=C["border"],
            border_color=C["border"], border_width=1,
            text_color=C["dimtext"], corner_radius=4,
            height=34, width=100,
            command=self._clear_all)
        self.btn_clear.grid(row=0, column=4, padx=4, pady=8)

        self.stats_lbl = ctk.CTkLabel(
            bar, text="",
            font=ctk.CTkFont("Courier", 11),
            text_color=C["muted"])
        self.stats_lbl.grid(row=0, column=5, padx=16, sticky="e")

        self.spin_lbl = ctk.CTkLabel(
            bar, text="idle",
            font=ctk.CTkFont("Courier", 10),
            text_color=C["muted"])
        self.spin_lbl.grid(row=0, column=6, padx=12)

    # --- editors ------------------------------------------------------
    def _build_editors(self):
        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.grid(row=2, column=0, sticky="nsew", padx=12, pady=(8, 4))
        pane.grid_columnconfigure((0, 1), weight=1)
        pane.grid_rowconfigure(1, weight=1)

        for col, (label, sub, color) in enumerate([
            ("SOURCE",   "paste or load HTML here", C["dimtext"]),
            ("HARDENED", "auto-sanitized output",   C["blue"]),
        ]):
            hdr = ctk.CTkFrame(pane, fg_color=C["surface"],
                               border_color=C["border"], border_width=1,
                               corner_radius=6, height=30)
            hdr.grid(row=0, column=col,
                     padx=(0, 4) if col == 0 else (4, 0),
                     pady=(0, 2), sticky="ew")
            hdr.grid_propagate(False)
            ctk.CTkLabel(hdr, text=f"  {label}",
                         font=ctk.CTkFont("Courier", 11, "bold"),
                         text_color=color).pack(side="left")
            ctk.CTkLabel(hdr, text=f" — {sub}",
                         font=ctk.CTkFont("Courier", 10),
                         text_color=C["muted"]).pack(side="left")

        self.txt_src = ctk.CTkTextbox(
            pane, font=ctk.CTkFont("Courier", 12),
            fg_color=C["panel"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"], corner_radius=6)
        self.txt_src.grid(row=1, column=0, padx=(0, 4), sticky="nsew")

        self.txt_out = ctk.CTkTextbox(
            pane, font=ctk.CTkFont("Courier", 12),
            fg_color=C["panel"], text_color=C["blue"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"], corner_radius=6,
            state="disabled")
        self.txt_out.grid(row=1, column=1, padx=(4, 0), sticky="nsew")

    # --- audit log ----------------------------------------------------
    def _build_audit(self):
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 4))
        wrap.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(wrap, fg_color=C["surface"],
                           border_color=C["border"], border_width=1,
                           corner_radius=6, height=26)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        hdr.grid_propagate(False)
        ctk.CTkLabel(hdr, text="  AUDIT LOG  —  build output & vulnerability report",
                     font=ctk.CTkFont("Courier", 10, "bold"),
                     text_color=C["muted"]).pack(side="left")

        self.txt_audit = TaggedTextbox(
            wrap, height=150,
            font=ctk.CTkFont("Courier", 11),
            fg_color=C["panel"], text_color=C["text"],
            border_color=C["border"], border_width=1,
            scrollbar_button_color=C["border"], corner_radius=6,
            state="disabled")
        self.txt_audit.grid(row=1, column=0, sticky="ew")
        self.txt_audit.setup_tags()

    # --- status bar ---------------------------------------------------
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=C["panel"],
                           border_color=C["border"], border_width=1,
                           corner_radius=0, height=24)
        bar.grid(row=4, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(0, weight=1)

        self.sbar_lbl = ctk.CTkLabel(
            bar, text=f"  compiler: {COMPILER_PATH}",
            font=ctk.CTkFont("Courier", 9),
            text_color=C["muted"])
        self.sbar_lbl.grid(row=0, column=0, sticky="w")

        self.compiler_status_dot = ctk.CTkLabel(
            bar, text="● NOT BUILT",
            font=ctk.CTkFont("Courier", 9),
            text_color=C["red"])
        self.compiler_status_dot.grid(row=0, column=1, padx=12, sticky="e")

    # =================================================================
    # Compiler existence check
    # =================================================================
    def _check_compiler_exists(self):
        if os.path.exists(COMPILER_PATH):
            self.compiler_status_dot.configure(
                text="● READY", text_color=C["green"])
            self._log_audit("Compiler found: " + COMPILER_PATH + "\n", "build_ok")
        else:
            self.compiler_status_dot.configure(
                text="● NOT BUILT", text_color=C["red"])
            self._show_setup_guide()

    def _show_setup_guide(self):
        guide = (
            "Compiler not found. Follow these steps to build it:\n"
            "\n"
            "  STEP 1 — Install WinFlex-Bison (Windows flex + bison):\n"
            "           https://github.com/lexxmark/winflexbison/releases\n"
            "           Extract and add the folder to your system PATH.\n"
            "\n"
            "  STEP 2 — Install MinGW-w64 (GCC for Windows):\n"
            "           https://www.mingw-w64.org/  or via MSYS2:\n"
            "           https://www.msys2.org/  then: pacman -S mingw-w64-x86_64-gcc\n"
            "           Add MinGW bin folder (e.g. C:\\msys64\\mingw64\\bin) to PATH.\n"
            "\n"
            "  STEP 3 — Place all files in ONE folder:\n"
            "           lexer.l   parser.y   Makefile   xss_guard_ui.py\n"
            "\n"
            "  STEP 4 — Click  [ BUILD COMPILER ]  button above.\n"
            "           This runs: win_flex -> win_bison -> gcc automatically.\n"
            "\n"
            "  STEP 5 — Click  [ RUN ANALYSIS ]  and paste your HTML.\n"
        )
        self._log_audit(guide, "warning")

    # =================================================================
    # BUILD COMPILER
    # =================================================================
    def _start_build(self):
        self.btn_build.configure(state="disabled", text="⏳  BUILDING...")
        self._set_spin("building...")
        self._clear_audit()
        threading.Thread(target=self._run_build, daemon=True).start()

    def _run_build(self):
        # Check prerequisites
        missing = []
        for tool in (["win_flex", "--version"] if sys.platform == "win32"
                     else ["flex", "--version"]):
            pass  # checked below

        cmds = (
            [["win_flex",  "--outfile=lex.yy.c",       "lexer.l"],
             ["win_bison", "-d", "parser.y"],
             ["gcc", "-o", EXE_NAME, "lex.yy.c", "parser.tab.c", "-lfl"]]
            if sys.platform == "win32" else
            [["flex",  "lexer.l"],
             ["bison", "-d", "parser.y"],
             ["g++", "-o", EXE_NAME, "lex.yy.c", "parser.tab.c",
              "-lstdc++", "-lfl"]]
        )

        # On Windows, parser.y uses C++ (iostream etc.) — compile as C++
        if sys.platform == "win32":
            cmds[-1] = ["g++", "-o", EXE_NAME,
                        "lex.yy.c", "parser.tab.c", "-lstdc++"]

        log_lines = []
        success   = True

        for cmd in cmds:
            self.after(0, self._log_audit,
                       f"$ {' '.join(cmd)}\n", "muted")
            try:
                result = subprocess.run(
                    cmd,
                    cwd=SCRIPT_DIR,
                    capture_output=True,
                    text=False,  # binary — decode manually, avoids cp1252 crash
                )
                out = result.stdout.decode("utf-8", errors="replace")
                err = result.stderr.decode("utf-8", errors="replace")
                if out.strip():
                    self.after(0, self._log_audit, out + "\n", "normal")
                if result.returncode != 0:
                    success = False
                    self.after(0, self._log_audit,
                               f"FAILED: {err or '(no error output)'}\n",
                               "build_err")
                    break
                else:
                    self.after(0, self._log_audit, "  OK\n", "build_ok")
            except FileNotFoundError:
                success = False
                self.after(0, self._log_audit,
                           f"ERROR: '{cmd[0]}' not found in PATH.\n"
                           "       See setup guide above.\n",
                           "build_err")
                break

        self.after(0, self._on_build_done, success)

    def _on_build_done(self, success: bool):
        if success and os.path.exists(COMPILER_PATH):
            self._log_audit(
                f"\nCompiler built successfully: {COMPILER_PATH}\n", "build_ok")
            self.compiler_status_dot.configure(
                text="● READY", text_color=C["green"])
            self._set_spin("compiler ready")
        else:
            self._log_audit(
                "\nBuild failed. Check the errors above.\n", "build_err")
            self.compiler_status_dot.configure(
                text="● BUILD FAILED", text_color=C["red"])
            self._set_spin("build failed")

        self.btn_build.configure(state="normal", text="⚙  BUILD COMPILER")

    # =================================================================
    # RUN ANALYSIS
    # =================================================================
    def _start_analysis(self):
        if not os.path.exists(COMPILER_PATH):
            messagebox.showerror(
                "Compiler not found",
                f"'{COMPILER_PATH}' does not exist.\n\n"
                "Click  BUILD COMPILER  first.")
            return
        self.btn_run.configure(state="disabled", text="⏳  ANALYZING...")
        self._set_spin("running analysis...")
        threading.Thread(target=self._run_compiler, daemon=True).start()

    def _run_compiler(self):
        code = self.txt_src.get("0.0", "end").strip()
        if not code:
            self.after(0, self._on_error, "Source editor is empty.")
            return
        try:
            proc = subprocess.Popen(
                [COMPILER_PATH],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Binary mode — avoids cp1252 UnicodeDecodeError on Windows
                text=False,
                cwd=SCRIPT_DIR,
            )
            raw_out, raw_err = proc.communicate(
                input=code.encode("utf-8"), timeout=15)
        except FileNotFoundError:
            self.after(0, self._on_error,
                       f"Compiler not found at:\n{COMPILER_PATH}\n\n"
                       "Click BUILD COMPILER first.")
            return
        except subprocess.TimeoutExpired:
            self.after(0, self._on_error, "Compiler timed out (>15 s).")
            return

        # Decode safely — replace any un-decodable bytes instead of crashing
        stdout = raw_out.decode("utf-8", errors="replace")
        if not stdout.strip() and raw_err:
            # Compiler wrote to stderr only (e.g. parse error with no output)
            stderr_txt = raw_err.decode("utf-8", errors="replace")
            self.after(0, self._on_error,
                       f"Compiler produced no output.\nStderr:\n{stderr_txt}")
            return

        self.after(0, self._on_result, stdout)

    def _on_result(self, stdout: str):
        score     = 100
        criticals = 0
        warnings  = 0
        infos     = 0
        entries   = []   # (text, tag)

        for raw in stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("SCORE:"):
                try:   score = int(line.split(":")[1].strip())
                except ValueError: pass
            elif line.startswith("[CRITICAL]"):
                criticals += 1
                entries.append((line, "critical"))
            elif line.startswith("[WARNING]"):
                warnings += 1
                entries.append((line, "warning"))
            elif line.startswith("[INFO]"):
                infos += 1
                entries.append((line, "info"))
            elif line.startswith("[SUMMARY]"):
                entries.append((line, "summary"))
            else:
                entries.append((line, "muted"))

        # Grade + score
        grade, color = score_to_grade(score)
        self.grade_badge.configure(text=f"  {grade}  ",
                                   text_color=color, fg_color=C["surface"])
        self.score_lbl.configure(text=f"Score\n{score}%", text_color=color)

        # Stats
        self.stats_lbl.configure(
            text=f"  ✖ {criticals} critical   ⚠ {warnings} warning   ℹ {infos} info")

        # Audit log
        self._clear_audit()
        if entries:
            for text, tag in entries:
                self._log_audit(text + "\n", tag)
        else:
            self._log_audit("No issues detected — source appears clean.\n", "info")

        # Hardened output
        out_path = os.path.join(SCRIPT_DIR, "hardened_output.html")
        self.txt_out.configure(state="normal")
        self.txt_out.delete("0.0", "end")
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                self.txt_out.insert("0.0", f.read())
        else:
            self.txt_out.insert("0.0",
                "hardened_output.html not found.\n"
                "The compiler may have encountered a parse error.")
        self.txt_out.configure(state="disabled")

        self.btn_run.configure(state="normal", text="▶  RUN ANALYSIS")
        self._set_spin(f"done — {datetime.now().strftime('%H:%M:%S')}")
        self.sbar_lbl.configure(
            text=f"  {COMPILER_PATH}   |   "
                 f"last run {datetime.now().strftime('%H:%M:%S')}  "
                 f"score={score}  criticals={criticals}")

    def _on_error(self, msg: str):
        self._clear_audit()
        self._log_audit(f"ERROR: {msg}\n", "build_err")
        self.btn_run.configure(state="normal", text="▶  RUN ANALYSIS")
        self._set_spin("error")

    # =================================================================
    # Helpers
    # =================================================================
    def _log_audit(self, text: str, tag: str = "normal"):
        self.txt_audit.configure(state="normal")
        self.txt_audit.insert_tagged(text, tag)
        self.txt_audit.configure(state="disabled")
        self.txt_audit._textbox.see("end")

    def _clear_audit(self):
        self.txt_audit.configure(state="normal")
        self.txt_audit.delete("0.0", "end")
        self.txt_audit.configure(state="disabled")

    def _set_spin(self, msg: str):
        self.spin_lbl.configure(text=msg)

    def _clear_all(self):
        self.txt_src.delete("0.0", "end")
        self.txt_out.configure(state="normal")
        self.txt_out.delete("0.0", "end")
        self.txt_out.configure(state="disabled")
        self._clear_audit()
        self.grade_badge.configure(text="  --  ", text_color=C["muted"])
        self.score_lbl.configure(text="Score\n--", text_color=C["muted"])
        self.stats_lbl.configure(text="")
        self._set_spin("cleared")

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Load HTML file",
            filetypes=[("HTML files", "*.html *.htm"), ("All files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                self.txt_src.delete("0.0", "end")
                self.txt_src.insert("0.0", f.read())
            self._set_spin(f"loaded: {os.path.basename(path)}")

    def _seed_placeholder(self):
        self.txt_src.insert("0.0", """\
<!DOCTYPE html>
<html>
<head><title>XSS Test</title></head>
<body>
  <div id="output"></div>
  <div id="preview"></div>
<script>
  const params = new URLSearchParams(window.location.search);
  const userInput = params.get("name");
  document.getElementById("output").innerHTML = userInput;
  eval(userInput);
</script>
</body>
</html>""")

if __name__ == "__main__":
    app = XSSGuard()
    app.mainloop()
