"""
MorphShell GUI — Shellcode Behavioral Emulation & Classification Engine
Defensive security research tool. Shellcode never executes natively.
"""

import json
import math
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font, messagebox, ttk

from classifier import FAMILIES, FAMILY_DESCRIPTIONS, load_or_train, predict
from emulator import Emulator
from features import extract, entropy

REPORTS = Path(__file__).with_name("reports")

# ── Palette ───────────────────────────────────────────────────────────────────
BG        = "#0D1117"   # GitHub-dark near-black
PANEL     = "#161B22"   # card background
BORDER    = "#30363D"   # subtle border
ACCENT    = "#58A6FF"   # blue accent
ACCENT2   = "#3FB950"   # green — safe/clean
WARN      = "#D29922"   # amber — warning
DANGER    = "#F85149"   # red — high risk
MUTED     = "#8B949E"   # secondary text
FG        = "#E6EDF3"   # primary text
FG2       = "#C9D1D9"   # secondary text
MONO      = "#A5D6FF"   # monospace highlight
TAG_BG    = "#1C2128"   # tag/badge background

# Family risk colours
FAMILY_COLOURS = {
    "reverse_shell":       DANGER,
    "bind_shell":          DANGER,
    "stager":              WARN,
    "encoder_loop":        WARN,
    "sandbox_evader":      "#DA3633",
    "process_injector":    DANGER,
    "file_dropper":        WARN,
    "privilege_escalator": DANGER,
    "keylogger_stub":      WARN,
    "unknown":             MUTED,
}

SYSCALL_NAMES = {
    1:"exit", 2:"fork", 3:"read", 4:"write", 5:"open", 6:"close",
    11:"execve", 20:"getpid", 33:"access", 41:"dup", 42:"pipe",
    45:"brk", 54:"ioctl", 63:"dup2", 91:"munmap", 102:"socketcall",
    119:"sigreturn", 125:"mprotect", 192:"mmap2",
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def yesno(v: bool) -> str:
    return "Yes" if v else "No"


def risk_label(family: str, conf: float) -> str:
    high = {"reverse_shell","bind_shell","process_injector","privilege_escalator","sandbox_evader"}
    if family in high and conf > 0.6:
        return "HIGH"
    if family == "unknown" or conf < 0.4:
        return "LOW"
    return "MEDIUM"


def risk_colour(level: str) -> str:
    return {
        "HIGH": DANGER,
        "MEDIUM": WARN,
        "LOW": ACCENT2,
    }.get(level, MUTED)


def analyze(path: Path) -> dict:
    shellcode = path.read_bytes()
    trace = Emulator().run(shellcode)
    feats = extract(trace, shellcode)
    model = load_or_train()
    family, confidence, all_scores = predict(model, feats)
    risk = risk_label(family, confidence)
    return {
        "file": path.name,
        "path": str(path),
        "size": len(shellcode),
        "family": family,
        "confidence": confidence,
        "all_scores": all_scores,
        "risk": risk,
        "features": feats,
        "trace": {
            "instructions": trace.instructions,
            "mem_writes": trace.mem_writes,
            "syscalls_attempted": trace.syscalls_attempted,
            "self_modifying": trace.self_modifying,
            "loop_detected": trace.loop_detected,
            "nop_sled": trace.nop_sled,
            "termination_reason": trace.termination_reason,
        },
        "note": "MVP — synthetic training data. Validate findings manually.",
    }


# ── Custom Widgets ────────────────────────────────────────────────────────────
class Card(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1, **kw)


class SectionLabel(tk.Label):
    def __init__(self, parent, text, **kw):
        super().__init__(parent, text=text.upper(), bg=PANEL,
                         fg=MUTED, font=("Consolas", 8, "bold"),
                         anchor="w", **kw)


class ValueLabel(tk.Label):
    def __init__(self, parent, text="—", colour=FG, **kw):
        super().__init__(parent, text=text, bg=PANEL,
                         fg=colour, font=("Consolas", 11, "bold"),
                         anchor="w", **kw)


class Badge(tk.Label):
    def __init__(self, parent, text, colour=ACCENT, **kw):
        super().__init__(parent, text=f" {text} ", bg=colour, fg="#FFFFFF",
                         font=("Consolas", 9, "bold"), padx=4, pady=2, **kw)


class StatBox(tk.Frame):
    """A single stat: label on top, value below."""
    def __init__(self, parent, label, value, colour=FG, **kw):
        super().__init__(parent, bg=TAG_BG,
                         highlightbackground=BORDER, highlightthickness=1, **kw)
        tk.Label(self, text=label, bg=TAG_BG, fg=MUTED,
                 font=("Consolas", 8)).pack(anchor="w", padx=8, pady=(6, 0))
        self.value_lbl = tk.Label(self, text=value, bg=TAG_BG, fg=colour,
                 font=("Consolas", 12, "bold"))
        self.value_lbl.pack(anchor="w", padx=8, pady=(0, 6))

    def set(self, value: str):
        self.value_lbl.config(text=value)


class HBar(tk.Canvas):
    """Horizontal confidence bar."""
    def __init__(self, parent, value: float, colour: str, width=160, height=6, **kw):
        super().__init__(parent, bg=TAG_BG, width=width, height=height,
                         highlightthickness=0, **kw)
        filled = int(width * value)
        if filled > 0:
            self.create_rectangle(0, 0, filled, height, fill=colour, outline="")


# ── Main Application ──────────────────────────────────────────────────────────
class MorphShellApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MorphShell — Shellcode Behavioral Analysis Engine")
        self.configure(bg=BG)
        self.geometry("1200x820")
        self.minsize(960, 700)
        self.resizable(True, True)

        self._result: dict | None = None
        self._history: list[dict] = []

        self._build_ui()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Top bar
        topbar = tk.Frame(self, bg=PANEL, height=52,
                          highlightbackground=BORDER, highlightthickness=1)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="⬡  MorphShell", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 15, "bold")).pack(side="left", padx=20, pady=12)
        tk.Label(topbar, text="Shellcode Behavioral Emulation & Classification",
                 bg=PANEL, fg=MUTED, font=("Consolas", 9)).pack(side="left", pady=12)

        tk.Label(topbar, text="⚠  Defensive Research Only",
                 bg=PANEL, fg=WARN, font=("Consolas", 9, "bold")).pack(side="right", padx=20)

        # Main paned layout
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG,
                               sashwidth=4, sashrelief="flat",
                               handlesize=0)
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        left  = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left,  minsize=340, width=400)
        paned.add(right, minsize=520)

        self._build_left(left)
        self._build_right(right)

    def _build_left(self, parent):
        # Drop/select zone
        drop_card = Card(parent)
        drop_card.pack(fill="x", pady=(0, 8))

        tk.Label(drop_card, text="ANALYZE SHELLCODE", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=16, pady=(14, 0))

        drop_zone = tk.Frame(drop_card, bg=TAG_BG,
                             highlightbackground=BORDER, highlightthickness=1)
        drop_zone.pack(fill="x", padx=12, pady=10)

        self._drop_label = tk.Label(
            drop_zone,
            text="📂  Click to select a .bin file\nor drag & drop here",
            bg=TAG_BG, fg=MUTED, font=("Consolas", 10),
            justify="center", pady=22
        )
        self._drop_label.pack(fill="x")

        drop_zone.bind("<Button-1>", lambda e: self._browse())
        self._drop_label.bind("<Button-1>", lambda e: self._browse())

        self._file_label = tk.Label(drop_card, text="No file selected",
                                    bg=PANEL, fg=MUTED, font=("Consolas", 9))
        self._file_label.pack(anchor="w", padx=16, pady=(0, 4))

        self._btn = tk.Button(
            drop_card, text="▶  Run Analysis",
            bg=ACCENT, fg="#FFFFFF", activebackground="#79C0FF",
            font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=8,
            command=self._run_analysis
        )
        self._btn.pack(fill="x", padx=12, pady=(4, 14))

        # Progress
        self._progress_frame = tk.Frame(drop_card, bg=PANEL)
        self._progress_frame.pack(fill="x", padx=12, pady=(0, 8))
        self._progress_label = tk.Label(self._progress_frame, text="",
                                        bg=PANEL, fg=ACCENT, font=("Consolas", 9))
        self._progress_label.pack(anchor="w")
        self._progress = ttk.Progressbar(self._progress_frame, mode="indeterminate", length=200)

        # Result summary card
        self._summary_card = Card(parent)
        self._summary_card.pack(fill="x", pady=(0, 8))
        tk.Label(self._summary_card, text="CLASSIFICATION RESULT", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=16, pady=(14, 0))

        self._family_label = tk.Label(self._summary_card, text="—",
                                      bg=PANEL, fg=FG,
                                      font=("Consolas", 18, "bold"), anchor="w")
        self._family_label.pack(anchor="w", padx=16, pady=(6, 0))

        self._desc_label = tk.Label(self._summary_card, text="Run analysis to see results",
                                    bg=PANEL, fg=MUTED,
                                    font=("Consolas", 9), anchor="w", wraplength=340, justify="left")
        self._desc_label.pack(anchor="w", padx=16, pady=(2, 8))

        conf_row = tk.Frame(self._summary_card, bg=PANEL)
        conf_row.pack(fill="x", padx=16, pady=(0, 4))
        tk.Label(conf_row, text="CONFIDENCE", bg=PANEL, fg=MUTED, font=("Consolas", 8)).pack(anchor="w")
        self._conf_bar_frame = tk.Frame(conf_row, bg=PANEL)
        self._conf_bar_frame.pack(fill="x", anchor="w")
        self._conf_val_label = tk.Label(conf_row, text="—", bg=PANEL, fg=FG,
                                        font=("Consolas", 10, "bold"))
        self._conf_val_label.pack(anchor="w", pady=(2, 0))

        self._risk_badge_frame = tk.Frame(self._summary_card, bg=PANEL)
        self._risk_badge_frame.pack(anchor="w", padx=16, pady=(4, 14))

        # Quick stats
        stats_card = Card(parent)
        stats_card.pack(fill="x", pady=(0, 8))
        tk.Label(stats_card, text="QUICK STATS", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=16, pady=(14, 8))

        self._stats_grid = tk.Frame(stats_card, bg=PANEL)
        self._stats_grid.pack(fill="x", padx=12, pady=(0, 14))
        self._stat_boxes: dict[str, StatBox] = {}
        stat_defs = [
            ("instructions", "Instructions", FG),
            ("entropy",      "Entropy",      ACCENT),
            ("syscalls",     "Syscalls",     ACCENT2),
            ("mem_writes",   "Mem Writes",   WARN),
            ("self_mod",     "Self-Mod",     DANGER),
            ("termination",  "Exit",         FG2),
        ]
        for i, (key, lbl, col) in enumerate(stat_defs):
            box = StatBox(self._stats_grid, lbl, "—", colour=col)
            box.grid(row=i // 2, column=i % 2, sticky="nsew", padx=3, pady=3)
            self._stat_boxes[key] = box
        self._stats_grid.columnconfigure(0, weight=1)
        self._stats_grid.columnconfigure(1, weight=1)

        # History
        hist_card = Card(parent)
        hist_card.pack(fill="both", expand=True)
        tk.Label(hist_card, text="HISTORY", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=16, pady=(14, 4))

        self._hist_list = tk.Listbox(
            hist_card, bg=TAG_BG, fg=FG2,
            font=("Consolas", 9), relief="flat",
            selectbackground=ACCENT, selectforeground="#FFFFFF",
            activestyle="none", highlightthickness=0, borderwidth=0
        )
        self._hist_list.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._hist_list.bind("<<ListboxSelect>>", self._on_history_select)

    def _build_right(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                         font=("Consolas", 9, "bold"), padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", TAG_BG)],
                  foreground=[("selected", ACCENT)])

        # Tab 1 — Probability Scores
        tab_scores = tk.Frame(nb, bg=BG)
        nb.add(tab_scores, text="  Family Scores  ")
        self._build_scores_tab(tab_scores)

        # Tab 2 — Feature Vector
        tab_feats = tk.Frame(nb, bg=BG)
        nb.add(tab_feats, text="  Feature Vector  ")
        self._build_features_tab(tab_feats)

        # Tab 3 — Instruction Trace
        tab_trace = tk.Frame(nb, bg=BG)
        nb.add(tab_trace, text="  Instruction Trace  ")
        self._build_trace_tab(tab_trace)

        # Tab 4 — Syscalls
        tab_sys = tk.Frame(nb, bg=BG)
        nb.add(tab_sys, text="  Syscalls  ")
        self._build_syscalls_tab(tab_sys)

        # Tab 5 — Raw JSON
        tab_json = tk.Frame(nb, bg=BG)
        nb.add(tab_json, text="  Raw JSON  ")
        self._build_json_tab(tab_json)

    def _build_scores_tab(self, parent):
        tk.Label(parent, text="BEHAVIORAL FAMILY PROBABILITY DISTRIBUTION",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(10, 4))
        self._scores_frame = tk.Frame(parent, bg=BG)
        self._scores_frame.pack(fill="both", expand=True, padx=12, pady=4)

    def _build_features_tab(self, parent):
        tk.Label(parent, text="11-DIMENSIONAL FEATURE VECTOR PASSED TO CLASSIFIER",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(10, 4))
        self._feat_frame = tk.Frame(parent, bg=BG)
        self._feat_frame.pack(fill="both", expand=True, padx=12, pady=4)

    def _build_trace_tab(self, parent):
        ctrl = tk.Frame(parent, bg=BG)
        ctrl.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(ctrl, text="DISASSEMBLY TRACE  (first 500 instructions)",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(side="left")

        self._trace_text = tk.Text(
            parent, bg=TAG_BG, fg=MONO, font=("Consolas", 9),
            relief="flat", wrap="none", state="disabled",
            insertbackground=FG, selectbackground=ACCENT,
            highlightthickness=0, borderwidth=0,
            padx=10, pady=8
        )
        trace_sb_y = ttk.Scrollbar(parent, command=self._trace_text.yview)
        trace_sb_x = ttk.Scrollbar(parent, command=self._trace_text.xview, orient="horizontal")
        self._trace_text.configure(yscrollcommand=trace_sb_y.set, xscrollcommand=trace_sb_x.set)
        trace_sb_y.pack(side="right", fill="y")
        trace_sb_x.pack(side="bottom", fill="x")
        self._trace_text.pack(fill="both", expand=True, padx=12, pady=(0, 8))

    def _build_syscalls_tab(self, parent):
        tk.Label(parent, text="ATTEMPTED SYSCALLS  (int 0x80 / EAX value)",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(10, 4))

        cols = ("idx", "eax", "name", "description")
        self._sys_tree = ttk.Treeview(parent, columns=cols, show="headings", height=20)

        style = ttk.Style()
        style.configure("Treeview", background=TAG_BG, foreground=FG2,
                         fieldbackground=TAG_BG, font=("Consolas", 9),
                         rowheight=24)
        style.configure("Treeview.Heading", background=PANEL, foreground=MUTED,
                         font=("Consolas", 8, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "#FFFFFF")])

        self._sys_tree.heading("idx",         text="#")
        self._sys_tree.heading("eax",         text="EAX (dec)")
        self._sys_tree.heading("name",        text="Syscall Name")
        self._sys_tree.heading("description", text="Common Usage")
        self._sys_tree.column("idx",         width=40,  anchor="center")
        self._sys_tree.column("eax",         width=80,  anchor="center")
        self._sys_tree.column("name",        width=160, anchor="w")
        self._sys_tree.column("description", width=400, anchor="w")

        sys_sb = ttk.Scrollbar(parent, command=self._sys_tree.yview)
        self._sys_tree.configure(yscrollcommand=sys_sb.set)
        sys_sb.pack(side="right", fill="y")
        self._sys_tree.pack(fill="both", expand=True, padx=12, pady=(0, 8))

    def _build_json_tab(self, parent):
        ctrl = tk.Frame(parent, bg=BG)
        ctrl.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(ctrl, text="RAW ANALYSIS JSON",
                 bg=BG, fg=MUTED, font=("Consolas", 8)).pack(side="left")
        tk.Button(ctrl, text="Save JSON", bg=PANEL, fg=ACCENT,
                  font=("Consolas", 8), relief="flat", cursor="hand2",
                  command=self._save_json).pack(side="right")

        self._json_text = tk.Text(
            parent, bg=TAG_BG, fg=MONO, font=("Consolas", 9),
            relief="flat", wrap="none", state="disabled",
            insertbackground=FG, selectbackground=ACCENT,
            highlightthickness=0, borderwidth=0,
            padx=10, pady=8
        )
        json_sb_y = ttk.Scrollbar(parent, command=self._json_text.yview)
        json_sb_x = ttk.Scrollbar(parent, command=self._json_text.xview, orient="horizontal")
        self._json_text.configure(yscrollcommand=json_sb_y.set, xscrollcommand=json_sb_x.set)
        json_sb_y.pack(side="right", fill="y")
        json_sb_x.pack(side="bottom", fill="x")
        self._json_text.pack(fill="both", expand=True, padx=12, pady=(0, 8))

    # ── File Selection ─────────────────────────────────────────────────────────
    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select shellcode binary",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if path:
            self._selected = Path(path)
            self._file_label.config(text=f"  {self._selected.name}  ({self._selected.stat().st_size} bytes)", fg=ACCENT2)
            self._drop_label.config(text=f"📄  {self._selected.name}", fg=FG)

    # ── Analysis ───────────────────────────────────────────────────────────────
    def _run_analysis(self):
        if not hasattr(self, "_selected") or not self._selected:
            messagebox.showwarning("No File", "Please select a .bin shellcode file first.")
            return
        self._btn.config(state="disabled", text="Analyzing…")
        self._progress_label.config(text="Emulating shellcode in sandbox…")
        self._progress.pack(fill="x", pady=4)
        self._progress.start(12)
        threading.Thread(target=self._analysis_thread, daemon=True).start()

    def _analysis_thread(self):
        try:
            result = analyze(self._selected)
            self.after(0, self._on_analysis_done, result)
        except Exception as exc:
            self.after(0, self._on_analysis_error, str(exc))

    def _on_analysis_done(self, result: dict):
        self._progress.stop()
        self._progress.pack_forget()
        self._progress_label.config(text="")
        self._btn.config(state="normal", text="▶  Run Analysis")
        import datetime
        self._result = result
        self._history.insert(0, result)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        conf_pct = f"{result['confidence'] * 100:.0f}%"
        self._hist_list.insert(0, f"  [{ts}]  {result['file']}  →  {result['family']}  ({conf_pct})")
        self._hist_list.selection_clear(0, "end")
        self._hist_list.selection_set(0)
        self._hist_list.activate(0)

        REPORTS.mkdir(exist_ok=True)
        (REPORTS / f"{result['file']}.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        self._render_result(result)

    def _on_analysis_error(self, msg: str):
        self._progress.stop()
        self._progress.pack_forget()
        self._progress_label.config(text="")
        self._btn.config(state="normal", text="▶  Run Analysis")
        messagebox.showerror("Analysis Error", f"Emulation failed:\n{msg}")

    # ── Render ─────────────────────────────────────────────────────────────────
    def _render_result(self, r: dict):
        family = r["family"]
        conf   = r["confidence"]
        risk   = r["risk"]
        feats  = r["features"]
        trace  = r["trace"]
        scores = r["all_scores"]

        fam_col = FAMILY_COLOURS.get(family, MUTED)

        # Summary card
        self._family_label.config(text=family.replace("_", " ").title(), fg=fam_col)
        self._desc_label.config(text=FAMILY_DESCRIPTIONS.get(family, ""))

        for w in self._conf_bar_frame.winfo_children():
            w.destroy()
        HBar(self._conf_bar_frame, conf, fam_col, width=300, height=8).pack(anchor="w", pady=2)
        self._conf_val_label.config(text=f"{conf * 100:.1f}%  confidence", fg=fam_col)

        for w in self._risk_badge_frame.winfo_children():
            w.destroy()
        Badge(self._risk_badge_frame, f"RISK: {risk}", colour=risk_colour(risk)).pack(side="left", padx=(0, 6))
        Badge(self._risk_badge_frame, family.upper(), colour=TAG_BG).pack(side="left")

        # Quick stats
        self._update_stat("instructions", str(feats["instruction_count"]))
        self._update_stat("entropy",      f"{feats['entropy_of_shellcode']:.3f}")
        self._update_stat("syscalls",     str(feats["syscall_count"]))
        self._update_stat("mem_writes",   str(feats["mem_write_count"]))
        self._update_stat("self_mod",     yesno(trace["self_modifying"]))
        self._update_stat("termination",  trace["termination_reason"])

        # Scores tab
        for w in self._scores_frame.winfo_children():
            w.destroy()
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        for i, (fam, sc) in enumerate(sorted_scores):
            col = FAMILY_COLOURS.get(fam, MUTED)
            row = tk.Frame(self._scores_frame, bg=BG)
            row.pack(fill="x", pady=3)

            is_winner = fam == family
            name_lbl = tk.Label(
                row, text=fam.replace("_", " ").title(),
                bg=BG, fg=col if is_winner else FG2,
                font=("Consolas", 10, "bold" if is_winner else "normal"),
                width=22, anchor="w"
            )
            name_lbl.pack(side="left")

            bar_frame = tk.Frame(row, bg=BG)
            bar_frame.pack(side="left", fill="x", expand=True, padx=(0, 8))
            bar_bg = tk.Frame(bar_frame, bg=BORDER, height=10)
            bar_bg.pack(fill="x", pady=4)
            bar_fill = tk.Frame(bar_bg, bg=col, height=10)
            bar_fill.place(x=0, y=0, relwidth=sc, relheight=1.0)

            sc_lbl = tk.Label(row, text=f"{sc * 100:5.1f}%",
                              bg=BG, fg=col if is_winner else MUTED,
                              font=("Consolas", 10))
            sc_lbl.pack(side="left")

            desc = tk.Label(
                row, text=FAMILY_DESCRIPTIONS.get(fam, ""),
                bg=BG, fg=MUTED, font=("Consolas", 8), anchor="w"
            )
            desc.pack(fill="x", padx=(2, 0))

        # Features tab
        for w in self._feat_frame.winfo_children():
            w.destroy()
        feat_names = {
            "instruction_count":    ("Total Instructions Executed",      FG),
            "unique_addresses":     ("Unique Code Addresses",            FG2),
            "mem_write_count":      ("Memory Write Operations",          WARN),
            "self_modifying":       ("Self-Modifying Code Detected",     DANGER),
            "loop_detected":        ("Loop Pattern Detected",            WARN),
            "nop_sled":             ("NOP Sled Detected",                WARN),
            "syscall_count":        ("Total Syscalls Attempted",         ACCENT2),
            "syscall_diversity":    ("Unique Syscall Numbers",           ACCENT2),
            "written_then_executed":("Write-Then-Execute Pattern",       DANGER),
            "entropy_of_shellcode": ("Shannon Entropy (raw bytes)",      ACCENT),
            "termination_code":     ("Termination Code (0=clean,1=TO…)", FG2),
        }
        for key, (desc, col) in feat_names.items():
            val = feats.get(key, "—")
            row = tk.Frame(self._feat_frame, bg=TAG_BG,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=desc, bg=TAG_BG, fg=MUTED,
                     font=("Consolas", 9), width=38, anchor="w").pack(side="left", padx=10, pady=5)
            display = f"{val:.4f}" if isinstance(val, float) else str(val)
            tk.Label(row, text=display, bg=TAG_BG, fg=col,
                     font=("Consolas", 10, "bold"), anchor="e").pack(side="right", padx=10)

        # Trace tab
        self._trace_text.config(state="normal")
        self._trace_text.delete("1.0", "end")
        insns = trace["instructions"][:500]
        for ins in insns:
            line = f"  0x{ins['address']:08X}    {ins['mnemonic']:<10}  {ins['op_str']}\n"
            self._trace_text.insert("end", line)
        if len(trace["instructions"]) > 500:
            self._trace_text.insert("end",
                f"\n  … {len(trace['instructions']) - 500} more instructions truncated …\n")
        self._trace_text.config(state="disabled")

        # Syscalls tab
        for row in self._sys_tree.get_children():
            self._sys_tree.delete(row)
        syscall_descs = {
            1:"Exit process", 2:"Fork child process", 3:"Read from fd",
            4:"Write to fd", 5:"Open file", 6:"Close fd",
            11:"Execute program", 20:"Get process ID", 33:"Check file access",
            41:"Duplicate fd", 42:"Create pipe", 45:"Change data segment",
            54:"I/O control", 63:"Duplicate fd (dup2)", 91:"Unmap memory",
            102:"Socket call (network)", 119:"Signal return", 125:"Memory protect",
            192:"Memory map (mmap2)",
        }
        for i, eax in enumerate(trace["syscalls_attempted"], 1):
            name = SYSCALL_NAMES.get(eax, f"sys_{eax}")
            desc = syscall_descs.get(eax, "Unknown / unlisted syscall")
            self._sys_tree.insert("", "end", values=(i, eax, name, desc))

        # JSON tab
        self._json_text.config(state="normal")
        self._json_text.delete("1.0", "end")
        dump = json.dumps(r, indent=2)
        self._json_text.insert("end", dump)
        self._json_text.config(state="disabled")

    def _update_stat(self, key: str, value: str):
        box = self._stat_boxes.get(key)
        if box:
            box.set(value)

    def _on_history_select(self, _event):
        sel = self._hist_list.curselection()
        if sel and self._history:
            idx = sel[0]
            if idx < len(self._history):
                self._render_result(self._history[idx])

    def _save_json(self):
        if not self._result:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"{self._result['file']}_report.json"
        )
        if path:
            Path(path).write_text(json.dumps(self._result, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = MorphShellApp()
    app.mainloop()
