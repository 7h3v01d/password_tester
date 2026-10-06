# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Password Tester GUI (Tkinter, no third-party packages). Run:  python -m password_tester"""
import math
import re
import threading
import tkinter as tk
import tkinter.font as tkfont
import urllib.error
import webbrowser
from tkinter import filedialog, ttk

from . import __version__, clipboard, data, hibp, wordlists
from .engine import ATTACKS, KIND_LABEL, Analyzer, checklist, crack_time, extend, grade_for, personal_tokens
from .generator import gen_phrase, gen_random
from .report import build_report, write_report

THEMES = {   # dark = Leon's design system; light kept for daylight use
    "dark": dict(bg="#0b0f14", card="#11161d", fg="#c8d3da", muted="#7d8b96", track="#1e2831",
                 hover="#26323d", good="#4be08a", bad="#ff6b6b", warn="#ffb454", tip="#2fd6c3", accent="#2fd6c3"),
    "light": dict(bg="#f4f6f8", card="#ffffff", fg="#1f2937", muted="#6b7280", track="#e5e7eb",
                  hover="#d1d5db", good="#15803d", bad="#b91c1c", warn="#b45309", tip="#1d4ed8", accent="#0f766e"),
}
GRADE_KEYS = ("bad", "warn", "warn", "good", "accent")
KIND_COLOUR = {"dict": "#3b82f6", "personal": "#ef4444", "keyboard": "#f59e0b",
               "sequence": "#f59e0b", "repeat": "#ec4899", "date": "#14b8a6"}
CLIP_SECONDS = 30
SEARCH_DEBOUNCE_MS = 150


def _pick(families, *names):
    return next((n for n in names if n in families), names[-1])


class App(tk.Tk):
    def __init__(self, autoload=True):
        super().__init__()
        self.title(f"Password Tester {__version__}")
        self.geometry("760x980")
        self.minsize(680, 840)
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        fams = set(tkfont.families(self))
        self.ui_font = _pick(fams, "JetBrains Mono", "Segoe UI", "TkDefaultFont")
        self.mono_font = _pick(fams, "JetBrains Mono", "Consolas", "Courier New")

        self.analyzer = Analyzer()
        self.theme = "dark"
        self.words = data.WORDS
        self.result = None
        self.breach = ("", "muted")
        self._last_pw = None
        self._clip_text, self._clip_job, self._clip_seq = None, None, None
        self._winclip = None
        if clipboard.available():
            try:
                self._winclip = clipboard.WinClipboard()
            except OSError:
                self._winclip = None
        self._pending = set()
        self.catalog, self.source, self.shown = [], [], []
        self.mode, self.email_shown = "catalog", ""
        self.sort_col, self.sort_rev = "date", True
        self._view_token, self._fetching, self._search_job = 0, False, None

        self.pw_var = tk.StringVar()
        self.pw_var.trace_add("write", lambda *_: self._on_pw_change())
        self.show_var = tk.BooleanVar(value=False)
        self.show_var.trace_add("write", lambda *_: self._render())
        self.include_pw = tk.BooleanVar(value=False)
        self.status = tk.StringVar()

        self._menu()
        head = ttk.Frame(self)
        head.pack(fill="x", padx=22, pady=(16, 0))
        ttk.Label(head, text="Password Tester", font=(self.ui_font, 18, "bold")).pack(side="left")
        ttk.Button(head, text="Theme", command=self.toggle_theme).pack(side="right")
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=22, pady=10)
        self._build_tester()
        self._build_gen()
        self._build_personal()
        self._build_explorer()
        ttk.Label(self, textvariable=self.status, style="Muted.TLabel").pack(anchor="w", padx=22, pady=(0, 8))

        self.apply_theme()
        self._on_pw_change()
        self._suggest()
        self._load_cache()
        if autoload:
            self._autoload_lists()

    # ================================================================ plumbing
    def _after(self, ms, fn):
        """after() that is cancelled on destroy, so no callbacks fire into a dead interpreter."""
        holder = []

        def run():
            self._pending.discard(holder[0])
            fn()
        holder.append(self.after(ms, run))
        self._pending.add(holder[0])
        return holder[0]

    def _cancel(self, job):
        if job is not None:
            self.after_cancel(job)
            self._pending.discard(job)

    def _run_bg(self, fn, done):
        """Run fn on a worker thread; done(kind, value) runs on the Tk thread."""
        box = []

        def work():
            try:
                box.append(("ok", fn()))
            except Exception as e:                      # noqa: BLE001 - reported to the UI via done()
                box.append(("err", e))

        def poll():
            if box:
                done(*box[0])
            else:
                self._after(100, poll)

        threading.Thread(target=work, daemon=True).start()
        self._after(100, poll)

    def destroy(self):
        self._clear_clip(final=True)                # don't leave a copied password behind on exit
        for job in list(self._pending):
            try:
                self.after_cancel(job)
            except tk.TclError:
                pass
        super().destroy()

    # ================================================================ menu / theme
    def _menu(self):
        bar = tk.Menu(self)
        tools = tk.Menu(bar, tearoff=0)
        tools.add_command(label="Load breached/common password list…", command=self._load_breached)
        tools.add_command(label="Load passphrase wordlist (e.g. EFF diceware)…", command=self._load_words)
        bar.add_cascade(label="Tools", menu=tools)
        self.config(menu=bar)

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self.apply_theme()

    def apply_theme(self):
        t, s, f = THEMES[self.theme], self.style, self.ui_font
        self.configure(bg=t["bg"])
        s.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["card"], font=(f, 10),
                    bordercolor=t["track"], lightcolor=t["bg"], darkcolor=t["bg"], relief="flat")
        s.configure("Muted.TLabel", foreground=t["muted"])
        s.configure("TNotebook", background=t["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", padding=(14, 6), background=t["track"], foreground=t["muted"])
        s.map("TNotebook.Tab", background=[("selected", t["card"])], foreground=[("selected", t["fg"])])
        s.configure("TButton", background=t["track"], foreground=t["fg"], padding=6, borderwidth=0)
        s.map("TButton", background=[("active", t["hover"]), ("disabled", t["bg"])],
              foreground=[("disabled", t["muted"])])
        s.configure("TEntry", fieldbackground=t["card"], foreground=t["fg"], insertcolor=t["fg"])
        s.map("TEntry", fieldbackground=[("readonly", t["card"])], foreground=[("readonly", t["fg"])])
        s.configure("TSpinbox", fieldbackground=t["card"], foreground=t["fg"], arrowcolor=t["fg"])
        for w in ("TCheckbutton", "TRadiobutton"):
            s.configure(w, background=t["bg"], foreground=t["fg"], indicatorbackground=t["card"],
                        indicatorforeground=t["fg"])
            s.map(w, background=[("active", t["bg"])])
        s.configure("Treeview", background=t["card"], fieldbackground=t["card"], foreground=t["fg"],
                    rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background=t["track"], foreground=t["fg"], relief="flat")
        s.map("Treeview", background=[("selected", t["track"])], foreground=[("selected", t["fg"])])
        s.configure("TLabelframe", background=t["bg"], bordercolor=t["track"])
        s.configure("TLabelframe.Label", background=t["bg"], foreground=t["fg"])

        self.bar.config(bg=t["track"])
        for txt in (self.report, self.seg, self.detail):
            txt.config(bg=t["card"], fg=t["fg"], highlightbackground=t["track"], insertbackground=t["fg"])
        for tag in ("bad", "good", "tip", "muted"):
            self.report.tag_configure(tag, foreground=t[tag])
            self.detail.tag_configure(tag, foreground=t[tag])
        self.seg.tag_configure("brute", foreground=t["fg"])
        for kind, colour in KIND_COLOUR.items():
            self.seg.tag_configure(kind, foreground=colour)
        self._render()
        self._show_breach(*self.breach)
        self._generate()
        self._draw_years()

    # ================================================================ tester tab
    def _build_tester(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Tester  ")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=(14, 4))
        self.entry = ttk.Entry(row, textvariable=self.pw_var, show="•", font=(self.mono_font, 14))
        self.entry.pack(side="left", fill="x", expand=True, ipady=4)
        self.entry.focus_set()
        ttk.Button(row, text="Clear", command=lambda: self.pw_var.set("")).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(f, text="Show password", variable=self.show_var).pack(anchor="w")

        self.bar = tk.Canvas(f, height=14, highlightthickness=0)
        self.bar.pack(fill="x", pady=(10, 4))
        self.fill = self.bar.create_rectangle(0, 0, 0, 14, width=0)
        self.bar.bind("<Configure>", lambda _e: self._draw_bar())

        head = ttk.Frame(f)
        head.pack(fill="x")
        self.grade_lbl = ttk.Label(head, font=(self.ui_font, 16, "bold"))
        self.grade_lbl.pack(side="left")
        self.score_lbl = ttk.Label(head, style="Muted.TLabel")
        self.score_lbl.pack(side="right")
        self.stats_lbl = ttk.Label(f, style="Muted.TLabel")
        self.stats_lbl.pack(anchor="w", pady=(0, 6))

        grid = ttk.Frame(f)
        grid.pack(fill="x", pady=4)
        self.checks = []
        for i in range(6):
            lbl = ttk.Label(grid)
            lbl.grid(row=i // 3, column=i % 3, sticky="w", padx=(0, 22), pady=1)
            self.checks.append(lbl)

        box = ttk.Frame(f)
        box.pack(fill="x", pady=(2, 4))
        ttk.Label(box, text="How an attacker sees it", style="Muted.TLabel").pack(anchor="w")
        self.seg = tk.Text(box, height=2, wrap="char", font=(self.mono_font, 13, "bold"), relief="flat",
                           padx=8, pady=4, highlightthickness=1, state="disabled")
        self.seg.pack(fill="x")
        legend = ttk.Frame(box)
        legend.pack(anchor="w", pady=(2, 0))
        for kind, colour in KIND_COLOUR.items():
            if kind != "sequence":
                ttk.Label(legend, text="■ " + KIND_LABEL[kind], foreground=colour,
                          font=(self.ui_font, 8)).pack(side="left", padx=(0, 10))
        ttk.Label(legend, text="■ random", style="Muted.TLabel", font=(self.ui_font, 8)).pack(side="left")

        self.tree = ttk.Treeview(f, columns=("s", "t"), show="headings", height=4, selectmode="none")
        self.tree.heading("s", text="Attack scenario")
        self.tree.heading("t", text="Avg. time to crack")
        self.tree.column("s", width=380)
        self.tree.column("t", width=180)
        self.tree.pack(fill="x", pady=8)

        brow = ttk.Frame(f)
        brow.pack(fill="x")
        ttk.Button(brow, text="Check breach database", command=self._check_breach).pack(side="left")
        self.breach_lbl = ttk.Label(brow, wraplength=300)
        self.breach_lbl.pack(side="left", padx=10)
        ttk.Button(brow, text="Export report", command=self._export).pack(side="right")
        ttk.Checkbutton(brow, text="include password", variable=self.include_pw).pack(side="right", padx=8)
        note = ttk.Frame(f)
        note.pack(fill="x", pady=(2, 0))
        ttk.Label(note, style="Muted.TLabel", font=(self.ui_font, 8),
                  text="Only 5 characters of a SHA-1 hash are sent. HIBP returns a count, never which sites."
                  ).pack(side="left")
        ttk.Button(note, text="Which sites & when", command=lambda: self.nb.select(self.ex_tab)).pack(side="right")

        self.report = tk.Text(f, height=6, wrap="word", font=(self.ui_font, 10), relief="flat", padx=10,
                              pady=8, state="disabled", highlightthickness=1)
        self.report.pack(fill="both", expand=True, pady=8)
        self.report.tag_configure("h", font=(self.ui_font, 10, "bold"), spacing1=4)

        ttk.Label(f, text="Suggested stronger alternatives", font=(self.ui_font, 11, "bold")).pack(anchor="w")
        self.sugg, self.sugg_entries = [], []
        for label in ("Yours + random tail", "Random passphrase", "Random password"):
            r = ttk.Frame(f)
            r.pack(fill="x", pady=2)
            ttk.Label(r, text=label, width=22, style="Muted.TLabel").pack(side="left")
            var = tk.StringVar(value="—")
            e = ttk.Entry(r, textvariable=var, state="readonly", font=(self.mono_font, 10))
            e.pack(side="left", fill="x", expand=True)
            ttk.Button(r, text="Use", width=5, command=lambda v=var: self._use(v)).pack(side="left", padx=(6, 0))
            ttk.Button(r, text="Copy", width=5, command=lambda v=var: self._copy(v.get())).pack(side="left", padx=(4, 0))
            self.sugg.append(var)
            self.sugg_entries.append(e)
        self.sugg_info = ttk.Label(f, style="Muted.TLabel", font=(self.ui_font, 8))
        self.sugg_info.pack(anchor="w")
        ttk.Button(f, text="New suggestions", command=self._suggest).pack(anchor="e", pady=6)

    def _on_pw_change(self):
        pw = self.pw_var.get()
        self.result = self.analyzer.analyze(pw)
        if pw != self._last_pw:                           # stale breach result no longer applies
            self._last_pw = pw
            self._show_breach("", "muted")
            self._improve(pw)
        self._render()

    def _reanalyze(self):
        self._last_pw = None
        self._on_pw_change()

    def _render(self):
        if not hasattr(self, "report"):
            return
        pw, r, t = self.pw_var.get(), self.result, THEMES[self.theme]
        reveal = "show" if self.show_var.get() else "mask"
        self.entry.config(show="" if self.show_var.get() else "•")
        self.sugg_entries[0].config(show="" if self.show_var.get() else "•")   # it contains your password
        for lbl, (text, ok) in zip(self.checks, checklist(pw, r)):
            lbl.config(text=("✔ " if ok else "○ ") + text, foreground=t["good"] if ok else t["muted"])
        self.tree.delete(*self.tree.get_children())
        self.report.config(state="normal")
        self.report.delete("1.0", "end")
        if not r:
            self.grade_lbl.config(text="Enter a password", foreground=t["muted"])
            self.score_lbl.config(text="")
            self.stats_lbl.config(text="")
            for name, _ in ATTACKS:
                self.tree.insert("", "end", values=(name, "—"))
            self.report.insert("end", "Type a password to see its grade, weaknesses and ways to improve it.")
        else:
            colour = t[GRADE_KEYS[r["level"]]]
            self.grade_lbl.config(text=r["grade"], foreground=colour)
            self.score_lbl.config(text=f"Score {r['score']}/100")
            self.stats_lbl.config(text=f"{r['length']} characters  •  ~{r['entropy']:.0f} bits of effective entropy")
            for name, rate in ATTACKS:
                self.tree.insert("", "end", values=(name, crack_time(r["entropy"], rate)))
            self.report.insert("end", "Findings\n", "h")
            if not r["findings"]:
                self.report.insert("end", "✔ No obvious weaknesses found.\n", "good")
            for fd in r["findings"]:
                self.report.insert("end", "✘ " + fd.render(reveal) + "\n", "bad")
            if r["tips"]:
                self.report.insert("end", "\nHow to improve\n", "h")
                for tip in r["tips"]:
                    self.report.insert("end", "→ " + tip + "\n", "tip")
        self.report.config(state="disabled")
        self._draw_bar()
        self._draw_seg()

    def _draw_bar(self):
        t, r = THEMES[self.theme], self.result
        w = max(self.bar.winfo_width(), 1)
        score = r["score"] if r else 0
        self.bar.coords(self.fill, 0, 0, w * max(score, 3 if r else 0) / 100, 14)
        self.bar.itemconfig(self.fill, fill=t[GRADE_KEYS[r["level"]]] if r else t["muted"])

    def _draw_seg(self):
        segs = self.result["segments"] if self.result else []
        self.seg.config(state="normal")
        self.seg.delete("1.0", "end")
        if not segs:
            self.seg.insert("end", "—", "brute")
        hide = not self.show_var.get()
        for text, kind in segs:
            self.seg.insert("end", "•" * len(text) if hide else text, kind)
        self.seg.config(state="disabled")

    # ---- breach check (password)
    def _show_breach(self, msg, kind):
        self.breach = (msg, kind)
        t = THEMES[self.theme]
        self.breach_lbl.config(text=msg, foreground=t.get(kind, t["muted"]))

    def _check_breach(self):
        pw = self.pw_var.get()
        if not pw:
            return self._show_breach("Enter a password first.", "muted")
        self._show_breach("Checking…", "muted")

        def done(kind, val):
            if self.pw_var.get() != pw:
                return
            if kind == "err":
                self._show_breach("Couldn't check: " + hibp.explain_error(val), "muted")
            elif val:
                self._show_breach(hibp.pwned_message(val), "bad")
            else:
                self._show_breach("✔ Not found in known breach data.", "good")
        self._run_bg(lambda: hibp.pwned_count(pw), done)

    # ---- export
    def _export(self):
        pw = self.pw_var.get()
        if not self.result:
            return self.status.set("Type a password first.")
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="password_report",
                                            filetypes=[("Text report", "*.txt"), ("JSON", "*.json")])
        if not path:
            return
        try:
            write_report(path, build_report(pw, self.result, self.breach[0], self.include_pw.get()))
        except OSError as e:
            return self.status.set(f"Couldn't save the report: {e.strerror or e}")
        self.status.set(f"Report saved to {path}")

    # ---- suggestions
    def _improve(self, pw):
        cand, bits = extend(pw)
        self.sugg[0].set(cand or "(type a password first)")
        self.sugg_info.config(text=(f"The random tail alone is ~{bits:.0f} bits, so it holds even if your "
                                    "old password is known." if cand else ""))

    def _suggest(self):
        self._improve(self.pw_var.get())
        self.sugg[1].set(gen_phrase(5, words=self.words)[0])
        self.sugg[2].set(gen_random(16)[0])

    def _use(self, var):
        if var.get() and not var.get().startswith(("—", "(")):
            self.pw_var.set(var.get())

    # ================================================================ generator tab
    def _build_gen(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Generator  ")
        self.gen_mode = tk.StringVar(value="random")
        m = ttk.Frame(f)
        m.pack(anchor="w", pady=(16, 8))
        ttk.Radiobutton(m, text="Random characters", value="random", variable=self.gen_mode,
                        command=self._switch_gen_mode).pack(side="left")
        ttk.Radiobutton(m, text="Passphrase", value="phrase", variable=self.gen_mode,
                        command=self._switch_gen_mode).pack(side="left", padx=16)
        opts = ttk.Frame(f)
        opts.pack(fill="x")
        self.rand_f, self.phrase_f = ttk.Frame(opts), ttk.Frame(opts)

        self.len_var = tk.StringVar(value="18")
        self.o_up, self.o_low, self.o_dig, self.o_sym, self.o_amb = (tk.BooleanVar(value=v)
                                                                      for v in (True, True, True, True, False))
        r1 = ttk.Frame(self.rand_f)
        r1.pack(anchor="w", pady=2)
        ttk.Label(r1, text="Length").pack(side="left")
        self._spin(r1, self.len_var, 8, 64)
        for text, var in (("A-Z", self.o_up), ("a-z", self.o_low), ("0-9", self.o_dig),
                          ("Symbols", self.o_sym), ("Avoid look-alikes (Il1O0)", self.o_amb)):
            ttk.Checkbutton(self.rand_f, text=text, variable=var, command=self._generate).pack(anchor="w")

        self.words_var, self.sep_var = tk.StringVar(value="5"), tk.StringVar(value="-")
        self.p_cap, self.p_num, self.p_sym = (tk.BooleanVar(value=True) for _ in range(3))
        p1 = ttk.Frame(self.phrase_f)
        p1.pack(anchor="w", pady=2)
        ttk.Label(p1, text="Words").pack(side="left")
        self._spin(p1, self.words_var, 3, 10)
        ttk.Label(p1, text="  Separator").pack(side="left")
        sep = ttk.Entry(p1, textvariable=self.sep_var, width=3)
        sep.pack(side="left", padx=6)
        sep.bind("<KeyRelease>", lambda _e: self._generate())
        for text, var in (("Capitalise words", self.p_cap), ("Add a number", self.p_num), ("Add a symbol", self.p_sym)):
            ttk.Checkbutton(self.phrase_f, text=text, variable=var, command=self._generate).pack(anchor="w")
        self.words_info = ttk.Label(self.phrase_f, style="Muted.TLabel")
        self.words_info.pack(anchor="w", pady=(4, 0))
        self._words_info()
        self.rand_f.pack(anchor="w")

        self.gen_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.gen_var, state="readonly", font=(self.mono_font, 15)
                  ).pack(fill="x", pady=(18, 6), ipady=6)
        self.gen_lbl = ttk.Label(f, font=(self.ui_font, 12, "bold"))
        self.gen_lbl.pack(anchor="w")
        btns = ttk.Frame(f)
        btns.pack(anchor="w", pady=12)
        ttk.Button(btns, text="Generate", command=self._generate).pack(side="left")
        ttk.Button(btns, text="Copy", command=lambda: self._copy(self.gen_var.get())).pack(side="left", padx=6)
        ttk.Button(btns, text="Test this password", command=self._send_to_tester).pack(side="left")
        ttk.Label(f, text="Entropy is calculated from how the password was generated, not guessed from its look. "
                          f"Copied passwords are cleared from the clipboard after {CLIP_SECONDS} s or when you quit.",
                  style="Muted.TLabel", wraplength=600, justify="left").pack(anchor="w")

    def _spin(self, parent, var, lo, hi):
        sp = ttk.Spinbox(parent, from_=lo, to=hi, textvariable=var, width=4, command=self._generate)
        sp.pack(side="left", padx=6)
        sp.bind("<KeyRelease>", lambda _e: self._generate())

    def _switch_gen_mode(self):
        self.rand_f.pack_forget()
        self.phrase_f.pack_forget()
        (self.rand_f if self.gen_mode.get() == "random" else self.phrase_f).pack(anchor="w")
        self._generate()

    def _words_info(self):
        self.words_info.config(text=f"Wordlist: {len(self.words):,} words "
                                    f"({math.log2(len(self.words)):.1f} bits per word)")

    @staticmethod
    def _int(var, lo, hi, default):
        try:
            return max(lo, min(hi, int(var.get())))
        except ValueError:
            return default

    def _generate(self):
        if not hasattr(self, "gen_lbl"):
            return
        if self.gen_mode.get() == "random":
            pw, bits = gen_random(self._int(self.len_var, 8, 64, 18), self.o_up.get(), self.o_low.get(),
                                  self.o_dig.get(), self.o_sym.get(), self.o_amb.get())
        else:
            pw, bits = gen_phrase(self._int(self.words_var, 3, 10, 5), self.sep_var.get(), self.p_cap.get(),
                                  self.p_num.get(), self.p_sym.get(), self.words)
        if pw is None:
            self.gen_var.set("(pick at least one character type)")
            return self.gen_lbl.config(text="")
        level, label = grade_for(min(100, bits / 80 * 100))
        self.gen_var.set(pw)
        self.gen_lbl.config(text=f"≈ {bits:.0f} bits of entropy  •  {label}",
                            foreground=THEMES[self.theme][GRADE_KEYS[level]])

    def _send_to_tester(self):
        if not self.gen_var.get().startswith("("):
            self.pw_var.set(self.gen_var.get())
            self.nb.select(0)

    # ---- clipboard (auto-clears, and on exit)
    def _copy(self, text):
        if not text or text.startswith(("—", "(")):
            return
        private, self._clip_seq = False, None
        if self._winclip is not None:
            try:
                self._clip_seq = self._winclip.copy(text)   # kept out of Win+V history and cloud sync
                private = True
            except OSError:
                pass
        if not private:
            self.clipboard_clear()
            self.clipboard_append(text)
        self._clip_text = text
        self.status.set(f"Copied{' (kept out of clipboard history)' if private else ''}. "
                        f"Clipboard will be cleared in {CLIP_SECONDS} s.")
        self._cancel(self._clip_job)
        self._clip_job = self._after(CLIP_SECONDS * 1000, self._clear_clip)

    def _clear_clip(self, final=False):
        text, seq = self._clip_text, self._clip_seq
        self._clip_text, self._clip_job, self._clip_seq = None, None, None
        if text is None:
            return
        if seq is not None and self._winclip is not None:
            # Windows path: decide by sequence number. Tk's clipboard_get can return a stale cached
            # copy after any Tk copy in this process (e.g. Ctrl+C in an entry), so it can't be trusted.
            try:
                self._winclip.clear_if_unchanged(seq)
            except OSError:
                pass
        else:
            try:
                if self.clipboard_get() == text:      # only clear what we put there
                    self.clipboard_clear()
                    self.clipboard_append("")
            except tk.TclError:
                pass
        if not final:
            self.status.set("Clipboard cleared.")

    # ---- wordlists (read on a worker thread; merged on the Tk thread)
    def _load_breached(self):
        path = filedialog.askopenfilename(title="Common/breached password list (one per line)")
        if not path:
            return
        self.status.set("Loading password list…")

        def done(kind, val):
            if kind == "err":
                return self.status.set(f"Couldn't read that file: {val}")
            self.analyzer.common |= val
            self.status.set(f"Loaded {len(val):,} passwords into the common-password check.")
            self._reanalyze()
        self._run_bg(lambda: wordlists.read_password_list(path), done)

    def _load_words(self):
        path = filedialog.askopenfilename(title="Passphrase wordlist (one word per line, diceware format OK)")
        if not path:
            return

        def done(kind, val):
            if kind == "err":
                return self.status.set(f"Couldn't read that file: {val}")
            if len(val) < 200:
                return self.status.set("That file has fewer than 200 usable words; keeping the current list.")
            self.words = tuple(sorted(val))
            self.analyzer.words |= val
            self._words_info()
            self.status.set(f"Loaded {len(val):,} words.")
            self._generate()
            self._reanalyze()
        self._run_bg(lambda: wordlists.read_word_list(path), done)

    def _autoload_lists(self):
        def done(kind, val):
            if kind == "err":
                return self.status.set(f"Couldn't read data/ lists: {val}")
            pw, words = val
            if not (pw or words):
                return
            self.analyzer.common |= pw
            self.analyzer.words |= words
            self.status.set(f"Loaded {len(pw):,} passwords and {len(words):,} words from data/.")
            self._reanalyze()
        self._run_bg(wordlists.bundled_lists, done)

    # ================================================================ personal tab
    def _build_personal(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Personal check  ")
        ttk.Label(f, wraplength=640, justify="left", style="Muted.TLabel",
                  text="Add details someone who knows you might try. If any appear in the password you test, "
                       "they're flagged and the score drops. Everything stays in memory only: never saved or sent.",
                  ).pack(anchor="w", pady=(16, 6))
        self.pv = {}
        for key, label, hint in (("names", "Name(s)", "e.g. Jane Tan, Rex"),
                                 ("email", "Email", "e.g. jane.tan@example.com"),
                                 ("dates", "Birthdays / anniversaries (numeric)", "e.g. 14/03/1990, 1990-03-14"),
                                 ("other", "Other: pets, places, teams, phone…", "comma separated")):
            ttk.Label(f, text=label).pack(anchor="w", pady=(10, 0))
            var = tk.StringVar()
            var.trace_add("write", lambda *_: self._personal_changed())
            ttk.Entry(f, textvariable=var).pack(fill="x", ipady=3)
            ttk.Label(f, text=hint, style="Muted.TLabel", font=(self.ui_font, 8)).pack(anchor="w")
            self.pv[key] = var
        self.pinfo = ttk.Label(f, style="Muted.TLabel")
        self.pinfo.pack(anchor="w", pady=(14, 4))
        ttk.Button(f, text="Clear all", command=lambda: [v.set("") for v in self.pv.values()]).pack(anchor="w")

    def _personal_changed(self):
        self.analyzer.personal = personal_tokens(*(self.pv[k].get() for k in ("names", "email", "dates", "other")))
        self.pinfo.config(text=f"Watching {len(self.analyzer.personal)} personal pattern(s).")
        self._on_pw_change()

    # ================================================================ breach explorer tab
    def _build_explorer(self):
        f = self.ex_tab = ttk.Frame(self.nb)
        self.nb.add(f, text="  Breach Explorer  ")
        top = ttk.Frame(f)
        top.pack(fill="x", pady=(12, 6))
        self.btn_fetch = ttk.Button(top, text="Load / refresh catalogue", command=self._fetch_catalog)
        self.btn_fetch.pack(side="left")
        self.ex_status = ttk.Label(top, style="Muted.TLabel", wraplength=480)
        self.ex_status.pack(side="left", padx=10)

        srow = ttk.Frame(f)
        srow.pack(fill="x")
        self.q = tk.StringVar()
        self.q.trace_add("write", lambda *_: self._schedule_filter())
        ttk.Entry(srow, textvariable=self.q).pack(side="left", fill="x", expand=True, ipady=3)
        self.f_pw, self.f_ver = tk.BooleanVar(), tk.BooleanVar()
        ttk.Checkbutton(srow, text="Passwords exposed", variable=self.f_pw, command=self._filter
                        ).pack(side="left", padx=(10, 0))
        ttk.Checkbutton(srow, text="Verified only", variable=self.f_ver, command=self._filter
                        ).pack(side="left", padx=(8, 0))
        self.ex_summary = ttk.Label(f, style="Muted.TLabel")
        self.ex_summary.pack(anchor="w", pady=(4, 2))

        self.chart = tk.Canvas(f, height=76, highlightthickness=0)
        self.chart.pack(fill="x")
        self.chart.bind("<Configure>", lambda _e: self._draw_years())

        tw = ttk.Frame(f)
        tw.pack(fill="both", expand=True, pady=6)
        heads = {"title": ("Breach", 140), "domain": ("Domain", 120), "date": ("Breached", 78),
                 "added": ("Added", 78), "count": ("Accounts", 88), "data": ("Data exposed", 190),
                 "flags": ("Flags", 100)}
        self.ex_tree = ttk.Treeview(tw, columns=list(heads), show="headings", height=8, selectmode="browse")
        for col, (text, width) in heads.items():
            self.ex_tree.heading(col, text=text, command=lambda c=col: self._sort(c))
            self.ex_tree.column(col, width=width, anchor="e" if col == "count" else "w", stretch=(col == "data"))
        sb = ttk.Scrollbar(tw, orient="vertical", command=self.ex_tree.yview)
        self.ex_tree.configure(yscrollcommand=sb.set)
        self.ex_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.ex_tree.bind("<<TreeviewSelect>>", self._show_detail)

        self.detail = tk.Text(f, height=7, wrap="word", font=(self.ui_font, 10), relief="flat", padx=10,
                              pady=6, highlightthickness=1, state="disabled")
        self.detail.pack(fill="x")
        self.detail.tag_configure("h", font=(self.ui_font, 11, "bold"))

        box = ttk.LabelFrame(f, text=" Check an email address (needs a HIBP API key) ", padding=8)
        box.pack(fill="x", pady=(8, 4))
        self.em, self.key = tk.StringVar(), tk.StringVar()
        for label, var, show in (("Email", self.em, ""), ("API key", self.key, "•")):
            r = ttk.Frame(box)
            r.pack(fill="x", pady=1)
            ttk.Label(r, text=label, width=8).pack(side="left")
            ttk.Entry(r, textvariable=var, show=show).pack(side="left", fill="x", expand=True)
        r = ttk.Frame(box)
        r.pack(fill="x", pady=(4, 2))
        ttk.Button(r, text="Look up", command=self._lookup_email).pack(side="left")
        ttk.Button(r, text="Try demo", command=self._demo).pack(side="left", padx=6)
        ttk.Button(r, text="Show full catalogue", command=self._on_show_catalog).pack(side="left")
        ttk.Label(box, style="Muted.TLabel", font=(self.ui_font, 8), wraplength=660, justify="left",
                  text="Keys are paid (haveibeenpwned.com/API/Key) and held in memory only. Your full address is "
                       "sent to HIBP, so only look up addresses you own. HIBP hides sensitive/retired breaches "
                       "from public lookups.").pack(anchor="w")
        link = ttk.Label(f, text="Breach data: Have I Been Pwned (haveibeenpwned.com), CC BY 4.0",
                         style="Muted.TLabel", cursor="hand2", font=(self.ui_font, 8, "underline"))
        link.pack(anchor="w", pady=(2, 0))
        link.bind("<Button-1>", lambda _e: webbrowser.open("https://haveibeenpwned.com"))
        self._show_detail()

    def _fetch_catalog(self):
        if self._fetching:
            return
        self._fetching = True
        self.btn_fetch.state(["disabled"])
        self.ex_status.config(text="Loading catalogue from HIBP…")

        def done(kind, val):
            self._fetching = False
            self.btn_fetch.state(["!disabled"])
            if kind == "err":
                return self.ex_status.config(text="Couldn't load: " + hibp.explain_error(val))
            self.catalog = hibp.prep(val)
            msg = f"{len(val):,} breaches loaded just now." + (
                "" if hibp.save_cache(hibp.cache_path(), val) else " (Couldn't save the cache.)")
            if self.mode == "catalog":
                self._use_catalog()
                self.ex_status.config(text=msg)
            else:                                    # don't yank the user out of their email results
                self.ex_status.config(text=msg + " Click “Show full catalogue” to browse it.")
        self._run_bg(lambda: hibp.clean_breaches(hibp.hibp_get("breaches")), done)

    def _load_cache(self):
        try:
            fetched, raw = hibp.load_cache_blob(hibp.cache_path())
        except (OSError, ValueError):
            self.ex_status.config(text="Click “Load / refresh catalogue” to download the list (free, no key).")
            return self._filter()
        self.catalog = hibp.prep(raw)
        self.ex_status.config(text=f"{len(raw):,} breaches (cached {hibp.age_text(fetched)}). Refresh for the latest.")
        self._use_catalog()

    def _use_catalog(self):
        self.source, self.mode, self.email_shown = self.catalog, "catalog", ""
        self._filter()

    def _on_show_catalog(self):
        self._view_token += 1                       # user chose the catalogue: discard pending lookups
        self._use_catalog()

    def _schedule_filter(self):
        self._cancel(self._search_job)
        self._search_job = self._after(SEARCH_DEBOUNCE_MS, self._run_scheduled_filter)

    def _run_scheduled_filter(self):
        self._search_job = None
        self._filter()

    def _filter(self):
        q = self.q.get().strip().lower()
        self.shown = [b for b in self.source
                      if (not self.f_pw.get() or "Passwords" in b["DataClasses"])
                      and (not self.f_ver.get() or b.get("IsVerified", True))
                      and (not q or q in b["_text"])]
        self._sort(None)

    def _sort(self, col):
        if col is not None:
            self.sort_rev = (not self.sort_rev) if col == self.sort_col else col in ("date", "added", "count")
            self.sort_col = col
        keys = {"title": lambda b: b["Title"].lower(), "domain": lambda b: b["Domain"].lower(),
                "date": lambda b: b["BreachDate"], "added": lambda b: b["AddedDate"],
                "count": lambda b: b["PwnCount"], "data": lambda b: len(b["DataClasses"]),
                "flags": lambda b: len(hibp.flags_of(b))}
        self.shown.sort(key=keys[self.sort_col], reverse=self.sort_rev)
        self.ex_tree.delete(*self.ex_tree.get_children())
        for i, b in enumerate(self.shown):
            dc = b["DataClasses"]
            data_txt = ", ".join(dc[:4]) + (f" +{len(dc) - 4}" if len(dc) > 4 else "")
            self.ex_tree.insert("", "end", iid=str(i), values=(
                b["Title"], b["Domain"], b["BreachDate"], b["AddedDate"][:10], f"{b['PwnCount']:,}",
                data_txt, ", ".join(hibp.flags_of(b))))
        pw = sum("Passwords" in b["DataClasses"] for b in self.shown)
        note = "Full HIBP catalogue" if self.mode == "catalog" else f"Breaches for {self.email_shown}"
        self.ex_summary.config(text=f"{note}: showing {len(self.shown):,} of {len(self.source):,} "
                                    f"breaches  •  {pw:,} exposed passwords")
        self._show_detail()
        self._draw_years()

    def _draw_years(self):
        if not hasattr(self, "chart"):
            return
        c, t = self.chart, THEMES[self.theme]
        c.delete("all")
        c.config(bg=t["card"])
        counts = {}
        for b in self.shown:
            y = b["BreachDate"][:4]
            if y.isdigit():
                d = counts.setdefault(int(y), [0, 0])
                d[0] += 1
                d[1] += "Passwords" in b["DataClasses"]
        if not counts:
            c.create_text(10, 38, anchor="w", fill=t["muted"], text="Breaches per year appear here once loaded.",
                          font=(self.ui_font, 9))
            return
        w, h = max(c.winfo_width(), 300), 76
        y0, y1 = min(counts), max(counts)
        span, mx = y1 - y0 + 1, max(v[0] for v in counts.values())
        bw, step = (w - 20) / span, max(1, span // 12)
        c.create_text(10, 7, anchor="w", fill=t["muted"], font=(self.ui_font, 8),
                      text="Breaches per year (red = passwords exposed)")
        for i, yr in enumerate(range(y0, y1 + 1)):
            total, pw = counts.get(yr, (0, 0))
            x, base = 10 + i * bw, h - 14
            if total:
                c.create_rectangle(x + 1, base - (h - 34) * total / mx, x + bw - 1, base, fill=t["tip"], width=0)
            if pw:
                c.create_rectangle(x + 1, base - (h - 34) * pw / mx, x + bw - 1, base, fill=t["bad"], width=0)
            if i % step == 0:
                c.create_text(x + bw / 2, h - 6, text=f"'{yr % 100:02d}", fill=t["muted"], font=(self.ui_font, 7))

    def _show_detail(self, _e=None):
        d = self.detail
        d.config(state="normal")
        d.delete("1.0", "end")
        sel = self.ex_tree.selection()
        if not sel:
            d.insert("end", "Select a breach to see what happened, when, and what leaked.", "muted")
        else:
            b = self.shown[int(sel[0])]
            dc = b["DataClasses"]
            d.insert("end", f"{b['Title']}  ({b['Domain'] or 'no domain'})\n", "h")
            d.insert("end", f"Breached: {b['BreachDate'] or '?'}   •   Added to HIBP: {b['AddedDate'][:10] or '?'}"
                            f"   •   Accounts: {b['PwnCount']:,}\n", "muted")
            d.insert("end", "Exposed: " + (", ".join(dc) or "unknown") + "\n")
            for fl in hibp.flags_of(b):
                if fl in hibp.FLAG_NOTES:
                    d.insert("end", "⚠ " + hibp.FLAG_NOTES[fl] + "\n", "bad")
            d.insert("end", "\n" + b["_desc"] + "\n")
            if "Passwords" in dc:
                d.insert("end", "\n→ " + ("You're in this breach and passwords leaked: change your password on this "
                                          "service, and anywhere you reused it." if self.mode == "email" else
                                          "Passwords leaked here. Any password you used on this service at the time "
                                          "should be treated as compromised."), "bad")
            d.insert("end", "\nBreach dates are the incident date as best known; breaches are often found later.", "muted")
        d.config(state="disabled")

    def _demo(self):
        self.em.set(hibp.DEMO_EMAIL)
        self._lookup_email(key_override=hibp.DEMO_KEY)  # test key never touches the key field

    def _lookup_email(self, key_override=None):
        email = self.em.get().strip()
        key = key_override or self.key.get().strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return self.ex_status.config(text="Enter a valid email address.")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", key):
            return self.ex_status.config(text="API key must be 32 hex characters.")
        self._view_token += 1
        token = self._view_token
        self.ex_status.config(text="Looking up…")
        path = hibp.breached_account_path(email)

        def show(rows, msg):
            self.source, self.mode, self.email_shown = hibp.prep(rows), "email", email
            self.q.set("")
            self.f_pw.set(False)
            self.f_ver.set(False)
            self._filter()
            self.ex_status.config(text=msg)

        def done(kind, val):
            if token != self._view_token:           # superseded by a newer lookup / view change
                return
            if kind == "ok":
                n_pw = sum("Passwords" in b["DataClasses"] for b in val)
                show(val, f"Found in {len(val)} breach{'es' if len(val) != 1 else ''}; "
                          f"passwords exposed in {n_pw}. Select a row for details.")
            elif isinstance(val, urllib.error.HTTPError) and val.code == 404:
                show([], "✔ Not found in any breach HIBP can show publicly.")
            else:
                self.ex_status.config(text="Lookup failed: " + hibp.explain_error(val))
        self._run_bg(lambda: hibp.clean_breaches(hibp.hibp_get(path, key)), done)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
