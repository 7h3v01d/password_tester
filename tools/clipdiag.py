# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Clipboard diagnostic (Windows). Run from the project folder:  python tools\\clipdiag.py
Overwrites your clipboard. Paste the whole output back."""
import ctypes
import os
import sys
import tkinter as tk
from ctypes import wintypes as w

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from password_tester import clipboard as cb  # noqa: E402

u = ctypes.WinDLL("user32", use_last_error=True)
k = ctypes.WinDLL("kernel32", use_last_error=True)
for fn, args, res in ((u.OpenClipboard, [w.HWND], w.BOOL), (u.CloseClipboard, [], w.BOOL),
                      (u.GetClipboardData, [w.UINT], w.HANDLE), (u.EnumClipboardFormats, [w.UINT], w.UINT),
                      (u.GetClipboardFormatNameW, [w.UINT, w.LPWSTR, ctypes.c_int], ctypes.c_int),
                      (u.GetClipboardSequenceNumber, [], w.DWORD), (u.GetClipboardOwner, [], w.HWND),
                      (u.GetParent, [w.HWND], w.HWND),
                      (k.GlobalLock, [w.HGLOBAL], w.LPVOID), (k.GlobalUnlock, [w.HGLOBAL], w.BOOL)):
    fn.argtypes, fn.restype = args, res
NAMES = {1: "CF_TEXT", 7: "CF_OEMTEXT", 13: "CF_UNICODETEXT", 16: "CF_LOCALE"}


def snap(label):
    if not u.OpenClipboard(None):
        return print(f"  {label}: could not open clipboard (err {ctypes.get_last_error()})")
    try:
        text = None
        h = u.GetClipboardData(13)
        if h:
            p = k.GlobalLock(h)
            if p:
                try:
                    text = ctypes.wstring_at(p)
                finally:
                    k.GlobalUnlock(h)
        fmts, f = [], 0
        while True:
            f = u.EnumClipboardFormats(f)
            if not f:
                break
            buf = ctypes.create_unicode_buffer(128)
            fmts.append(buf.value if u.GetClipboardFormatNameW(f, buf, 128) else NAMES.get(f, str(f)))
    finally:
        u.CloseClipboard()
    print(f"  {label}: raw={text!r} seq={u.GetClipboardSequenceNumber()} owner={u.GetClipboardOwner()} "
          f"formats={fmts}")


def tk_read(label):
    r = tk.Tk()
    r.withdraw()
    try:
        print(f"  {label}: tk_read={r.clipboard_get()!r}")
    except tk.TclError as e:
        print(f"  {label}: tk_read error {e}")
    finally:
        r.destroy()


class OwnedClip(cb.WinClipboard):
    """Candidate fix: open the clipboard with a real owner window instead of NULL."""
    def __init__(self, hwnd):
        super().__init__()
        self.hwnd = hwnd

    def _open(self):
        if not self.user32.OpenClipboard(self.hwnd):
            raise OSError(f"OpenClipboard failed ({ctypes.get_last_error()})")


def run(name, fn):
    print(f"[{name}]")
    try:
        fn()
    except Exception as e:                       # noqa: BLE001 - diagnostic: report everything
        print(f"  EXCEPTION {type(e).__name__}: {e}")


def a_fresh():
    snap("before")
    cb.WinClipboard().copy("diag-A-é✓")
    snap("after copy")
    tk_read("new Tk root")


def b_after_tk_owned():
    r = tk.Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append("TK-OWNED")
    r.update()
    r.destroy()
    snap("after Tk copy + destroy")
    cb.WinClipboard().copy("diag-B-é✓")
    snap("after copy")
    tk_read("new Tk root")


def c_owned_window():
    r = tk.Tk()
    r.withdraw()
    r.update()
    hwnd = u.GetParent(r.winfo_id()) or r.winfo_id()
    OwnedClip(hwnd).copy("diag-C-é✓")
    snap(f"after copy (owner hwnd {hwnd})")
    print(f"  same root: tk_read={r.clipboard_get()!r}")
    r.destroy()
    snap("after root destroyed")
    tk_read("new Tk root")


print(sys.version.split()[0], sys.platform, "Tk", tk.TkVersion)
for name, fn in (("A fresh process", a_fresh), ("B after a Tk copy", b_after_tk_owned),
                 ("C owner window", c_owned_window)):
    run(name, fn)
