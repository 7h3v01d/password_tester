# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Clipboard diagnostic #2 (Windows). Run from the project folder:  python tools\\clipdiag2.py
Overwrites your clipboard. Takes ~10 s. Paste the whole output back."""
import ctypes
import os
import sys
import time
import tkinter as tk
from ctypes import wintypes as w

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from password_tester import clipboard as cb  # noqa: E402

u = ctypes.WinDLL("user32", use_last_error=True)
for fn, args, res in ((u.OpenClipboard, [w.HWND], w.BOOL), (u.CloseClipboard, [], w.BOOL),
                      (u.GetOpenClipboardWindow, [], w.HWND), (u.GetClipboardOwner, [], w.HWND),
                      (u.GetWindowThreadProcessId, [w.HWND, ctypes.POINTER(w.DWORD)], w.DWORD),
                      (u.GetClassNameW, [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int)):
    fn.argtypes, fn.restype = args, res
ME = os.getpid()
WC = cb.WinClipboard()


def who(hwnd):
    if not hwnd:
        return "none"
    pid = w.DWORD()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    buf = ctypes.create_unicode_buffer(128)
    u.GetClassNameW(hwnd, buf, 128)
    return f"hwnd={hwnd} class={buf.value!r} {'THIS process' if pid.value == ME else f'pid {pid.value}'}"


def tk_copy_and_destroy(text):
    r = tk.Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append(text)
    r.update()
    r.destroy()


def poll_open(label, pump=None, limit=3.0):
    t0, holders = time.perf_counter(), {}
    while time.perf_counter() - t0 < limit:
        if u.OpenClipboard(None):
            u.CloseClipboard()
            break
        holders[who(u.GetOpenClipboardWindow())] = ctypes.get_last_error()
        if pump:
            pump()
        time.sleep(0.05)
    else:
        print(f"  {label}: still locked after {limit:.0f} s; held by {holders}")
        return
    print(f"  {label}: opened after {(time.perf_counter() - t0) * 1000:.0f} ms; "
          f"held by {holders or 'nobody'}; owner now {who(u.GetClipboardOwner())}")


def tk_read(root):
    try:
        return repr(root.clipboard_get())
    except tk.TclError as e:
        return f"error {e}"


def run(name, fn):
    print(f"[{name}]")
    try:
        fn()
    except Exception as e:                       # noqa: BLE001 - diagnostic: report everything
        print(f"  EXCEPTION {type(e).__name__}: {e}")


def b_no_pump():
    tk_copy_and_destroy("TK-B1")
    poll_open("after Tk copy+destroy, no message pumping")


def b_pump():
    tk_copy_and_destroy("TK-B2")
    r = tk.Tk()
    r.withdraw()
    poll_open("after Tk copy+destroy, pumping Tk messages", pump=r.update)
    r.destroy()


def b_alive():
    r = tk.Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append("TK-B3")
    r.update()
    poll_open("Tk copy, root still alive and pumping", pump=r.update)
    r.destroy()


def d_selection_clear():
    r = tk.Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append("TK-D")
    r.update()
    WC.copy("diag-D1")
    r.update()
    print(f"  Win32 copy after Tk copy: raw={WC.read()!r} tk={tk_read(r)}")
    r.clipboard_clear()
    r.clipboard_append("TK-D2")
    r.update()
    r.selection_clear(selection="CLIPBOARD")
    r.update()
    print(f"  after selection_clear: raw={WC.read()!r}")
    WC.copy("diag-D2")
    r.update()
    print(f"  Win32 copy after selection_clear: raw={WC.read()!r} tk={tk_read(r)}")
    r.destroy()


def e_app():
    from password_tester.app import App
    a = App(autoload=False)
    a.update()
    a._copy("diag-E-secret")
    print(f"  app copy: status={a.status.get()!r} raw={WC.read()!r}")
    a._clear_clip()
    print(f"  app clear: raw={WC.read()!r}")
    a.clipboard_clear()                          # what Ctrl+C in one of the app's entries does
    a.clipboard_append("user Ctrl+C text")
    a.update()
    a._copy("diag-E-secret2")
    print(f"  app copy after a Tk copy: status={a.status.get()!r} raw={WC.read()!r}")
    a._clear_clip()
    print(f"  app clear: raw={WC.read()!r}")
    a.destroy()


print(sys.version.split()[0], sys.platform, "Tk", tk.TkVersion, "pid", ME)
for name, fn in (("B1 Tk copy, destroyed, no pump", b_no_pump), ("B2 Tk copy, destroyed, pump", b_pump),
                 ("B3 Tk copy, alive", b_alive), ("D selection_clear", d_selection_clear),
                 ("E real app", e_app)):
    run(name, fn)
