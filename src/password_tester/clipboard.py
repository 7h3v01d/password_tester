# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Copy secrets so Windows keeps them out of clipboard history (Win+V) and cloud clipboard sync.

Windows honours three registered clipboard formats placed alongside the text:
  ExcludeClipboardContentFromMonitorProcessing   - history, cloud and clipboard monitors skip it
  CanIncludeInClipboardHistory = DWORD 0         - not saved to Win+V history
  CanUploadToCloudClipboard    = DWORD 0         - not synced to other devices
Tk's own clipboard API can't add extra formats, hence ctypes. On other platforms `available()`
is False and the app falls back to Tk.
"""
import ctypes
import sys
import time

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
SECRET_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing",
                  "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")
_DWORD_ZERO = b"\x00\x00\x00\x00"


def available():
    return sys.platform == "win32"


class WinClipboard:
    def __init__(self, user32=None, kernel32=None, memmove=None, retries=10, delay=0.02):
        if user32 is None or kernel32 is None:
            user32, kernel32 = self._load()
        self.user32, self.kernel32 = user32, kernel32
        self._memmove = memmove or ctypes.memmove
        self.retries, self.delay = retries, delay

    @staticmethod
    def _load():
        from ctypes import wintypes as w
        u = ctypes.WinDLL("user32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        # Handles are pointer-sized: without explicit restypes they'd be truncated to 32 bits on x64.
        for fn, args, res in ((u.OpenClipboard, [w.HWND], w.BOOL), (u.CloseClipboard, [], w.BOOL),
                              (u.EmptyClipboard, [], w.BOOL), (u.SetClipboardData, [w.UINT, w.HANDLE], w.HANDLE),
                              (u.RegisterClipboardFormatW, [w.LPCWSTR], w.UINT),
                              (u.IsClipboardFormatAvailable, [w.UINT], w.BOOL),
                              (k.GlobalAlloc, [w.UINT, ctypes.c_size_t], w.HGLOBAL),
                              (k.GlobalLock, [w.HGLOBAL], w.LPVOID), (k.GlobalUnlock, [w.HGLOBAL], w.BOOL),
                              (k.GlobalFree, [w.HGLOBAL], w.HGLOBAL)):
            fn.argtypes, fn.restype = args, res
        return u, k

    def _open(self):
        for _ in range(self.retries):            # another app may hold the clipboard briefly
            if self.user32.OpenClipboard(None):
                return
            time.sleep(self.delay)
        raise OSError("clipboard is busy")

    def _put(self, fmt, data):
        k = self.kernel32
        h = k.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not h:
            raise OSError("GlobalAlloc failed")
        p = k.GlobalLock(h)
        if not p:
            k.GlobalFree(h)
            raise OSError("GlobalLock failed")
        try:
            self._memmove(p, data, len(data))
        finally:
            k.GlobalUnlock(h)
        if not self.user32.SetClipboardData(fmt, h):
            k.GlobalFree(h)                      # ownership only passes to Windows on success
            raise OSError("SetClipboardData failed")

    def copy(self, text):
        self._open()
        try:
            if not self.user32.EmptyClipboard():
                raise OSError("EmptyClipboard failed")
            self._put(CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
            for name in SECRET_FORMATS:
                fmt = self.user32.RegisterClipboardFormatW(name)
                if fmt:
                    self._put(fmt, _DWORD_ZERO)
        finally:
            self.user32.CloseClipboard()

    def clear(self):
        self._open()
        try:
            self.user32.EmptyClipboard()
        finally:
            self.user32.CloseClipboard()
