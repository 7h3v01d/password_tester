# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Win32 clipboard logic. Fakes test the call sequence everywhere; the last test hits real Win32 on Windows."""
import struct
import sys

import pytest

from password_tester import clipboard as cb


class FakeUser32:
    def __init__(self, open_fails=0, set_fails_for=None):
        self.open_fails, self.set_fails_for = open_fails, set_fails_for
        self.log, self.data, self.formats = [], {}, {}

    def OpenClipboard(self, hwnd):
        self.log.append("open")
        if self.open_fails:
            self.open_fails -= 1
            return 0
        return 1

    def CloseClipboard(self):
        self.log.append("close")
        return 1

    def EmptyClipboard(self):
        self.log.append("empty")
        self.data.clear()
        return 1

    def RegisterClipboardFormatW(self, name):
        return self.formats.setdefault(name, 0xC000 + len(self.formats))

    def SetClipboardData(self, fmt, h):
        if fmt == self.set_fails_for:
            return 0
        self.data[fmt] = h
        return h


class FakeKernel32:
    def __init__(self):
        self.mem, self.freed, self.next = {}, [], 1

    def GlobalAlloc(self, flags, size):
        h, self.next = self.next, self.next + 1
        self.mem[h] = bytearray(size)
        return h

    def GlobalLock(self, h):
        return h

    def GlobalUnlock(self, h):
        return 1

    def GlobalFree(self, h):
        self.freed.append(h)
        return 0


def make(**kw):
    u, k = FakeUser32(**kw), FakeKernel32()

    def memmove(dst, src, n):
        k.mem[dst][:n] = src[:n]
    return cb.WinClipboard(u, k, memmove, retries=3, delay=0), u, k


def test_copy_writes_text_and_all_privacy_formats():
    w, u, k = make()
    w.copy("pässwörd")
    assert k.mem[u.data[cb.CF_UNICODETEXT]] == "pässwörd\0".encode("utf-16-le")
    for name in cb.SECRET_FORMATS:
        assert struct.unpack("<I", bytes(k.mem[u.data[u.formats[name]]]))[0] == 0
    assert u.log == ["open", "empty", "close"]


def test_busy_clipboard_retries_then_raises_and_never_closes_unopened():
    w, u, _ = make(open_fails=99)
    with pytest.raises(OSError):
        w.copy("x")
    assert u.log == ["open"] * 3


def test_busy_clipboard_recovers_within_retries():
    w, u, _ = make(open_fails=2)
    w.copy("x")
    assert u.log[-1] == "close" and cb.CF_UNICODETEXT in u.data


def test_failed_set_frees_memory_and_still_closes():
    w, u, k = make(set_fails_for=cb.CF_UNICODETEXT)
    with pytest.raises(OSError):
        w.copy("x")
    assert k.freed and u.log[-1] == "close"


def test_clear_empties_and_closes():
    w, u, _ = make()
    w.copy("x")
    w.clear()
    assert not u.data and u.log[-2:] == ["empty", "close"]


@pytest.mark.skipif(sys.platform != "win32", reason="real Win32 clipboard")
def test_real_windows_clipboard():
    """Overwrites your clipboard while it runs."""
    tk = pytest.importorskip("tkinter")
    w = cb.WinClipboard()
    w.copy("pt-test-é✓")
    root = tk.Tk()
    try:
        assert root.clipboard_get() == "pt-test-é✓"
        for name in cb.SECRET_FORMATS:
            assert w.user32.IsClipboardFormatAvailable(w.user32.RegisterClipboardFormatW(name)), name
        w.clear()
        assert not w.user32.IsClipboardFormatAvailable(cb.CF_UNICODETEXT)
    finally:
        root.destroy()
