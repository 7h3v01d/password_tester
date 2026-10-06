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
        self.log, self.data, self.formats, self.seq = [], {}, {}, 100

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
        self.seq += 1
        return 1

    def GetClipboardSequenceNumber(self):
        return self.seq

    def GetClipboardData(self, fmt):
        return self.data.get(fmt, 0)

    def RegisterClipboardFormatW(self, name):
        return self.formats.setdefault(name, 0xC000 + len(self.formats))

    def SetClipboardData(self, fmt, h):
        if fmt == self.set_fails_for:
            return 0
        self.data[fmt] = h
        self.seq += 1
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
    def wstring_at(p):
        return bytes(k.mem[p]).decode("utf-16-le").split("\0")[0]
    return cb.WinClipboard(u, k, memmove, wstring_at, retries=3, delay=0), u, k


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


def test_read_returns_text_from_windows_not_tk():
    w, _, _ = make()
    w.copy("pässwörd")
    assert w.read() == "pässwörd"


def test_clear_if_unchanged_only_clears_our_own_write():
    w, u, _ = make()
    seq = w.copy("secret")
    assert w.clear_if_unchanged(seq) and not u.data
    seq = w.copy("secret")
    u.seq += 1                                   # someone else copied something since
    assert not w.clear_if_unchanged(seq) and u.data


@pytest.mark.skipif(sys.platform != "win32", reason="real Win32 clipboard")
def test_real_windows_clipboard():
    """Overwrites your clipboard while it runs. Reads via Win32: Tk's view can be stale (see clipdiag)."""
    w = cb.WinClipboard()
    seq = w.copy("pt-test-é✓")
    assert w.read() == "pt-test-é✓"
    for name in cb.SECRET_FORMATS:
        assert w.user32.IsClipboardFormatAvailable(w.user32.RegisterClipboardFormatW(name)), name
    assert w.clear_if_unchanged(seq)
    assert w.read() is None
