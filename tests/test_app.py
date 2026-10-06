# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""GUI behaviour. Needs a display (normal on Windows)."""
import json
import secrets
import string
import time

import pytest

tk = pytest.importorskip("tkinter")
from password_tester import app as appmod, hibp  # noqa: E402

BR = lambda t: {"Name": t, "Title": t, "Domain": t.lower() + ".com", "BreachDate": "2019-01-01",  # noqa: E731
                "AddedDate": "2019-02-01T00:00:00Z", "PwnCount": 10, "Description": "<b>x</b>",
                "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    p = tmp_path / "cache.json"
    monkeypatch.setattr(hibp, "cache_path", lambda: str(p))
    return p


@pytest.fixture
def app(cache):
    try:
        a = appmod.App(autoload=False)
    except tk.TclError:
        pytest.skip("no display")
    a.errors = []
    a.report_callback_exception = lambda *e: a.errors.append(e[1])
    yield a
    a.destroy()


def pump(a, cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        a.update()
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_long_password_renders_without_error(app):
    app.pw_var.set("".join(secrets.choice(string.ascii_letters + string.digits + "!@#") for _ in range(400)))
    app.update()
    assert not app.errors and app.result["crack_time"] == "trillions of years"


def test_masked_view_hides_fragments_and_derived_suggestion(app):
    app.pv["names"].set("Jane Tan")
    app.pw_var.set("Jane1990qwerty!")
    app.update()
    text = app.report.get("1.0", "end")
    assert "qwerty" not in text and "1990" not in text and "Jane" not in text
    assert app.sugg_entries[0].cget("show") == "•"
    app.show_var.set(True)
    app.update()
    assert "qwerty" in app.report.get("1.0", "end") and app.sugg_entries[0].cget("show") == ""


def test_export_failure_reports_in_status(app, monkeypatch, tmp_path):
    app.pw_var.set("Hello2024!")
    monkeypatch.setattr(appmod.filedialog, "asksaveasfilename", lambda **k: str(tmp_path))   # a directory
    app._export()
    app.update()
    assert not app.errors and app.status.get().startswith("Couldn't save")


def test_clipboard_cleared_on_exit_tk_path(cache):
    a = appmod.App(autoload=False)
    a._winclip = None                            # force the Tk path on every platform
    calls = []
    a._copy("Secret-Pass-123!")
    real = a.clipboard_clear
    a.clipboard_clear = lambda: (calls.append(1), real())[1]
    a.destroy()
    assert calls, "destroy() must clear a password it copied"


class FakeWinClip:
    def __init__(self, app, fail=False):
        self.app, self.fail, self.copied, self.cleared = app, fail, [], 0

    def copy(self, text):
        if self.fail:
            raise OSError("busy")
        self.copied.append(text)
        self.app.clipboard_clear()               # mirror the text so clipboard_get() sees it
        self.app.clipboard_append(text)

    def clear(self):
        self.cleared += 1


def test_windows_path_used_and_cleared_on_exit(cache):
    a = appmod.App(autoload=False)
    a._winclip = fake = FakeWinClip(a)
    a._copy("Secret-Pass-123!")
    assert fake.copied == ["Secret-Pass-123!"] and "history" in a.status.get()
    a.destroy()
    assert fake.cleared == 1


def test_windows_path_failure_falls_back_to_tk(cache):
    a = appmod.App(autoload=False)
    a._winclip = FakeWinClip(a, fail=True)
    a._copy("Secret-Pass-123!")
    assert a.clipboard_get() == "Secret-Pass-123!" and "history" not in a.status.get()
    a.destroy()


def test_startup_survives_corrupt_cache(cache):
    cache.write_text(json.dumps({"fetched": 1, "data": [{"Title": None}]}))
    appmod.App(autoload=False).destroy()


def test_refresh_does_not_kick_user_out_of_email_results(app, monkeypatch):
    monkeypatch.setattr(hibp, "hibp_get", lambda path, key=None, timeout=30:
                        [BR("Mine")] if path.startswith("breachedaccount") else [BR("A"), BR("B")])
    app.em.set("me@example.com")
    app.key.set("a" * 32)
    app._lookup_email()
    assert pump(app, lambda: app.mode == "email")
    app._fetch_catalog()
    assert pump(app, lambda: "loaded" in app.ex_status.cget("text"))
    assert [b["Title"] for b in app.shown] == ["Mine"]


def test_latest_lookup_wins(app, monkeypatch):
    def slow(path, key=None, timeout=30):
        if "first%40" in path:
            time.sleep(0.5)
            return [BR("FirstOnly")]
        return [BR("SecondOnly")]
    monkeypatch.setattr(hibp, "hibp_get", slow)
    app.key.set("a" * 32)
    app.em.set("first@example.com")
    app._lookup_email()
    app.em.set("second@example.com")
    app._lookup_email()
    pump(app, lambda: False, timeout=1.0)
    assert [b["Title"] for b in app.shown] == ["SecondOnly"]


def test_demo_does_not_leave_test_key(app, monkeypatch):
    monkeypatch.setattr(hibp, "hibp_get", lambda path, key=None, timeout=30: [BR("T")])
    app._demo()
    assert pump(app, lambda: app.mode == "email")
    assert app.key.get() == ""


def test_bad_catalogue_shape_reports_error(app, monkeypatch):
    monkeypatch.setattr(hibp, "hibp_get", lambda path, key=None, timeout=30: {"error": "challenge"})
    app._fetch_catalog()
    assert pump(app, lambda: "Couldn't load" in app.ex_status.cget("text") or app.errors)
    assert not app.errors


def test_breach_check_message(app, monkeypatch):
    monkeypatch.setattr(hibp, "pwned_count", lambda pw: 1)
    app.pw_var.set("hunter2")
    app._check_breach()
    assert pump(app, lambda: "once" in app.breach[0])
