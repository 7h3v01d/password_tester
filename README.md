# Password Tester

Local password strength tester, generator, personal-info check and Have I Been Pwned breach explorer.
Tkinter only; no third-party runtime packages. Apache-2.0, © Leon Priest (GitHub: 7h3v01d).

```
setup.bat      # .venv + pytest
run.bat        # or: set PYTHONPATH=src && python -m password_tester
test.bat
```

Layout: `src/password_tester/` — `engine.py` (scoring, pure), `generator.py`, `hibp.py` (network + cache),
`report.py`, `wordlists.py`, `clipboard.py` (Windows: copies skip Win+V history and cloud sync), `data.py` (built-in lists), `app.py` (GUI). Drop bigger lists into `data/`
(see `data/README.md`) — the scorer is only as good as its dictionary.

Breach data: Have I Been Pwned (haveibeenpwned.com), CC BY 4.0.

`tests/test_clipboard.py::test_real_windows_clipboard` runs only on Windows and briefly overwrites your clipboard.
