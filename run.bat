@echo off
REM SPDX-License-Identifier: Apache-2.0
set PYTHONPATH=%~dp0src
if exist "%~dp0.venv\Scripts\pythonw.exe" ("%~dp0.venv\Scripts\pythonw" -m password_tester) else (pythonw -m password_tester)
