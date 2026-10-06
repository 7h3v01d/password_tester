@echo off
REM SPDX-License-Identifier: Apache-2.0
if exist "%~dp0.venv\Scripts\python.exe" ("%~dp0.venv\Scripts\python" -m pytest "%~dp0tests" -q %*) else (python -m pytest "%~dp0tests" -q %*)
