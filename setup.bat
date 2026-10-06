@echo off
REM SPDX-License-Identifier: Apache-2.0
python -m venv .venv || exit /b 1
.venv\Scripts\python -m pip install -r requirements-dev.txt
