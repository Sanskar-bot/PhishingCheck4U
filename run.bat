@echo off
cd /d "%~dp0"

if not exist ".env" (
    echo [ERROR] .env file not found.
    echo         Run: copy .env.example .env  and fill in your credentials.
    pause
    exit /b 1
)

if exist "venv\Scripts\python.exe" (
    set PYTHON=venv\Scripts\python.exe
) else (
    set PYTHON=python
)

echo [INFO] Starting PhishingCheck4U...
%PYTHON% start.py
