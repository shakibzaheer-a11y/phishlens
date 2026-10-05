@echo off
setlocal
echo ===================================================
echo   PhishLens - Collaborator Workspace Setup
echo ===================================================

echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python is not installed or not in PATH.
    echo     Please install Python 3.10+ from python.org and re-run this script.
    pause
    exit /b 1
)

echo [*] Creating virtual environment (.venv)...
python -m venv .venv

echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [*] Installing project dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo [*] Running test suite to verify setup...
python -m pytest

echo.
echo ===================================================
echo   Setup Complete!
echo   Double-click 'phishlens.code-workspace' to open
echo   and edit this project in VS Code.
echo ===================================================
echo.
pause
