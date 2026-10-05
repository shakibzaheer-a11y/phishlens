#!/usr/bin/env bash
set -e

echo "==================================================="
echo "  PhishLens - Collaborator Workspace Setup"
echo "==================================================="

if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed or not in PATH."
    exit 1
fi

echo "[*] Creating virtual environment (.venv)..."
python3 -m venv .venv

echo "[*] Activating virtual environment..."
source .venv/bin/activate

echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Running unit test suite..."
pytest

echo ""
echo "==================================================="
echo "  Setup Complete!"
echo "  Open 'phishlens.code-workspace' in VS Code:"
echo "  code phishlens.code-workspace"
echo "==================================================="
