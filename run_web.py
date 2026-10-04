#!/usr/bin/env python3
"""
PhishLens Web Runner: Launches the interactive browser-based SOC dashboard.
"""

import argparse
import sys
import webbrowser
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishlens.web.server import start_server


def main():
    parser = argparse.ArgumentParser(description="Launch PhishLens Web SOC Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Port to run web server on")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    print(f"\n==================================================================")
    print(f"  PHISHLENS: Interactive Email Forensics & Threat Intel Pipeline  ")
    print(f"==================================================================")
    print(f"[*] Starting local SOC Dashboard on: {url}")
    print(f"[*] Press CTRL+C to terminate.")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    start_server(port=args.port)


if __name__ == "__main__":
    main()
