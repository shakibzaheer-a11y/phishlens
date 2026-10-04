"""
Configuration management for PhishLens.
Supports reading from environment variables or .env file.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Threat Intel API Keys (optional; pipeline falls back gracefully to mock/heuristics)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")

# Cache settings
CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", str(BASE_DIR / "cache.db"))
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))

# Network timeouts
HTTP_TIMEOUT_SECONDS = int(os.getenv("HTTP_TIMEOUT_SECONDS", "5"))
MAX_REDIRECT_HOPS = int(os.getenv("MAX_REDIRECT_HOPS", "5"))

# Offline / Mock mode (default true if no API keys provided)
OFFLINE_MODE = os.getenv("PHISHLENS_OFFLINE", "false").lower() in ("1", "true", "yes")

# High-risk extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".cpl", ".msc", ".jar", ".ps1", ".iso",
    ".img", ".dmg", ".dll", ".pif", ".application", ".gadget"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".potm", ".ppam"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "buzz", "cn", "ru", "work", "tk", "ml", "ga", "cf", "gq",
    "loan", "click", "rest", "fit", "live", "country", "stream", "download"
}
