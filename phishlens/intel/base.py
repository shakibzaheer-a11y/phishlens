"""
Base Threat Intel Client with SQLite caching, response normalization, and offline mock support.
"""

import sqlite3
import json
import time
from typing import Dict, Any, Optional
from pathlib import Path

from config import CACHE_DB_PATH, CACHE_TTL_HOURS


class BaseIntelClient:
    """Abstract base class for threat intel service clients with caching."""

    def __init__(self, service_name: str, api_key: str = "", offline_mode: bool = False):
        self.service_name = service_name
        self.api_key = api_key
        self.offline_mode = offline_mode
        self._init_cache()

    def _init_cache(self):
        """Initializes SQLite database for intel query caching."""
        try:
            db_path = Path(CACHE_DB_PATH)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS intel_cache (
                        service TEXT,
                        indicator TEXT,
                        indicator_type TEXT,
                        response_json TEXT,
                        timestamp REAL,
                        PRIMARY KEY (service, indicator, indicator_type)
                    )
                """)
                conn.commit()
        except Exception:
            pass

    def get_cached(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached response if valid within TTL."""
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT response_json, timestamp FROM intel_cache WHERE service=? AND indicator=? AND indicator_type=?",
                    (self.service_name, indicator, indicator_type)
                )
                row = cursor.fetchone()
                if row:
                    cached_json, ts = row
                    ttl_seconds = CACHE_TTL_HOURS * 3600
                    if time.time() - ts < ttl_seconds:
                        return json.loads(cached_json)
        except Exception:
            return None
        return None

    def save_cache(self, indicator: str, indicator_type: str, data: Dict[str, Any]):
        """Persists query response to local SQLite cache."""
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO intel_cache (service, indicator, indicator_type, response_json, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (self.service_name, indicator, indicator_type, json.dumps(data), time.time())
                )
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def normalize_verdict(
        service: str,
        indicator: str,
        indicator_type: str,
        is_malicious: bool,
        is_suspicious: bool = False,
        threat_score: int = 0,
        detections: int = 0,
        total_engines: int = 0,
        details: str = "",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Produces a standardized threat intelligence verdict dictionary."""
        status = "clean"
        if is_malicious:
            status = "malicious"
        elif is_suspicious:
            status = "suspicious"

        return {
            "service": service,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": status,
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "threat_score": threat_score,
            "detections": detections,
            "total_engines": total_engines,
            "details": details,
            "raw_data": raw_data or {}
        }
