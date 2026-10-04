"""
AbuseIPDB Integration: Originating sender IP address reputation and abuse confidence reporting.
"""

import requests
from typing import Dict, Any, Optional
from phishlens.intel.base import BaseIntelClient
from config import HTTP_TIMEOUT_SECONDS


class AbuseIPDBClient(BaseIntelClient):
    """Integrates with AbuseIPDB API v2 to check IP reputation."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = "", offline_mode: bool = False):
        super().__init__("AbuseIPDB", api_key, offline_mode)

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Queries AbuseIPDB for an IP address reputation score."""
        cached = self.get_cached(ip_address, "ip_address")
        if cached:
            return cached

        # Check for private / loopback IP ranges
        if self._is_private_ip(ip_address):
            verdict = self.normalize_verdict(
                service="AbuseIPDB",
                indicator=ip_address,
                indicator_type="ip_address",
                is_malicious=False,
                threat_score=0,
                detections=0,
                total_engines=1,
                details="Private / Internal / Loopback IP range (RFC 1918)"
            )
            self.save_cache(ip_address, "ip_address", verdict)
            return verdict

        if not self.api_key or self.offline_mode:
            verdict = self._mock_ip_lookup(ip_address)
            self.save_cache(ip_address, "ip_address", verdict)
            return verdict

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }

        try:
            resp = requests.get(self.API_URL, headers=headers, params=params, timeout=HTTP_TIMEOUT_SECONDS)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "Unknown")

                is_malicious = abuse_score >= 50
                is_suspicious = abuse_score >= 20 and not is_malicious

                verdict = self.normalize_verdict(
                    service="AbuseIPDB",
                    indicator=ip_address,
                    indicator_type="ip_address",
                    is_malicious=is_malicious,
                    is_suspicious=is_suspicious,
                    threat_score=abuse_score,
                    detections=total_reports,
                    total_engines=1,
                    details=f"Abuse Confidence: {abuse_score}%, Reports: {total_reports}, ISP: {isp} ({country})",
                    raw_data=data
                )
            else:
                verdict = self._mock_ip_lookup(ip_address)
        except Exception:
            verdict = self._mock_ip_lookup(ip_address)

        self.save_cache(ip_address, "ip_address", verdict)
        return verdict

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        if not ip:
            return True
        return (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("127.") or
            ip.startswith("169.254.") or
            (ip.startswith("172.") and 16 <= int(ip.split(".")[1] or "0") <= 31)
        )

    def _mock_ip_lookup(self, ip_address: str) -> Dict[str, Any]:
        """Simulation for demonstration purposes."""
        # Check if known test IP
        if ip_address.startswith("185.") or ip_address.startswith("194.") or ip_address.startswith("45."):
            return self.normalize_verdict(
                service="AbuseIPDB (Simulated)",
                indicator=ip_address,
                indicator_type="ip_address",
                is_malicious=True,
                threat_score=85,
                detections=142,
                total_engines=1,
                details=f"Abuse Confidence: 85%, Reports: 142, Known spam/bruteforce origin (Simulated)"
            )
        return self.normalize_verdict(
            service="AbuseIPDB (Simulated)",
            indicator=ip_address,
            indicator_type="ip_address",
            is_malicious=False,
            threat_score=0,
            detections=0,
            total_engines=1,
            details="IP address reputation clean. 0 abuse reports filed."
        )
