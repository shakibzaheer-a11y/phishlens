"""
URLhaus (abuse.ch) Threat Intelligence Integration.
Queries public URLhaus database for active malware and phishing URLs.
"""

import requests
from typing import Dict, Any, Optional
from phishlens.intel.base import BaseIntelClient
from config import HTTP_TIMEOUT_SECONDS


class URLhausClient(BaseIntelClient):
    """Integrates with URLhaus API for malicious URL detection."""

    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, api_key: str = "", offline_mode: bool = False):
        super().__init__("URLhaus", api_key, offline_mode)

    def check_url(self, target_url: str) -> Dict[str, Any]:
        """Queries URLhaus for a specific URL."""
        cached = self.get_cached(target_url, "url")
        if cached:
            return cached

        if self.offline_mode:
            verdict = self._mock_url_lookup(target_url)
            self.save_cache(target_url, "url", verdict)
            return verdict

        try:
            data = {"url": target_url}
            headers = {}
            if self.api_key:
                headers["Auth-Key"] = self.api_key

            resp = requests.post(self.API_URL, data=data, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
            if resp.status_code == 200:
                res_json = resp.json()
                query_status = res_json.get("query_status", "")
                if query_status == "ok":
                    url_status = res_json.get("url_status", "")
                    threat = res_json.get("threat", "malware_download")
                    tags = res_json.get("tags") or []
                    verdict = self.normalize_verdict(
                        service="URLhaus",
                        indicator=target_url,
                        indicator_type="url",
                        is_malicious=True,
                        threat_score=90,
                        detections=1,
                        total_engines=1,
                        details=f"Listed in URLhaus database: Threat='{threat}', Status='{url_status}', Tags={tags}",
                        raw_data=res_json
                    )
                else:
                    verdict = self.normalize_verdict(
                        service="URLhaus",
                        indicator=target_url,
                        indicator_type="url",
                        is_malicious=False,
                        threat_score=0,
                        detections=0,
                        total_engines=1,
                        details="Not listed in URLhaus database",
                        raw_data=res_json
                    )
            else:
                verdict = self._mock_url_lookup(target_url)
        except Exception:
            verdict = self._mock_url_lookup(target_url)

        self.save_cache(target_url, "url", verdict)
        return verdict

    def _mock_url_lookup(self, target_url: str) -> Dict[str, Any]:
        """Offline simulation for test scenarios."""
        target_lower = target_url.lower()
        if any(term in target_lower for term in ["malware", "payload", "dropper", "trojan", "evil.exe"]):
            return self.normalize_verdict(
                service="URLhaus (Simulated)",
                indicator=target_url,
                indicator_type="url",
                is_malicious=True,
                threat_score=95,
                detections=1,
                total_engines=1,
                details="Listed in URLhaus malware distribution feed (Simulated test hit)"
            )
        return self.normalize_verdict(
            service="URLhaus (Simulated)",
            indicator=target_url,
            indicator_type="url",
            is_malicious=False,
            threat_score=0,
            detections=0,
            total_engines=1,
            details="Not listed in URLhaus malware database"
        )
