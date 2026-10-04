"""
Intel Manager: Orchestrates concurrent threat intelligence lookups across VirusTotal,
URLhaus, AbuseIPDB, and RDAP/WHOIS.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

from phishlens.intel.virustotal import VirusTotalClient
from phishlens.intel.urlhaus import URLhausClient
from phishlens.intel.abuseipdb import AbuseIPDBClient
from phishlens.intel.rdap_whois import RDAPClient
from phishlens.parser.url_extractor import URLExtractor
from config import (
    VIRUSTOTAL_API_KEY, URLHAUS_API_KEY, ABUSEIPDB_API_KEY,
    OFFLINE_MODE
)


class IntelManager:
    """Coordinates threat intel enrichments for all extracted email artifacts."""

    def __init__(self, offline_mode: bool = OFFLINE_MODE):
        self.offline_mode = offline_mode
        self.vt = VirusTotalClient(api_key=VIRUSTOTAL_API_KEY, offline_mode=offline_mode)
        self.urlhaus = URLhausClient(api_key=URLHAUS_API_KEY, offline_mode=offline_mode)
        self.abuseipdb = AbuseIPDBClient(api_key=ABUSEIPDB_API_KEY, offline_mode=offline_mode)
        self.rdap = RDAPClient(offline_mode=offline_mode)

    def enrich(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Runs concurrent enrichment queries across all email IOCs."""
        sender_analysis = parsed_email.get("sender_analysis", {})
        sender_domain = sender_analysis.get("from_domain", "")
        originating_ip = sender_analysis.get("originating_ip")
        urls = parsed_email.get("urls", [])
        attachments = parsed_email.get("attachments", [])

        intel_results = {
            "sender_ip_intel": None,
            "sender_domain_intel": None,
            "sender_domain_age": None,
            "url_intel": [],
            "attachment_intel": [],
            "total_malicious_indicators": 0,
            "total_suspicious_indicators": 0
        }

        with ThreadPoolExecutor(max_workers=8) as executor:
            future_to_task = {}

            # 1. IP Lookup
            if originating_ip:
                future_to_task[executor.submit(self.abuseipdb.check_ip, originating_ip)] = ("ip", originating_ip)

            # 2. Sender Domain Lookups
            if sender_domain:
                future_to_task[executor.submit(self.vt.check_domain, sender_domain)] = ("domain_vt", sender_domain)
                future_to_task[executor.submit(self.rdap.check_domain_age, sender_domain)] = ("domain_rdap", sender_domain)

            # 3. URL Lookups
            for u in urls[:5]:  # Analyze top 5 URLs to manage rate limits
                url_str = u["url"]
                future_to_task[executor.submit(self._enrich_single_url, url_str)] = ("url", url_str)

            # 4. Attachment Hash Lookups
            for att in attachments:
                sha256 = att["sha256"]
                future_to_task[executor.submit(self.vt.check_hash, sha256)] = ("hash", att)

            # Collect results
            for future in as_completed(future_to_task):
                task_type, target = future_to_task[future]
                try:
                    res = future.result()
                    if task_type == "ip":
                        intel_results["sender_ip_intel"] = res
                    elif task_type == "domain_vt":
                        intel_results["sender_domain_intel"] = res
                    elif task_type == "domain_rdap":
                        intel_results["sender_domain_age"] = res
                    elif task_type == "url":
                        intel_results["url_intel"].append(res)
                    elif task_type == "hash":
                        intel_results["attachment_intel"].append({
                            "filename": target["filename"],
                            "sha256": target["sha256"],
                            "intel": res
                        })
                except Exception:
                    pass

        # Calculate total malicious and suspicious flags
        mal_count = 0
        susp_count = 0

        for category in [
            intel_results["sender_ip_intel"],
            intel_results["sender_domain_intel"],
            intel_results["sender_domain_age"]
        ]:
            if category:
                if category.get("is_malicious"):
                    mal_count += 1
                elif category.get("is_suspicious"):
                    susp_count += 1

        for u in intel_results["url_intel"]:
            if u.get("is_malicious"):
                mal_count += 1
            elif u.get("is_suspicious"):
                susp_count += 1

        for att in intel_results["attachment_intel"]:
            intel = att.get("intel", {})
            if intel.get("is_malicious"):
                mal_count += 1
            elif intel.get("is_suspicious"):
                susp_count += 1

        intel_results["total_malicious_indicators"] = mal_count
        intel_results["total_suspicious_indicators"] = susp_count

        return intel_results

    def _enrich_single_url(self, url: str) -> Dict[str, Any]:
        """Queries VirusTotal and URLhaus for a single URL and traces redirects."""
        vt_res = self.vt.check_url(url)
        uh_res = self.urlhaus.check_url(url)
        redirect_res = URLExtractor.trace_redirects(url)

        is_malicious = vt_res.get("is_malicious", False) or uh_res.get("is_malicious", False)
        is_suspicious = vt_res.get("is_suspicious", False) or uh_res.get("is_suspicious", False) or redirect_res.get("is_redirected", False)
        threat_score = max(vt_res.get("threat_score", 0), uh_res.get("threat_score", 0))

        details = []
        if vt_res.get("is_malicious"):
            details.append(f"VirusTotal: {vt_res.get('details')}")
        if uh_res.get("is_malicious"):
            details.append(f"URLhaus: {uh_res.get('details')}")
        if redirect_res.get("is_redirected"):
            details.append(f"Redirect chain detected ({redirect_res.get('hop_count')} hops -> {redirect_res.get('final_url')})")

        return {
            "url": url,
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "threat_score": threat_score,
            "virustotal": vt_res,
            "urlhaus": uh_res,
            "redirects": redirect_res,
            "summary_details": "; ".join(details) if details else "No threat intelligence alerts"
        }
