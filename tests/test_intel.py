"""
Unit tests for Threat Intel Clients and Caching.
"""

import pytest
from phishlens.intel.virustotal import VirusTotalClient
from phishlens.intel.urlhaus import URLhausClient
from phishlens.intel.abuseipdb import AbuseIPDBClient
from phishlens.intel.rdap_whois import RDAPClient
from phishlens.intel.intel_manager import IntelManager


def test_virustotal_mock_hash():
    vt = VirusTotalClient(offline_mode=True)
    # Test EICAR hash
    res = vt.check_hash("44d88612fea8a8f36de82e1278abb02f")
    assert res["is_malicious"] is True
    assert res["threat_score"] > 80


def test_urlhaus_mock_url():
    uh = URLhausClient(offline_mode=True)
    res = uh.check_url("http://malware-payload-drop.xyz/dropper.exe")
    assert res["is_malicious"] is True


def test_abuseipdb_private_ip():
    ip_client = AbuseIPDBClient(offline_mode=True)
    res = ip_client.check_ip("192.168.1.1")
    assert res["is_malicious"] is False
    assert "Private" in res["details"]


def test_rdap_domain_age():
    rdap = RDAPClient(offline_mode=True)
    res = rdap.check_domain_age("microsoft.com")
    assert res["is_malicious"] is False
    assert "Established" in res["details"]

    res_phish = rdap.check_domain_age("sec-m365-verify.xyz")
    assert res_phish["is_malicious"] is True
    assert res_phish["raw_data"]["is_new_domain"] is True


def test_intel_manager_enrichment():
    mgr = IntelManager(offline_mode=True)
    mock_parsed = {
        "sender_analysis": {
            "from_domain": "sec-m365-verify.xyz",
            "originating_ip": "185.220.101.5"
        },
        "urls": [{"url": "http://login-security-update.xyz/auth"}],
        "attachments": []
    }
    enriched = mgr.enrich(mock_parsed)
    assert enriched["total_malicious_indicators"] >= 1
