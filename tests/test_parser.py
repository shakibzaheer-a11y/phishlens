"""
Unit tests for Email Parser, Auth Validator, URL Extractor, and Attachment Extractor.
"""

import pytest
from pathlib import Path
from phishlens.parser.email_parser import EmailParser
from phishlens.parser.auth_validator import AuthValidator
from phishlens.parser.url_extractor import URLExtractor, defang_url, refang_url

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"


def test_defang_and_refang():
    original = "https://evil-phish.xyz/login?id=123"
    defanged = defang_url(original)
    assert defanged == "hxxps[://]evil-phish[.]xyz/login?id=123"
    assert refang_url(defanged) == original


def test_url_extractor_mismatch():
    html = '<a href="http://evil-domain.xyz">https://legit-bank.com/login</a>'
    extracted = URLExtractor.extract_from_html_and_text(html, "")
    assert len(extracted) == 1
    item = extracted[0]
    assert item["text_mismatch"] is True
    assert "evil-domain.xyz" in item["mismatch_detail"]


def test_auth_validator_parsing():
    headers = {
        "Authentication-Results": "mx.test.com; spf=pass (client-ip=1.2.3.4); dkim=pass header.d=test.com; dmarc=pass"
    }
    res = AuthValidator.parse_auth_headers(headers)
    assert res["spf"]["verdict"] == "pass"
    assert res["dkim"]["verdict"] == "pass"
    assert res["dmarc"]["verdict"] == "pass"
    assert res["all_passed"] is True
    assert res["any_failed"] is False


def test_parse_phishing_sample():
    sample_path = SAMPLES_DIR / "phishing" / "m365_credential_harvest.eml"
    assert sample_path.is_file()

    parsed = EmailParser.parse_file(str(sample_path))
    assert "Password Expires" in parsed["metadata"]["subject"]
    assert parsed["sender_analysis"]["reply_to_mismatch"] is True
    assert parsed["authentication"]["spf"]["verdict"] == "fail"
    assert len(parsed["urls"]) > 0


def test_parse_attachment_sample():
    sample_path = SAMPLES_DIR / "phishing" / "fake_invoice_malware.eml"
    assert sample_path.is_file()

    parsed = EmailParser.parse_file(str(sample_path))
    assert parsed["metadata"]["has_attachments"] is True
    assert parsed["metadata"]["attachment_count"] == 1

    att = parsed["attachments"][0]
    assert att["has_double_ext"] is True
    assert att["magic_mz"] is True
    assert len(att["sha256"]) == 64
