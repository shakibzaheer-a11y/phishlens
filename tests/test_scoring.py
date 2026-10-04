"""
Unit tests for Scoring Rules, Scoring Engine, and ML Feature Extraction.
"""

import pytest
from phishlens.scoring.rules import RuleSPFFail, RuleURLTextMismatch, RuleDoubleExtensionAttachment
from phishlens.scoring.engine import ScoringEngine


def test_rule_spf_fail():
    rule = RuleSPFFail()
    triggered, detail = rule.evaluate({"authentication": {"spf": {"verdict": "fail"}}}, {})
    assert triggered is True
    assert "FAIL" in detail

    triggered_pass, _ = rule.evaluate({"authentication": {"spf": {"verdict": "pass"}}}, {})
    assert triggered_pass is False


def test_rule_url_mismatch():
    rule = RuleURLTextMismatch()
    mock_email = {
        "urls": [{
            "text_mismatch": True,
            "mismatch_detail": "Anchor text shows 'google.com' but link points to 'evil.com'"
        }]
    }
    triggered, detail = rule.evaluate(mock_email, {})
    assert triggered is True
    assert "deceptive link" in detail


def test_scoring_engine_composite():
    engine = ScoringEngine()
    mock_email = {
        "authentication": {"spf": {"verdict": "fail"}, "dkim": {"verdict": "fail"}, "dmarc": {"verdict": "fail"}},
        "sender_analysis": {"reply_to_mismatch": True, "display_name_spoof": True, "spoof_indicator": "Spoofed Brand"},
        "urls": [{"text_mismatch": True, "mismatch_detail": "Mismatch", "is_ip": False, "is_suspicious_tld": True, "tld": "xyz"}],
        "attachments": [{"has_double_ext": True, "filename": "inv.pdf.exe", "is_suspicious_ext": True, "magic_mz": True}],
        "body_analysis": {"urgency_count": 3, "detected_urgency_keywords": ["urgent", "immediately"]}
    }
    mock_intel = {
        "total_malicious_indicators": 2,
        "sender_domain_age": {"is_malicious": True, "details": "New domain"},
        "sender_ip_intel": {"is_malicious": True}
    }

    results = engine.evaluate(mock_email, mock_intel)
    assert results["risk_score"] >= 75
    assert results["verdict"] == "MALICIOUS"
    assert results["risk_level"] == "CRITICAL"
    assert len(results["triggered_rules"]) >= 4

    features = results["features"]
    assert features["feat_spf_fail"] == 1.0
    assert features["feat_has_double_ext"] == 1.0
    assert features["feat_urgency_count"] == 3.0
