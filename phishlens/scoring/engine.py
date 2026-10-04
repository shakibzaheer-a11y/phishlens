"""
Scoring & Classification Engine: Aggregates rule weights, computes composite Phishing Risk Score (0-100),
assigns forensic verdicts, and extracts numerical feature vectors for ML evaluation.
"""

from typing import Dict, Any, List
from phishlens.scoring.rules import DEFAULT_RULES, ForensicRule


class ScoringEngine:
    """Core scoring and risk classification engine."""

    def __init__(self, rules: List[ForensicRule] = None):
        self.rules = rules or DEFAULT_RULES

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Dict[str, Any]:
        """Runs all rules and computes the composite forensic risk verdict."""
        triggered_rules = []
        raw_score = 0
        total_possible = sum(r.weight for r in self.rules)

        for rule in self.rules:
            triggered, detail = rule.evaluate(parsed_email, intel_results)
            if triggered:
                triggered_rules.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "category": rule.category,
                    "severity": rule.severity,
                    "weight": rule.weight,
                    "description": rule.description,
                    "detail": detail
                })
                raw_score += rule.weight

        # Normalize score into 0-100 range with non-linear saturation for critical hits
        # (e.g., threat intel hits or double extensions should guarantee high severity)
        has_critical = any(r["severity"] == "CRITICAL" for r in triggered_rules)
        has_high = any(r["severity"] == "HIGH" for r in triggered_rules)

        calculated_score = min(raw_score, 100)
        if has_critical and calculated_score < 75:
            calculated_score = max(calculated_score, 75)
        elif has_high and calculated_score < 50:
            calculated_score = max(calculated_score, 50)

        # Verdict classification
        if calculated_score >= 75:
            verdict = "MALICIOUS"
            risk_level = "CRITICAL"
            color = "#ef4444"  # Red
            recommendation = (
                "IMMEDIATE ACTION REQUIRED: Quarantine or delete email immediately. Block sender address, "
                "add originating IP to edge firewall blacklist, and inspect endpoints if attachments were opened."
            )
        elif calculated_score >= 50:
            verdict = "HIGH RISK"
            risk_level = "HIGH"
            color = "#f97316"  # Orange
            recommendation = (
                "HIGH SUSPICION: Quarantining advised. Significant phishing and impersonation indicators detected. "
                "Do not click links or execute attachments without sandbox detonation."
            )
        elif calculated_score >= 25:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
            color = "#eab308"  # Yellow
            recommendation = (
                "CAUTION ADVISED: Minor security anomalies identified (e.g. unverified sender or urgency cues). "
                "Verify sender authenticity via an out-of-band channel before taking action."
            )
        else:
            verdict = "BENIGN"
            risk_level = "LOW"
            color = "#22c55e"  # Green
            recommendation = (
                "CLEAN: Email conforms to standard authentication protocols and exhibits no known malicious indicators. "
                "Safe for regular delivery."
            )

        # Extract ML feature vector
        features = self.extract_features(parsed_email, intel_results)

        return {
            "risk_score": calculated_score,
            "verdict": verdict,
            "risk_level": risk_level,
            "theme_color": color,
            "recommendation": recommendation,
            "triggered_rules_count": len(triggered_rules),
            "triggered_rules": triggered_rules,
            "features": features,
            "rule_breakdown_by_category": self._breakdown_by_category(triggered_rules)
        }

    @staticmethod
    def _breakdown_by_category(triggered_rules: List[Dict[str, Any]]) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for r in triggered_rules:
            cat = r["category"]
            breakdown[cat] = breakdown.get(cat, 0) + 1
        return breakdown

    @staticmethod
    def extract_features(parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Dict[str, float]:
        """
        Extracts 15 numerical and normalized features suitable for training or evaluating ML classifiers.
        """
        auth = parsed_email.get("authentication", {})
        sender = parsed_email.get("sender_analysis", {})
        urls = parsed_email.get("urls", [])
        atts = parsed_email.get("attachments", [])
        body = parsed_email.get("body_analysis", {})

        # Domain age
        domain_age_info = intel_results.get("sender_domain_age", {}).get("raw_data", {})
        domain_age_days = float(domain_age_info.get("age_days") or 365.0)

        return {
            "feat_spf_fail": 1.0 if auth.get("spf", {}).get("verdict") in ("fail", "softfail") else 0.0,
            "feat_dkim_fail": 1.0 if auth.get("dkim", {}).get("verdict") == "fail" else 0.0,
            "feat_dmarc_fail": 1.0 if auth.get("dmarc", {}).get("verdict") in ("fail", "reject") else 0.0,
            "feat_reply_to_mismatch": 1.0 if sender.get("reply_to_mismatch") else 0.0,
            "feat_display_spoof": 1.0 if sender.get("display_name_spoof") else 0.0,
            "feat_url_count": float(len(urls)),
            "feat_has_ip_url": 1.0 if any(u.get("is_ip") for u in urls) else 0.0,
            "feat_has_mismatch_url": 1.0 if any(u.get("text_mismatch") for u in urls) else 0.0,
            "feat_has_suspicious_tld": 1.0 if any(u.get("is_suspicious_tld") for u in urls) else 0.0,
            "feat_has_attachment": 1.0 if len(atts) > 0 else 0.0,
            "feat_has_dangerous_attachment": 1.0 if any(a.get("is_suspicious_ext") or a.get("magic_mz") for a in atts) else 0.0,
            "feat_has_double_ext": 1.0 if any(a.get("has_double_ext") for a in atts) else 0.0,
            "feat_urgency_count": float(body.get("urgency_count", 0)),
            "feat_domain_age_days": min(domain_age_days, 1000.0) / 1000.0,  # normalized 0-1
            "feat_intel_malicious_count": float(intel_results.get("total_malicious_indicators", 0))
        }
