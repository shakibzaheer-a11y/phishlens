"""
Forensic Security Rules Engine: Evaluates individual heuristic indicators across headers,
content, authentication, URLs, attachments, and threat intelligence.
"""

from typing import Dict, Any, List, Tuple


class ForensicRule:
    def __init__(self, rule_id: str, name: str, category: str, severity: str, weight: int, description: str):
        self.rule_id = rule_id
        self.name = name
        self.category = category  # "AUTH", "HEADER", "URL", "ATTACHMENT", "INTEL", "CONTENT"
        self.severity = severity  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        self.weight = weight
        self.description = description

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        """Returns (triggered: bool, detail: str). Must be implemented by subclasses."""
        raise NotImplementedError


class RuleSPFFail(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_AUTH_01", "SPF Validation Failure", "AUTH", "HIGH", 25,
            "Sender Policy Framework (SPF) failed or returned softfail, indicating sender IP is unauthorized."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        spf = parsed_email.get("authentication", {}).get("spf", {})
        verdict = spf.get("verdict", "")
        if verdict in ("fail", "softfail"):
            return True, f"SPF returned '{verdict.upper()}'. {spf.get('details', '')}"
        return False, ""


class RuleDKIMFail(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_AUTH_02", "DKIM Validation Failure", "AUTH", "HIGH", 20,
            "DomainKeys Identified Mail (DKIM) signature failed validation or was tampered with in transit."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        dkim = parsed_email.get("authentication", {}).get("dkim", {})
        verdict = dkim.get("verdict", "")
        if verdict == "fail":
            return True, f"DKIM validation failed for domain '{dkim.get('domain', 'unknown')}'"
        return False, ""


class RuleDMARCFail(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_AUTH_03", "DMARC Policy Violation", "AUTH", "HIGH", 25,
            "DMARC validation failed. Sender domain policy prohibits unaligned messages."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        dmarc = parsed_email.get("authentication", {}).get("dmarc", {})
        verdict = dmarc.get("verdict", "")
        if verdict in ("fail", "reject", "quarantine"):
            return True, f"DMARC verdict '{verdict.upper()}'. Policy action: {dmarc.get('action', 'none')}"
        return False, ""


class RuleDisplayNameSpoof(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_HDR_01", "Display Name Brand Impersonation", "HEADER", "CRITICAL", 35,
            "Sender display name claims a trusted brand or email address that differs from the actual envelope sender."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        sender = parsed_email.get("sender_analysis", {})
        if sender.get("display_name_spoof"):
            return True, sender.get("spoof_indicator", "Display name impersonation detected")
        return False, ""


class RuleReplyToMismatch(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_HDR_02", "Reply-To Address Mismatch", "HEADER", "MEDIUM", 20,
            "Reply-To address points to an external or conflicting mailbox, typical of BEC and credential harvest."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        sender = parsed_email.get("sender_analysis", {})
        if sender.get("reply_to_mismatch"):
            return True, f"Sender is '{sender.get('from_addr')}', but replies route to '{sender.get('reply_to_addr')}'"
        return False, ""


class RuleURLTextMismatch(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_URL_01", "Phishing Link Text Mismatch", "URL", "CRITICAL", 40,
            "Anchor text shows a legitimate domain, but hyperlinked href target redirects to an unrelated domain."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        urls = parsed_email.get("urls", [])
        mismatches = [u for u in urls if u.get("text_mismatch")]
        if mismatches:
            details = "; ".join([m["mismatch_detail"] for m in mismatches[:2]])
            return True, f"{len(mismatches)} deceptive link(s) detected: {details}"
        return False, ""


class RuleURLRawIP(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_URL_02", "URL Host is Raw IP Address", "URL", "HIGH", 25,
            "Links in email body use raw IP addresses rather than registered hostnames to evade DNS filtering."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        urls = parsed_email.get("urls", [])
        ip_urls = [u for u in urls if u.get("is_ip")]
        if ip_urls:
            return True, f"{len(ip_urls)} link(s) point directly to raw IP addresses ({ip_urls[0]['hostname']})"
        return False, ""


class RuleSuspiciousTLD(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_URL_03", "High-Risk Suspicious TLD", "URL", "MEDIUM", 15,
            "URLs utilize top-level domains statistically associated with bulk spam and credential phishing."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        urls = parsed_email.get("urls", [])
        bad_tld_urls = [u for u in urls if u.get("is_suspicious_tld")]
        if bad_tld_urls:
            tlds = list({u['tld'] for u in bad_tld_urls})
            return True, f"Links utilize high-risk TLDs: {', '.join(tlds)}"
        return False, ""


class RuleDangerousAttachment(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_ATT_01", "Dangerous Executable or Script Attachment", "ATTACHMENT", "CRITICAL", 45,
            "Attachment contains an executable, script, or installer capable of arbitrary code execution."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        attachments = parsed_email.get("attachments", [])
        bad_atts = [a for a in attachments if a.get("is_suspicious_ext") or a.get("magic_mz")]
        if bad_atts:
            names = [a["filename"] for a in bad_atts]
            return True, f"Dangerous attachment detected: {', '.join(names)}"
        return False, ""


class RuleDoubleExtensionAttachment(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_ATT_02", "Double Extension Obfuscation", "ATTACHMENT", "CRITICAL", 50,
            "Attachment disguised as a benign file type (e.g. .pdf.exe) to trick users into executing malware."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        attachments = parsed_email.get("attachments", [])
        double_exts = [a for a in attachments if a.get("has_double_ext")]
        if double_exts:
            names = [a["filename"] for a in double_exts]
            return True, f"Double extension masquerade detected: {', '.join(names)}"
        return False, ""


class RuleMacroDocument(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_ATT_03", "Macro-Enabled Office Document", "ATTACHMENT", "HIGH", 35,
            "Attachment is a macro-enabled document (.docm/.xlsm), standard vehicle for malware droppers."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        attachments = parsed_email.get("attachments", [])
        macros = [a for a in attachments if a.get("is_macro")]
        if macros:
            names = [a["filename"] for a in macros]
            return True, f"Macro-enabled document(s) detected: {', '.join(names)}"
        return False, ""


class RuleUrgencyPhrasing(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_CONTENT_01", "Psychological Urgency & Coercive Phrasing", "CONTENT", "MEDIUM", 15,
            "High frequency of urgent, punitive, or panic-inducing phrasing used in social engineering."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        urgency_count = parsed_email.get("body_analysis", {}).get("urgency_count", 0)
        keywords = parsed_email.get("body_analysis", {}).get("detected_urgency_keywords", [])
        if urgency_count >= 2:
            return True, f"Social engineering triggers detected ({urgency_count}): {', '.join(keywords[:4])}"
        return False, ""


class RuleNewlyRegisteredDomain(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_INTEL_01", "Newly Registered Sender Domain", "INTEL", "HIGH", 35,
            "Sender domain was registered less than 30 days ago, a hallmark of disposable phishing infrastructure."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        domain_age = intel_results.get("sender_domain_age", {})
        if domain_age and domain_age.get("is_malicious"):
            return True, domain_age.get("details", "Sender domain created <30 days ago")
        return False, ""


class RuleThreatIntelHit(ForensicRule):
    def __init__(self):
        super().__init__(
            "RULE_INTEL_02", "External Threat Intelligence Blacklist Hit", "INTEL", "CRITICAL", 50,
            "One or more indicators (URL, attachment hash, domain, sender IP) flagged by VirusTotal/URLhaus/AbuseIPDB."
        )

    def evaluate(self, parsed_email: Dict[str, Any], intel_results: Dict[str, Any]) -> Tuple[bool, str]:
        mal_count = intel_results.get("total_malicious_indicators", 0)
        if mal_count > 0:
            hits = []
            if intel_results.get("sender_ip_intel", {}).get("is_malicious"):
                hits.append("Sender IP flagged")
            if intel_results.get("sender_domain_intel", {}).get("is_malicious"):
                hits.append("Sender domain flagged")
            for u in intel_results.get("url_intel", []):
                if u.get("is_malicious"):
                    hits.append(f"Malicious URL ({u['url'][:30]}...)")
            for att in intel_results.get("attachment_intel", []):
                if att.get("intel", {}).get("is_malicious"):
                    hits.append(f"Malicious Hash for {att['filename']}")
            return True, f"{mal_count} indicator(s) confirmed malicious: {', '.join(hits[:3])}"
        return False, ""


DEFAULT_RULES = [
    RuleSPFFail(),
    RuleDKIMFail(),
    RuleDMARCFail(),
    RuleDisplayNameSpoof(),
    RuleReplyToMismatch(),
    RuleURLTextMismatch(),
    RuleURLRawIP(),
    RuleSuspiciousTLD(),
    RuleDangerousAttachment(),
    RuleDoubleExtensionAttachment(),
    RuleMacroDocument(),
    RuleUrgencyPhrasing(),
    RuleNewlyRegisteredDomain(),
    RuleThreatIntelHit()
]
