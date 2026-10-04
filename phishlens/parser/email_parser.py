"""
Email Parser Engine: Complete RFC 5322 MIME email parsing, header forensic analysis,
received hop tracking, urgency keyword profiling, and integration with auth, URL, and attachment extractors.
"""

import email
from email import policy
from email.utils import parseaddr
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from phishlens.parser.auth_validator import AuthValidator
from phishlens.parser.url_extractor import URLExtractor
from phishlens.parser.attachment_extractor import AttachmentExtractor


URGENCY_KEYWORDS = [
    "urgent", "immediately", "account suspended", "suspended", "action required",
    "verify your account", "security alert", "unauthorized access", "password expire",
    "terminate", "violation", "unusual activity", "wire transfer", "gift card",
    "giftcard", "payroll", "invoice due", "within 24 hours", "within 48 hours",
    "final notice", "confirm identity", "tax refund", "kyc"
]


class EmailParser:
    """Core parser for email forensic artifacts."""

    @classmethod
    def parse_file(cls, file_path: str) -> Dict[str, Any]:
        """Loads and parses an .eml file from disk."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        return cls.parse_message(msg, source_filename=path.name)

    @classmethod
    def parse_raw(cls, raw_email_bytes: bytes, source_filename: str = "raw_email.eml") -> Dict[str, Any]:
        """Parses email from raw bytes."""
        msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
        return cls.parse_message(msg, source_filename=source_filename)

    @classmethod
    def parse_message(cls, msg: email.message.EmailMessage, source_filename: str = "email.eml") -> Dict[str, Any]:
        """Performs deep forensic extraction on an EmailMessage object."""
        # 1. Header Extraction
        headers: Dict[str, Any] = {}
        for k, v in msg.items():
            if k in headers:
                if isinstance(headers[k], list):
                    headers[k].append(str(v))
                else:
                    headers[k] = [headers[k], str(v)]
            else:
                headers[k] = str(v)

        subject = str(msg.get("Subject", "(No Subject)"))
        date_str = str(msg.get("Date", ""))
        message_id = str(msg.get("Message-ID", ""))
        x_mailer = str(msg.get("X-Mailer", "") or msg.get("User-Agent", ""))

        # Addresses
        from_raw = str(msg.get("From", ""))
        from_display, from_addr = parseaddr(from_raw)
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

        to_raw = str(msg.get("To", ""))
        to_display, to_addr = parseaddr(to_raw)

        reply_to_raw = str(msg.get("Reply-To", ""))
        reply_display, reply_addr = parseaddr(reply_to_raw)
        reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

        return_path_raw = str(msg.get("Return-Path", ""))
        _, return_path_addr = parseaddr(return_path_raw)
        return_path_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""

        # Discrepancy Analysis
        reply_to_mismatch = bool(reply_addr and from_addr and reply_addr.lower() != from_addr.lower())
        return_path_mismatch = bool(return_path_addr and from_addr and return_path_domain != from_domain)

        # Display name spoofing: e.g. From: "Microsoft Office 365 <attacker@gmail.com>"
        display_name_spoof = False
        spoof_indicator = ""
        if "@" in from_display and from_addr not in from_display:
            display_name_spoof = True
            spoof_indicator = f"Display name contains conflicting email: {from_display}"
        elif any(brand in from_display.lower() for brand in ["microsoft", "google", "apple", "paypal", "dhl", "fedex", "chase", "bank of america"]) and from_domain not in ["microsoft.com", "google.com", "apple.com", "paypal.com", "dhl.com", "fedex.com", "chase.com", "bankofamerica.com"]:
            display_name_spoof = True
            spoof_indicator = f"Display name claims trusted brand '{from_display}' but sender domain is '{from_domain}'"

        # 2. Received Chain (Hops) Parsing
        received_headers = msg.get_all("Received", [])
        hops = cls._parse_received_hops(received_headers)
        originating_ip = hops[-1]["ip"] if hops and hops[-1]["ip"] else None

        # 3. Body Extraction
        text_content = ""
        html_content = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" not in content_disposition.lower():
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            decoded = payload.decode(charset, errors="replace")
                            if content_type == "text/plain":
                                text_content += decoded + "\n"
                            elif content_type == "text/html":
                                html_content += decoded + "\n"
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace") if payload else ""
                if msg.get_content_type() == "text/html":
                    html_content = decoded
                else:
                    text_content = decoded
            except Exception:
                pass

        # Urgency & Social Engineering Keywords
        combined_text = (subject + " " + text_content + " " + html_content).lower()
        detected_urgency_keywords = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]

        # 4. Authentication Validation (SPF/DKIM/DMARC)
        auth_status = AuthValidator.parse_auth_headers(headers)

        # 5. URL Extraction & Analysis
        extracted_urls = URLExtractor.extract_from_html_and_text(html_content, text_content)

        # 6. Attachment Extraction & Hashing
        attachments = AttachmentExtractor.extract_attachments(msg)

        return {
            "metadata": {
                "source_filename": source_filename,
                "subject": subject,
                "date": date_str,
                "message_id": message_id,
                "x_mailer": x_mailer,
                "has_attachments": len(attachments) > 0,
                "attachment_count": len(attachments),
                "url_count": len(extracted_urls)
            },
            "sender_analysis": {
                "from_raw": from_raw,
                "from_display": from_display,
                "from_addr": from_addr,
                "from_domain": from_domain,
                "to_raw": to_raw,
                "to_addr": to_addr,
                "reply_to_addr": reply_addr,
                "reply_to_mismatch": reply_to_mismatch,
                "return_path_addr": return_path_addr,
                "return_path_mismatch": return_path_mismatch,
                "display_name_spoof": display_name_spoof,
                "spoof_indicator": spoof_indicator,
                "originating_ip": originating_ip
            },
            "authentication": auth_status,
            "received_chain": {
                "total_hops": len(hops),
                "hops": hops,
                "originating_ip": originating_ip
            },
            "body_analysis": {
                "has_plain_text": bool(text_content),
                "has_html": bool(html_content),
                "plain_text_snippet": text_content[:500] if text_content else "",
                "detected_urgency_keywords": detected_urgency_keywords,
                "urgency_count": len(detected_urgency_keywords)
            },
            "urls": extracted_urls,
            "attachments": attachments,
            "raw_headers": headers
        }

    @staticmethod
    def _parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
        """Parses individual Received headers into sequential hops."""
        hops = []
        ip_regex = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

        for idx, header in enumerate(received_headers):
            # Extract IP
            ip_match = ip_regex.search(header)
            ip = ip_match.group(1) if ip_match else None

            # Extract From and By MTAs
            from_mta = None
            by_mta = None
            from_match = re.search(r"from\s+([^\s]+)", header, re.IGNORECASE)
            if from_match:
                from_mta = from_match.group(1)

            by_match = re.search(r"by\s+([^\s]+)", header, re.IGNORECASE)
            if by_match:
                by_mta = by_match.group(1)

            hops.append({
                "hop_number": idx + 1,
                "raw": header.strip(),
                "ip": ip,
                "from_mta": from_mta,
                "by_mta": by_mta
            })

        return hops
